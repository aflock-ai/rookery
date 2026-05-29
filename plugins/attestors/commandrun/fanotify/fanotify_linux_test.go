// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package fanotify

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// skipIfNoFanotify skips when the test environment can't run
// fanotify (no CAP_SYS_ADMIN, kernel doesn't support, mount type
// rejects mark).
func skipIfNoFanotify(t *testing.T, path string) {
	t.Helper()
	if err := Probe(path); err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
}

// chownToSudoInvoker walks dir and chowns/chmods everything so the
// SUDO_UID-downgraded child can read+execute. Mirrors the production
// case where the build user owns the workspace.
func chownToSudoInvoker(dir string) {
	sudoUidStr := os.Getenv("SUDO_UID")
	sudoGidStr := os.Getenv("SUDO_GID")
	if sudoUidStr == "" || sudoGidStr == "" {
		return
	}
	uid, e1 := strconv.Atoi(sudoUidStr)
	gid, e2 := strconv.Atoi(sudoGidStr)
	if e1 != nil || e2 != nil {
		return
	}
	for cur := dir; cur != "" && cur != "/tmp" && cur != "/"; cur = filepath.Dir(cur) {
		_ = os.Chmod(cur, 0o755)
	}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		_ = os.Chown(p, uid, gid)
		if info.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
}

func TestProbe_AvailableUnderSudo(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("fanotify needs CAP_SYS_ADMIN; run under sudo")
	}
	dir := t.TempDir()
	if err := Probe(dir); err != nil {
		t.Fatalf("Probe should succeed under root on tmpfs/ext4: %v", err)
	}
}

func TestProbe_FailsWithoutCaps(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test asserts EPERM path; running as root")
	}
	dir := t.TempDir()
	if err := Probe(dir); err == nil {
		t.Fatalf("Probe should fail without CAP_SYS_ADMIN")
	}
}

// TestHandler_HashesOpenedFile is the full end-to-end: launch a
// child that opens a known file, verify the fanotify handler
// captured the digest and the child was allowed to proceed.
func TestHandler_HashesOpenedFile(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for fanotify")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	skipIfNoFanotify(t, dir)

	target := filepath.Join(dir, "witness.bin")
	content := []byte("FANOTIFY-WITNESS-CONTENT-V1\n")
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatal(err)
	}
	chownToSudoInvoker(dir)

	h, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer h.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	var runErr error
	go func() {
		defer wg.Done()
		runErr = h.Run(ctx)
	}()

	// Give the handler a moment to enter the poll loop before we
	// kick off the tracee — without this the tracee can open before
	// fanotify is armed (we already marked but the goroutine may
	// not be polling yet on slow systems).
	time.Sleep(50 * time.Millisecond)

	// Child: cat the file. We use /bin/cat because it's a known
	// stable path. It performs openat → read → close.
	cmd := exec.Command("/bin/cat", target)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if sudoUid := os.Getenv("SUDO_UID"); sudoUid != "" {
		uid, _ := strconv.Atoi(sudoUid)
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true},
		}
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("cat: %v", err)
	}

	// Allow the handler to process the event.
	time.Sleep(100 * time.Millisecond)

	digests := h.Digests()
	want := sha256.Sum256(content)
	got, ok := digests[target]
	if !ok {
		t.Fatalf("witness file not in digests; got %d entries: %+v", len(digests), digests)
	}
	if got != want {
		t.Fatalf("digest mismatch: got %x want %x", got, want)
	}

	stats := h.GetStats()
	if stats.EventsHashed == 0 {
		t.Errorf("EventsHashed should be > 0; stats=%+v", stats)
	}
	if stats.HandlerTimeouts > 0 {
		t.Errorf("HandlerTimeouts should be 0 for a single fast open; got %d", stats.HandlerTimeouts)
	}

	cancel()
	_ = h.Close()
	wg.Wait()
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		t.Errorf("Run returned unexpected error: %v", runErr)
	}
}

// TestHandler_SkipHashSkipsMatchingPaths verifies the SkipHash hook:
// an opened file whose path matches the predicate is released WITHOUT
// hashing (no digest stored, counted under CacheSkips), while a
// non-matching file in the same mark is still hashed normally. This is
// the capture-time cache/temp skip that removes the dominant hash load
// on cold builds.
func TestHandler_SkipHashSkipsMatchingPaths(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for fanotify")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	skipIfNoFanotify(t, dir)

	cacheDir := filepath.Join(dir, "cache")
	if err := os.Mkdir(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	skipped := filepath.Join(cacheDir, "module.go")
	kept := filepath.Join(dir, "source.go")
	for _, f := range []string{skipped, kept} {
		if err := os.WriteFile(f, []byte("content of "+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	chownToSudoInvoker(dir)

	h, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer h.Close()
	// Skip anything under the cache/ subdir.
	h.SkipHash = func(p string) bool { return strings.HasPrefix(p, cacheDir+"/") }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = h.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	for _, f := range []string{skipped, kept} {
		cmd := exec.Command("/bin/cat", f)
		if sudoUid := os.Getenv("SUDO_UID"); sudoUid != "" {
			uid, _ := strconv.Atoi(sudoUid)
			gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true},
			}
		}
		if err := cmd.Run(); err != nil {
			t.Fatalf("cat %s: %v", f, err)
		}
	}
	time.Sleep(100 * time.Millisecond)

	digests := h.Digests()
	if _, ok := digests[skipped]; ok {
		t.Errorf("%s matched SkipHash but was still hashed", skipped)
	}
	if _, ok := digests[kept]; !ok {
		t.Errorf("%s did not match SkipHash but was not hashed; digests=%+v", kept, digests)
	}
	if stats := h.GetStats(); stats.CacheSkips == 0 {
		t.Errorf("CacheSkips should be > 0; stats=%+v", stats)
	}

	cancel()
	_ = h.Close()
	wg.Wait()
}

// TestHandler_ZeroDropUnderBurst opens N files in tight succession
// from a child. fanotify's synchronous backpressure means EVERY
// open is hashed; no drops by construction.
func TestHandler_ZeroDropUnderBurst(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for fanotify")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	skipIfNoFanotify(t, dir)

	// Create N witness files with known content.
	const N = 100
	var paths []string
	var expected = map[string][32]byte{}
	for i := 0; i < N; i++ {
		p := filepath.Join(dir, "burst-"+strconv.Itoa(i)+".bin")
		content := []byte("burst-content-" + strconv.Itoa(i) + "\n")
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		expected[p] = sha256.Sum256(content)
	}
	chownToSudoInvoker(dir)

	h, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer h.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = h.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Child opens every file via cat in one shell invocation.
	args := append([]string{"-c", "for f in \"$@\"; do cat \"$f\" >/dev/null; done", "--"}, paths...)
	cmd := exec.Command("/bin/sh", args...)
	if sudoUid := os.Getenv("SUDO_UID"); sudoUid != "" {
		uid, _ := strconv.Atoi(sudoUid)
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true},
		}
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("sh -c: %v", err)
	}

	// Drain time for the handler to catch up. We're synchronous so
	// the child can't finish until every open has been hashed, but
	// the final response may take a few ms to materialize.
	time.Sleep(200 * time.Millisecond)

	digests := h.Digests()
	missing := 0
	mismatched := 0
	for p, want := range expected {
		got, ok := digests[p]
		if !ok {
			missing++
			continue
		}
		if got != want {
			mismatched++
		}
	}
	if missing > 0 {
		t.Errorf("missing digests: %d / %d (zero-drop violated!)", missing, N)
	}
	if mismatched > 0 {
		t.Errorf("wrong digests: %d / %d", mismatched, N)
	}
	stats := h.GetStats()
	t.Logf("burst test: N=%d EventsHashed=%d Timeouts=%d Bytes=%d",
		N, stats.EventsHashed, stats.HandlerTimeouts, stats.BytesHashed)
	if stats.EventsHashed < uint64(N) {
		t.Errorf("EventsHashed=%d < N=%d (drops or filtered events)", stats.EventsHashed, N)
	}

	cancel()
	_ = h.Close()
	wg.Wait()
}
