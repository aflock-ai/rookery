// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package fanotify

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// catTwice runs `/bin/cat target` once, snapshots EventsHashed, runs it
// again, and returns (hashedAfterFirst, deltaOnSecond). Each cat opens the
// target plus its own shared libs; both runs touch the same set.
func catTwice(t *testing.T, h *Handler, target string) (uint64, uint64) {
	t.Helper()
	run := func() {
		cmd := exec.Command("/bin/cat", target)
		if sudoUid := os.Getenv("SUDO_UID"); sudoUid != "" {
			uid, _ := strconv.Atoi(sudoUid)
			gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true},
			}
		}
		if err := cmd.Run(); err != nil {
			t.Fatalf("cat %s: %v", target, err)
		}
		time.Sleep(150 * time.Millisecond) // let the handler drain
	}
	run()
	first := h.GetStats().EventsHashed
	run()
	second := h.GetStats().EventsHashed
	return first, second - first
}

// TestIgnoreOnce_SuppressesRepeatOpenPerm is the LOAD-BEARING experiment:
// it proves on the running kernel that adding an inode FAN_MARK_IGNORE for
// FAN_OPEN_PERM actually stops the kernel re-delivering open-permission
// events for that inode. The whole "hash each inode once" design rests on
// this — both agents flagged it as unverified. If this passes, the storm
// of repeat opens on a cold build collapses in-kernel.
//
// Signal: with ignoreOnce ON, a SECOND identical `cat` adds ZERO new hash
// events (everything it touches was hashed + ignored on the first run).
func TestIgnoreOnce_SuppressesRepeatOpenPerm(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for fanotify")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	skipIfNoFanotify(t, dir)

	target := dir + "/material.bin"
	if err := os.WriteFile(target, []byte("once-only content"), 0o644); err != nil {
		t.Fatal(err)
	}
	chownToSudoInvoker(dir)

	t.Setenv(EnvVarIgnoreOnce, "1")
	h, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer h.Close()
	if !h.ignoreOnce {
		t.Fatal("ignoreOnce not enabled despite env")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = h.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	first, delta := catTwice(t, h, target)

	stats := h.GetStats()
	if first == 0 {
		t.Fatalf("first run hashed nothing; handler not active? stats=%+v", stats)
	}
	if stats.IgnoreMarksAdded == 0 {
		t.Fatalf("no ignore marks were added; experiment inactive; stats=%+v", stats)
	}
	if delta != 0 {
		t.Errorf("FAN_MARK_IGNORE did NOT suppress repeat opens: second run hashed %d new events (want 0); stats=%+v", delta, stats)
	}

	cancel()
	_ = h.Close()
	wg.Wait()
}

// TestIgnoreOnce_DisabledStillRehashes is the control: WITHOUT the
// experiment, the kernel re-delivers FAN_OPEN_PERM on every open, so a
// second cat re-hashes. Confirms the delta==0 above is caused by the
// ignore mark, not by some other dedup masking the measurement.
func TestIgnoreOnce_DisabledStillRehashes(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for fanotify")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	skipIfNoFanotify(t, dir)

	target := dir + "/material.bin"
	if err := os.WriteFile(target, []byte("rehash me"), 0o644); err != nil {
		t.Fatal(err)
	}
	chownToSudoInvoker(dir)

	// ignoreOnce is default-on now, so explicitly DISABLE it for the control.
	t.Setenv(EnvVarIgnoreOnce, "0")
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

	_, delta := catTwice(t, h, target)
	if delta == 0 {
		t.Errorf("control failed: second run hashed 0 new events without ignore-once — the measurement is masked by another dedup, so the suppression test is not meaningful")
	}

	cancel()
	_ = h.Close()
	wg.Wait()
}
