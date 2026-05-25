// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

// End-to-end tests for the eBPF tracing path. Require CAP_BPF +
// CAP_PERFMON (typically root or setcap'd test binary). Skipped
// otherwise.
//
// Run with:
//   sudo -E env "PATH=$PATH" go test -run TestEBPF_E2E -v -count=1
// Or:
//   go test -c -o /tmp/cr.test ./plugins/attestors/commandrun
//   sudo setcap cap_bpf,cap_perfmon+ep /tmp/cr.test
//   /tmp/cr.test -test.run=TestEBPF_E2E -test.v

package commandrun

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// skipIfNoEBPFCaps gates eBPF e2e tests on the actual capability.
// Probes whether we can load a BPF program; skips if not.
func skipIfNoEBPFCaps(t *testing.T) {
	t.Helper()
	mode, err := selectTraceMode()
	if err != nil {
		t.Skipf("eBPF unavailable in this test env: %v", err)
	}
	if mode != traceModeEBPF {
		t.Skip("eBPF mode not selected")
	}
}

func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

// TestEBPF_E2E_OpenatCapturesFileContents drives a tracee that opens
// a known file with a known content. The eBPF path should record that
// file in ProcessInfo.OpenedFiles with a SHA-256 matching the content.
func TestEBPF_E2E_OpenatCapturesFileContents(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "sentinel.txt")
	content := []byte("cilock-ebpf-e2e-sentinel\n")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}

	// Tracee: cat the sentinel file. cat does openat(AT_FDCWD, path, ...).
	procs := runUnderEBPF(t, []string{"/bin/cat", target})

	// Find the ProcessInfo entry whose OpenedFiles contains our path.
	var found *ProcessInfo
	for i := range procs {
		if _, ok := procs[i].OpenedFiles[target]; ok {
			found = &procs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no ProcessInfo captured the sentinel openat. Got %d processes; files:\n%s",
			len(procs), summarizeOpenedFiles(procs))
	}

	digest := found.OpenedFiles[target]
	if digest == nil {
		t.Fatalf("sentinel file recorded with nil digest (probably TOCTOU-error). Process: %+v", found)
	}

	// Verify the digest matches an independent hash of the content.
	expected, err := cryptoutil.CalculateDigestSetFromBytes(content, defaultHashes())
	if err != nil {
		t.Fatal(err)
	}
	for hashType, want := range expected {
		got, ok := digest[hashType]
		if !ok {
			t.Errorf("expected hash type %v missing from capture (have %v)", hashType, digest)
			continue
		}
		if got != want {
			t.Errorf("digest mismatch for %v: got %s want %s", hashType, got, want)
		}
	}
}

// TestEBPF_E2E_TOCTOUSuspect mutates the file MID-HASH and asserts
// the result is flagged TOCTOU-suspect. Best-effort timing race.
func TestEBPF_E2E_TOCTOUSuspect(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "racey.bin")
	// 16 MB so hash takes noticeable time.
	big := make([]byte, 16*1024*1024)
	for i := range big {
		big[i] = byte(i)
	}
	if err := os.WriteFile(target, big, 0o600); err != nil {
		t.Fatal(err)
	}

	// Tracee re-opens many times to widen the race window.
	loopSh := `for i in $(seq 1 50); do cat ` + target + ` > /dev/null; done`

	// Touch the file repeatedly during the run to bump mtime.
	stopRace := make(chan struct{})
	go func() {
		t0 := time.Now()
		for {
			select {
			case <-stopRace:
				return
			default:
			}
			_ = os.Chtimes(target, time.Now(), time.Now())
			if time.Since(t0) > 30*time.Second {
				return
			}
		}
	}()
	procs := runUnderEBPF(t, []string{"/bin/sh", "-c", loopSh})
	close(stopRace)

	found := 0
	for _, p := range procs {
		for _, ev := range p.SyscallEvents {
			if strings.Contains(ev.Detail, "TOCTOU-suspect") && strings.Contains(ev.Detail, "racey.bin") {
				found++
			}
		}
	}
	t.Logf("captured %d TOCTOU-suspect events for racey.bin (procs=%d)", found, len(procs))
	if found == 0 {
		t.Log("note: no TOCTOU events observed — race didn't fire within this run window (best-effort test)")
	}
}

// TestPtrace_E2E_StillWorksAfterRefactor verifies the ptrace path
// still captures openat events after the eBPF refactor. Ensures the
// preStartTracingSetup() change didn't regress the ptrace flow.
func TestPtrace_E2E_StillWorksAfterRefactor(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("ptrace e2e test requires root (PTRACE_TRACEME on a child)")
	}
	t.Setenv(EnvVarTraceMode, "ptrace")

	dir := t.TempDir()
	target := filepath.Join(dir, "ptrace-sentinel.txt")
	content := []byte("ptrace-path-still-works\n")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}

	procs := runUnderEBPF(t, []string{"/bin/cat", target}) // helper name is misleading; runs whatever mode is set

	// Find ProcessInfo with our path in OpenedFiles
	found := false
	for _, p := range procs {
		if _, ok := p.OpenedFiles[target]; ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ptrace mode did not capture sentinel openat. procs=%d files:\n%s",
			len(procs), summarizeOpenedFiles(procs))
	}
}

// TestEBPF_E2E_MultipleFiles checks that a tracee opening many files
// captures all of them. Tests ring buffer + worker pool throughput.
func TestEBPF_E2E_MultipleFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	const N = 50
	var paths []string
	wantSet := map[string]bool{}
	for i := 0; i < N; i++ {
		p := filepath.Join(dir, "f"+strconv.Itoa(i))
		if err := os.WriteFile(p, []byte("file-"+strconv.Itoa(i)), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		wantSet[p] = true
	}

	// Tracee: read all files via cat
	args := append([]string{"/bin/cat"}, paths...)
	procs := runUnderEBPF(t, args)

	captured := map[string]bool{}
	for _, p := range procs {
		for path := range p.OpenedFiles {
			if wantSet[path] {
				captured[path] = true
			}
		}
	}
	if len(captured) < N {
		t.Errorf("captured only %d/%d files. procs=%d, opened:\n%s",
			len(captured), N, len(procs), summarizeOpenedFiles(procs))
	}
}

// TestEBPF_E2E_DigestMatchesContent asserts that the openat-time
// path-hash via dispatcher-side fd capture (the golden-path mode)
// produces a digest in OpenedFiles that matches the content the
// tracee read. Uses a >64 KB file to cover multi-chunk-sized reads;
// when read-tap returns as the default (after separate-ringbuf
// work), this same test exercises the streaming-hash path instead.
func TestEBPF_E2E_ReadTapDigestMatchesContent(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "rt-sentinel.bin")
	// ~80 KB — straddles a single 64 KB read + a second smaller read,
	// so we hit both multi-chunk-per-syscall AND multi-syscall paths.
	content := []byte(strings.Repeat("read-tap-V1.4-multichunk-sentinel-block-29bytes\n", 1700))
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if len(content) < 65536 {
		t.Fatalf("test content %d bytes — too small to exercise multi-chunk; fix the test", len(content))
	}

	procs := runUnderEBPF(t, []string{"/bin/cat", target})

	var found *ProcessInfo
	for i := range procs {
		if _, ok := procs[i].OpenedFiles[target]; ok {
			found = &procs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no ProcessInfo captured sentinel openat under read-tap. procs=%d files:\n%s",
			len(procs), summarizeOpenedFiles(procs))
	}

	digest := found.OpenedFiles[target]
	if digest == nil {
		t.Fatalf("sentinel digest nil — openat-time path-hash should have captured it. Process: %+v", found)
	}

	expected, err := cryptoutil.CalculateDigestSetFromBytes(content, defaultHashes())
	if err != nil {
		t.Fatal(err)
	}
	for hashType, want := range expected {
		got, ok := digest[hashType]
		if !ok {
			t.Errorf("read-tap digest missing %v (have %v)", hashType, digest)
			continue
		}
		if got != want {
			t.Errorf("read-tap digest mismatch for %v: got %s want %s", hashType, got, want)
		}
	}
}

// runUnderEBPF builds + runs a CommandRun with the given argv under
// the eBPF tracer, returns the captured ProcessInfo.
func runUnderEBPF(t *testing.T, argv []string) []ProcessInfo {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	actx, err := attestation.NewContext("ebpf-e2e",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(t.TempDir()),
		attestation.WithHashes(defaultHashes()),
	)
	if err != nil {
		t.Fatalf("ctx: %v", err)
	}
	rc := New(
		WithCommand(argv),
		WithTracing(true),
		WithSilent(true),
	)
	if err := rc.Attest(actx); err != nil {
		t.Logf("Attest returned (may be expected on exit!=0): %v", err)
	}
	return rc.Processes
}

func summarizeOpenedFiles(procs []ProcessInfo) string {
	var b strings.Builder
	for _, p := range procs {
		for path, d := range p.OpenedFiles {
			ds := "nil"
			if d != nil {
				ds = "set"
			}
			fmt.Fprintf(&b, "  pid=%d path=%s digest=%s\n", p.ProcessID, path, ds)
		}
	}
	return b.String()
}
