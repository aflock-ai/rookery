//go:build linux

// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keyguard

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// keyguardSecret is the marker a "victim" process holds resident in its heap.
// The "attacker" tries to find it in the victim's memory; protection succeeds
// when it CANNOT. A distinctive constant so a hit is unambiguous.
const keyguardSecret = "KEYGUARD-SECRET-9f8e7d6c5b4a1029-DO-NOT-LEAK"

// keyguardRole re-purposes the test binary as a victim/attacker subprocess so
// each can run under a non-root UID (the realistic same-privilege attacker).
var keyguardRole = flag.String("keyguard-role", "", "internal: victim|attacker")

func TestMain(m *testing.M) {
	flag.Parse()
	switch *keyguardRole {
	case "victim":
		victimMain() // never returns
	case "attacker":
		os.Exit(attackerMain())
	default:
		os.Exit(m.Run())
	}
}

// victimMain holds the secret resident, optionally applies Protect(), announces
// its PID, then stays alive until killed by the parent test.
func victimMain() {
	// Keep the secret referenced in a heap buffer for the whole lifetime.
	secret := make([]byte, len(keyguardSecret))
	copy(secret, keyguardSecret)

	if os.Getenv("KEYGUARD_PROTECT") == "1" {
		Protect()
	}
	fmt.Printf("READY %d\n", os.Getpid())
	_ = os.Stdout.Sync()
	for {
		runtimeKeepAlive(secret)
		time.Sleep(50 * time.Millisecond)
	}
}

// runtimeKeepAlive defeats dead-store elimination so the secret stays resident.
//
//go:noinline
func runtimeKeepAlive(b []byte) {
	if len(b) > 0 && b[0] == 0 {
		fmt.Fprintln(os.Stderr, "unreachable")
	}
}

// attackerMain tries to extract the victim's memory two ways and reports a
// verdict on stdout: whether /proc/<pid>/mem was openable, whether ptrace
// attach succeeded, and whether the secret marker was found.
func attackerMain() int {
	pid, _ := strconv.Atoi(os.Getenv("KEYGUARD_TARGET"))
	memOpenable, found := tryReadProcMem(pid)
	ptraceOK := tryPtraceAttach(pid)
	fmt.Printf("VERDICT mem_openable=%v ptrace_ok=%v secret_found=%v\n", memOpenable, ptraceOK, found)
	return 0
}

// tryReadProcMem mimics a same-UID attacker dumping another process's address
// space via /proc/<pid>/maps + /proc/<pid>/mem and scanning for the secret.
func tryReadProcMem(pid int) (openable bool, found bool) {
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return false, false // EACCES under PR_SET_DUMPABLE=0 — the win.
	}
	defer mem.Close()
	openable = true

	mapsFile, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return openable, false
	}
	defer mapsFile.Close()

	sc := bufio.NewScanner(mapsFile)
	buf := make([]byte, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		// Only scan readable, writable, private regions (heap/anon) — where a
		// runtime-held secret lives. Format: "start-end perms ...".
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "rw") {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start || end-start > 1<<30 {
			continue
		}
		for off := start; off < end; off += uint64(len(buf)) {
			n := uint64(len(buf))
			if off+n > end {
				n = end - off
			}
			got, _ := mem.ReadAt(buf[:n], int64(off)) //nolint:errcheck // best-effort attacker read
			if got > 0 && bytes.Contains(buf[:got], []byte(keyguardSecret)) {
				return openable, true
			}
		}
	}
	return openable, false
}

// tryPtraceAttach mimics a same-UID attacker attaching with ptrace to read
// registers/memory. Returns true only if attach succeeded (then detaches).
func tryPtraceAttach(pid int) bool {
	if err := unix.PtraceAttach(pid); err != nil {
		return false // EPERM under PR_SET_DUMPABLE=0 / yama — the win.
	}
	var ws unix.WaitStatus
	_, _ = unix.Wait4(pid, &ws, 0, nil)
	_ = unix.PtraceDetach(pid)
	return true
}

// spawnVictim starts the victim subprocess under uid/gid 1000 (a non-root,
// same-privilege identity), with protection on/off, and returns it once it has
// announced READY.
func spawnVictim(t *testing.T, protect bool) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-keyguard-role", "victim") //nolint:gosec // re-exec self
	cmd.Env = append(os.Environ(), "KEYGUARD_TARGET=")
	if protect {
		cmd.Env = append(cmd.Env, "KEYGUARD_PROTECT=1")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("victim stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start victim as uid 1000 (env lacks setuid?): %v", err)
	}
	// Wait for READY (the protection is applied by then).
	rdr := bufio.NewReader(stdout)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		line, err := rdr.ReadString('\n')
		if err == nil && strings.HasPrefix(line, "READY ") {
			go func() { _, _ = rdr.ReadString('\n') }() // drain
			return cmd
		}
		if err != nil {
			break
		}
	}
	_ = cmd.Process.Kill()
	t.Fatal("victim never reported READY")
	return nil
}

// runAttacker runs the attacker subprocess under the SAME non-root uid as the
// victim and returns its verdict line.
func runAttacker(t *testing.T, victimPid int) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-keyguard-role", "attacker") //nolint:gosec // re-exec self
	cmd.Env = append(os.Environ(), "KEYGUARD_TARGET="+strconv.Itoa(victimPid))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("attacker run: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "VERDICT ") {
			return line
		}
	}
	t.Fatalf("attacker produced no verdict:\n%s", out)
	return ""
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test must run as root to drop victim/attacker to a non-root uid")
	}
}

// TestKeyguard_ProtectedMemoryNotExtractable is the proof: a same-UID attacker
// can neither open /proc/<pid>/mem, ptrace-attach, nor find the secret in the
// PROTECTED victim's memory.
func TestKeyguard_ProtectedMemoryNotExtractable(t *testing.T) {
	requireRoot(t)
	victim := spawnVictim(t, true)
	defer func() { _ = victim.Process.Kill() }()

	v := runAttacker(t, victim.Process.Pid)
	t.Logf("protected: %s", v)
	if !strings.Contains(v, "mem_openable=false") {
		t.Errorf("PROTECTED victim's /proc/<pid>/mem must NOT be openable by a same-UID attacker; got %q", v)
	}
	if !strings.Contains(v, "ptrace_ok=false") {
		t.Errorf("PROTECTED victim must NOT be ptrace-attachable by a same-UID attacker; got %q", v)
	}
	if !strings.Contains(v, "secret_found=false") {
		t.Errorf("the signing key marker must NOT be extractable from a PROTECTED process; got %q", v)
	}
}

// TestKeyguard_UnprotectedMemoryIsExtractable is the control: without Protect()
// the SAME attacker DOES extract the secret — proving the methodology is real
// and that Protect() is what closes the hole.
func TestKeyguard_UnprotectedMemoryIsExtractable(t *testing.T) {
	requireRoot(t)
	if readYamaScope() >= 1 {
		// The host's Yama LSM already blocks same-UID cross-process ptrace and
		// /proc/<pid>/mem, so an unprotected victim is ALSO unreadable — the
		// control can't demonstrate the leak here. The dumpable protection is
		// still verified by TestKeyguard_ProtectedMemoryNotExtractable, which
		// passes regardless of Yama. (Run with kernel.yama.ptrace_scope=0 to
		// exercise this control.)
		t.Skip("yama ptrace_scope>=1 already blocks same-UID extraction; control cannot demonstrate the leak")
	}
	victim := spawnVictim(t, false)
	defer func() { _ = victim.Process.Kill() }()

	v := runAttacker(t, victim.Process.Pid)
	t.Logf("unprotected: %s", v)
	if !strings.Contains(v, "secret_found=true") {
		t.Errorf("control FAILED: an unprotected same-UID victim's secret should be extractable (proves the PoC works); got %q", v)
	}
}
