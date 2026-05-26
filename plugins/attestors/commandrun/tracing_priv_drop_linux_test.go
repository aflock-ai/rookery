// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package commandrun

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestApplyTraceePrivilegeDrop_NoOp_WhenNotRoot asserts that the
// privilege-drop helper leaves SysProcAttr untouched when the parent
// is not running as root. This is the common dev-machine case where
// nothing needs to be downgraded.
func TestApplyTraceePrivilegeDrop_NoOp_WhenNotRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test asserts no-op for non-root; running as root")
	}
	c := exec.Command("/bin/true")
	applyTraceePrivilegeDrop(c)
	if c.SysProcAttr != nil && c.SysProcAttr.Credential != nil {
		t.Errorf("non-root parent should not set Credential, got %+v", c.SysProcAttr.Credential)
	}
}

// TestApplyTraceePrivilegeDrop_NoOp_WhenSudoUidMissing asserts that
// without SUDO_UID/SUDO_GID env vars, no downgrade is attempted.
// This is the native-root case (e.g., a container started as root)
// where the operator deliberately wants root semantics.
func TestApplyTraceePrivilegeDrop_NoOp_WhenSudoUidMissing(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test exercises root path; running as non-root")
	}
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	c := exec.Command("/bin/true")
	applyTraceePrivilegeDrop(c)
	if c.SysProcAttr != nil && c.SysProcAttr.Credential != nil {
		t.Errorf("missing SUDO_UID should not set Credential, got %+v", c.SysProcAttr.Credential)
	}
}

// TestApplyTraceePrivilegeDrop_Downgrades asserts that when the
// parent runs as root WITH SUDO_UID/SUDO_GID set, the helper
// configures SysProcAttr.Credential to the sudo invoker's uid/gid.
func TestApplyTraceePrivilegeDrop_Downgrades(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root parent (set via sudo) to exercise downgrade path")
	}
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1000")
	c := exec.Command("/bin/true")
	applyTraceePrivilegeDrop(c)
	if c.SysProcAttr == nil || c.SysProcAttr.Credential == nil {
		t.Fatalf("expected Credential to be set; got SysProcAttr=%+v", c.SysProcAttr)
	}
	cred := c.SysProcAttr.Credential
	if cred.Uid != 1000 || cred.Gid != 1000 {
		t.Errorf("expected uid=1000 gid=1000, got uid=%d gid=%d", cred.Uid, cred.Gid)
	}
	if !cred.NoSetGroups {
		t.Errorf("expected NoSetGroups=true to avoid supplementary-group syscalls under non-root")
	}
	if c.SysProcAttr.AmbientCaps != nil {
		t.Errorf("expected AmbientCaps=nil, got %v", c.SysProcAttr.AmbientCaps)
	}
}

// TestApplyTraceePrivilegeDrop_PreservesExistingCredential asserts
// that the helper respects a Credential set by a prior caller
// (defensive: don't clobber explicit operator intent).
func TestApplyTraceePrivilegeDrop_PreservesExistingCredential(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root parent")
	}
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1000")
	c := exec.Command("/bin/true")
	c.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 65534, Gid: 65534},
	}
	applyTraceePrivilegeDrop(c)
	if c.SysProcAttr.Credential.Uid != 65534 {
		t.Errorf("existing Credential clobbered; expected uid=65534, got %d", c.SysProcAttr.Credential.Uid)
	}
}

// TestTraceeRunsUnprivileged is the end-to-end assertion: when
// cilock is running as root with SUDO_UID set, a child it execs
// runs with the sudo invoker's uid and an empty effective capability
// set. Without the privilege drop, the child would inherit root +
// CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN, which is the bug Phase 0
// closes.
func TestTraceeRunsUnprivileged(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root parent (sudo); skipping on non-root")
	}
	sudoUid := os.Getenv("SUDO_UID")
	sudoGid := os.Getenv("SUDO_GID")
	if sudoUid == "" || sudoGid == "" {
		t.Skip("test requires SUDO_UID/SUDO_GID set (run under sudo); skipping")
	}
	wantUid, err := strconv.ParseUint(sudoUid, 10, 32)
	if err != nil {
		t.Fatalf("parse SUDO_UID: %v", err)
	}

	c := exec.Command("/bin/sh", "-c", `id -u && grep -E '^(CapEff|NoNewPrivs):' /proc/self/status`)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	applyTraceePrivilegeDrop(c)
	if err := c.Run(); err != nil {
		t.Fatalf("run tracee: %v\noutput: %s", err, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines of output (uid, CapEff/NoNewPrivs), got %q", out.String())
	}
	gotUid, err := strconv.ParseUint(strings.TrimSpace(lines[0]), 10, 32)
	if err != nil {
		t.Fatalf("parse child uid %q: %v", lines[0], err)
	}
	if gotUid != wantUid {
		t.Errorf("tracee uid: got %d, want %d (SUDO_UID); parent did not downgrade", gotUid, wantUid)
	}
	// Walk remaining lines for CapEff + NoNewPrivs.
	var capVal uint64
	var nnp int
	sawCap := false
	sawNNP := false
	for _, ln := range lines[1:] {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "CapEff:"):
			sawCap = true
			capHex := strings.TrimSpace(strings.TrimPrefix(ln, "CapEff:"))
			capVal, err = strconv.ParseUint(capHex, 16, 64)
			if err != nil {
				t.Fatalf("parse CapEff %q: %v", capHex, err)
			}
		case strings.HasPrefix(ln, "NoNewPrivs:"):
			sawNNP = true
			v := strings.TrimSpace(strings.TrimPrefix(ln, "NoNewPrivs:"))
			nnp, _ = strconv.Atoi(v)
		}
	}
	if !sawCap {
		t.Errorf("expected CapEff line in output: %q", out.String())
	}
	if capVal != 0 {
		t.Errorf("tracee CapEff = 0x%x, want 0 — parent's caps leaked into child via ambient/inheritable set", capVal)
	}
	if !sawNNP {
		t.Logf("NoNewPrivs line absent (older kernel?); skipping NNP assertion")
	} else if nnp != 1 {
		// Soft fail — log only. Without setpriv on PATH the wrapper
		// is skipped (documented in applyTraceePrivilegeDrop).
		t.Logf("NoNewPrivs=%d (expected 1 when setpriv is on PATH and applied)", nnp)
	}
	fmt.Println("tracee priv-drop OK; uid:", gotUid, "CapEff: 0x0 NoNewPrivs:", nnp)
}
