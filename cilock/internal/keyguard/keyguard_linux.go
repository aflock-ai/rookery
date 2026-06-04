//go:build linux

// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keyguard

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func protect() State {
	s := State{}

	// PR_SET_DUMPABLE=0 is the highest-leverage control. Once cleared, the
	// kernel: (a) denies ptrace(PTRACE_ATTACH) and process_vm_readv from any
	// process that is not root and not already the same privilege, (b) makes
	// /proc/<pid>/mem and /proc/<pid>/maps owned by root and unreadable by the
	// same UID, and (c) excludes the process from core dumps. Net effect: a
	// co-tenant or compromised same-UID process can no longer read the signing
	// key out of cilock's address space. One syscall, no privilege required.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)

	// Read back the real state — never assert protection we didn't verify.
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err == nil {
		s.Dumpable = d != 0
	}
	s.Applied = !s.Dumpable
	if s.Dumpable {
		s.Note = "PR_SET_DUMPABLE did not take effect; process memory may be readable by a same-UID attacker"
	}

	// Best-effort mlock of the currently-resident pages so secrets already in
	// memory aren't swapped to disk. Bounded to CURRENT pages (not MCL_FUTURE)
	// so a content-heavy run can't blow RLIMIT_MEMLOCK or pin gigabytes. We do
	// NOT surface this as keyGuard evidence: it locks pages resident at this
	// instant, which does not cover the signing key allocated later — claiming
	// it as key protection would over-state the guarantee. The dumpable bit is
	// the real, signed key-extraction control.
	_ = unix.Mlockall(unix.MCL_CURRENT)

	s.YamaPtraceScope = readYamaScope()
	return s
}

// readYamaScope returns /proc/sys/kernel/yama/ptrace_scope, or -1 when the Yama
// LSM isn't present. >=1 means the host additionally restricts cross-process
// ptrace (defense in depth on top of the dumpable bit).
func readYamaScope() int {
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return n
}
