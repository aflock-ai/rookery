// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package keyguard hardens the cilock process against extraction or tampering
// of in-memory secrets — above all the signing key — by a same-privilege local
// attacker. This is a NON-FALSIFIABLE-PROVENANCE control: if an attacker on the
// build host can lift the signing key out of cilock's memory mid-build (via
// ptrace, process_vm_readv, /proc/<pid>/mem, or a core dump), then a keyless
// "isolated workflow identity" no longer makes the provenance non-forgeable —
// the key it signs with is exfiltratable. SLSA Build L3 non-forgeability
// therefore requires the key to be unextractable while it is live.
//
// The protection is recorded (read back from the kernel, never asserted blindly)
// so a verifier/policy can treat it as evidence: dumpable==false means a
// same-UID attacker cannot read the process's memory.
//
// Software memory protection raises the bar against same-UID (and, with BPF LSM,
// root software) attackers; a kernel-level root attacker or hypervisor/physical
// access still wins. True non-forgeability ultimately wants the key in hardware
// (TPM/HSM/TEE) that never exposes it to process memory. This package is the
// strong, attestable software-only mitigation.
package keyguard

import "sync"

// State records the anti-tamper protections actually in effect, read back from
// the kernel after Protect() runs. Serialized into the run summary so a verifier
// can gate on it (e.g. require Dumpable==false for an L3 verdict).
type State struct {
	// Applied is true when at least the dumpable protection took effect
	// (Linux). False on platforms without support (e.g. macOS dev).
	Applied bool `json:"applied"`
	// Dumpable is the PR_GET_DUMPABLE read-back: FALSE means protected — a
	// same-UID ptrace / process_vm_readv / /proc/<pid>/mem read is denied and
	// the process is excluded from core dumps.
	Dumpable bool `json:"dumpable"`
	// YamaPtraceScope echoes /proc/sys/kernel/yama/ptrace_scope (-1 if absent).
	// >=1 means the host kernel additionally restricts ptrace across processes.
	YamaPtraceScope int `json:"yama_ptrace_scope"`
	// Note carries a short human explanation (e.g. why a layer didn't apply).
	Note string `json:"note,omitempty"`
}

var (
	mu      sync.Mutex
	current State
)

// Protect applies the in-process anti-tamper hardening and returns (and caches)
// the protection state actually achieved. Idempotent; safe to call once early
// in process startup. Linux-only; a no-op (Applied=false) elsewhere.
func Protect() State {
	s := protect()
	mu.Lock()
	current = s
	mu.Unlock()
	return s
}

// Current returns the protection state from the last Protect() call (zero value
// if Protect was never called).
func Current() State {
	mu.Lock()
	defer mu.Unlock()
	return current
}
