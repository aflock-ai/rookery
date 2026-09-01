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
// can gate on it — via Protected(), NOT by reading a field directly.
//
// Why Protected() and not `Dumpable == false`: this struct's ZERO VALUE has
// Dumpable false, and false is the PROTECTED reading. A State that was never
// populated — Current() before Protect() ran, a decoded summary that omitted the
// object, a zero value from any future code path — therefore satisfies
// "Dumpable == false" while describing a process that was never hardened at all.
// Absence would read as protection, which is the wrong direction for a control
// whose entire job is to make a signing key unextractable.
//
// Applied is the discriminator, so the safe predicate needs both fields. It is a
// method rather than a documented convention because a convention has to be
// re-derived correctly by every future caller, and this one is easy to get
// backwards.
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
//
// A zero value here is NOT "protected" — see State and Protected(). Callers
// gating on hardening must use Protected(), never a bare field read.
func Current() State {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// Protected reports whether the process was actually hardened: the protection
// was applied AND the kernel read-back confirms the process is non-dumpable.
//
// This is the ONE predicate a verifier or policy should use. Both terms are
// required, and the reason is the zero value: State{} has Dumpable false, which
// on its own reads as protected, so a state that was never populated would pass
// a Dumpable-only check. Applied is what distinguishes "the kernel told us the
// process is non-dumpable" from "nobody ever asked".
//
// Fails closed by construction: every way of not knowing — never called, absent
// from a decoded summary, an unsupported platform — yields false.
func (s State) Protected() bool {
	return s.Applied && !s.Dumpable
}
