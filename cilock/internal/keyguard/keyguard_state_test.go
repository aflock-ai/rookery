// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keyguard

import "testing"

// The zero value must NOT read as protected.
//
// keyguard exists so a same-privilege attacker cannot lift the signing key out
// of cilock's memory — without that, keyless provenance is forgeable. The
// struct's zero value has Dumpable false, and false is the PROTECTED reading, so
// a bare `Dumpable == false` check is satisfied by a State nobody ever
// populated: Current() before Protect() ran, an omitted object in a decoded run
// summary, any future path that returns State{}.
//
// That is absence reading as protection, on the control that makes provenance
// non-forgeable. Protected() requires Applied too, so every way of not knowing
// answers false.
//
// These run on every platform, unlike keyguard_tamper_linux_test.go — which is
// //go:build linux and therefore invisible on the macOS machines this is
// developed on. It reported "no test files" there, which is how this package
// looked untested while carrying 252 lines of tamper tests.
func TestProtectedFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		state State
		want  bool
	}{
		{
			// THE TRAP. Satisfies "Dumpable == false" while describing a
			// process that was never hardened.
			name:  "zero value is not protected",
			state: State{},
			want:  false,
		},
		{
			name:  "applied and non-dumpable is protected",
			state: State{Applied: true, Dumpable: false},
			want:  true,
		},
		{
			// Applied but the kernel read-back says the process is still
			// dumpable: the hardening did not take. Claiming protection here
			// would trust the attempt over the read-back, which is the reason
			// the read-back exists.
			name:  "applied but still dumpable is not protected",
			state: State{Applied: true, Dumpable: true},
			want:  false,
		},
		{
			// The non-Linux stub's shape.
			name:  "unsupported platform is not protected",
			state: State{Applied: false, Dumpable: true, YamaPtraceScope: -1},
			want:  false,
		},
		{
			// Yama hardening on the host says nothing about THIS process being
			// non-dumpable; it must not carry the verdict on its own.
			name:  "yama alone does not confer protection",
			state: State{Applied: false, Dumpable: false, YamaPtraceScope: 2},
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.Protected(); got != tc.want {
				t.Errorf("State{Applied:%v Dumpable:%v Yama:%d}.Protected() = %v, want %v",
					tc.state.Applied, tc.state.Dumpable, tc.state.YamaPtraceScope, got, tc.want)
			}
		})
	}
}

// Current() before Protect() must not claim protection. This is the concrete
// path by which a zero value reaches a caller.
func TestCurrentBeforeProtectIsNotProtected(t *testing.T) {
	mu.Lock()
	saved := current
	current = State{}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		current = saved
		mu.Unlock()
	})

	if Current().Protected() {
		t.Error("Current() reported protected before Protect() ever ran — absence must not read as protection")
	}
}
