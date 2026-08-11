// Copyright 2026 TestifySec, Inc.
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

package policyverify

import "testing"

// ---------------------------------------------------------------------------
// The minimum-witness option reaches the policy engine through an ANONYMOUS
// INTERFACE ASSERTION in attestation/workflow/verify.go:
//
//	if lw, ok := att.(interface{ SetLazyWitness(bool) }); ok { lw.SetLazyWitness(true) }
//
// That pattern (copied from the fan-out guard) keeps third-party attestors
// compiling, and it has one failure mode: rename or re-sign the method and the
// assertion silently stops matching. The flag then reads as "on" everywhere in
// config while being INERT in the engine — the worst possible state for a
// rollout flag, because the operator has no signal.
//
// These two tests make that failure a compile/test failure instead.
// ---------------------------------------------------------------------------

// The attestor must satisfy the EXACT anonymous interface the workflow layer
// asserts on. Written as the same anonymous type, deliberately: a named
// interface here could drift from the one at the call site.
func TestAttestor_SatisfiesTheLazyWitnessConfigurerAssertion(t *testing.T) {
	var att interface{} = New()
	lw, ok := att.(interface{ SetLazyWitness(bool) })
	if !ok {
		t.Fatal("*Attestor does not satisfy interface{ SetLazyWitness(bool) }; " +
			"attestation/workflow/verify.go asserts exactly this shape, so VerifyWithLazyWitness would silently do nothing")
	}
	lw.SetLazyWitness(true)
}

// And the setter must actually latch, in both directions.
func TestAttestor_SetLazyWitnessLatches(t *testing.T) {
	a := New()
	if a.lazyWitness {
		t.Fatal("a fresh attestor must default to eager verification")
	}
	a.SetLazyWitness(true)
	if !a.lazyWitness {
		t.Fatal("SetLazyWitness(true) must enable the minimum-witness option")
	}
	a.SetLazyWitness(false)
	if a.lazyWitness {
		t.Fatal("SetLazyWitness(false) must disable it again")
	}
}
