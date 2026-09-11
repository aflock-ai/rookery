// Copyright 2025 The Witness Contributors
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

// The material-manifest knob reaches this attestor through a DUCK-TYPED
// assertion in attestation/workflow/verify.go:
//
//	if mm, ok := att.(interface{ SetMaterialManifests(map[string][]byte) }); ok {
//		mm.SetMaterialManifests(vo.materialManifests)
//	}
//
// The failure mode of that pattern is SILENCE. Rename or re-sign the method and
// the assertion simply stops matching: the option still reads as set in the
// caller, no compiler error appears, and the engine never receives the
// manifests — so every detached-leaf chain fails closed with "manifest not
// found" while the caller believes it supplied them.
//
// This test pins the EXACT anonymous interface the workflow asserts, which is
// the only thing that turns that silent break into a red build.
func TestAttestorSatisfiesMaterialManifestSetter(t *testing.T) {
	var att any = New()

	mm, ok := att.(interface {
		SetMaterialManifests(map[string][]byte)
	})
	if !ok {
		t.Fatal("*Attestor does not satisfy interface{ SetMaterialManifests(map[string][]byte) }; " +
			"applyOptionalVerifyCapabilities in attestation/workflow/verify.go asserts exactly " +
			"this shape, so the manifests would be silently dropped")
	}
	mm.SetMaterialManifests(map[string][]byte{"abc": []byte("{}")})
}

// TestSetMaterialManifestsLatches: the value must survive on the attestor, since
// it is read later, at Attest time, when the policy verify options are built.
func TestSetMaterialManifestsLatches(t *testing.T) {
	a := New()
	if len(a.materialManifests) != 0 {
		t.Fatalf("a fresh attestor already carries %d manifests", len(a.materialManifests))
	}

	body := []byte(`{"schemaVersion":"x"}`)
	a.SetMaterialManifests(map[string][]byte{"deadbeef": body})

	got, ok := a.materialManifests["deadbeef"]
	if !ok {
		t.Fatal("SetMaterialManifests did not latch the value")
	}
	if string(got) != string(body) {
		t.Errorf("latched %q, want %q", got, body)
	}
}
