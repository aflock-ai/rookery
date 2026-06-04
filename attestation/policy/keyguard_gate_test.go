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

package policy

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// keyGuardRego is the SLSA-L3 non-forgeability gate for command-run/v0.2.
// It MUST stay byte-identical (modulo the leading comment block) to the
// deployable at deploy/dist/rego/commandrun-keyguard.rego — that file is what
// gets base64'd into the dist verify policies; this const is what the engine
// test below proves. A drift here is a security regression.
const keyGuardRego = `package commandrun.keyguard

deny[msg] {
	not _kg
	msg := "command-run keyGuard evidence missing: cannot establish the signing key was protected from extraction while live (SLSA L3 non-forgeability unverifiable)"
}

deny[msg] {
	_kg
	not _kg.applied == true
	msg := "command-run keyGuard.applied is not true: in-memory signing-key protection did not take effect on the build host"
}

deny[msg] {
	_kg
	not _kg.dumpable == false
	msg := "command-run keyGuard.dumpable is not false: the signing key was extractable from the signer's memory during the build (a same-UID attacker could forge provenance) — SLSA L3 requires an isolated, protected signer"
}

_kg := input._meta.keyGuard

_kg := input.attestation._meta.keyGuard
`

// TestCommandRunKeyGuardGate proves the L3 gate against the REAL rego engine
// (EvaluateRegoPolicy): a protected signer passes; a dumpable/unapplied/
// missing/empty keyGuard is denied with a specific reason. Both input shapes
// (raw predicate, and the cross-step `input.attestation` wrap) are exercised.
func TestCommandRunKeyGuardGate(t *testing.T) {
	const crType = "https://aflock.ai/attestations/command-run/v0.2"
	pol := []RegoPolicy{{Name: "commandrun-keyguard.rego", Module: []byte(keyGuardRego)}}

	cases := []struct {
		name     string
		body     string
		wantDeny string // substring of the expected deny reason; "" = must PASS
	}{
		{"protected", `{"_meta":{"keyGuard":{"applied":true,"dumpable":false,"mlocked":true,"yamaPtraceScope":0}}}`, ""},
		{"dumpable", `{"_meta":{"keyGuard":{"applied":true,"dumpable":true}}}`, "dumpable is not false"},
		{"not-applied", `{"_meta":{"keyGuard":{"applied":false,"dumpable":false}}}`, "applied is not true"},
		{"missing-keyguard", `{"_meta":{"version":"v0.2"}}`, "evidence missing"},
		{"no-meta", `{"processes":[]}`, "evidence missing"},
		{"empty-keyguard", `{"_meta":{"keyGuard":{}}}`, "applied is not true"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			att := attestation.NewRawAttestation(crType, []byte(c.body))
			err := EvaluateRegoPolicy(att, pol)
			if c.wantDeny == "" {
				if err != nil {
					t.Fatalf("protected signer must PASS, got deny: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected deny containing %q, got PASS", c.wantDeny)
			}
			if !strings.Contains(err.Error(), c.wantDeny) {
				t.Errorf("deny reason mismatch:\n want substring %q\n got          %v", c.wantDeny, err)
			}
		})
	}
}

// TestCommandRunKeyGuardGate_WrappedInput exercises the real cross-step input
// shape: when stepContext is supplied, EvaluateRegoPolicy wraps the predicate
// under input.attestation, and the gate must still resolve _meta.keyGuard.
func TestCommandRunKeyGuardGate_WrappedInput(t *testing.T) {
	const crType = "https://aflock.ai/attestations/command-run/v0.2"
	pol := []RegoPolicy{{Name: "commandrun-keyguard.rego", Module: []byte(keyGuardRego)}}
	// Non-empty stepContext triggers the input.attestation wrapping.
	stepCtx := map[string]interface{}{"source-git": map[string]interface{}{}}

	protected := attestation.NewRawAttestation(crType, []byte(`{"_meta":{"keyGuard":{"applied":true,"dumpable":false}}}`))
	if err := EvaluateRegoPolicy(protected, pol, stepCtx); err != nil {
		t.Fatalf("wrapped protected signer must PASS, got deny: %v", err)
	}

	dumpable := attestation.NewRawAttestation(crType, []byte(`{"_meta":{"keyGuard":{"applied":true,"dumpable":true}}}`))
	if err := EvaluateRegoPolicy(dumpable, pol, stepCtx); err == nil {
		t.Fatal("wrapped dumpable signer must be DENIED, got PASS")
	}
}
