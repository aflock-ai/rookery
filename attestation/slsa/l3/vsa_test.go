// jade:ring local

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

package l3

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	vsa "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestVSAStatesTheVerifiedLevel(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	pass := Result{ObservedLevel: 3}
	v := NewVSA(honestPolicy(), pass, "app", nil, now)
	if v.VerificationResult != "PASSED" || len(v.VerifiedLevels) != 1 || v.VerifiedLevels[0] != "SLSA_BUILD_LEVEL_3" {
		t.Fatalf("passing VSA: %+v", v)
	}
	if v.Policy.URI != PolicyURI || v.Policy.Digest["sha256"] == "" || v.ResourceURI != "app" || !v.TimeVerified.Equal(now) {
		t.Fatalf("passing VSA metadata: %+v", v)
	}
	// SLSA VSA v1: verifiedLevels is "FAILED" if policy verification failed.
	fail := NewVSA(honestPolicy(), Result{}, "app", nil, now)
	if fail.VerificationResult != "FAILED" || len(fail.VerifiedLevels) != 1 || fail.VerifiedLevels[0] != "FAILED" {
		t.Fatalf("failing VSA: %+v", fail)
	}
	// The policy digest changes with the pin: a VSA names the exact policy.
	other := honestPolicy()
	other.SHA = "fedcba9876543210fedcba9876543210fedcba98"
	if NewVSA(other, pass, "app", nil, now).Policy.Digest["sha256"] == v.Policy.Digest["sha256"] {
		t.Fatal("two pins produced one policy digest")
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"verifier", "timeVerified", "resourceUri", "policy", "verificationResult", "verifiedLevels"} {
		if _, ok := m[k]; !ok {
			t.Errorf("VSA JSON lacks %q (SLSA VSA v1 field)", k)
		}
	}
}

// Both outcomes decode strictly into the in-toto reference VSA v1 type (no
// field outside the spec, every value the right JSON type) and carry the
// fields SLSA VSA v1 marks REQUIRED, with verifier.id and resourceUri URIs.
func TestVSAConformsToReferenceType(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	inputs := []VSADescriptor{{URI: "provenance.json", Digest: map[string]string{"sha256": "ab"}}}
	for name, r := range map[string]Result{"passed": {ObservedLevel: 3}, "failed": {}} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(NewVSA(honestPolicy(), r, "https://example.com/app.tar.gz", inputs, now))
			if err != nil {
				t.Fatal(err)
			}
			requireConformingVSA(t, b)
		})
	}
}

func requireConformingVSA(t *testing.T, predicate []byte) {
	t.Helper()
	var ref vsa.VerificationSummary
	if err := protojson.Unmarshal(predicate, &ref); err != nil {
		t.Fatalf("predicate is outside the VSA v1 reference type: %v\n%s", err, predicate)
	}
	if _, err := url.ParseRequestURI(ref.GetVerifier().GetId()); err != nil {
		t.Errorf("verifier.id %q is not a URI", ref.GetVerifier().GetId())
	}
	if ref.GetResourceUri() == "" || ref.GetPolicy().GetUri() == "" || len(ref.GetPolicy().GetDigest()) == 0 {
		t.Errorf("resourceUri, policy.uri and policy.digest are required: %s", predicate)
	}
	switch ref.GetVerificationResult() {
	case "PASSED":
		if len(ref.GetVerifiedLevels()) != 1 || !strings.HasPrefix(ref.GetVerifiedLevels()[0], "SLSA_BUILD_LEVEL_") {
			t.Errorf("PASSED VSA verifiedLevels %v", ref.GetVerifiedLevels())
		}
	case "FAILED":
		if len(ref.GetVerifiedLevels()) != 1 || ref.GetVerifiedLevels()[0] != "FAILED" {
			t.Errorf("FAILED VSA verifiedLevels %v", ref.GetVerifiedLevels())
		}
	default:
		t.Errorf("verificationResult %q", ref.GetVerificationResult())
	}
}
