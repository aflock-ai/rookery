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

package slsa

import (
	"crypto"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	vsa "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// #9836: the VSA predicate decodes strictly into the in-toto reference VSA v1
// type and carries every field SLSA VSA v1 marks REQUIRED.
func TestVerificationSummaryConformsToReferenceType(t *testing.T) {
	sha := cryptoutil.DigestValue{Hash: crypto.SHA256}
	for name, s := range map[string]VerificationSummary{
		"passed": {
			Verifier: Verifier{ID: PolicyVerifierID}, TimeVerified: time.Unix(1700000000, 0).UTC(),
			ResourceURI: "sha256:" + "ab", Policy: ResourceDescriptor{URI: "https://aflock.ai/policy/v0.1", Digest: cryptoutil.DigestSet{sha: "cd"}},
			InputAttestations:  []ResourceDescriptor{{URI: "gitoid:x", Digest: cryptoutil.DigestSet{sha: "ef"}}},
			VerificationResult: PassedVerificationResult, VerifiedLevels: VerifiedLevelsFor(PassedVerificationResult),
		},
		"failed": {
			Verifier: Verifier{ID: PolicyVerifierID}, ResourceURI: "sha256:ab",
			Policy:             ResourceDescriptor{URI: "https://aflock.ai/policy/v0.1", Digest: cryptoutil.DigestSet{sha: "cd"}},
			VerificationResult: FailedVerificationResult, VerifiedLevels: VerifiedLevelsFor(FailedVerificationResult),
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var ref vsa.VerificationSummary
			if err := protojson.Unmarshal(b, &ref); err != nil {
				t.Fatalf("outside the VSA v1 reference type: %v\n%s", err, b)
			}
			if _, err := url.ParseRequestURI(ref.GetVerifier().GetId()); err != nil {
				t.Errorf("verifier.id %q is not a URI", ref.GetVerifier().GetId())
			}
			if ref.GetResourceUri() == "" || ref.GetPolicy().GetUri() == "" || len(ref.GetVerifiedLevels()) != 1 {
				t.Errorf("missing a required field: %s", b)
			}
		})
	}
}

// A policy verification assesses no SLSA Build level, so a pass is
// UNEVALUATED; a failure is "FAILED" (SLSA VSA v1, verifiedLevels).
func TestVerifiedLevelsFor(t *testing.T) {
	if got := VerifiedLevelsFor(PassedVerificationResult); len(got) != 1 || got[0] != "SLSA_BUILD_LEVEL_UNEVALUATED" {
		t.Errorf("passed: %v", got)
	}
	if got := VerifiedLevelsFor(FailedVerificationResult); len(got) != 1 || got[0] != "FAILED" {
		t.Errorf("failed: %v", got)
	}
}
