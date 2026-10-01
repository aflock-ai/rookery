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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const (
	// VerifierID names cilock's L3 verifier in a VSA.
	VerifierID = "https://aflock.ai/cilock/verify/slsa-build-l3@v1"
	// PolicyURI names the built-in L3 policy; the VSA's policy digest pins
	// the roots, workflow path and commit it was evaluated with.
	PolicyURI = "https://aflock.ai/cilock/policy/slsa-build-l3@v1"
)

// VSADescriptor is a resource descriptor in a VSA.
type VSADescriptor struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// VSA is a SLSA Verification Summary Attestation v1 predicate
// (https://slsa.dev/spec/v1.0/verification_summary) for one L3 verification.
type VSA struct {
	Verifier struct {
		ID string `json:"id"`
	} `json:"verifier"`
	TimeVerified       time.Time       `json:"timeVerified"`
	ResourceURI        string          `json:"resourceUri"`
	Policy             VSADescriptor   `json:"policy"`
	InputAttestations  []VSADescriptor `json:"inputAttestations,omitempty"`
	VerificationResult string          `json:"verificationResult"`
	VerifiedLevels     []string        `json:"verifiedLevels"`
}

// NewVSA summarises r. It states SLSA_BUILD_LEVEL_3 only when r observed L3;
// a failed verification is a FAILED VSA whose verifiedLevels is ["FAILED"].
func NewVSA(pol Policy, r Result, resourceURI string, inputs []VSADescriptor, now time.Time) VSA {
	polJSON, _ := json.Marshal(pol) // a struct of strings; cannot fail
	sum := sha256.Sum256(polJSON)
	v := VSA{
		TimeVerified: now.UTC(), ResourceURI: resourceURI,
		Policy: VSADescriptor{URI: PolicyURI, Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
		// SLSA VSA v1: verifiedLevels is "FAILED" if policy verification failed.
		InputAttestations: inputs, VerificationResult: "FAILED", VerifiedLevels: []string{"FAILED"},
	}
	v.Verifier.ID = VerifierID
	if r.ObservedLevel == 3 {
		v.VerificationResult = "PASSED"
		v.VerifiedLevels = []string{"SLSA_BUILD_LEVEL_3"}
	}
	return v
}
