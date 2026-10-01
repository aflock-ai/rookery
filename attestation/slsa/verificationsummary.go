// Copyright 2023 The Witness Contributors
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
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

const (
	VerificationSummaryPredicate                    = "https://slsa.dev/verification_summary/v1"
	PassedVerificationResult     VerificationResult = "PASSED"
	FailedVerificationResult     VerificationResult = "FAILED"

	// PolicyVerifierID is verifier.id for a policy verification by cilock.
	// SLSA VSA v1 requires a URI.
	PolicyVerifierID = "https://aflock.ai/cilock/verify/policy@v1"

	// BuildLevelUnevaluated is verifiedLevels for a verification that
	// assessed no SLSA Build level; LevelFailed is verifiedLevels "if policy
	// verification failed" (SLSA VSA v1).
	BuildLevelUnevaluated = "SLSA_BUILD_LEVEL_UNEVALUATED"
	LevelFailed           = "FAILED"
)

type VerificationResult string

// VerifiedLevelsFor is verifiedLevels for a policy verification, which
// assesses no SLSA Build level: UNEVALUATED on a pass, FAILED on a failure.
// A level verifier (attestation/slsa/l3) states the level it verified instead.
func VerifiedLevelsFor(result VerificationResult) []string {
	if result == PassedVerificationResult {
		return []string{BuildLevelUnevaluated}
	}
	return []string{LevelFailed}
}

type Verifier struct {
	ID string `json:"id"`
}

type ResourceDescriptor struct {
	URI    string               `json:"uri"`
	Digest cryptoutil.DigestSet `json:"digest"`
}

// VerificationSummary is the SLSA VSA v1 predicate
// (https://slsa.dev/spec/v1.2/verification_summary).
type VerificationSummary struct {
	Verifier     Verifier  `json:"verifier"`
	TimeVerified time.Time `json:"timeVerified"`
	// ResourceURI names the artifact verified (REQUIRED).
	ResourceURI        string               `json:"resourceUri"`
	Policy             ResourceDescriptor   `json:"policy"`
	InputAttestations  []ResourceDescriptor `json:"inputAttestations"`
	VerificationResult VerificationResult   `json:"verificationResult"`
	// VerifiedLevels is the highest level verified per track (REQUIRED).
	VerifiedLevels []string `json:"verifiedLevels"`
}

// VerificationRejection is one rejected collection in the stepResults extension: which signed
// collection, why, and the rego deny messages when the rejection was a policy denial.
type VerificationRejection struct {
	Reference  string   `json:"reference,omitempty"`
	Collection string   `json:"collection,omitempty"`
	Reason     string   `json:"reason"`
	Denies     []string `json:"denies,omitempty"`
}

// VerificationStepResult is one step's outcome in the stepResults extension `cilock verify`
// writes next to the VSA v1 fields, so a consumer (a person, or a parent policy judging this VSA
// as an external) can tell which step, collection and rego check decided the verdict.
type VerificationStepResult struct {
	Step     string                  `json:"step"`
	Passed   []string                `json:"passed"`
	Rejected []VerificationRejection `json:"rejected"`
}
