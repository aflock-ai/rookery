// jade:ring local
// Copyright 2026 The Witness Contributors
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvidenceOlderThan24hDoesNotCount answers "can a policy say evidence
// older than 24h does not count", written the way a policy author writes it:
// a step's timestampConstraint.maxAge, judged against the RFC3161
// TSA-verified signing time of the functionary's own signature. Rego cannot
// do this: its input is the attestor's JSON plus other steps' attestor JSON
// (buildRegoInput, buildStepContext), with no verified time in it, so a Rego
// age rule could only compare time.now_ns() with a self-asserted field.
func TestEvidenceOlderThan24hDoesNotCount(t *testing.T) {
	now := time.Now()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	var step Step
	require.NoError(t, json.Unmarshal([]byte(`{"name":"image-build",
		"functionaries":[{"publickeyid":"`+keyID+`"}],
		"timestampConstraint":{"maxAge":"24h"}}`), &step))
	require.NotNil(t, step.TimestampConstraint)
	require.NoError(t, step.TimestampConstraint.Validate())

	signedAgo := func(age time.Duration) []source.CollectionVerificationResult {
		return []source.CollectionVerificationResult{{
			CollectionEnvelope:        source.CollectionEnvelope{Statement: intoto.Statement{PredicateType: attestation.CollectionType}},
			Verifiers:                 []cryptoutil.Verifier{verifier},
			VerifiedTimestampsByKeyID: map[string][]time.Time{keyID: {now.Add(-age)}},
		}}
	}
	assert.Len(t, step.checkFunctionaries(signedAgo(23*time.Hour), nil).Passed, 1)
	stale := step.checkFunctionaries(signedAgo(25*time.Hour), nil)
	assert.Empty(t, stale.Passed)
	require.Len(t, stale.Rejected, 1)
	assert.Contains(t, stale.Rejected[0].Reason.Error(), "exceeding the policy's maxAge 24h0m0s")
}

// time.now_ns() is callable from step Rego (it is in neither
// disallowedBuiltins nor evaluateRegoInput's UnsafeBuiltins), but no trusted
// time to compare it with reaches the input.
func TestRegoHasNowButNoVerifiedSigningTime(t *testing.T) {
	err := EvaluateRegoPolicy(&marshalableAttestor{AttName: "test", AttType: "test"}, []RegoPolicy{{
		Name: "age.rego",
		Module: []byte(`package age
deny[msg] {
  time.now_ns() > 0
  not input.verified_timestamps
  not input.signed_at
  msg := "now available, no signing time in input"
}`),
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "now available, no signing time in input")
}
