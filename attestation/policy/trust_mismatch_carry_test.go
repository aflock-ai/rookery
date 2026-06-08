// Copyright 2022 The Witness Contributors
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
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckFunctionaries_CarriesTrustMismatchIntoReason locks in the behavior
// that, when a collection's signature failed to verify (zero verifiers) and the
// failure carries a dsse.TrustNameKeyMismatchError, that typed error is carried
// into RejectedCollection.Reason — NOT flattened to the bare "no verifiers
// present" text. This is the load-bearing thread that lets the cilock CLI pull
// the diagnostic out with errors.As at the top-level error.
func TestCheckFunctionaries_CarriesTrustMismatchIntoReason(t *testing.T) {
	tm := &dsse.TrustNameKeyMismatchError{
		CommonName:    "TestifySec Platform Root CA",
		ArtifactKeyID: "29d022f5",
		PolicyKeyID:   "9fed6167",
	}
	// Reproduce the exact wrapping source.VerifiedSource.Search applies to a
	// failed envelope verification.
	dsseErr := dsse.ErrNoMatchingSigs{TrustMismatch: tm}
	collErr := fmt.Errorf("failed to verify envelope: %w", dsseErr)

	statement := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Envelope:  dsse.Envelope{Payload: []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`)},
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
		// Zero Verifiers (signature failed) + the failure recorded in Errors —
		// exactly what VerifiedSource produces on a trust-mismatched envelope.
		Verifiers: nil,
		Errors:    []error{collErr},
	}

	step := Step{Name: "source-git"}
	result := step.checkFunctionaries([]source.CollectionVerificationResult{statement}, map[string]TrustBundle{})

	require.Empty(t, result.Passed, "a signature-failed collection must not pass")
	require.Len(t, result.Rejected, 1)

	reason := result.Rejected[0].Reason
	require.NotNil(t, reason)

	var got *dsse.TrustNameKeyMismatchError
	require.True(t, errors.As(reason, &got),
		"trust mismatch must survive in RejectedCollection.Reason; got: %v", reason)
	assert.Equal(t, tm.CommonName, got.CommonName)
	assert.Equal(t, tm.ArtifactKeyID, got.ArtifactKeyID)
	assert.Equal(t, tm.PolicyKeyID, got.PolicyKeyID)

	// The human-readable text still leads with the generic explanation and now
	// also renders the diagnostic block.
	assert.Contains(t, reason.Error(), "no verifiers present")
	assert.Contains(t, reason.Error(), "TRUST MISMATCH")
}
