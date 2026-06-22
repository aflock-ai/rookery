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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSecurity_RGP5_NoStepPolicyMustNotPassVacuously proves that a policy which
// declares no steps and verifies nothing affirmatively does NOT pass
// (GHSA-rgp5-33mp-jhfm).
//
// Rookery already rejects a policy with no steps AND no external attestations
// (verifySteps returns an error). The residual hole is a policy with no steps
// and only a *non-required* external attestation that matches nothing: that
// external is marked Skipped, ExternalResult.Analyze() returns true for a
// Skipped result, and the pass accumulator (which started at true) stayed true
// — a policy that proved nothing verified successfully.
func TestSecurity_RGP5_NoStepPolicyMustNotPassVacuously(t *testing.T) {
	t.Run("no steps + only a skipped optional external must not pass", func(t *testing.T) {
		p := Policy{
			Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
			Steps:   map[string]Step{},
			ExternalAttestations: map[string]ExternalAttestation{
				"optional-vsa": {
					PredicateType: "https://example.com/vsa/v1",
					Required:      false, // optional: an unmatched optional external is Skipped
				},
			},
		}

		// mockVerifiedSource returns no envelopes -> the optional external is Skipped.
		pass, _, err := p.Verify(context.Background(),
			WithVerifiedSource(&mockVerifiedSource{}),
			WithSubjectDigests([]string{"sha256:abc"}),
		)
		require.NoError(t, err, "a skipped optional external is not an error; the policy should fail by verdict")
		require.False(t, pass,
			"a policy with no steps whose only external attestation was Skipped verifies nothing and must not pass (GHSA-rgp5-33mp-jhfm)")
	})

	t.Run("no steps and no externals fails closed (documents existing guard)", func(t *testing.T) {
		p := Policy{
			Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
			Steps:   map[string]Step{},
		}

		pass, _, err := p.Verify(context.Background(),
			WithVerifiedSource(&mockVerifiedSource{}),
			WithSubjectDigests([]string{"sha256:abc"}),
		)
		require.Error(t, err, "a policy with nothing to verify must not succeed")
		require.False(t, pass)
	})

	t.Run("no steps + optional external that is found-but-rejected must not pass", func(t *testing.T) {
		const predicateType = "https://example.com/vsa/v1"
		p := Policy{
			Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
			Steps:   map[string]Step{},
			ExternalAttestations: map[string]ExternalAttestation{
				"optional-vsa": {PredicateType: predicateType, Required: false},
			},
		}

		// The optional external IS found (an envelope matches the predicate) but
		// is rejected — the envelope carries verification errors and no verifiers.
		// It is not Skipped, and it has no Passed envelope, so the external fails
		// Analyze() and the policy must not pass.
		ms := &mockVerifiedSource{externalResults: []source.StatementEnvelope{
			{
				Statement: intoto.Statement{PredicateType: predicateType},
				Errors:    []error{errors.New("signature verification failed")},
			},
		}}

		pass, _, err := p.Verify(context.Background(),
			WithVerifiedSource(ms),
			WithSubjectDigests([]string{"sha256:abc"}),
		)
		require.NoError(t, err, "a rejected optional external is a verdict, not an error")
		require.False(t, pass,
			"a no-step policy whose only external was found-but-rejected must not pass (GHSA-rgp5-33mp-jhfm)")
	})
}
