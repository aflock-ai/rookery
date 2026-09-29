// jade:ring local

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/stretchr/testify/require"
)

// The signed stepResults carry every deny of a rejected collection, exactly as
// Rego wrote it: one per attestor, and a message containing ", " kept whole.
func TestVSAPredicateCarriesEveryDeny(t *testing.T) {
	col := source.CollectionVerificationResult{CollectionEnvelope: source.CollectionEnvelope{
		Reference: "gitoid:c1", Collection: attestation.Collection{Name: "build"},
	}}
	reason := policy.ErrCollectionValidationFailed{Reasons: []error{
		fmt.Errorf("rego a: %w", policy.ErrPolicyDenied{Reasons: []string{"check:x, want y"}}),
		fmt.Errorf("rego b: %w", policy.ErrPolicyDenied{Reasons: []string{"check:z"}}),
		errors.New("unrelated"),
	}}
	ev := workflow.VerifyResult{
		VerificationSummary: slsa.VerificationSummary{VerificationResult: slsa.FailedVerificationResult},
		StepResults: map[string]policy.StepResult{
			"build": {Step: "build", Rejected: []policy.RejectedCollection{{Collection: col, Reason: reason}}},
		},
	}
	raw, err := marshalVSAPredicate(ev)
	require.NoError(t, err)
	var got struct {
		VerificationResult string                        `json:"verificationResult"`
		StepResults        []slsa.VerificationStepResult `json:"stepResults"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, "FAILED", got.VerificationResult)
	require.Len(t, got.StepResults, 1)
	require.Equal(t, []string{"check:x, want y", "check:z"}, got.StepResults[0].Rejected[0].Denies)
	require.Equal(t, "gitoid:c1", got.StepResults[0].Rejected[0].Reference)
}
