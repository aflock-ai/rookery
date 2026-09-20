// jade:ring local

package policy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// refusedAIResults turns an unanswered AI question into a verification error
// rather than a signed negative verdict -- unless the step or external was
// already satisfied by another witness. These tests pin that exemption from
// both sides: a refusal beside a passing witness is not an error, a refusal
// with no passing witness is, and a skipped external is never consulted.

func refusedStep(name string) RejectedCollection {
	return RejectedCollection{Reason: ErrAIEvaluationRefused{Code: jevCancelled}}
}

func TestRefusedAIResultsStepExemptWhenAnotherWitnessPassed(t *testing.T) {
	steps := map[string]StepResult{
		"build": {
			Step:     "build",
			Passed:   []PassedCollection{{}},
			Rejected: []RejectedCollection{refusedStep("build")},
		},
	}
	require.NoError(t, refusedAIResults(steps, nil),
		"a refusal on one collection must not fail a step another collection already satisfied")
}

func TestRefusedAIResultsStepRefusedWithoutPassingWitness(t *testing.T) {
	steps := map[string]StepResult{
		"build": {
			Step:     "build",
			Rejected: []RejectedCollection{refusedStep("build")},
		},
	}
	err := refusedAIResults(steps, nil)
	var refusal ErrAIEvaluationRefused
	require.ErrorAs(t, err, &refusal, "with no passing witness a refusal is a verification error, not a verdict")
	require.Equal(t, jevCancelled, refusal.Code)
}

func TestRefusedAIResultsStepOrdinaryRejectionIsNotARefusal(t *testing.T) {
	steps := map[string]StepResult{
		"build": {
			Step:     "build",
			Rejected: []RejectedCollection{{Reason: errors.New("rego denied")}},
		},
	}
	require.NoError(t, refusedAIResults(steps, nil),
		"a genuine policy rejection is a verdict and must not be reported as a refusal")
}

func TestRefusedAIResultsExternalExemptWhenAnotherWitnessPassed(t *testing.T) {
	externals := map[string]ExternalResult{
		"review": {
			Name:     "review",
			Passed:   []PassedExternal{{}},
			Rejected: []RejectedExternal{{Reason: ErrAIEvaluationRefused{Code: jevCancelled}}},
		},
	}
	require.NoError(t, refusedAIResults(nil, externals),
		"a refusal beside a passing external witness must not fail the external")
}

func TestRefusedAIResultsExternalRefusedWithoutPassingWitness(t *testing.T) {
	externals := map[string]ExternalResult{
		"review": {
			Name:     "review",
			Rejected: []RejectedExternal{{Reason: ErrAIEvaluationRefused{Code: jevCancelled}}},
		},
	}
	err := refusedAIResults(nil, externals)
	var refusal ErrAIEvaluationRefused
	require.ErrorAs(t, err, &refusal)
}

func TestRefusedAIResultsSkippedExternalIsNotConsulted(t *testing.T) {
	externals := map[string]ExternalResult{
		"review": {
			Name:     "review",
			Skipped:  true,
			Rejected: []RejectedExternal{{Reason: ErrAIEvaluationRefused{Code: jevCancelled}}},
		},
	}
	require.NoError(t, refusedAIResults(nil, externals),
		"a skipped external carries no requirement, so a refusal recorded on it is not an error")
}
