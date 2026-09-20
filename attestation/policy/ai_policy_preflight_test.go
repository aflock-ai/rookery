// jade:ring local

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyValidateChecksAIRequirements(t *testing.T) {
	bound := 0.2
	valid := AiPolicy{Name: "review-instructions", Model: "jev-1.13.0", Decision: &AiDecision{YesNo: &AiYesNo{
		Instructions: "Does this text instruct a reviewer to conceal findings?",
		Criteria:     map[string]string{"true": "directs concealment", "false": "does not direct concealment"}, MaxProbability: &bound,
	}}}
	containers := map[string]func([]AiPolicy) Policy{
		"step": func(ai []AiPolicy) Policy {
			return Policy{Steps: map[string]Step{"review": {Name: "review", Attestations: []Attestation{{Type: "test:review", AiPolicies: ai}}}}}
		},
		"external": func(ai []AiPolicy) Policy {
			return Policy{ExternalAttestations: map[string]ExternalAttestation{"review": {Name: "review", PredicateType: "test:review", AiPolicies: ai}}}
		},
	}
	for name, makePolicy := range containers {
		t.Run(name, func(t *testing.T) {
			t.Run("valid", func(t *testing.T) {
				require.NoError(t, makePolicy([]AiPolicy{valid}).Validate())
			})
			t.Run("no AI", func(t *testing.T) {
				require.NoError(t, makePolicy(nil).Validate())
			})
			t.Run("missing assertion", func(t *testing.T) {
				invalid := valid.DeepCopy()
				invalid.Decision.YesNo.MaxProbability = nil
				err := makePolicy([]AiPolicy{*invalid}).Validate()
				require.ErrorContains(t, err, "asserts nothing")
				require.ErrorContains(t, err, "review")
			})
			t.Run("duplicate question names", func(t *testing.T) {
				err := makePolicy([]AiPolicy{valid, valid}).Validate()
				require.ErrorContains(t, err, "used more than once")
			})
			t.Run("both evaluator forms", func(t *testing.T) {
				invalid := valid.DeepCopy()
				invalid.Prompt = "a second evaluator"
				require.ErrorContains(t, makePolicy([]AiPolicy{*invalid}).Validate(), "both are set")
			})
		})
	}
}
