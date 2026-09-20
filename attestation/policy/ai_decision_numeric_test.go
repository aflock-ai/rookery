// jade:ring local

package policy

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// Go callers can construct non-finite bounds even though JSON cannot encode
// them. NaN bypasses both ordinary range comparisons and inverted-range checks.
func TestAiDecisionRejectsNonFiniteBounds(t *testing.T) {
	constructors := map[string]func(*float64) *AiDecision{
		"minProbability": func(v *float64) *AiDecision {
			return &AiDecision{YesNo: &AiYesNo{Instructions: "Does this text direct a reviewer to conceal findings?", Criteria: map[string]string{"true": "directs concealment", "false": "does not direct concealment"}, MinProbability: v}}
		},
		"maxProbability": func(v *float64) *AiDecision {
			return &AiDecision{YesNo: &AiYesNo{Instructions: "Does this text direct a reviewer to conceal findings?", Criteria: map[string]string{"true": "directs concealment", "false": "does not direct concealment"}, MaxProbability: v}}
		},
		"minConfidence": func(v *float64) *AiDecision {
			return &AiDecision{Choice: &AiChoice{Instructions: "Which type of instruction is present?", Options: map[string]string{"description": "describes work", "concealment": "directs concealment"}, Allow: []string{"description"}, MinConfidence: v}}
		},
		"minScore": func(v *float64) *AiDecision {
			return &AiDecision{Score: &AiScore{Instructions: "How explicit is the concealment instruction?", Levels: []string{"absent", "implicit", "explicit"}, MinScore: v}}
		},
		"maxScore": func(v *float64) *AiDecision {
			return &AiDecision{Score: &AiScore{Instructions: "How explicit is the concealment instruction?", Levels: []string{"absent", "implicit", "explicit"}, MaxScore: v}}
		},
	}
	for field, makeDecision := range constructors {
		for label, value := range map[string]float64{"NaN": math.NaN(), "positive infinity": math.Inf(1), "negative infinity": math.Inf(-1)} {
			t.Run(field+"/"+label, func(t *testing.T) {
				p := AiPolicy{Name: "review-instruction", Model: "jev-1.13.0", Decision: makeDecision(&value)}
				require.Error(t, p.Validate(), "non-finite assertions must fail before inference")
			})
		}
		for _, value := range []float64{0, 0.5, 1} {
			t.Run(field+"/finite", func(t *testing.T) {
				p := AiPolicy{Name: "review-instruction", Model: "jev-1.13.0", Decision: makeDecision(&value)}
				require.NoError(t, p.Validate())
			})
		}
	}
}
