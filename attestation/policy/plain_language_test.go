// jade:ring local

package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A policy carries its own plain-language description: the policy, each step (title and
// description), and each check a module decides (check id -> what must be true). The author signs it
// with the rules, and a countersigner approves both together. The fields are documentation only.
func TestPlainLanguageRoundTrips(t *testing.T) {
	for _, pt := range []string{decTypeV01, decTypeLegacyV01, decTypeV02} {
		raw := decPolicyJSON(t, "k", func(doc map[string]any) {
			doc["description"] = "The author attests these descriptions match the rules."
			for name := range doc["steps"].(map[string]any) {
				st := decStep(doc, name)
				st["title"] = "A step"
				st["description"] = "What this evidence is for."
				for _, a := range st["attestations"].([]any) {
					rps, _ := a.(map[string]any)["regopolicies"].([]any)
					for _, rp := range rps {
						rp.(map[string]any)["checks"] = map[string]any{"some-check": "Something must be true."}
					}
				}
			}
		})
		p, err := DecodePolicyEnvelope(pt, raw)
		require.NoError(t, err, pt)
		require.Equal(t, "The author attests these descriptions match the rules.", p.Description, pt)
		for _, st := range p.Steps {
			require.Equal(t, "A step", st.Title, pt)
			require.Equal(t, "What this evidence is for.", st.Description, pt)
			for _, a := range st.Attestations {
				for _, rp := range a.RegoPolicies {
					require.Equal(t, "Something must be true.", rp.Checks["some-check"], pt)
				}
			}
		}
		out, err := json.Marshal(p)
		require.NoError(t, err)
		require.Contains(t, string(out), `"checks":{"some-check":"Something must be true."}`)
	}
}

// Without descriptions a policy serializes exactly as before: every field is omitempty.
func TestPlainLanguageAbsentIsByteIdentical(t *testing.T) {
	raw := decPolicyJSON(t, "k", nil)
	var p Policy
	require.NoError(t, json.Unmarshal(raw, &p))
	out, err := json.Marshal(p)
	require.NoError(t, err)
	require.NotContains(t, string(out), `"description"`)
	require.NotContains(t, string(out), `"title"`)
	require.NotContains(t, string(out), `"checks"`)
}

// Checks is a map, so a deep copy must not share it: a copied policy edited in
// place (a template renderer filling a check) would rewrite the original.
func TestPlainLanguageChecksDeepCopy(t *testing.T) {
	orig := RegoPolicy{Name: "m", Checks: map[string]string{"c": "must hold"}}
	cp := orig.DeepCopy()
	cp.Checks["c"] = "edited"
	require.Equal(t, "must hold", orig.Checks["c"], "DeepCopy shared the Checks map")
}
