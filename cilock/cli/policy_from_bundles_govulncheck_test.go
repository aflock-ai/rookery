// jade:ring local
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/policy"
)

const govulncheckPredicateType = "https://aflock.ai/attestations/govulncheck/v0.1"

// writeGovulncheckBundle is the compact collection of a step that ran tests
// and govulncheck, as `cilock run -a govulncheck` records it.
func writeGovulncheckBundle(t *testing.T, dir, step string) string {
	t.Helper()
	path := filepath.Join(dir, step+".bundle.json")
	writeEnvelope(t, path, map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://aflock.ai/attestation-collection/v0.1",
		"subject":       []any{},
		"predicate": map[string]any{
			"name": step,
			"attestations": []any{
				map[string]any{
					"type":        "https://aflock.ai/attestations/command-run/v0.2",
					"attestation": map[string]any{"cmd": []string{"go", "test", "./..."}, "exitcode": 0},
				},
				map[string]any{
					"type":        govulncheckPredicateType,
					"attestation": govulncheckPredicate(0, 0, "symbol", nil),
				},
			},
		},
	})
	return path
}

func govulncheckPredicate(reachable, unreachable any, level any, findings any) map[string]any {
	summary := map[string]any{"reachableCount": reachable, "unreachableCount": unreachable,
		"findings": findings}
	if level != nil {
		summary["scanLevel"] = level
	}
	return map[string]any{"summary": summary}
}

func finding(id string, reachable any) map[string]any {
	return map[string]any{"osvId": id, "reachable": reachable, "traceLength": 1}
}

// A starter policy's govulncheck rule blocks on vulnerabilities the code can
// reach, the reading the catalog documents for this attestor ("findings
// without a call-trace are advisory"). An agent without a rule wrote its own
// that counted every finding, so Hugo's three imported-but-unreachable
// advisories refused every push under an activated policy (fullblind49, L3).
// Reachability is only meaningful from a symbol-level scan, and every
// unreadable or self-contradicting summary is a refusal, never a pass.
func TestFromBundlesGovulncheckBlocksReachableFindingsOnly(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "policy.json")
	if err := runPolicyFromBundles(&bytes.Buffer{}, &bytes.Buffer{},
		[]string{writeGovulncheckBundle(t, dir, "vulns")}, nil, out, 24*time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var pol policy.Policy
	if err := json.Unmarshal(raw, &pol); err != nil {
		t.Fatal(err)
	}
	var regos []policy.RegoPolicy
	for _, a := range pol.Steps["vulns"].Attestations {
		if a.Type == govulncheckPredicateType {
			regos = a.RegoPolicies
		}
	}
	if len(regos) == 0 {
		t.Fatalf("govulncheck must carry a Rego rule: %s", raw)
	}
	unreachable3 := []any{finding("GO-2026-5932", false), finding("GO-2026-6354", false), finding("GO-2026-6355", false)}
	cases := []struct {
		name      string
		predicate map[string]any
		admit     bool
	}{
		{"clean scan, findings null", govulncheckPredicate(0, 0, "symbol", nil), true},
		{"clean scan, findings empty", govulncheckPredicate(0, 0, "symbol", []any{}), true},
		{"fullblind49: 3 imported, none reachable", govulncheckPredicate(0, 3, "symbol", unreachable3), true},
		{"one reachable", govulncheckPredicate(1, 0, "symbol", []any{finding("GO-1", true)}), false},
		{"count says 0, list says reachable", govulncheckPredicate(0, 1, "symbol", []any{finding("GO-1", true)}), false},
		{"counts disagree with list", govulncheckPredicate(0, 0, "symbol", unreachable3), false},
		{"negative count", govulncheckPredicate(-1, 1, "symbol", []any{}), false},
		{"module-level scan cannot see reachability", govulncheckPredicate(0, 3, "module", unreachable3), false},
		{"no scan level", govulncheckPredicate(0, 0, nil, nil), false},
		{"string count", govulncheckPredicate("0", 0, "symbol", nil), false},
		// The reachable-finding denial must not depend on a diagnostic field:
		// an undefined osvId inside sprintf would drop the whole rule.
		{"reachable finding without osvId", govulncheckPredicate(0, 1, "symbol", []any{map[string]any{"reachable": true}}), false},
		{"reachable finding with null osvId", govulncheckPredicate(0, 1, "symbol", []any{map[string]any{"osvId": nil, "reachable": true}}), false},
		{"reachable finding with numeric osvId", govulncheckPredicate(0, 1, "symbol", []any{map[string]any{"osvId": 42, "reachable": true}}), false},
		{"finding without reachable flag", govulncheckPredicate(0, 1, "symbol", []any{map[string]any{"osvId": "GO-1"}}), false},
		{"string reachable flag", govulncheckPredicate(0, 1, "symbol", []any{finding("GO-1", "false")}), false},
		{"findings not a list", govulncheckPredicate(0, 0, "symbol", "none"), false},
		{"no summary", map[string]any{"report": []any{}}, false},
	}
	for _, c := range cases {
		err := policy.EvaluateRegoPolicy(predicateAttestor{c.predicate}, regos)
		if c.admit && err != nil {
			t.Errorf("%s: must admit, got %v", c.name, err)
		}
		if !c.admit && err == nil {
			t.Errorf("%s: must refuse, got admit", c.name)
		}
	}
}
