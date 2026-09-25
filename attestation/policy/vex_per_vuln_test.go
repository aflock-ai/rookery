// jade:ring local
package policy

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/invopop/jsonschema"
)

// vexPerVulnModule requires one VEX statement per vulnerability finding. It
// runs on the govulncheck attestation of a step that declares
// attestationsFrom: ["vex"], so the verifier hands it that step's VEX
// documents as input.steps.vex.collections[].attestations["https://openvex.dev/ns"].
// Every finding must be covered by a statement for its exact id that is fixed,
// or not_affected with a justification or impact statement. Findings with no
// VEX step fail closed, and fields are read with object.get so a missing one
// never makes a deny undefined.
const vexPerVulnModule = `package vex_per_vuln

findings = [] { input.attestation.summary.findings == null }
findings = fs { is_array(input.attestation.summary.findings); fs := input.attestation.summary.findings }

statements[s] {
	c := input.steps.vex.collections[_]
	doc := object.get(object.get(c.attestations, "https://openvex.dev/ns", {}), "vexDocument", {})
	s := object.get(doc, "statements", [])[_]
}

ids(s) = x { x := {object.get(object.get(s, "vulnerability", {}), "name", "")} | {a | a := object.get(object.get(s, "vulnerability", {}), "aliases", [])[_]} }

explained(s) { s.status == "fixed" }
explained(s) { s.status == "not_affected"; object.get(s, "justification", "") != "" }
explained(s) { s.status == "not_affected"; object.get(s, "impact_statement", "") != "" }

covered(id) { s := statements[_]; ids(s)[id]; explained(s) }

deny[msg] {
	not is_array(findings)
	msg := "unreadable evidence: govulncheck findings are not a list"
}

deny[msg] {
	f := findings[_]
	id := object.get(f, "osvId", "")
	not covered(id)
	msg := sprintf("vulnerability %v has no VEX statement marking it fixed or not_affected with a justification", [id])
}
`

type govulnPredicate struct{ predicate map[string]any }

func (p govulnPredicate) Name() string                                   { return "govulncheck" }
func (p govulnPredicate) Type() string                                   { return "https://aflock.ai/attestations/govulncheck/v0.1" }
func (p govulnPredicate) RunType() attestation.RunType                   { return "postproduct" }
func (p govulnPredicate) Attest(_ *attestation.AttestationContext) error { return nil }
func (p govulnPredicate) Schema() *jsonschema.Schema                     { return nil }
func (p govulnPredicate) MarshalJSON() ([]byte, error)                   { return json.Marshal(p.predicate) }

// Cole asked whether a policy can require one VEX per vulnerability. It can,
// across steps: this runs the verifier's own Rego evaluation with the
// cross-step context exactly as buildStepContext shapes it.
func TestPolicyCanRequireOneVEXPerVulnerability(t *testing.T) {
	regos := []RegoPolicy{{Name: "vex-per-vuln", Module: []byte(vexPerVulnModule)}}
	findings := func(ids ...string) govulnPredicate {
		fs := make([]any, 0, len(ids))
		for _, id := range ids {
			fs = append(fs, map[string]any{"osvId": id, "reachable": false})
		}
		return govulnPredicate{map[string]any{"summary": map[string]any{"findings": fs}}}
	}
	vex := func(statements ...map[string]any) map[string]interface{} {
		ss := make([]any, 0, len(statements))
		for _, s := range statements {
			ss = append(ss, s)
		}
		return map[string]interface{}{"vex": map[string]interface{}{"collections": []any{
			map[string]any{"attestations": map[string]any{"https://openvex.dev/ns": map[string]any{
				"vexDocument": map[string]any{"statements": ss}}}}}}}
	}
	notAffected := func(id string) map[string]any {
		return map[string]any{"vulnerability": map[string]any{"name": id}, "status": "not_affected",
			"justification": "vulnerable_code_not_in_execute_path"}
	}
	cases := []struct {
		name  string
		pred  govulnPredicate
		ctx   map[string]interface{}
		admit bool
	}{
		{"fullblind49's three unreachable advisories, each explained",
			findings("GO-2026-5932", "GO-2026-6354", "GO-2026-6355"),
			vex(notAffected("GO-2026-5932"), notAffected("GO-2026-6354"), notAffected("GO-2026-6355")), true},
		{"one advisory without a statement", findings("GO-2026-5932", "GO-2026-6354"),
			vex(notAffected("GO-2026-5932")), false},
		{"not_affected with no justification", findings("GO-1"),
			vex(map[string]any{"vulnerability": map[string]any{"name": "GO-1"}, "status": "not_affected"}), false},
		{"affected is not an explanation", findings("GO-1"),
			vex(map[string]any{"vulnerability": map[string]any{"name": "GO-1"}, "status": "affected"}), false},
		{"fixed covers it", findings("GO-1"),
			vex(map[string]any{"vulnerability": map[string]any{"name": "GO-1"}, "status": "fixed"}), true},
		{"covered through an alias", findings("GO-1"),
			vex(map[string]any{"vulnerability": map[string]any{"name": "CVE-2026-1", "aliases": []any{"GO-1"}},
				"status": "fixed"}), true},
		{"findings and no VEX step at all", findings("GO-1"), map[string]interface{}{"vex": map[string]interface{}{"collections": []any{}}}, false},
		{"no findings needs no VEX", findings(), map[string]interface{}{"vex": map[string]interface{}{"collections": []any{}}}, true},
		{"a statement for a different vulnerability", findings("GO-1"), vex(notAffected("GO-2")), false},
	}
	for _, c := range cases {
		err := EvaluateRegoPolicy(c.pred, regos, c.ctx)
		if c.admit && err != nil {
			t.Errorf("%s: must admit, got %v", c.name, err)
		}
		if !c.admit && err == nil {
			t.Errorf("%s: must refuse, got admit", c.name)
		}
	}
}
