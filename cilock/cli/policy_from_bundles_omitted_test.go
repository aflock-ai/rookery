// jade:ring local

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/invopop/jsonschema"
)

// predicateAttestor feeds a fixed predicate to the verifier's own Rego
// evaluator, so the generated module is judged by the code that enforces it.
type predicateAttestor struct{ predicate map[string]any }

func (p predicateAttestor) Name() string { return "command-run" }
func (p predicateAttestor) Type() string {
	return "https://aflock.ai/attestations/command-run/v0.2"
}
func (p predicateAttestor) RunType() attestation.RunType                   { return "execute" }
func (p predicateAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (p predicateAttestor) Schema() *jsonschema.Schema                     { return nil }
func (p predicateAttestor) MarshalJSON() ([]byte, error)                   { return json.Marshal(p.predicate) }

// A starter policy for a step that wraps a command must require the command to
// have SUCCEEDED. It used to require only that a command-run attestation
// existed, so the verifier accepted evidence of a failed test run, which fails
// open for exactly the goal "tests pass" (found by running the local-key loop
// end to end: verify of a `false` run exited 0). Absence of a numeric exit
// code is a refusal, never a pass.
func TestFromBundlesRequiresCommandRunToSucceed(t *testing.T) {
	dir := t.TempDir()
	bundle := writeOmittedInventoryBundle(t, dir, "tests")
	out := filepath.Join(dir, "policy.json")
	if err := runPolicyFromBundles(&bytes.Buffer{}, &bytes.Buffer{}, []string{bundle}, nil, out, 24*time.Hour, ""); err != nil {
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
	for _, a := range pol.Steps["tests"].Attestations {
		if a.Type == "https://aflock.ai/attestations/command-run/v0.2" {
			regos = a.RegoPolicies
		}
	}
	if len(regos) == 0 {
		t.Fatalf("command-run must carry a Rego rule requiring success: %s", raw)
	}
	cases := []struct {
		name      string
		predicate map[string]any
		admit     bool
	}{
		{"exit 0", map[string]any{"cmd": []string{"go", "test"}, "exitcode": 0}, true},
		{"exit 1", map[string]any{"cmd": []string{"go", "test"}, "exitcode": 1}, false},
		{"exit -1", map[string]any{"cmd": []string{"go", "test"}, "exitcode": -1}, false},
		{"no exitcode", map[string]any{"cmd": []string{"go", "test"}}, false},
		{"string exitcode", map[string]any{"cmd": []string{"go", "test"}, "exitcode": "0"}, false},
		{"null exitcode", map[string]any{"cmd": []string{"go", "test"}, "exitcode": nil}, false},
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

// writeOmittedInventoryBundle writes the collection a stock compact
// `cilock run` produces: the material attestation carries a signed Merkle root
// and an inventory reference whose state is "omitted" (no per-file leaves).
// The shape is copied from a real `cilock run -o` envelope.
func writeOmittedInventoryBundle(t *testing.T, dir, step string) string {
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
					"type": "https://aflock.ai/attestations/material/v0.3",
					"attestation": map[string]any{
						"merkleRoot":    manifestTestDigest("material-root-" + step),
						"treeSize":      24,
						"hashAlgorithm": "sha256",
						"construction":  "RFC6962",
						"inventory": map[string]any{
							"schema":       "https://aflock.ai/attestations/file-inventory/v0.1",
							"kind":         "material",
							"state":        "omitted",
							"fileCount":    25,
							"captureMode":  "walk",
							"captureScope": "working-directory",
						},
					},
				},
				map[string]any{
					"type":        "https://aflock.ai/attestations/command-run/v0.2",
					"attestation": map[string]any{"cmd": []string{"go", "test", "./..."}, "exitcode": 0},
				},
			},
		},
	})
	return path
}

// A single step has no cross-step artifact edges to infer, so an omitted
// material inventory must not stop the generator. Before this, the stock
// output of `cilock run -o` could not seed a policy at all (fullblind27: an
// agent read the help, saw no way through, and hand-wrote its policy).
func TestFromBundlesSingleStepToleratesOmittedInventory(t *testing.T) {
	dir := t.TempDir()
	bundle := writeOmittedInventoryBundle(t, dir, "tests")
	out := filepath.Join(dir, "policy.json")
	var stderr bytes.Buffer
	if err := runPolicyFromBundles(&bytes.Buffer{}, &stderr, []string{bundle}, nil, out, 24*time.Hour, ""); err != nil {
		t.Fatalf("single-step compact bundle must yield a starter policy, got: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var pol struct {
		Steps map[string]struct {
			Attestations []struct {
				Type string `json:"type"`
			} `json:"attestations"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &pol); err != nil {
		t.Fatal(err)
	}
	step, ok := pol.Steps["tests"]
	if !ok {
		t.Fatalf("policy has no tests step: %s", raw)
	}
	var sawRun bool
	for _, a := range step.Attestations {
		sawRun = sawRun || a.Type == "https://aflock.ai/attestations/command-run/v0.2"
	}
	if !sawRun {
		t.Fatalf("tests step must require command-run: %s", raw)
	}
	if !strings.Contains(stderr.String(), "no cross-step edges") {
		t.Fatalf("the omitted inventory must be reported, not silently ignored; stderr: %q", stderr.String())
	}
}

// Across several steps an omitted inventory WOULD hide an artifactsFrom edge,
// and a starter policy missing an edge is weaker than the evidence supports.
// That case still refuses, naming the step and the flag that retains the
// inventory, instead of failing on the first envelope it reads.
func TestFromBundlesMultiStepRefusesOmittedInventoryByName(t *testing.T) {
	dir := t.TempDir()
	a := writeOmittedInventoryBundle(t, dir, "tests")
	b := writeInlineProductBundle(t, dir, "build", map[string]string{"bin/app": manifestTestDigest("app")})
	err := runPolicyFromBundles(&bytes.Buffer{}, &bytes.Buffer{}, []string{b, a}, nil,
		filepath.Join(dir, "policy.json"), 24*time.Hour, "")
	if err == nil {
		t.Fatal("multi-step generation must refuse when an inventory it needs for edges is omitted")
	}
	for _, want := range []string{"tests", "--material-manifest"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal must name %q; got: %v", want, err)
		}
	}
}
