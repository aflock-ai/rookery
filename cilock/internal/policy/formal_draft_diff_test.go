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

// jade:ring local

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"math/rand"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
)

// Differential test: the authoring-validator rules in the Lean model
// (formal/cilock-policy, CilockPolicy/Draft.lean, `lake exe cilock-policy-eval
// --draft-*`) against ValidateRawPolicy and ValidatePolicy. Skips when `lake`
// is not on PATH.

var (
	formalDraftN    = flag.Int("formal-draft-n", 400, "random cases per draft differential")
	formalDraftSeed = flag.Int64("formal-draft-seed", 1, "seed for the draft differential")
)

func draftLeanRun(t *testing.T, cases []json.RawMessage, args ...string) []string {
	t.Helper()
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("lake not on PATH; the differential test needs the Lean toolchain")
	}
	dir := filepath.Join("..", "..", "..", "formal", "cilock-policy")
	build := exec.Command(lake, "build", "cilock-policy-eval")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build cilock-policy-eval: %v\n%s", err, out)
	}
	in, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	run := exec.Command(filepath.Join(dir, ".lake", "build", "bin", "cilock-policy-eval"), args...)
	run.Stdin = bytes.NewReader(in)
	out, err := run.Output()
	if err != nil {
		t.Fatalf("cilock-policy-eval: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(cases) {
		t.Fatalf("lean printed %d verdicts for %d cases:\n%s", len(lines), len(cases), out)
	}
	return lines
}

// draftSlotBase is a draft that decodes and validates on its own, with its
// functionary's common name left as a parameter and an unknown member "x" the
// typed decode ignores, so any JSON can sit there.
func draftSlotBase(commonName string, x any) map[string]any {
	return map[string]any{
		"expires": "2030-01-01T00:00:00Z",
		"roots":   map[string]any{"r": map[string]any{"certificate": "QUJD"}},
		"steps": map[string]any{
			"build": map[string]any{
				"name": "build",
				"functionaries": []any{map[string]any{"type": "root",
					"certConstraint": map[string]any{"roots": []any{"r"}, "commonname": commonName}}},
				"attestations": []any{map[string]any{"type": "https://aflock.ai/attestations/command-run/v0.1"}},
			},
		},
		"x": x,
	}
}

var (
	draftKeys    = []string{"a", "b", "Z", "a.b", "", "é", "__FILL__k"}
	draftStrings = []string{"", "ok", "__FILL__", "__FILL__ the step's argv", "_FILL__", " __FILL__", "x__FILL__"}
)

func randDraftJSON(r *rand.Rand, depth int) any {
	k := r.Intn(7)
	if depth <= 0 && k >= 5 {
		k = r.Intn(5)
	}
	switch k {
	case 0:
		return nil
	case 1:
		return r.Intn(2) == 0
	case 2:
		return r.Intn(10)
	case 3, 4:
		return draftStrings[r.Intn(len(draftStrings))]
	case 5:
		xs := make([]any, r.Intn(4))
		for i := range xs {
			xs[i] = randDraftJSON(r, depth-1)
		}
		return xs
	default:
		m := map[string]any{}
		for i := r.Intn(4); i > 0; i-- {
			m[draftKeys[r.Intn(len(draftKeys))]] = randDraftJSON(r, depth-1)
		}
		return m
	}
}

// goSlotPaths is the slot half of a Go verdict: the path of every
// "unfilled template slot" error, in the order the validator reported them.
func goSlotPaths(res *ValidationResult) []string {
	out := []string{}
	for _, e := range res.Errors {
		if path, _, ok := strings.Cut(e, ": unfilled template slot: "); ok {
			out = append(out, path)
		}
	}
	return out
}

// Without the Lean toolchain too: an out-of-range number the typed decode
// skips must not hide the slots beside it, and the Rego skip of a slotted
// module must never be the only thing that looked at it.
func TestDraftSlotsSurviveAnUnrepresentableNumber(t *testing.T) {
	doc, err := json.Marshal(draftSlotBase("__FILL__ cn", json.RawMessage(`[1e1000,"__FILL__"]`)))
	if err != nil {
		t.Fatal(err)
	}
	for name, res := range map[string]*ValidationResult{
		"raw":      ValidateRawPolicy(context.Background(), doc),
		"envelope": ValidatePolicy(context.Background(), dsse.Envelope{PayloadType: ExpectedPolicyTypeAflock, Payload: doc}, nil),
	} {
		want := []string{"steps.build.functionaries[0].certConstraint.commonname", "x[1]"}
		if got := goSlotPaths(res); !slices.Equal(got, want) || res.Valid {
			t.Errorf("%s: slots %q valid=%v, want %q and invalid\n%v", name, got, res.Valid, want, res.Errors)
		}
	}
}

func TestFormalDraftSlots(t *testing.T) {
	r := rand.New(rand.NewSource(*formalDraftSeed))
	docs := []map[string]any{
		draftSlotBase("*", nil),
		draftSlotBase("__FILL__ the agent's common name", nil),
		draftSlotBase("*", map[string]any{"__FILL__k": "v", "Z": []any{nil, "__FILL__"}, "a": map[string]any{"": "__FILL__"}}),
		// A number no float64 holds, in a member the typed decode ignores:
		// the slots beside it are still named.
		draftSlotBase("__FILL__ cn", json.RawMessage(`1e1000`)),
		draftSlotBase("*", json.RawMessage(`[1e1000,"__FILL__",-1e999999]`)),
		draftSlotBase("*", json.RawMessage(`1e1000`)),
	}
	for i := 0; i < *formalDraftN; i++ {
		cn := "*"
		if r.Intn(4) == 0 {
			cn = draftStrings[r.Intn(len(draftStrings))]
		}
		docs = append(docs, draftSlotBase(cn, randDraftJSON(r, 3)))
	}
	cases := make([]json.RawMessage, len(docs))
	for i, d := range docs {
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		cases[i] = b
	}
	lean := draftLeanRun(t, cases, "--draft-slots")
	slotted := 0
	for i, c := range cases {
		raw := goSlotPaths(ValidateRawPolicy(context.Background(), c))
		env := goSlotPaths(ValidatePolicy(context.Background(),
			dsse.Envelope{PayloadType: ExpectedPolicyTypeAflock, Payload: c}, nil))
		var want []string
		if err := json.Unmarshal([]byte(lean[i]), &want); err != nil {
			t.Fatalf("case %d: lean printed %q: %v", i, lean[i], err)
		}
		if !slices.Equal(raw, want) || !slices.Equal(env, want) {
			t.Errorf("case %d: lean %q, raw %q, envelope %q\n%s", i, want, raw, env, c)
		}
		if len(raw) > 0 {
			slotted++
		}
	}
	// Non-vacuity: the generator must reach both verdicts.
	if slotted == 0 || slotted == len(cases) {
		t.Fatalf("%d of %d cases carried a slot; the generator does not exercise both verdicts", slotted, len(cases))
	}
}

// A repeated key is refused before any slot is looked for: Go's typed decode
// merges a second "steps" into the map the first one filled, while the slot
// scan keeps only the second, so a slotted module in the first would reach
// neither the slot check nor the Rego check.
func TestDraftDuplicateKeysAreRefused(t *testing.T) {
	doc := []byte(`{"expires":"2030-01-01T00:00:00Z","steps":{"build":{"name":"build","attestations":[{"type":"https://aflock.ai/attestations/command-run/v0.2","regopolicies":[{"name":"r","module":"__FILL__ write the rule"}]}]}},"steps":{}}`)
	for name, res := range map[string]*ValidationResult{
		"raw":      ValidateRawPolicy(context.Background(), doc),
		"envelope": ValidatePolicy(context.Background(), dsse.Envelope{PayloadType: ExpectedPolicyTypeAflock, Payload: doc}, nil),
	} {
		if res.Valid || !slices.ContainsFunc(res.Errors, func(e string) bool { return strings.Contains(e, "duplicate object key") }) {
			t.Errorf("%s: valid=%v, want a duplicate-key refusal\n%v", name, res.Valid, res.Errors)
		}
	}
}
