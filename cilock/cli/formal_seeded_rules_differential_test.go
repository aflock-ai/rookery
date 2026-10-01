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

package cli

// Differential test: every seeded rule in policy_rules.go, evaluated by the
// verifier's own evaluator (policy.EvaluateRegoPolicy), against the Lean model
// of the same rule in formal/cilock-evaluators/CilockEvaluators/Seeded (the
// oracle's `seeded` case kind).
//
// Each rule starts from a predicate it admits, then takes random mutations:
// deleted keys, values of the wrong kind, boundary numbers, empty and
// path-traversal strings, SARIF spellings the rule must resolve, and an
// attestationsFrom wrapper. The two verdicts must agree on every case, and
// every rule must be admitted at least once, so a model that denies
// everything cannot pass.
//
// The rule set is read from ruleTemplates, so a rule added to the code without
// a model is an oracle error, and fails here.
//
// Skips when the oracle is absent (Lean is not provisioned on CI).
// CILOCK_EVALUATORS_ORACLE names another oracle binary; FORMAL_DIFF_SEED and
// FORMAL_DIFF_N change the seed and the cases per rule.
//
// formal:differential cilock-evaluators TestFormalDifferentialSeededRules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// seededRulesModel is the Lean project the oracle is built from. A path
// literal on purpose: `jade check formal-differential-inputs` reads it.
const seededRulesModel = "../../formal/cilock-evaluators"

func seededOracle(t *testing.T) string {
	t.Helper()
	_ = viper.BindEnv("cilock_evaluators_oracle", "CILOCK_EVALUATORS_ORACLE")
	if p := viper.GetString("cilock_evaluators_oracle"); p != "" {
		return p
	}
	dir, err := filepath.Abs(seededRulesModel)
	require.NoError(t, err)
	// Always run the incremental build: lake rebuilds only what changed, and
	// reusing an existing binary would compare the code against whatever
	// model was built last rather than the model in the tree.
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("`lake` not on PATH, so the Lean oracle cannot be rebuilt from the current model; install elan")
	}
	build := exec.Command(lake, "build", "cilock-evaluators-oracle")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build cilock-evaluators-oracle: %v\n%s", err, out)
	}
	return filepath.Join(dir, ".lake", "build", "bin", "cilock-evaluators-oracle")
}

func seededEnvInt(name string, def int) int {
	_ = viper.BindEnv(strings.ToLower(name), name)
	if v, err := strconv.Atoi(viper.GetString(strings.ToLower(name))); err == nil && v > 0 {
		return v
	}
	return def
}

// seededBase is, per rule, the fill value and a predicate the rule admits.
// The bases are rich on purpose: every branch a mutation can reach is present
// in them (SARIF results naming their rule by index, by id, by rule object and
// by hierarchical id; govulncheck findings on both sides of the reachable
// flag).
func seededBase(id string) (param any, pred map[string]any) {
	switch id {
	case ruleCommandSucceeded:
		return nil, map[string]any{"exitcode": 0, "cmd": []any{"go", "test"}}
	case ruleCommandPin:
		return []any{"go", "test", "./..."}, map[string]any{"exitcode": 0, "cmd": []any{"go", "test", "./..."}}
	case ruleProductRecorded:
		return nil, map[string]any{"treeSize": 2, "merkleRoot": "ab12"}
	case ruleTestsPass:
		return nil, map[string]any{"predicate": map[string]any{"summary": map[string]any{
			"total": 3, "passed": 2, "failed": 0, "errors": 0, "skipped": 1}}}
	case ruleSARIFNoErrors:
		rules := []any{
			map[string]any{"id": "W1"},
			map[string]any{"id": "E1", "defaultConfiguration": map[string]any{"level": "error"}},
			map[string]any{"id": "N1", "defaultConfiguration": map[string]any{"level": "note"}},
		}
		results := []any{
			map[string]any{"ruleId": "W1", "level": "warning"},
			map[string]any{"ruleId": "E1", "ruleIndex": 1, "level": "note"},
			map[string]any{"ruleIndex": 2},
			map[string]any{"rule": map[string]any{"id": "W1", "index": 0}},
			map[string]any{"ruleId": "N1/sub"},
			map[string]any{"ruleId": "E1", "level": "none",
				"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "a.go"}}}}},
		}
		run := map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "lint", "rules": rules}},
			"results": results, "invocations": []any{map[string]any{"executionSuccessful": true}}}
		return nil, map[string]any{"report": map[string]any{"runs": []any{run}}}
	case ruleSecretscanClean:
		return nil, map[string]any{"findings": []any{}, "scope": map[string]any{"files": "diff", "productDigestMismatches": []any{}}}
	case ruleGovulncheckReachable:
		return nil, map[string]any{"summary": map[string]any{
			"reachableCount": 0, "unreachableCount": 2, "scanLevel": "symbol",
			"findings": []any{
				map[string]any{"osvId": "GO-1", "reachable": false},
				map[string]any{"osvId": "GO-2", "reachable": false},
			}}}
	}
	return nil, nil
}

// seededKeys are the keys a mutation adds to an object: every key a seeded
// rule reads, so an added key can change a verdict.
var seededKeys = []string{
	"exitcode", "cmd", "treeSize", "merkleRoot", "predicate", "summary", "total", "passed", "failed",
	"errors", "skipped", "report", "runs", "results", "tool", "driver", "rules", "id", "level",
	"defaultConfiguration", "ruleId", "ruleIndex", "rule", "index", "toolComponent", "invocations",
	"ruleConfigurationOverrides", "policies", "findings", "scope", "productDigestMismatches",
	"reachableCount", "unreachableCount", "scanLevel", "reachable", "osvId", "attestation",
}

func seededScalar(r *rand.Rand) any {
	switch r.IntN(4) {
	case 0:
		return nil
	case 1:
		return r.IntN(2) == 0
	case 2:
		return []int{-1, 0, 1, 2, 3, 5, 99}[r.IntN(7)]
	default:
		return []string{"", "../x", "/etc/passwd", "error", "warning", "note", "none", "ERROR", "symbol",
			"module", "W1", "E1", "N1", "E1/sub", "W1/", "GO-1"}[r.IntN(16)]
	}
}

func seededValue(r *rand.Rand, depth int) any {
	if depth <= 0 || r.IntN(3) > 0 {
		return seededScalar(r)
	}
	if r.IntN(2) == 0 {
		n := r.IntN(3)
		xs := make([]any, n)
		for i := range xs {
			xs[i] = seededValue(r, depth-1)
		}
		return xs
	}
	m := map[string]any{}
	for range r.IntN(3) {
		m[seededKeys[r.IntN(len(seededKeys))]] = seededValue(r, depth-1)
	}
	return m
}

// seededClone deep-copies a JSON value built from maps, slices and scalars.
func seededClone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = seededClone(e)
		}
		return m
	case []any:
		xs := make([]any, len(x))
		for i, e := range x {
			xs[i] = seededClone(e)
		}
		return xs
	}
	return v
}

// seededMutate applies one random edit at a random node of v, returning the
// new value (the root can be replaced).
func seededMutate(r *rand.Rand, v any) any {
	// Descend with probability 2/3 while there is somewhere to go.
	switch x := v.(type) {
	case map[string]any:
		// Sorted, so a seed names one sequence of cases.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(x) > 0 && r.IntN(3) > 0 {
			k := keys[r.IntN(len(keys))]
			x[k] = seededMutate(r, x[k])
			return x
		}
		switch r.IntN(4) {
		case 0: // delete a key
			if len(keys) > 0 {
				delete(x, keys[r.IntN(len(keys))])
			}
		case 1: // add or overwrite a key the rules read
			x[seededKeys[r.IntN(len(seededKeys))]] = seededValue(r, 2)
		default:
			return seededValue(r, 2)
		}
		return x
	case []any:
		if len(x) > 0 && r.IntN(3) > 0 {
			i := r.IntN(len(x))
			x[i] = seededMutate(r, x[i])
			return x
		}
		switch r.IntN(4) {
		case 0:
			if len(x) > 0 {
				return x[:len(x)-1]
			}
			return x
		case 1:
			if len(x) > 0 {
				return append(x, seededClone(x[r.IntN(len(x))]))
			}
			return append(x, seededValue(r, 2))
		case 2:
			return append(x, seededValue(r, 2))
		default:
			return seededValue(r, 2)
		}
	}
	return seededValue(r, 2)
}

type seededCase struct {
	Kind      string         `json:"kind"`
	Rule      string         `json:"rule"`
	Param     any            `json:"param"`
	Predicate map[string]any `json:"predicate"`
	Steps     map[string]any `json:"steps,omitempty"`
}

func TestFormalDifferentialSeededRules(t *testing.T) {
	bin := seededOracle(t)
	seed := uint64(seededEnvInt("FORMAL_DIFF_SEED", 20260928))
	n := seededEnvInt("FORMAL_DIFF_N", 400)
	r := rand.New(rand.NewPCG(seed, seed^0x5eed))

	var cases []seededCase
	for _, id := range sortedRuleIDs() {
		param, base := seededBase(id)
		require.NotNil(t, base, "rule %s has no differential base; add one to seededBase", id)
		for i := 0; i < n; i++ {
			pred := seededClone(base).(map[string]any)
			// Case 0 is the base itself; the rest take 1 to 3 edits.
			for range min(i, 1+r.IntN(3)) {
				if m, ok := seededMutate(r, pred).(map[string]any); ok {
					pred = m
				}
			}
			c := seededCase{Kind: "seeded", Rule: id, Param: seededClone(param), Predicate: pred}
			if i%4 == 3 {
				c.Steps = map[string]any{"build": map[string]any{"collections": []any{}}}
			}
			cases = append(cases, c)
		}
	}

	var in strings.Builder
	for _, c := range cases {
		b, err := json.Marshal(c)
		require.NoError(t, err)
		in.Write(b)
		in.WriteByte('\n')
	}
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(in.String())
	out, err := cmd.Output()
	require.NoError(t, err, "oracle failed")
	var lean []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lean = append(lean, sc.Text())
	}
	require.Len(t, lean, len(cases), "oracle must answer every case")

	admitted := map[string]int{}
	mismatches := map[string]int{}
	var examples []string
	for i, c := range cases {
		var raw json.RawMessage
		if c.Param != nil {
			b, err := json.Marshal(c.Param)
			require.NoError(t, err)
			raw = b
		}
		src, err := renderRule(c.Rule, raw)
		require.NoError(t, err)
		regos := []policy.RegoPolicy{{Name: c.Rule, Module: []byte(src)}}
		var evalErr error
		if c.Steps != nil {
			evalErr = policy.EvaluateRegoPolicy(predicateAttestor{c.Predicate}, regos, c.Steps)
		} else {
			evalErr = policy.EvaluateRegoPolicy(predicateAttestor{c.Predicate}, regos)
		}
		goV := "admit"
		if evalErr != nil {
			goV = "deny"
		} else {
			admitted[c.Rule]++
		}
		if lean[i] != goV {
			mismatches[c.Rule]++
			if len(examples) < 8 {
				b, _ := json.Marshal(c)
				examples = append(examples, fmt.Sprintf("go=%s lean=%s (go err: %v) %s", goV, lean[i], evalErr, b))
			}
		}
	}
	total := 0
	for _, id := range sortedRuleIDs() {
		t.Logf("%s: %d cases, %d admitted, %d mismatches", id, n, admitted[id], mismatches[id])
		total += mismatches[id]
		if admitted[id] == 0 {
			t.Errorf("%s: no case was admitted; the differential proves nothing about this rule", id)
		}
	}
	for _, e := range examples {
		t.Log("  example: " + e)
	}
	if total > 0 {
		t.Errorf("%d/%d seeded-rule cases disagree with the Lean model (seed %d)", total, len(cases), seed)
	}
}
