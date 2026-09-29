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

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/policy"
	internalpolicy "github.com/aflock-ai/rookery/cilock/internal/policy"
	"github.com/stretchr/testify/require"
)

// evalRule runs one seeded rule through the verifier's own evaluator.
// wrapped hands it the {attestation, steps} input a step with
// attestationsFrom produces.
func evalRule(t *testing.T, id string, param string, predicate map[string]any, steps map[string]any) error {
	t.Helper()
	var raw json.RawMessage
	if param != "" {
		raw = json.RawMessage(param)
	}
	src, err := renderRule(id, raw)
	require.NoError(t, err)
	regos := []policy.RegoPolicy{{Name: id, Module: []byte(src)}}
	if steps != nil {
		return policy.EvaluateRegoPolicy(predicateAttestor{predicate}, regos, steps)
	}
	return policy.EvaluateRegoPolicy(predicateAttestor{predicate}, regos)
}

func requireDenied(t *testing.T, err error, contains string) {
	t.Helper()
	require.Error(t, err)
	var denied policy.ErrPolicyDenied
	require.True(t, errors.As(err, &denied), "want a rego denial, got %v", err)
	require.Contains(t, strings.Join(denied.Reasons, " | "), contains)
}

// Every seeded rule parses as RegoV0, passes cilock policy validate's syntax
// check, and refuses the empty predicate: a rule that admits {} admits any
// predicate missing the fields it reads.
func TestSeededRulesFailClosedOnEmptyPredicate(t *testing.T) {
	for _, id := range sortedRuleIDs() {
		r := ruleTemplates[id]
		t.Run(id, func(t *testing.T) {
			param := ""
			if r.requiresParam() {
				param = r.Example
			}
			err := evalRule(t, id, param, map[string]any{}, nil)
			require.Error(t, err, "rule %s admitted an empty predicate", id)
			var denied policy.ErrPolicyDenied
			require.True(t, errors.As(err, &denied), "rule %s must deny, not error, on {}: %v", id, err)

			src, err := renderRule(id, json.RawMessage(param))
			if !r.requiresParam() {
				src, err = renderRule(id, nil)
			}
			require.NoError(t, err)
			doc := map[string]any{
				"expires": "2099-01-01T00:00:00Z",
				"steps": map[string]any{"s": map[string]any{
					"name":          "s",
					"functionaries": []any{map[string]any{"type": "publickey", "publickeyid": "k"}},
					"attestations": []any{map[string]any{"type": r.Type, "regopolicies": []any{
						map[string]any{"name": id, "module": base64.StdEncoding.EncodeToString([]byte(src))},
					}}},
				}},
				"publickeys": map[string]any{"k": map[string]any{"keyid": "k", "key": ""}},
			}
			raw, err := json.Marshal(doc)
			require.NoError(t, err)
			res := internalpolicy.ValidateRawPolicy(context.Background(), raw)
			require.True(t, res.Valid, "validate rejected rule %s: %v", id, res.Errors)
			for _, w := range res.Warnings {
				require.NotContains(t, w, "deny nothing on an empty predicate", "rule %s", id)
			}
		})
	}
}

// Every seeded rule reads the predicate the same way whether the step has an
// attestationsFrom edge or not: the wrapped input must not turn a pass into
// an "unreadable evidence" refusal.
func TestSeededRulesReadTheWrappedInput(t *testing.T) {
	ok := map[string]any{"exitcode": 0, "cmd": []any{"go", "test", "./..."}}
	require.NoError(t, evalRule(t, ruleCommandSucceeded, "", ok, nil))
	require.NoError(t, evalRule(t, ruleCommandSucceeded, "", ok, map[string]any{"build": map[string]any{}}))
	require.NoError(t, evalRule(t, ruleCommandPin, `["go","test","./..."]`, ok, map[string]any{"build": map[string]any{}}))
	requireDenied(t, evalRule(t, ruleCommandSucceeded, "", map[string]any{"exitcode": 1}, map[string]any{"build": map[string]any{}}), "exited 1")
}

func TestCommandRules(t *testing.T) {
	requireDenied(t, evalRule(t, ruleCommandSucceeded, "", map[string]any{"exitcode": "0"}, nil), "no numeric exitcode")
	requireDenied(t, evalRule(t, ruleCommandSucceeded, "", map[string]any{"exitcode": 2}, nil), "exited 2")
	requireDenied(t, evalRule(t, ruleCommandPin, `["go","test","./..."]`, map[string]any{"cmd": []any{"true"}}, nil), `command must be ["go", "test", "./..."]; got ["true"]`)
	requireDenied(t, evalRule(t, ruleCommandPin, `["go","test","./..."]`, map[string]any{"exitcode": 0}, nil), "no cmd argv")
	_, err := renderRule(ruleCommandPin, json.RawMessage(`[]`))
	require.Error(t, err, "an empty pin would pin nothing")
	_, err = renderRule(ruleCommandPin, json.RawMessage(`["__FILL__ x"]`))
	require.Error(t, err, "a slot is not a value")
}

func TestTestsPassRule(t *testing.T) {
	pred := func(summary map[string]any) map[string]any {
		return map[string]any{"predicate": map[string]any{"summary": summary}}
	}
	require.NoError(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 12, "passed": 12, "failed": 0, "skipped": 0}), nil))
	requireDenied(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 0, "passed": 0, "failed": 0}), nil), "0 tests")
	requireDenied(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 3, "passed": 2, "failed": 1}), nil), "1 of 3 tests failed")
	requireDenied(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 3, "passed": 1, "failed": 0, "errors": 2}), nil), "2 tests errored")
	requireDenied(t, evalRule(t, ruleTestsPass, "", map[string]any{"summary": map[string]any{"total": 3, "failed": 0}}, nil), "unreadable evidence")
	// Every test skipped: nothing ran, so nothing passed.
	requireDenied(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 4, "passed": 0, "failed": 0, "skipped": 4}), nil), "none of 4 tests passed (4 skipped)")
	// No passed count: the attestor always writes one, so its absence is unreadable, not a pass.
	requireDenied(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 4, "failed": 0, "skipped": 4}), nil), "unreadable evidence")
}

func TestSARIFNoErrorsRule(t *testing.T) {
	report := func(runs ...any) map[string]any { return map[string]any{"report": map[string]any{"runs": runs}} }
	run := func(rules []any, results ...any) map[string]any {
		if results == nil {
			results = []any{}
		}
		return map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "lint", "rules": rules}}, "results": results}
	}
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(run(nil)), nil), "a run with no results is clean")
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(run(nil, map[string]any{"ruleId": "W1", "level": "warning"})), nil))
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(nil, map[string]any{"ruleId": "E1", "level": "error",
		"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "main.go"}}}}})), nil), "rule E1 at main.go")
	// No level on the result: the rule's defaultConfiguration decides (SARIF 2.1.0 §3.27.10).
	rules := []any{map[string]any{"id": "E2", "defaultConfiguration": map[string]any{"level": "error"}}}
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(rules, map[string]any{"ruleId": "E2", "ruleIndex": 0})), nil), "rule E2 at an unknown location")
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(run(nil, map[string]any{"ruleId": "N1"})), nil), "no level anywhere is warning")
	// No level and no ruleIndex: the rule is found by ruleId, and its default decides.
	byID := []any{map[string]any{"id": "W9"}, map[string]any{"id": "E3", "defaultConfiguration": map[string]any{"level": "error"}}}
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(byID, map[string]any{"ruleId": "E3"})), nil), "rule E3 at an unknown location")
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(run(byID, map[string]any{"ruleId": "W9"})), nil), "a rule with no default is a warning")
	// Two rules sharing an id, one an error: the result is an error, not an evaluation conflict.
	dup := []any{map[string]any{"id": "D1", "defaultConfiguration": map[string]any{"level": "note"}}, map[string]any{"id": "D1", "defaultConfiguration": map[string]any{"level": "error"}}}
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(dup, map[string]any{"ruleId": "D1"})), nil), "rule D1")
	// An explicit level still wins over the rule's default.
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(run(byID, map[string]any{"ruleId": "E3", "level": "note"})), nil))
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(map[string]any{"tool": map[string]any{}}), nil), "unreadable evidence")
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(), nil), "unreadable evidence")
	// Codex round 1 on #10194: a level outside SARIF's enum used to fail the
	// "error" test AND suppress the rule's default, reading as a warning.
	errRule := []any{map[string]any{"id": "E", "defaultConfiguration": map[string]any{"level": "error"}}}
	for _, bad := range []any{42, "ERROR", "fatal", nil, true} {
		requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, map[string]any{"ruleId": "E", "level": bad})), nil), "unreadable evidence")
	}
	badDefault := []any{map[string]any{"id": "E", "defaultConfiguration": map[string]any{"level": 7}}}
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(badDefault, map[string]any{"ruleId": "E"})), nil), "unreadable evidence")
	// A ruleIndex that names no listed rule cannot supply a level.
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, map[string]any{"ruleId": "E", "ruleIndex": 5})), nil), "unreadable evidence")
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, map[string]any{"ruleId": "E", "ruleIndex": "0"})), nil), "unreadable evidence")
	// A result, run or tool that is not an object is unreadable, never clean.
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, []any{nil}...)), nil), "unreadable evidence")
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, map[string]any{"ruleId": "E", "ruleIndex": -1})), nil), "unreadable evidence")
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, "E")), nil), "unreadable evidence")
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report("run"), nil), "unreadable evidence")
	notObjectTool := map[string]any{"tool": "lint", "results": []any{map[string]any{"ruleId": "X", "level": "error"}}}
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(notObjectTool), nil), "sarif: a tool reported an error-level result: rule X")
}

func TestProductRecordedRule(t *testing.T) {
	require.NoError(t, evalRule(t, ruleProductRecorded, "", map[string]any{"treeSize": 2, "merkleRoot": "ab"}, nil))
	requireDenied(t, evalRule(t, ruleProductRecorded, "", map[string]any{"treeSize": 0, "merkleRoot": ""}, nil), "recorded no products")
}

func TestSecretscanRule(t *testing.T) {
	require.NoError(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{}}, nil))
	require.NoError(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{}, "scope": map[string]any{"files": "diff"}}, nil))
	requireDenied(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{map[string]any{"ruleId": "aws-key", "location": "file:a.go"}}}, nil), "rule aws-key at file:a.go")
	// Codex round 1 on #10194: a finding that is not an object used to make
	// the deny's message undefined, dropping the only deny.
	for _, bad := range []any{nil, "aws-key", 3, []any{}} {
		requireDenied(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{bad}}, nil), "unreadable evidence")
	}
	// A finding object missing its fields still denies, with defaults in the message.
	requireDenied(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{map[string]any{}}}, nil), "rule unnamed at an unknown location")
	// productDigestMismatches that is not a list is unreadable, not "none".
	for _, bad := range []any{false, "x", 0} {
		requireDenied(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{}, "scope": map[string]any{"productDigestMismatches": bad}}, nil), "unreadable evidence")
	}
}
