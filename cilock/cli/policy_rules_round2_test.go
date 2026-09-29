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
	"testing"

	"github.com/stretchr/testify/require"
)

// Codex round 2 on #10194: a counter the tests-pass rule reads must be a
// nonnegative integer. A negative failed or errors count is not "> 0", so it
// used to read as a pass. The mechanism is every counter a seeded rule
// compares, so the govulncheck counts are held to the same shape.
func TestSeededRuleCountersAreNonnegativeIntegers(t *testing.T) {
	pred := func(summary map[string]any) map[string]any {
		return map[string]any{"predicate": map[string]any{"summary": summary}}
	}
	bad := []any{-1, -0.5, 1.5, 0.25}
	for _, field := range []string{"total", "passed", "failed", "errors", "skipped"} {
		for _, v := range bad {
			s := map[string]any{"total": 2, "passed": 2, "failed": 0, "errors": 0, "skipped": 0}
			s[field] = v
			requireDenied(t, evalRule(t, ruleTestsPass, "", pred(s), nil), "unreadable evidence")
		}
	}
	// The exact bypass Codex named.
	requireDenied(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 1, "passed": 1, "failed": -1, "errors": -1}), nil), "unreadable evidence")
	// 2.0 is an integer however it was encoded.
	require.NoError(t, evalRule(t, ruleTestsPass, "", pred(map[string]any{"total": 2.0, "passed": 2, "failed": 0}), nil))

	gv := func(reach, unreach any, findings []any) map[string]any {
		return map[string]any{"summary": map[string]any{"reachableCount": reach, "unreachableCount": unreach, "scanLevel": "symbol", "findings": findings}}
	}
	require.NoError(t, evalRule(t, ruleGovulncheckReachable, "", gv(0, 1, []any{map[string]any{"osvId": "GO-1", "reachable": false}}), nil))
	for _, v := range bad {
		requireDenied(t, evalRule(t, ruleGovulncheckReachable, "", gv(v, 0, []any{}), nil), "unreadable evidence")
		requireDenied(t, evalRule(t, ruleGovulncheckReachable, "", gv(0, v, []any{}), nil), "unreadable evidence")
	}
}

// Codex round 2 on #10194: a result may name its rule through a
// reportingDescriptorReference (`rule: {id, index}`, SARIF 2.1.0 §3.27.7,
// §3.52) instead of the top-level ruleIndex/ruleId, and the rule it names
// supplies the default level exactly as ruleIndex does. The mechanism is
// every way SARIF lets a result's level come from somewhere other than the
// result: each is resolved, or refused as unreadable, never read as warning.
func TestSARIFResolvesEveryRuleReference(t *testing.T) {
	report := func(runs ...any) map[string]any { return map[string]any{"report": map[string]any{"runs": runs}} }
	run := func(rules []any, results ...any) map[string]any {
		return map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "lint", "rules": rules}}, "results": results}
	}
	errRule := []any{map[string]any{"id": "W"}, map[string]any{"id": "E", "defaultConfiguration": map[string]any{"level": "error"}}}

	cases := map[string]map[string]any{
		"rule.id and rule.index":     {"rule": map[string]any{"id": "E", "index": 1}},
		"rule.index only":            {"rule": map[string]any{"index": 1}},
		"rule.id only":               {"rule": map[string]any{"id": "E"}},
		"rule.index beside ruleId W": {"ruleId": "W", "rule": map[string]any{"index": 1}},
		"ruleIndex beside rule.id W": {"ruleIndex": 1, "rule": map[string]any{"id": "W"}},
		"hierarchical ruleId":        {"ruleId": "E/sub"},
		"hierarchical rule.id":       {"rule": map[string]any{"id": "E/sub"}},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, r)), nil), "error-level result")
		})
	}
	// The references still resolve to a warning rule without a denial.
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, map[string]any{"rule": map[string]any{"id": "W", "index": 0}})), nil))
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, map[string]any{"ruleId": "Wx"})), nil), "a prefix that is not a hierarchy level names no rule")

	unreadable := map[string]map[string]any{
		"rule not an object":        {"rule": "E"},
		"rule.index names no rule":  {"rule": map[string]any{"index": 9}},
		"rule.index not a number":   {"rule": map[string]any{"index": "1"}},
		"rule in a tool extension":  {"rule": map[string]any{"id": "E", "toolComponent": map[string]any{"index": 0}}},
		"rule.id not a string":      {"rule": map[string]any{"id": 1}},
		"ruleId not a string":       {"ruleId": 7},
		"ruleIndex beside bad rule": {"ruleIndex": 1, "rule": []any{}},
	}
	for name, r := range unreadable {
		t.Run(name, func(t *testing.T) {
			requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(run(errRule, r)), nil), "unreadable evidence")
		})
	}

	// A run whose invocations override a rule's configuration, or that
	// carries policies, can raise a warning rule to an error (§3.27.10).
	// The rule does not resolve overrides, so it refuses them as unreadable.
	for _, extra := range []map[string]any{
		{"invocations": []any{map[string]any{"ruleConfigurationOverrides": []any{map[string]any{
			"descriptor": map[string]any{"index": 0}, "configuration": map[string]any{"level": "error"}}}}}},
		{"policies": []any{map[string]any{"name": "strict"}}},
	} {
		r := run(errRule, map[string]any{"ruleId": "W"})
		for k, v := range extra {
			r[k] = v
		}
		requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", report(r), nil), "unreadable evidence")
	}
	// Empty override lists change nothing.
	r := run(errRule, map[string]any{"ruleId": "W"})
	r["invocations"] = []any{map[string]any{"ruleConfigurationOverrides": []any{}, "executionSuccessful": true}}
	r["policies"] = []any{}
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", report(r), nil))
}
