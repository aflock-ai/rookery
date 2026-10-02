// jade:ring local

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

package policy

// A deny body that reads a field the attestor did not emit never
// fires, so the step passed. An admit that rests on such a read is refused,
// with no warn mode, under every hardening setting.

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

func forgetStrictCaches(t *testing.T) {
	t.Helper()
	forgetFailOpenLint(t)
	forget := func() {
		strictProbesMu.Lock()
		defer strictProbesMu.Unlock()
		clear(strictProbesCache)
	}
	forget()
	t.Cleanup(forget)
}

func requireRefusal(t *testing.T, err error, path string) {
	t.Helper()
	require.Error(t, err)
	require.ErrorContains(t, err, "#9820")
	require.ErrorContains(t, err, path)
	var denied ErrPolicyDenied
	require.False(t, errors.As(err, &denied), "a refusal, not a deny the policy made: %v", err)
}

func requireDenied(t *testing.T, err error) {
	t.Helper()
	var denied ErrPolicyDenied
	require.True(t, errors.As(err, &denied), "want the policy's own deny, got %v", err)
}

func evalModule(t *testing.T, att *lintAttestor, module string, ctx ...map[string]interface{}) error {
	t.Helper()
	return EvaluateRegoPolicy(att, []RegoPolicy{{Name: "m", Module: []byte(module)}}, ctx...)
}

// The shape the issue names: a comparison in the deny body over a field the
// attestor did not emit.
func TestStrictDeny_PositiveReadOfMissingFieldIsRefused(t *testing.T) {
	forgetStrictCaches(t)
	module := "package p\ndeny[msg] { input.reftype != \"tag\"; msg := \"not a tag\" }\n"

	requireRefusal(t, evalModule(t, &lintAttestor{}, module), "input.reftype")
	require.NoError(t, evalModule(t, &lintAttestor{Reftype: "tag"}, module))
	requireDenied(t, evalModule(t, &lintAttestor{Reftype: "branch"}, module))

	// The same under every hardening option, and under none: no warn mode.
	withHardening(t, HardeningOptions{})
	requireRefusal(t, evalModule(t, &lintAttestor{}, module), "input.reftype")
	withHardening(t, everyHardening())
	requireRefusal(t, evalModule(t, &lintAttestor{}, module), "input.reftype")
}

// The lint's shape: a negation whose read the compiler hoists.
func TestStrictDeny_HoistedNegationOfMissingFieldIsRefused(t *testing.T) {
	forgetStrictCaches(t)
	module := v0Deny(`	not startswith(input.reftype, "tag")`)

	requireRefusal(t, evalModule(t, &lintAttestor{}, module), "input.reftype")
	require.NoError(t, evalModule(t, &lintAttestor{Reftype: "tag"}, module))
	requireDenied(t, evalModule(t, &lintAttestor{Reftype: "branch"}, module))
}

// A read through an alias resolves to the input path under it.
func TestStrictDeny_AliasedReadIsFollowed(t *testing.T) {
	forgetStrictCaches(t)
	module := "package p\ndeny[msg] { r := input.reftype; r != \"tag\"; msg := \"not a tag\" }\n"
	requireRefusal(t, evalModule(t, &lintAttestor{}, module), "input.reftype")
	require.NoError(t, evalModule(t, &lintAttestor{Reftype: "tag"}, module))
}

// A negation in a helper rule deny reaches is the lint's finding; it is
// refused on a missing field too.
func TestStrictDeny_HelperNegationFindingIsRefused(t *testing.T) {
	forgetStrictCaches(t)
	requireRefusal(t, EvaluateRegoPolicy(&lintAttestor{Reftype: "tag"}, siblingModules()), "input.ref")
}

// Under cross-step context the input is wrapped; the check follows the path
// the policy wrote.
func TestStrictDeny_WrappedInput(t *testing.T) {
	forgetStrictCaches(t)
	module := "package p\ndeny[msg] { input.attestation.reftype != \"tag\"; msg := \"x\" }\n"
	ctx := map[string]interface{}{"build": map[string]interface{}{}}
	requireRefusal(t, evalModule(t, &lintAttestor{}, module, ctx), "input.attestation.reftype")
	require.NoError(t, evalModule(t, &lintAttestor{Reftype: "tag"}, module, ctx))
}

// The spellings that handle a missing field are not refused: object.get with
// a default, `not input.x` as an absence test, a helper consumed as
// `not helper`, and a read inside a comprehension (empty, not undefined).
func TestStrictDeny_FailClosedSpellingsAreUnaffected(t *testing.T) {
	forgetStrictCaches(t)
	for name, c := range map[string]struct {
		module string
		denies bool
	}{
		"object.get default":  {"package p\ndeny[msg] { object.get(input, \"reftype\", \"\") != \"tag\"; msg := \"x\" }\n", true},
		"absence test":        {"package p\ndeny[msg] { not input.reftype; msg := \"reftype required\" }\n", true},
		"helper as not":       {v0Deny(`	not tagged`, `tagged { startswith(input.reftype, "tag") }`), true},
		"comprehension count": {"package p\ndeny[msg] { count([x | x := input.items[_]]) > 3; msg := \"x\" }\n", false},
		// "Deny if present": the bare reference is the condition, and
		// missing means it does not hold.
		"existence test": {"package p\ndeny[msg] { input.debug; msg := \"debug build\" }\n", false},
		// An explicit presence guard opts a later read into "only when
		// present".
		"explicit guard": {"package p\ndeny[msg] { input.reftype; input.reftype != \"tag\"; msg := \"x\" }\n", false},
	} {
		forgetStrictCaches(t)
		err := evalModule(t, &lintAttestor{}, c.module)
		if c.denies {
			requireDenied(t, err)
		} else {
			require.NoError(t, err, name)
		}
	}
}

// Helper rules may read optional fields positively; the shipped vuln-scan and
// dev-security policies tell SARIF shapes apart that way. Only deny bodies are
// held to the rule.
func TestStrictDeny_HelperShapeDetectionIsUnaffected(t *testing.T) {
	forgetStrictCaches(t)
	module := `package shapes
runs := input.report.runs { input.report.runs }
runs := input.runs { not input.report; input.runs }
deny[msg] { some i; runs[i].bad == true; msg := "bad run" }
`
	require.NoError(t, evalModule(t, &lintAttestor{}, module))
}

func evalRaw(t *testing.T, predicate string, module string) error {
	t.Helper()
	forgetStrictCaches(t)
	att := attestation.NewRawAttestation("https://example.com/raw/v1", json.RawMessage(predicate))
	return EvaluateRegoPolicy(att, []RegoPolicy{{Name: "m", Module: []byte(module)}})
}

// Review: a static "does some child have the field" check let one
// complete element hide another element's missing field, and ignored which
// key a dynamic lookup actually used. The probes ask Rego for the bindings
// the deny body had.
func TestStrictDeny_OneCompleteElementDoesNotMaskAnother(t *testing.T) {
	module := "package p\ndeny[msg] { input.items[_].status != \"ok\"; msg := \"bad\" }\n"
	requireRefusal(t, evalRaw(t, `{"items":[{"status":"ok"},{}]}`, module), "input.items")
	require.NoError(t, evalRaw(t, `{"items":[{"status":"ok"},{"status":"ok"}]}`, module))
	require.NoError(t, evalRaw(t, `{"items":[]}`, module), "an empty list is nothing to deny")
	requireRefusal(t, evalRaw(t, `{}`, module), "input.items")

	// The same through a `some ... in` alias.
	alias := "package p\nimport rego.v1\ndeny contains \"bad\" if { some it in input.items; it.status != \"ok\" }\n"
	requireRefusal(t, evalRaw(t, `{"items":[{"status":"ok"},{}]}`, alias), "status")
	require.NoError(t, evalRaw(t, `{"items":[{"status":"ok"}]}`, alias))
}

func TestStrictDeny_DynamicKeyIsJudgedForTheKeyUsed(t *testing.T) {
	inline := "package p\ndeny[msg] { input.values[input.required] != \"tag\"; msg := \"bad\" }\n"
	requireRefusal(t, evalRaw(t, `{"required":"release","values":{"other":"tag"}}`, inline), "input.values")
	require.NoError(t, evalRaw(t, `{"required":"release","values":{"release":"tag"}}`, inline))

	bound := "package p\ndeny[msg] { k := input.required; input.values[k] != \"ok\"; msg := \"bad\" }\n"
	requireRefusal(t, evalRaw(t, `{"required":"signature","values":{"other":"ok"}}`, bound), "input.values[k]")
	require.NoError(t, evalRaw(t, `{"required":"signature","values":{"signature":"ok"}}`, bound))
	requireRefusal(t, evalRaw(t, `{"values":{"signature":"ok"}}`, bound), "input.required")
}

// A deny the policy itself fires is the verdict; the probes run only on an
// admit.
func TestStrictDeny_ADenyIsNotReplacedByARefusal(t *testing.T) {
	module := "package p\ndeny[msg] { input.items[_].status != \"ok\"; msg := \"bad\" }\n"
	requireDenied(t, evalRaw(t, `{"items":[{"status":"bad"},{}]}`, module))
}
