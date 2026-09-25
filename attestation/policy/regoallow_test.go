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

// #9820 E3: the engine is deny-only. A module that defines `allow` and has
// no deny depending on it reads as if allow gated the step, and it does not:
// `default allow := false` over an empty deny passed.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func evalAllow(t *testing.T, module string) error {
	t.Helper()
	forgetAllowCheck(t)
	return EvaluateRegoPolicy(&lintAttestor{Reftype: "tag"}, []RegoPolicy{{Name: "m", Module: []byte(module)}})
}

func forgetAllowCheck(t *testing.T) {
	t.Helper()
	forget := func() {
		allowCheckMu.Lock()
		defer allowCheckMu.Unlock()
		clear(allowCheckCache)
	}
	forget()
	t.Cleanup(forget)
}

func TestAllowWithoutDeny_IsRefused(t *testing.T) {
	for name, module := range map[string]string{
		// The issue's case: allow is false and nothing denies, and it passed.
		"allow false, empty deny": "package p\ndefault allow := false\ndeny[msg] { false; msg := \"x\" }\n",
		// The shipped slsa-l3 / build-integrity stub shape.
		"allow true, empty deny": "package p\nimport rego.v1\ndefault allow := true\ndeny contains msg if { false; msg := \"x\" }\n",
		// allow has a body, but deny never reads it.
		"allow with a body, deny ignores it": "package p\nallow { input.reftype == \"tag\" }\ndeny[msg] { input.reftype == \"nope\"; msg := \"x\" }\n",
	} {
		err := evalAllow(t, module)
		require.ErrorContains(t, err, "allow", name)
		require.ErrorContains(t, err, "#9820", name)
		var denied ErrPolicyDenied
		require.False(t, errors.As(err, &denied), "%s: a policy error, not a deny: %v", name, err)
	}
}

func TestAllowUsedByDeny_Evaluates(t *testing.T) {
	// The vsa-chain-gate shape: deny consumes allow.
	gate := "package p\ndefault allow := false\nallow { input.reftype == \"tag\" }\ndeny[msg] { not allow; msg := \"not allowed\" }\n"
	require.NoError(t, evalAllow(t, gate))
	forgetAllowCheck(t)
	err := EvaluateRegoPolicy(&lintAttestor{Reftype: "branch"}, []RegoPolicy{{Name: "m", Module: []byte(gate)}})
	var denied ErrPolicyDenied
	require.True(t, errors.As(err, &denied), "the policy's own deny, got %v", err)

	// Through a helper rule deny reaches.
	helper := "package p\nallow { input.reftype == \"tag\" }\nok { allow }\ndeny[msg] { not ok; msg := \"x\" }\n"
	require.NoError(t, evalAllow(t, helper))

	// The example in site/docs/reference/policy-schema.md ("Deny-only").
	doc := "package example.gate\n\nimport rego.v1\n\ndefault allow := false\n\nallow if input.verificationResult == \"PASSED\"\n\ndeny contains \"verification did not pass\" if not allow\n"
	require.NoError(t, CheckRegoAllowUsed([]RegoPolicy{{Name: "doc", Module: []byte(doc)}}))
	_, err = LintRegoFailOpenSet([]RegoPolicy{{Name: "doc", Module: []byte(doc)}})
	require.NoError(t, err, "the documented example compiles in the verifier")

	// A module with no allow is not affected.
	require.NoError(t, evalAllow(t, "package p\ndeny[msg] { input.reftype == \"nope\"; msg := \"x\" }\n"))
}

// A deny that reads the whole package document (or data) depends on every
// rule in it, allow included: object.get(data.gate, "allow", false) reads
// allow through its parent. Found by review on #9870.
func TestAllowUsedThroughAParentDocument(t *testing.T) {
	gate := RegoPolicy{Name: "gate", Module: []byte("package gate\ndefault allow := true\ndeny[msg] { false; msg := \"x\" }\n")}
	for name, user := range map[string]string{
		"package document":   "package user\ndeny[msg] { not object.get(data.gate, \"allow\", false); msg := \"blocked\" }\n",
		"data root document": "package user\ndeny[msg] { not object.get(data, [\"gate\", \"allow\"], false); msg := \"blocked\" }\n",
	} {
		set := []RegoPolicy{gate, {Name: "user", Module: []byte(user)}}
		require.NoError(t, CheckRegoAllowUsed(set), name)
	}
	// A sibling package that merely shares a prefix does not count.
	sibling := []RegoPolicy{gate, {Name: "user", Module: []byte("package user\ndeny[msg] { data.gatekeeper.x; msg := \"x\" }\n")}}
	require.Error(t, CheckRegoAllowUsed(sibling))
}

func TestCheckRegoAllowUsed_ForValidation(t *testing.T) {
	require.Error(t, CheckRegoAllowUsed([]RegoPolicy{{Name: "m", Module: []byte("package p\ndefault allow := false\ndeny[msg] { false; msg := \"x\" }\n")}}))
	require.NoError(t, CheckRegoAllowUsed([]RegoPolicy{{Name: "m", Module: []byte("package p\ndefault allow := false\ndeny[msg] { not allow; msg := \"x\" }\n")}}))
}
