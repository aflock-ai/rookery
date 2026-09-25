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

package testresults

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The verifier hands rego json.Marshal(attestor) as `input`
// (attestation/policy/rego.go EvaluateRegoPolicy). This attestor's
// registered struct wraps its fields under `predicate`, so a policy reads
// input.predicate.summary.*, NOT input.summary.*. Issue #9312 was filed by
// an author who wrote the flat form and got "unreadable evidence" back.
// These tests pin the wire shape and prove the documented example evaluates
// against the real attestor output, so the docs and the bytes cannot drift.

// attestFixture runs the attestor over a testdata report and returns it.
func attestFixture(t *testing.T, name string) *Attestor {
	t.Helper()
	tmp := t.TempDir()
	src := mustReadFile(t, filepath.Join("testdata", name))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, name), src, 0o644)) //nolint:gosec // test fixture
	att := New()
	ctx := newCtxWithProduct(t, tmp, name, src, att)
	require.NoError(t, ctx.RunAttestors())
	return att
}

// TestRegoInput_IsWrappedUnderPredicate pins the on-the-wire shape: the
// ONLY top-level key is "predicate", and the summary lives beneath it. A
// flattening change (or an accidental second top-level field) fails here
// before it silently breaks every shipped policy that reads the wrapper.
func TestRegoInput_IsWrappedUnderPredicate(t *testing.T) {
	att := attestFixture(t, "junit-failing.xml")

	raw, err := json.Marshal(att)
	require.NoError(t, err)

	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &top))
	assert.Equal(t, []string{"predicate"}, keysOf(top),
		"rego input top level must be exactly {predicate}; the docs and the Pushgate tests-ran preset read input.predicate.*")

	var pred map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(top["predicate"], &pred))
	for _, k := range []string{"format", "summary", "reportFile", "reportDigest"} {
		assert.Contains(t, pred, k, "predicate.%s must be present", k)
	}

	var summary map[string]json.Number
	require.NoError(t, json.Unmarshal(pred["summary"], &summary))
	assert.Equal(t, json.Number("2"), summary["failed"], "input.predicate.summary.failed")
	assert.Equal(t, json.Number("6"), summary["total"], "input.predicate.summary.total")
}

// TestRegoInput_DocumentedExampleEvaluates extracts the rego block from the
// attestor's long-form doc (attestation/detection/docs/test-results.doc.md,
// the single source of truth for `cilock tools show` and the website) and
// runs it through the real verifier entry point against real attestor
// output. A failing report must deny; a passing report must not. If the
// doc snippet ever drifts from the wire shape, this fails.
func TestRegoInput_DocumentedExampleEvaluates(t *testing.T) {
	doc, ok, err := detection.Default().LookupDoc(Name)
	require.NoError(t, err)
	require.True(t, ok, "attestation/detection/docs/%s.doc.md must exist", Name)

	module := documentedRego(t, doc)
	pol := []policy.RegoPolicy{{Name: "test-results.doc.md", Module: module}}

	failing := attestFixture(t, "junit-failing.xml")
	err = policy.EvaluateRegoPolicy(failing, pol)
	require.Error(t, err, "documented policy must deny a report with failed tests")
	assert.Contains(t, err.Error(), "2 test(s) failed", "deny message must carry the failed count read from input.predicate.summary.failed")

	passing := attestFixture(t, "junit-passing.xml")
	require.NoError(t, policy.EvaluateRegoPolicy(passing, pol), "documented policy must not deny a clean report")
}

// TestRegoInput_FlatFormDoesNotEvaluate is the negative that makes the
// documentation necessary: the flat form every other attestor uses reads
// nothing here. input.summary is undefined, so a deny that walks it never
// fires. That used to pass a failing suite silently; since #9820 the
// verifier refuses it. This is the trap the doc warns about; if it ever
// stops being a trap (flattening landed), the doc text must change with it.
func TestRegoInput_FlatFormDoesNotEvaluate(t *testing.T) {
	flat := []policy.RegoPolicy{{Name: "flat.rego", Module: []byte(`package testresults

deny[msg] {
	input.summary.failed > 0
	msg := sprintf("%d test(s) failed", [input.summary.failed])
}`)}}

	failing := attestFixture(t, "junit-failing.xml")
	// input.summary is undefined, so the flat form cannot see the summary.
	// That used to admit silently; since #9820 the verifier refuses it.
	assert.ErrorContains(t, policy.EvaluateRegoPolicy(failing, flat), "#9820",
		"the flat form must NOT see the summary, and is refused; if it denies on the summary, the attestor was flattened and the doc + this test must be updated together")
}

var regoFenceRE = regexp.MustCompile("(?s)```rego\n(.*?)\n```")

// documentedRego returns the first ```rego fence in the doc's
// rego-input section, which is the copy-pasteable example users are told
// to start from.
func documentedRego(t *testing.T, doc *detection.DetectorDoc) []byte {
	t.Helper()
	for _, s := range doc.Sections {
		if s.Slug != "rego-input-shape" {
			continue
		}
		m := regoFenceRE.FindStringSubmatch(s.Markdown)
		require.NotNil(t, m, "section %q must contain a ```rego fence", s.Slug)
		return []byte(m[1])
	}
	t.Fatalf("doc has no 'Rego input shape' section; sections: %v", sectionSlugs(doc))
	return nil
}

func sectionSlugs(doc *detection.DetectorDoc) []string {
	out := make([]string, 0, len(doc.Sections))
	for _, s := range doc.Sections {
		out = append(out, s.Slug)
	}
	return out
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRegoInput_DocumentedExampleRefusesAnUnreadableSummary is the fail-open
// case Codex found in review: a predicate whose summary carries only
// `failed: 0` satisfies every count rule vacuously — nothing failed, nothing
// errored, and `passed` is undefined so the "no test passed" rule never
// fires — and the gate passes a run in which NO TEST RAN. Each count the
// policy depends on needs its own is_number guard.
//
// It evaluates the doc's snippet against raw predicates rather than through
// the attestor: this attestor's Go struct types its counts, so it can never
// itself emit a missing or non-numeric one. The policy is copied by hand into
// other people's policies and evaluated against whatever `test-results/v0.1`
// evidence arrives, so the text has to hold on input the struct cannot make.
func TestRegoInput_DocumentedExampleRefusesAnUnreadableSummary(t *testing.T) {
	doc, ok, err := detection.Default().LookupDoc(Name)
	require.NoError(t, err)
	require.True(t, ok, "attestation/detection/docs/%s.doc.md must exist", Name)
	module := documentedRego(t, doc)

	cases := []struct {
		name      string
		predicate map[string]any
		deny      string
	}{
		{"passed absent", map[string]any{"summary": map[string]any{"failed": 0}}, "summary.passed missing or malformed"},
		{"passed not a number", map[string]any{"summary": map[string]any{"failed": 0, "passed": "3"}}, "summary.passed missing or malformed"},
		{"failed absent", map[string]any{"summary": map[string]any{"passed": 3}}, "summary.failed missing or malformed"},
		{"summary absent entirely", map[string]any{}, "missing or malformed"},
		{"nothing passed", map[string]any{"summary": map[string]any{"failed": 0, "passed": 0}}, "no test passed"},
		{"errors present", map[string]any{"summary": map[string]any{"failed": 0, "passed": 3, "errors": 2}}, "errored before reaching a verdict"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			denials := evalDocumentedPolicy(t, module, map[string]any{"predicate": c.predicate})
			require.NotEmpty(t, denials, "an unreadable, empty or errored summary must deny, not pass")
			assert.Contains(t, strings.Join(denials, "; "), c.deny)
		})
	}

	t.Run("a clean readable summary passes", func(t *testing.T) {
		denials := evalDocumentedPolicy(t, module, map[string]any{
			"predicate": map[string]any{"summary": map[string]any{"failed": 0, "passed": 3}},
		})
		assert.Empty(t, denials)
	})
}

// evalDocumentedPolicy runs the doc's module over an arbitrary input document
// and returns its deny messages, the same query the verifier evaluates
// (attestation/policy/rego.go).
func evalDocumentedPolicy(t *testing.T, src []byte, input map[string]any) []string {
	t.Helper()
	q, err := rego.New(
		rego.Query("data.testresults.deny"),
		rego.Module("test-results.doc.md", string(src)),
		rego.Input(input),
	).PrepareForEval(context.Background())
	require.NoError(t, err)

	rs, err := q.Eval(context.Background())
	require.NoError(t, err)

	var msgs []string
	for _, result := range rs {
		for _, expr := range result.Expressions {
			set, ok := expr.Value.([]any)
			if !ok {
				continue
			}
			for _, m := range set {
				msgs = append(msgs, fmt.Sprint(m))
			}
		}
	}
	return msgs
}
