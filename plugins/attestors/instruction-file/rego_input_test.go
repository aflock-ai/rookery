// Copyright 2026 The Rookery Contributors
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

package instructionfile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// The verifier hands rego json.Marshal(attestor) as `input`
// (attestation/policy/rego.go EvaluateRegoPolicy). This attestor registers
// a FLAT struct — files, signer, status, warnings, caveat sit at the top
// level — so a policy reads input.signer.kind, NOT input.predicate.signer.kind.
// The long-form doc used to print the predicate-wrapped form, and without
// `import rego.v1` its `contains`/`if`/`in` keywords did not even parse
// under the engine's default Rego v0 parser: the example could never fire.
// These tests pin the wire shape and run the documented example through the
// real engine against real attestor output, so the doc and the bytes cannot
// drift apart again.

const verifierSectionSlug = "how-a-verifier-consumes-this"

var docRegoFenceRE = regexp.MustCompile("(?s)```rego\n(.*?)\n```")

// documentedRego returns the first ```rego fence in the doc section that
// tells policy authors how to consume this attestor.
func documentedRego(t *testing.T) []byte {
	t.Helper()
	doc, ok, err := detection.Default().LookupDoc(Name)
	if err != nil {
		t.Fatalf("lookup doc: %v", err)
	}
	if !ok {
		t.Fatalf("attestation/detection/docs/%s.doc.md must exist", Name)
	}
	var slugs []string
	for _, s := range doc.Sections {
		slugs = append(slugs, s.Slug)
		if s.Slug != verifierSectionSlug {
			continue
		}
		m := docRegoFenceRE.FindStringSubmatch(s.Markdown)
		if m == nil {
			t.Fatalf("section %q must contain a ```rego fence", s.Slug)
		}
		return []byte(m[1])
	}
	t.Fatalf("doc has no %q section; sections: %v", verifierSectionSlug, slugs)
	return nil
}

func documentedPolicy(t *testing.T) []policy.RegoPolicy {
	t.Helper()
	return []policy.RegoPolicy{{Name: Name + ".doc.md", Module: documentedRego(t)}}
}

// documentedWrappedRego returns the SECOND rego fence in the verifier section:
// the same gate written for the {attestation, steps, external} shape a step
// gets once it declares attestationsFrom or externalFrom. Extracted from the
// page for the same reason as the first — so the doc cannot drift from what
// the attestor emits.
func documentedWrappedRego(t *testing.T) []byte {
	t.Helper()
	doc, ok, err := detection.Default().LookupDoc(Name)
	if err != nil {
		t.Fatalf("lookup doc: %v", err)
	}
	if !ok {
		t.Fatalf("attestation/detection/docs/%s.doc.md must exist", Name)
	}
	for _, sec := range doc.Sections {
		if sec.Slug != verifierSectionSlug {
			continue
		}
		ms := docRegoFenceRE.FindAllStringSubmatch(sec.Markdown, -1)
		if len(ms) < 2 {
			t.Fatalf("section %q must contain a SECOND ```rego fence (the input.attestation form); found %d", sec.Slug, len(ms))
		}
		return []byte(ms[1][1])
	}
	t.Fatalf("doc has no %q section", verifierSectionSlug)
	return nil
}

func documentedWrappedPolicy(t *testing.T) []policy.RegoPolicy {
	t.Helper()
	return []policy.RegoPolicy{{Name: Name + ".doc.md#wrapped", Module: documentedWrappedRego(t)}}
}

// TestRegoInput_CrossStepContextReshapesInput is the finding this page exists
// to stop repeating. A step that declares attestationsFrom or externalFrom
// gets input re-shaped to {attestation, steps, external}, so a module written
// for the flat shape reads undefined paths. In Rego an undefined path is not
// an error: every deny body simply fails, and a policy written to refuse
// admits instead. The first subtest pins that hazard so it cannot be quietly
// re-introduced; the second proves the documented wrapped form still denies
// the very same fixtures.
func TestRegoInput_CrossStepContextReshapesInput(t *testing.T) {
	// Any non-nil step context activates the wrap; its contents do not matter here.
	stepCtx := map[string]interface{}{"gomod-drift": map[string]interface{}{}}

	t.Run("flat_module_is_refused_once_context_is_present", func(t *testing.T) {
		clearWorkloadEnv(t)
		a := attestRoot(t, rootWithInstructionFile(t))
		if err := policy.EvaluateRegoPolicy(a, documentedPolicy(t)); err == nil {
			t.Fatal("fixture: the flat module must deny WITHOUT step context, or this test proves nothing")
		}
		// Under the wrapped shape the flat paths are undefined. That used to
		// admit silently; since #9820 the verifier refuses it instead.
		err := policy.EvaluateRegoPolicy(a, documentedPolicy(t), stepCtx)
		var denied policy.ErrPolicyDenied
		if err == nil || errors.As(err, &denied) || !strings.Contains(err.Error(), "#9820") {
			t.Fatalf("flat module under the wrapped shape: want the #9820 missing-field refusal, got %v", err)
		}
	})

	t.Run("wrapped_module_still_denies_every_violation", func(t *testing.T) {
		clearWorkloadEnv(t)
		a := attestRoot(t, rootWithInstructionFile(t))
		err := policy.EvaluateRegoPolicy(a, documentedWrappedPolicy(t), stepCtx)
		if err == nil {
			t.Fatal("wrapped module must deny a non-workload signer with an unapproved instruction file")
		}
		for _, want := range []string{"workload identity required", "unapproved instruction file CLAUDE.md"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("wrapped deny message must contain %q; got %v", want, err)
			}
		}
	})

	t.Run("wrapped_module_allows_a_clean_scan", func(t *testing.T) {
		forceWorkloadEnv(t)
		a := attestRoot(t, t.TempDir())
		if err := policy.EvaluateRegoPolicy(a, documentedWrappedPolicy(t), stepCtx); err != nil {
			t.Fatalf("wrapped module must not deny a complete workload scan with no instruction files: %v", err)
		}
	})
}

// attestRoot runs the real attestor over root and returns it.
func attestRoot(t *testing.T, root string) *Attestor {
	t.Helper()
	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	return a
}

// rootWithInstructionFile is a workspace holding one readable CLAUDE.md whose
// digest is, of course, not in the doc's placeholder allowlist.
func rootWithInstructionFile(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("real instructions\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return root
}

// forceWorkloadEnv makes detectSigner, which Attest feeds from os.Getenv,
// classify the process as a workload identity. Provider detection outranks
// the TTY check, so this holds whether or not the test has a terminal.
func forceWorkloadEnv(t *testing.T) {
	t.Helper()
	for k, v := range fullEnvFor(workloadProviders[0]) {
		t.Setenv(k, v)
	}
}

// clearWorkloadEnv strips every declared provider's variables so a run
// inside real CI still classifies as a non-workload signer.
func clearWorkloadEnv(t *testing.T) {
	t.Helper()
	for _, p := range workloadProviders {
		for _, k := range append(append([]string{}, p.RequiredEnv...), p.TokenRequestEnv...) {
			t.Setenv(k, "")
		}
	}
}

// TestRegoInput_IsFlat pins the on-the-wire shape: the registered struct's
// fields are the top-level keys, and there is no `predicate` wrapper.
func TestRegoInput_IsFlat(t *testing.T) {
	a := attestRoot(t, rootWithInstructionFile(t))
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"files", "signer", "status", "caveat"} {
		if _, ok := top[k]; !ok {
			t.Errorf("top-level key %q missing; the doc tells policies to read input.%s", k, k)
		}
	}
	if _, ok := top["predicate"]; ok {
		t.Errorf("top level carries a predicate wrapper; the doc and this test say the shape is flat: %s", raw)
	}
}

// TestRegoInput_DocumentedExampleEvaluates runs the doc's rego through the
// real verifier entry point against real attestor output. Each documented
// deny condition must deny, and a clean workload scan must not.
func TestRegoInput_DocumentedExampleEvaluates(t *testing.T) {
	t.Run("non_workload_signer_denies", func(t *testing.T) {
		clearWorkloadEnv(t)
		a := attestRoot(t, t.TempDir())
		if a.Signer.Kind == SignerKindWorkloadIdentity {
			t.Fatalf("fixture: signer still classifies as workload-identity after clearing provider env; evidence %v", a.Signer.Evidence)
		}
		err := policy.EvaluateRegoPolicy(a, documentedPolicy(t))
		if err == nil {
			t.Fatal("documented policy must deny a signer that is not a workload identity")
		}
		if !strings.Contains(err.Error(), "workload identity required") {
			t.Errorf("deny message must come from the signer rule; got %v", err)
		}
	})

	t.Run("incomplete_scan_denies", func(t *testing.T) {
		forceWorkloadEnv(t)
		root := t.TempDir()
		skipFixtures()[0].setup(t, root)
		a := attestRoot(t, root)
		if a.Status == StatusComplete {
			t.Fatal("fixture: a refused file must not leave the scan complete")
		}
		err := policy.EvaluateRegoPolicy(a, documentedPolicy(t))
		if err == nil {
			t.Fatal("documented policy must deny an incomplete scan")
		}
		if !strings.Contains(err.Error(), "scan status "+string(a.Status)) {
			t.Errorf("deny message must carry the status read from input.status; got %v", err)
		}
	})

	t.Run("unapproved_file_denies", func(t *testing.T) {
		forceWorkloadEnv(t)
		a := attestRoot(t, rootWithInstructionFile(t))
		err := policy.EvaluateRegoPolicy(a, documentedPolicy(t))
		if err == nil {
			t.Fatal("documented policy must deny an instruction file whose digest is not allowlisted")
		}
		if !strings.Contains(err.Error(), "unapproved instruction file CLAUDE.md") {
			t.Errorf("deny message must name the file read from input.files; got %v", err)
		}
	})

	t.Run("clean_workload_scan_allows", func(t *testing.T) {
		forceWorkloadEnv(t)
		a := attestRoot(t, t.TempDir())
		if a.Signer.Kind != SignerKindWorkloadIdentity || a.Status != StatusComplete {
			t.Fatalf("fixture: want workload-identity + complete, got %q + %q", a.Signer.Kind, a.Status)
		}
		if err := policy.EvaluateRegoPolicy(a, documentedPolicy(t)); err != nil {
			t.Fatalf("documented policy must not deny a complete workload scan with no instruction files: %v", err)
		}
	})
}

// TestRegoInput_PredicateFormDoesNotEvaluate is the negative that makes the
// documentation necessary: the predicate-wrapped form the doc used to print
// reads nothing here. Every documented deny condition is present in the
// fixture, and none fires. Derived from the current doc by rewriting its
// paths, so it tracks the example rather than a frozen copy.
func TestRegoInput_PredicateFormDoesNotEvaluate(t *testing.T) {
	clearWorkloadEnv(t)
	wrapped := strings.ReplaceAll(string(documentedRego(t)), "input.", "input.predicate.")
	if wrapped == string(documentedRego(t)) {
		t.Fatal("documented rego reads no input.* path at all")
	}
	pol := []policy.RegoPolicy{{Name: "predicate-wrapped.rego", Module: []byte(wrapped)}}

	root := t.TempDir()
	skipFixtures()[0].setup(t, root)
	a := attestRoot(t, root)
	if a.Signer.Kind == SignerKindWorkloadIdentity || a.Status == StatusComplete {
		t.Fatalf("fixture: want a non-workload signer and an incomplete scan, got %q + %q", a.Signer.Kind, a.Status)
	}
	// The input.predicate.* paths are undefined, so the form cannot see the
	// attestor. That used to admit silently; since #9820 it is refused.
	err := policy.EvaluateRegoPolicy(a, pol)
	var denied policy.ErrPolicyDenied
	if err == nil || errors.As(err, &denied) || !strings.Contains(err.Error(), "#9820") {
		t.Fatalf("the input.predicate.* form must NOT see the attestor, and is now refused (#9820); if it denies, the attestor grew a wrapper and the doc + this test must change together: %v", err)
	}
}

// TestRegoInput_V1KeywordsNeedTheImport pins the second half of the old
// failure: the engine parses Rego v0 by default, so the doc's `contains`,
// `if` and `in` keywords are a parse error without `import rego.v1`. A
// parse error is not a deny — the policy never runs at all.
func TestRegoInput_V1KeywordsNeedTheImport(t *testing.T) {
	forceWorkloadEnv(t)
	src := string(documentedRego(t))
	if !strings.Contains(src, "import rego.v1") {
		t.Fatal("documented rego must carry `import rego.v1`; the engine's default parser is Rego v0")
	}
	stripped := strings.Replace(src, "import rego.v1\n", "", 1)
	pol := []policy.RegoPolicy{{Name: "no-import.rego", Module: []byte(stripped)}}

	a := attestRoot(t, rootWithInstructionFile(t))
	err := policy.EvaluateRegoPolicy(a, pol)
	if err == nil {
		t.Fatal("without the import the module must fail to parse; it evaluated cleanly instead")
	}
	if strings.Contains(err.Error(), "unapproved instruction file") {
		t.Fatalf("without the import the module was expected to fail parsing, but it denied: %v", err)
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected a rego parse error, got %v", err)
	}
}
