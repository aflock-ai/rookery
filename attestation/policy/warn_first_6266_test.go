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

// Warn-first hardening tests for issue #6266. Each of the five dangerous
// configurations surfaced by the -tags audit detector sweep now emits a loud
// WARN via the attestation/log package WITHOUT any enforcement/behavior change.
// The audit detector tests (which assert enforcement) deliberately stay red;
// these tests assert only that the WARN fires on the dangerous config and does
// NOT fire on a clean config. They capture logger output by swapping in a
// recording Logger via log.SetLogger.

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/log"
)

// warnCapture is a log.Logger that records Warn/Warnf output so a test can
// assert whether a specific warning fired.
type warnCapture struct {
	mu    sync.Mutex
	lines []string
}

func (w *warnCapture) add(s string) {
	w.mu.Lock()
	w.lines = append(w.lines, s)
	w.mu.Unlock()
}

func (w *warnCapture) Warnf(format string, args ...interface{}) { w.add(fmt.Sprintf(format, args...)) }
func (w *warnCapture) Warn(args ...interface{})                 { w.add(fmt.Sprint(args...)) }
func (w *warnCapture) Errorf(string, ...interface{})            {}
func (w *warnCapture) Error(...interface{})                     {}
func (w *warnCapture) Debugf(string, ...interface{})            {}
func (w *warnCapture) Debug(...interface{})                     {}
func (w *warnCapture) Infof(string, ...interface{})             {}
func (w *warnCapture) Info(...interface{})                      {}

func (w *warnCapture) sawContaining(sub string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, l := range w.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// installWarnCapture swaps in a recording logger for the duration of the test
// and restores the previous logger on cleanup. These tests must not call
// t.Parallel(): they mutate the package-global logger.
func installWarnCapture(t *testing.T) *warnCapture {
	t.Helper()
	prev := log.GetLogger()
	c := &warnCapture{}
	log.SetLogger(c)
	t.Cleanup(func() { log.SetLogger(prev) })
	return c
}

// warnFakeVerifier is a minimal cryptoutil.Verifier whose KeyID is fixed, so a
// Functionary.PublicKeyID short-circuit can be exercised deterministically.
type warnFakeVerifier struct{ id string }

func (v warnFakeVerifier) KeyID() (string, error)         { return v.id, nil }
func (v warnFakeVerifier) Verify(io.Reader, []byte) error { return nil }
func (v warnFakeVerifier) Bytes() ([]byte, error)         { return []byte(v.id), nil }

// R3_184: Functionary.Validate short-circuits on a PublicKeyID match before
// CertConstraint.Check runs, so a functionary that sets BOTH fields has its
// certificate constraint silently ignored.
func TestWarn_R3_184_BothPublicKeyIDAndCertConstraint(t *testing.T) {
	const want = "certificate constraint is IGNORED"

	t.Run("dangerous_both_set_fires", func(t *testing.T) {
		cap := installWarnCapture(t)
		f := Functionary{
			PublicKeyID:    "key-1",
			CertConstraint: CertConstraint{Roots: []string{"root-a"}},
		}
		if err := f.Validate(warnFakeVerifier{id: "key-1"}, nil); err != nil {
			t.Fatalf("Validate returned unexpected error (behavior must be unchanged): %v", err)
		}
		if !cap.sawContaining(want) {
			t.Fatalf("expected WARN containing %q, got lines: %v", want, cap.lines)
		}
	})

	t.Run("clean_only_publickeyid_no_warn", func(t *testing.T) {
		cap := installWarnCapture(t)
		f := Functionary{PublicKeyID: "key-1"}
		if err := f.Validate(warnFakeVerifier{id: "key-1"}, nil); err != nil {
			t.Fatalf("Validate returned unexpected error: %v", err)
		}
		if cap.sawContaining(want) {
			t.Fatalf("did not expect WARN %q on clean config, got lines: %v", want, cap.lines)
		}
	})
}

// R3_201: once cross-step context is present, buildRegoInput re-shapes the input
// to {attestation, steps, external}, so legacy modules referencing top-level
// input fields silently stop matching.
func TestWarn_R3_201_CrossStepInputShape(t *testing.T) {
	const want = "cross-step rego input shape active"
	attestorData := map[string]interface{}{"name": "example"}

	t.Run("dangerous_stepcontext_active_fires", func(t *testing.T) {
		cap := installWarnCapture(t)
		stepCtx := []map[string]interface{}{{"stepA": map[string]interface{}{"type": "x"}}}
		_ = buildRegoInput(attestorData, stepCtx)
		if !cap.sawContaining(want) {
			t.Fatalf("expected WARN containing %q, got lines: %v", want, cap.lines)
		}
	})

	t.Run("clean_no_stepcontext_no_warn", func(t *testing.T) {
		cap := installWarnCapture(t)
		_ = buildRegoInput(attestorData, nil)
		if cap.sawContaining(want) {
			t.Fatalf("did not expect WARN %q with no step context, got lines: %v", want, cap.lines)
		}
	})
}

// R3_181: an empty constraint against an empty cert field is a no-op match that
// currently passes; combined with permissive roots this weakens identity.
func TestWarn_R3_181_EmptyConstraintEmptyValues(t *testing.T) {
	const want = "empty constraint matched empty cert field"

	t.Run("dangerous_both_empty_fires", func(t *testing.T) {
		cap := installWarnCapture(t)
		if err := checkCertConstraint("email", nil, nil); err != nil {
			t.Fatalf("checkCertConstraint returned unexpected error (behavior must be unchanged): %v", err)
		}
		if !cap.sawContaining(want) {
			t.Fatalf("expected WARN containing %q, got lines: %v", want, cap.lines)
		}
	})

	t.Run("clean_nonempty_no_warn", func(t *testing.T) {
		cap := installWarnCapture(t)
		if err := checkCertConstraint("email", []string{"a@b.com"}, []string{"a@b.com"}); err != nil {
			t.Fatalf("checkCertConstraint returned unexpected error: %v", err)
		}
		if cap.sawContaining(want) {
			t.Fatalf("did not expect WARN %q on non-empty config, got lines: %v", want, cap.lines)
		}
	})
}

// R3_183: two rego modules sharing a package name are merged by OPA — their
// rules coexist and can shadow each other.
func TestWarn_R3_183_DuplicateRegoPackageName(t *testing.T) {
	const want = "duplicate rego package name"
	attestor := &marshalableAttestor{AttName: "n", AttType: "https://witness.dev/attestations/test/v0.1"}
	mod := func(pkg string) RegoPolicy {
		return RegoPolicy{
			Name:   pkg + "-module",
			Module: []byte("package " + pkg + "\n\ndeny[msg] {\n\tinput.nonexistent == \"x\"\n\tmsg := \"unreachable\"\n}\n"),
		}
	}

	t.Run("dangerous_duplicate_package_fires", func(t *testing.T) {
		cap := installWarnCapture(t)
		if err := EvaluateRegoPolicy(attestor, []RegoPolicy{mod("shared"), mod("shared")}); err != nil {
			t.Fatalf("EvaluateRegoPolicy returned unexpected error (behavior must be unchanged): %v", err)
		}
		if !cap.sawContaining(want) {
			t.Fatalf("expected WARN containing %q, got lines: %v", want, cap.lines)
		}
	})

	t.Run("clean_distinct_packages_no_warn", func(t *testing.T) {
		cap := installWarnCapture(t)
		if err := EvaluateRegoPolicy(attestor, []RegoPolicy{mod("alpha"), mod("beta")}); err != nil {
			t.Fatalf("EvaluateRegoPolicy returned unexpected error: %v", err)
		}
		if cap.sawContaining(want) {
			t.Fatalf("did not expect WARN %q on distinct packages, got lines: %v", want, cap.lines)
		}
	})
}

// R3_185/187/209: Policy.Validate does not verify that a step's Name matches its
// map key or that Name is non-empty; a mismatch fails later with a misleading
// error.
func TestWarn_R3_185_187_209_StepNameCoherence(t *testing.T) {
	const wantEmpty = "empty Name"
	const wantMismatch = "mismatched Name"

	t.Run("dangerous_empty_name_fires", func(t *testing.T) {
		cap := installWarnCapture(t)
		p := Policy{Steps: map[string]Step{"build": {Name: ""}}}
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate returned unexpected error (behavior must be unchanged): %v", err)
		}
		if !cap.sawContaining(wantEmpty) {
			t.Fatalf("expected WARN containing %q, got lines: %v", wantEmpty, cap.lines)
		}
	})

	t.Run("dangerous_name_key_mismatch_fires", func(t *testing.T) {
		cap := installWarnCapture(t)
		p := Policy{Steps: map[string]Step{"build": {Name: "compile"}}}
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate returned unexpected error: %v", err)
		}
		if !cap.sawContaining(wantMismatch) {
			t.Fatalf("expected WARN containing %q, got lines: %v", wantMismatch, cap.lines)
		}
	})

	t.Run("clean_name_matches_key_no_warn", func(t *testing.T) {
		cap := installWarnCapture(t)
		p := Policy{Steps: map[string]Step{"build": {Name: "build"}}}
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate returned unexpected error: %v", err)
		}
		if cap.sawContaining(wantEmpty) || cap.sawContaining(wantMismatch) {
			t.Fatalf("did not expect a name-coherence WARN on clean config, got lines: %v", cap.lines)
		}
	})
}
