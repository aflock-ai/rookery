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

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
)

type stubStore struct {
	gitoid string
	err    error
	calls  int
}

func (s *stubStore) Store(context.Context, dsse.Envelope) (string, error) {
	s.calls++
	return s.gitoid, s.err
}

// captureEvidenceLoss points the wrapper's annotation writer at a buffer for
// the duration of one test. Every storeEvidence assertion reads from this
// buffer rather than calling reportEvidenceLoss itself: the property under test
// is that the WRAPPER reports, and a test that called the reporter directly
// would keep passing after the call inside storeEvidence was deleted.
func captureEvidenceLoss(t *testing.T) *bytes.Buffer {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "true")
	prev := evidenceLossOut
	var out bytes.Buffer
	evidenceLossOut = &out
	t.Cleanup(func() { evidenceLossOut = prev })
	return &out
}

// countAnnotations counts emitted workflow commands, not bytes, so a test
// distinguishes "reported once" from "reported twice" as well as from "never".
func countAnnotations(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "::error title=") {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// The signal itself, observed through the choke point
// ---------------------------------------------------------------------------

func TestStoreEvidence_SuccessEmitsNothing(t *testing.T) {
	out := captureEvidenceLoss(t)
	target := &stubStore{gitoid: "gitoid:blob:sha256:abc"}

	got, err := storeEvidence(context.Background(), target, dsse.Envelope{}, evidenceRef{Step: "build"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "gitoid:blob:sha256:abc" {
		t.Fatalf("gitoid = %q", got)
	}
	if out.Len() != 0 {
		t.Fatalf("a successful store must not raise the loss signal, wrote %q", out.String())
	}
}

// A store error is the case the signal exists for: the envelope was signed and
// the platform never received it.
func TestStoreEvidence_StoreErrorReportsLoss(t *testing.T) {
	out := captureEvidenceLoss(t)
	cause := errors.New("archivista store returned 503")
	target := &stubStore{err: cause}

	got, err := storeEvidence(context.Background(), target, dsse.Envelope{}, evidenceRef{Step: "push-tests"})
	if !errors.Is(err, cause) {
		t.Fatalf("storeEvidence must return the store's error, got %v", err)
	}
	if got != "" {
		t.Fatalf("no gitoid can exist for a failed store, got %q", got)
	}
	if n := countAnnotations(out.String()); n != 1 {
		t.Fatalf("expected exactly one annotation from the wrapper, got %d:\n%s", n, out.String())
	}
}

// An empty gitoid is a stored-nothing response. It was already treated as an
// error at the call site this replaces, and it must keep raising the loss
// signal: a 200 that stores nothing loses the evidence exactly as a 503 does.
func TestStoreEvidence_EmptyGitoidIsLoss(t *testing.T) {
	out := captureEvidenceLoss(t)
	target := &stubStore{gitoid: ""}

	if _, err := storeEvidence(context.Background(), target, dsse.Envelope{}, evidenceRef{Step: "push-tests"}); err == nil {
		t.Fatal("an empty gitoid must be an error")
	}
	if n := countAnnotations(out.String()); n != 1 {
		t.Fatalf("expected exactly one annotation for an empty gitoid, got %d:\n%s", n, out.String())
	}
}

// ---------------------------------------------------------------------------
// Message content, exercised on the reporter directly
// ---------------------------------------------------------------------------

// Criterion: the signal NAMES the affected step and the evidence that was lost,
// so the gap is auditable after the fact rather than reconstructable only from
// logs.
func TestReportEvidenceLoss_NamesStepAndEvidence(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	var out bytes.Buffer

	reportEvidenceLoss(&out, evidenceRef{
		Step:     "push-tests",
		Subjects: []string{"git/v0.1/commithash:deadbeef", "material/v0.3/tree:materials"},
		Outfile:  "/tmp/run/collection.json",
	}, errors.New("archivista store returned 503"))

	got := out.String()
	for _, want := range []string{
		"::error title=" + evidenceLossTitle + "::",
		"step push-tests",
		"signed but NOT stored",
		"git/v0.1/commithash:deadbeef",
		"material/v0.3/tree:materials",
		"/tmp/run/collection.json",
		"archivista store returned 503",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("annotation missing %q\ngot: %s", want, got)
		}
	}
}

// A workflow command is newline-terminated. A literal newline anywhere in the
// message ends the annotation early and dumps the rest to stdout as bare text —
// silently truncating the record this exists to preserve. The cause routinely
// carries a server response body, which is exactly where a stray newline comes
// from.
func TestReportEvidenceLoss_IsASingleLine(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	var out bytes.Buffer

	reportEvidenceLoss(&out, evidenceRef{
		Step:     "push-tests",
		Subjects: []string{"a\nb"},
	}, errors.New("archivista store returned 503: {\n  \"error\": \"boom\"\n}"))

	got := out.String()
	if n := strings.Count(strings.TrimSuffix(got, "\n"), "\n"); n != 0 {
		t.Fatalf("annotation spans %d extra lines, so the runner truncates it:\n%s", n+1, got)
	}
	if !strings.Contains(got, "%0A") {
		t.Errorf("real newlines must survive as %%0A so the runner renders them: %s", got)
	}
}

// The runner decodes the annotation once, so the emitted text must be the
// input encoded exactly once. Encoding a piece and then the whole would turn
// "%" into "%2525" and render as "%25"; writing separators pre-encoded and
// un-escaping them afterwards would turn a literal "%0A" in a subject name
// into a line break. Both are round-trip failures the runner cannot detect,
// so the transcript is asserted character-for-character here.
func TestEvidenceLossMessage_EncodesExactlyOnce(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")

	t.Run("percent in cause is escaped once", func(t *testing.T) {
		var out bytes.Buffer
		reportEvidenceLoss(&out, evidenceRef{Step: "s"}, errors.New("100% done"))
		got := out.String()
		if strings.Contains(got, "%2525") {
			t.Fatalf("percent was encoded twice: %s", got)
		}
		if n := strings.Count(got, "100%25 done"); n != 1 {
			t.Fatalf("want %q exactly once, found %d times in: %s", "100%25 done", n, got)
		}
	})

	t.Run("literal %0A in a subject stays literal", func(t *testing.T) {
		var out bytes.Buffer
		reportEvidenceLoss(&out, evidenceRef{Step: "s", Subjects: []string{"name%0Awith-escape"}}, nil)
		got := out.String()
		if !strings.Contains(got, "name%250Awith-escape") {
			t.Fatalf("literal %%0A in input must render as the text %%0A, so it must be emitted as %%250A: %s", got)
		}
	})

	t.Run("CRLF in cause becomes %0D%0A", func(t *testing.T) {
		var out bytes.Buffer
		reportEvidenceLoss(&out, evidenceRef{Step: "s"}, errors.New("line one\r\nline two"))
		got := out.String()
		if !strings.Contains(got, "line one%0D%0Aline two") {
			t.Fatalf("CRLF must survive as %%0D%%0A: %s", got)
		}
		if n := strings.Count(strings.TrimSuffix(got, "\n"), "\n"); n != 0 {
			t.Fatalf("annotation spans %d extra lines: %s", n+1, got)
		}
	})
}

// Outside Actions the workflow-command syntax means nothing, the caller already
// returns a described error, and printing it would be noise on a developer's
// console.
func TestReportEvidenceLoss_SilentOutsideActions(t *testing.T) {
	for _, v := range []string{"", "false", "1"} {
		t.Setenv("GITHUB_ACTIONS", v)
		var out bytes.Buffer
		reportEvidenceLoss(&out, evidenceRef{Step: "s"}, errors.New("boom"))
		if out.Len() != 0 {
			t.Errorf("GITHUB_ACTIONS=%q emitted %q", v, out.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Criterion: quantify over outcomes, not one path
// ---------------------------------------------------------------------------

// TestNoDirectStoreCallsOutsideChokePoint is the criterion the issue actually
// asks for: "every upload path that signs without storing emits the loss signal
// — not just the one call site fixed here."
//
// Asserting that the two paths known TODAY emit the signal would not satisfy
// that — it would pass unchanged on the day someone adds a third. So this does
// not enumerate call sites at all. It parses the package and fails if ANY
// expression calls .Store(...) outside storeEvidence, which makes the choke
// point the only way to upload a signed envelope. A new path either routes
// through it and inherits the signal, or trips this test.
func TestNoDirectStoreCallsOutsideChokePoint(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	var offenders []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if fn.Name.Name == "storeEvidence" {
				return false // the choke point is allowed to call Store
			}
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Store" {
					return true
				}
				offenders = append(offenders,
					fmt.Sprintf("%s: %s calls .Store(...) directly", fset.Position(call.Pos()), fn.Name.Name))
				return true
			})
			return false
		})
	}

	if len(offenders) > 0 {
		t.Fatalf("an upload path bypasses storeEvidence, so it cannot emit the evidence-loss signal:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
