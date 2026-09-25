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
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// The door verifies EVERY binding of the product. The gate passes only when
// every binding's verdict is accepted (PASSED with a VSA); a binding the door
// could not evaluate is reported as such, distinct from FAILED, and never
// passes; a product with no binding is an error, not a vacuous pass.

type doorMultiFake struct {
	bindings []options.BoundPolicy
	listErr  error
	evals    map[string]*options.PlatformEvaluation
	errs     map[string]error

	mu    sync.Mutex
	asked []string
}

func (f *doorMultiFake) ListProductBindings(_ context.Context, _ string) ([]options.BoundPolicy, error) {
	return f.bindings, f.listErr
}

func (f *doorMultiFake) VerifyComplianceSync(_ context.Context, bindingID, _ string, _ []string, _ bool) (*options.PlatformEvaluation, error) {
	f.mu.Lock()
	f.asked = append(f.asked, bindingID)
	f.mu.Unlock()
	if err := f.errs[bindingID]; err != nil {
		return nil, err
	}
	if e, ok := f.evals[bindingID]; ok {
		return e, nil
	}
	return nil, errors.New("fake door: no answer scripted")
}

func doorMultiBinding(id, name, tag string) options.BoundPolicy {
	return options.BoundPolicy{BindingID: id, DefinitionName: name, ReleaseTag: tag}
}

func doorMultiPass(id string) *options.PlatformEvaluation {
	return &options.PlatformEvaluation{ID: "eval-" + id, Status: "PASSED", VsaGitoidSha256: "vsa-" + id, CommitHash: "abc123"}
}

func doorMultiFail(id string) *options.PlatformEvaluation {
	return &options.PlatformEvaluation{ID: "eval-" + id, Status: "FAILED", VsaGitoidSha256: "vsa-" + id, CommitHash: "abc123",
		Reasons: []string{"step " + id + " missing"}}
}

type doorMultiJSON struct {
	Passed          bool     `json:"passed"`
	Status          string   `json:"status"`
	Reasons         []string `json:"reasons"`
	VsaGitoidSha256 string   `json:"vsaGitoidSha256"`
	EvaluationID    string   `json:"evaluationId"`
	CommitHash      string   `json:"commitHash"`
	Bindings        []struct {
		BindingID       string   `json:"bindingId"`
		Policy          string   `json:"policy"`
		Release         string   `json:"release"`
		Passed          bool     `json:"passed"`
		Status          string   `json:"status"`
		Reasons         []string `json:"reasons"`
		VsaGitoidSha256 string   `json:"vsaGitoidSha256"`
		EvaluationID    string   `json:"evaluationId"`
		Error           string   `json:"error"`
	} `json:"bindings"`
}

// doorMultiRun evaluates and renders in both formats, returning the parsed
// JSON, the human text, and each render's exit decision.
func doorMultiRun(t *testing.T, fake *doorMultiFake) (doorMultiJSON, string, error) {
	t.Helper()
	gate, err := evaluateAllBindings(context.Background(), fake, "prod-1", "abc123", nil)
	if err != nil {
		t.Fatalf("evaluateAllBindings: %v", err)
	}

	var stdout, stderr bytes.Buffer
	jerr := renderPlatformGate(options.VerifyOptions{OutputFormat: "json"}, gate, &stdout, &stderr)
	var out doorMultiJSON
	if uerr := json.Unmarshal(stdout.Bytes(), &out); uerr != nil {
		t.Fatalf("stdout must be one JSON verdict: %v (%q)", uerr, stdout.String())
	}
	if out.Passed != (jerr == nil) {
		t.Fatalf("JSON passed=%v but exit err=%v: one predicate, both surfaces", out.Passed, jerr)
	}

	var hout, herr bytes.Buffer
	textErr := renderPlatformGate(options.VerifyOptions{}, gate, &hout, &herr)
	if (textErr == nil) != (jerr == nil) {
		t.Fatalf("text exit %v and json exit %v disagree", textErr, jerr)
	}
	return out, herr.String(), jerr
}

func TestDoorMultiZeroBindingsIsAnError(t *testing.T) {
	fake := &doorMultiFake{}
	gate, err := evaluateAllBindings(context.Background(), fake, "prod-1", "abc123", nil)
	if err == nil {
		t.Fatalf("zero bindings must be an error, got verdict %+v", gate)
	}
	if !strings.Contains(err.Error(), "cilock policy bind") {
		t.Fatalf("the error must name the remedy: %v", err)
	}
	if len(fake.asked) != 0 {
		t.Fatalf("nothing to evaluate, yet the door was asked: %v", fake.asked)
	}
}

func TestDoorMultiListingErrorIsAnError(t *testing.T) {
	fake := &doorMultiFake{listErr: errors.New("graphql down")}
	if _, err := evaluateAllBindings(context.Background(), fake, "prod-1", "abc123", nil); err == nil {
		t.Fatal("a failed binding listing must be an error, never 'no bindings'")
	}
}

func TestDoorMultiSinglePassKeepsTheLegacyShape(t *testing.T) {
	fake := &doorMultiFake{
		bindings: []options.BoundPolicy{doorMultiBinding("b1", "gate", "v1")},
		evals:    map[string]*options.PlatformEvaluation{"b1": doorMultiPass("b1")},
	}
	out, text, err := doorMultiRun(t, fake)
	if err != nil {
		t.Fatalf("one PASSED binding must pass: %v", err)
	}
	// Legacy top-level fields carry the one binding's answer, unchanged.
	if out.Status != "PASSED" || out.VsaGitoidSha256 != "vsa-b1" || out.EvaluationID != "eval-b1" || out.CommitHash != "abc123" {
		t.Fatalf("single-binding top-level fields changed: %+v", out)
	}
	if len(out.Bindings) != 1 || out.Bindings[0].BindingID != "b1" || !out.Bindings[0].Passed {
		t.Fatalf("bindings array: %+v", out.Bindings)
	}
	if !strings.Contains(text, "vsa-b1") || !strings.Contains(text, "PASSED") {
		t.Fatalf("human output must name the verdict and VSA: %q", text)
	}
}

func TestDoorMultiTwoPassesPass(t *testing.T) {
	fake := &doorMultiFake{
		bindings: []options.BoundPolicy{doorMultiBinding("b2", "zeta", "v2"), doorMultiBinding("b1", "alpha", "v1")},
		evals:    map[string]*options.PlatformEvaluation{"b1": doorMultiPass("b1"), "b2": doorMultiPass("b2")},
	}
	out, text, err := doorMultiRun(t, fake)
	if err != nil {
		t.Fatalf("every binding PASSED: %v", err)
	}
	if out.Status != "PASSED" || len(out.Bindings) != 2 {
		t.Fatalf("got %+v", out)
	}
	// No single VSA speaks for two policies: the top level does not pick one.
	if out.VsaGitoidSha256 != "" || out.EvaluationID != "" {
		t.Fatalf("top level must not pick one binding's VSA for a multi-binding verdict: %+v", out)
	}
	if len(fake.asked) != 2 {
		t.Fatalf("both bindings must be evaluated, asked %v", fake.asked)
	}
	for _, id := range []string{"b1", "b2", "vsa-b1", "vsa-b2", "alpha", "zeta"} {
		if !strings.Contains(text, id) {
			t.Fatalf("human output must carry one line per binding naming %q: %q", id, text)
		}
	}
}

func TestDoorMultiPassPlusFailFails(t *testing.T) {
	fake := &doorMultiFake{
		bindings: []options.BoundPolicy{doorMultiBinding("b1", "alpha", "v1"), doorMultiBinding("b2", "beta", "v1")},
		evals:    map[string]*options.PlatformEvaluation{"b1": doorMultiPass("b1"), "b2": doorMultiFail("b2")},
	}
	out, _, err := doorMultiRun(t, fake)
	if err == nil {
		t.Fatal("one FAILED binding must fail the gate")
	}
	if out.Status != "FAILED" {
		t.Fatalf("overall status = %q, want FAILED", out.Status)
	}
	if out.Bindings[1].Status != "FAILED" || out.Bindings[1].VsaGitoidSha256 != "vsa-b2" {
		t.Fatalf("the failing binding keeps its own VSA: %+v", out.Bindings[1])
	}
	if len(out.Reasons) == 0 || !strings.Contains(strings.Join(out.Reasons, "\n"), "beta") {
		t.Fatalf("aggregate reasons must name the failing policy: %v", out.Reasons)
	}
}

func TestDoorMultiPassPlusUnavailableCouldNotEvaluate(t *testing.T) {
	fake := &doorMultiFake{
		bindings: []options.BoundPolicy{doorMultiBinding("b1", "alpha", "v1"), doorMultiBinding("b2", "beta", "v1")},
		evals:    map[string]*options.PlatformEvaluation{"b1": doorMultiPass("b1")},
		errs:     map[string]error{"b2": errors.New("platform verify: 503")},
	}
	out, text, err := doorMultiRun(t, fake)
	if err == nil {
		t.Fatal("a binding the door could not evaluate must never pass the gate")
	}
	if !strings.Contains(err.Error(), "could not evaluate") {
		t.Fatalf("the refusal must say 'could not evaluate', not FAILED: %v", err)
	}
	if out.Status == "FAILED" || out.Status == "PASSED" {
		t.Fatalf("an unevaluated binding is neither FAILED nor PASSED, got %q", out.Status)
	}
	b2 := out.Bindings[1]
	if b2.Passed || b2.Error == "" || !strings.Contains(b2.Error, "503") || b2.Status == "FAILED" {
		t.Fatalf("unavailable binding must carry its cause and not read as FAILED: %+v", b2)
	}
	if !strings.Contains(text, "could not evaluate") {
		t.Fatalf("human output must say 'could not evaluate': %q", text)
	}
}

// FAILED is the definitive answer and wins over an unevaluated sibling.
func TestDoorMultiFailPlusUnavailableIsFailed(t *testing.T) {
	fake := &doorMultiFake{
		bindings: []options.BoundPolicy{doorMultiBinding("b1", "alpha", "v1"), doorMultiBinding("b2", "beta", "v1")},
		evals:    map[string]*options.PlatformEvaluation{"b1": doorMultiFail("b1")},
		errs:     map[string]error{"b2": errors.New("timeout")},
	}
	out, _, err := doorMultiRun(t, fake)
	if err == nil || out.Status != "FAILED" {
		t.Fatalf("want FAILED + error, got %q / %v", out.Status, err)
	}
}

// A PASSED binding with no VSA is not independently verifiable; one such
// binding refuses the whole gate even when its siblings are clean.
func TestDoorMultiPassWithoutVSAFailsClosed(t *testing.T) {
	noVSA := doorMultiPass("b2")
	noVSA.VsaGitoidSha256 = ""
	fake := &doorMultiFake{
		bindings: []options.BoundPolicy{doorMultiBinding("b1", "alpha", "v1"), doorMultiBinding("b2", "beta", "v1")},
		evals:    map[string]*options.PlatformEvaluation{"b1": doorMultiPass("b1"), "b2": noVSA},
	}
	out, _, err := doorMultiRun(t, fake)
	if err == nil || out.Passed {
		t.Fatalf("a PASSED binding without a VSA must fail the gate closed: %+v / %v", out, err)
	}
}

// A nil evaluation with a nil error is not an answer.
func TestDoorMultiNilEvaluationIsUnavailable(t *testing.T) {
	fake := &doorMultiFake{
		bindings: []options.BoundPolicy{doorMultiBinding("b1", "alpha", "v1")},
		evals:    map[string]*options.PlatformEvaluation{"b1": nil},
	}
	out, _, err := doorMultiRun(t, fake)
	if err == nil || out.Passed {
		t.Fatal("a nil evaluation must not pass")
	}
}

// An anchorless platform verify is unaskable, so it is refused before the
// binding listing or any door call leaves the machine.
func TestDoorMultiAnchorlessRefusedBeforeAnyRequest(t *testing.T) {
	sandboxVerifyEnv(t)
	platformURL, strays := approvalReaderSession(t)
	_, _, err := executeCmdOutput("verify", "--platform-url", platformURL)
	if err == nil || !strings.Contains(err.Error(), "no anchor") {
		t.Fatalf("want the anchor refusal, got %v", err)
	}
	if n := strays.Load(); n != 0 {
		t.Fatalf("an anchorless verify reached the platform (%d requests)", n)
	}
}

func TestDoorMultiOrderingIsDeterministic(t *testing.T) {
	bindings := []options.BoundPolicy{
		doorMultiBinding("b3", "zeta", "v1"),
		doorMultiBinding("b2", "alpha", "v2"),
		doorMultiBinding("b1", "alpha", "v1"),
		doorMultiBinding("b0", "mid", "v1"),
	}
	evals := map[string]*options.PlatformEvaluation{}
	for _, b := range bindings {
		evals[b.BindingID] = doorMultiPass(b.BindingID)
	}
	var first []string
	for run := 0; run < 5; run++ {
		// Reverse the input each run: order must come from the data, not the
		// server or goroutine scheduling.
		in := append([]options.BoundPolicy(nil), bindings...)
		if run%2 == 1 {
			for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
				in[i], in[j] = in[j], in[i]
			}
		}
		out, _, err := doorMultiRun(t, &doorMultiFake{bindings: in, evals: evals})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(out.Bindings))
		for _, b := range out.Bindings {
			ids = append(ids, b.BindingID)
		}
		if first == nil {
			first = ids
			if want := "b1,b2,b0,b3"; strings.Join(ids, ",") != want {
				t.Fatalf("order = %v, want %s (policy name, then release, then binding id)", ids, want)
			}
			continue
		}
		if strings.Join(ids, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d order %v differs from %v", run, ids, first)
		}
	}
}
