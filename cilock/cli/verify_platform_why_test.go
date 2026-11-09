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
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// A platform-mode refusal must carry its why, the next step and the evidence
// link in CI's own channel (evidence-loops model, ledger L2): a CI log that
// says only "status FAILED" sends the reader to the UI to learn anything.

func whyFailedGate() *platformGate {
	return &platformGate{Outcomes: []bindingOutcome{{
		Binding: options.BoundPolicy{BindingID: "b1", DefinitionName: "release", ReleaseTag: "v3"},
		Eval: &options.PlatformEvaluation{
			ID: "eval-1", Status: "FAILED", VsaGitoidSha256: "abc123", CommitHash: "c0ffee",
			Reasons: []string{"step build: no evidence for this commit"},
			StepResults: map[string]options.PlatformStepResult{
				"test":  {Passed: false, Command: "cilock run --step test -a git -- '<the command this step attests>'"},
				"build": {Passed: false, Command: "cilock run --step build -a git -a sbom -- make build"},
				"lint":  {Passed: true},
				"scan":  {Passed: false}, // an older platform names no command: no Run line
			},
		},
	}}}
}

func TestPlatformGateFailedPrintsWhyNextStepAndLink(t *testing.T) {
	var stdout, stderr bytes.Buffer
	vo := options.VerifyOptions{PlatformURL: "https://platform.example/"}
	if err := renderPlatformGate(vo, whyFailedGate(), &stdout, &stderr); err == nil {
		t.Fatal("FAILED must refuse")
	}
	const golden = `[1/1] policy "release" release "v3" (binding b1): FAILED, VSA abc123
  reason: step build: no evidence for this commit
  Run: cilock run --step build -a git -a sbom -- make build
  Run: cilock run --step test -a git -- '<the command this step attests>'
  Details: https://platform.example/attestations/abc123
FAILED: 0 of 1 bound policy passed; 1 failed
`
	if got := stderr.String(); got != golden {
		t.Fatalf("human output drifted\n--- got ---\n%s--- want ---\n%s", got, golden)
	}
}

func TestPlatformGatePassedPrintsLink(t *testing.T) {
	var stdout, stderr bytes.Buffer
	g := &platformGate{Outcomes: []bindingOutcome{{
		Binding: options.BoundPolicy{BindingID: "b1", DefinitionName: "release", ReleaseTag: "v3"},
		Eval:    &options.PlatformEvaluation{ID: "eval-1", Status: "PASSED", VsaGitoidSha256: "abc123"},
	}}}
	if err := renderPlatformGate(options.VerifyOptions{PlatformURL: "https://platform.example"}, g, &stdout, &stderr); err != nil {
		t.Fatalf("PASSED with a VSA must pass: %v", err)
	}
	const golden = `[1/1] policy "release" release "v3" (binding b1): PASSED, VSA abc123
  Details: https://platform.example/attestations/abc123
PASSED: all 1 bound policy passed, each with its own VSA
`
	if got := stderr.String(); got != golden {
		t.Fatalf("human output drifted\n--- got ---\n%s--- want ---\n%s", got, golden)
	}
}

// No platform URL (or no VSA) means no link: a guessed host would send the
// reader somewhere that is not their platform.
func TestPlatformGateNoLinkWithoutURLOrVSA(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = renderPlatformGate(options.VerifyOptions{}, whyFailedGate(), &stdout, &stderr)
	if bytes.Contains(stderr.Bytes(), []byte("Details:")) {
		t.Fatalf("no platform URL, yet a link was printed:\n%s", stderr.String())
	}
}

func TestPlatformGateJSONCarriesNextStepsAndLink(t *testing.T) {
	var stdout, stderr bytes.Buffer
	vo := options.VerifyOptions{PlatformURL: "https://platform.example", OutputFormat: "json"}
	_ = renderPlatformGate(vo, whyFailedGate(), &stdout, &stderr)
	var out struct {
		NextSteps  []string `json:"nextSteps"`
		DetailsURL string   `json:"detailsUrl"`
		Bindings   []struct {
			NextSteps  []string `json:"nextSteps"`
			DetailsURL string   `json:"detailsUrl"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout must be one JSON verdict: %v", err)
	}
	want := []string{
		"cilock run --step build -a git -a sbom -- make build",
		"cilock run --step test -a git -- '<the command this step attests>'",
	}
	for _, got := range [][]string{out.NextSteps, out.Bindings[0].NextSteps} {
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("nextSteps = %q, want %q", got, want)
		}
	}
	const link = "https://platform.example/attestations/abc123"
	if out.DetailsURL != link || out.Bindings[0].DetailsURL != link {
		t.Fatalf("detailsUrl = %q / %q, want %q", out.DetailsURL, out.Bindings[0].DetailsURL, link)
	}
}
