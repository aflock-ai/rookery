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

package buildpacks

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

func TestDetectorYAMLParses(t *testing.T) {
	d, err := detection.ParseDetectorYAML(detectorYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Name != Name {
		t.Errorf("name mismatch: yaml=%q plugin=%q", d.Name, Name)
	}
	if d.Pre == nil {
		t.Errorf("expected pre block")
	}
	if d.Post == nil {
		t.Errorf("expected post block")
	}
}

func TestDetectorFiresOnPackBuild(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"pack", "build", "demo-app", "--builder", "heroku/builder:24"},
		Cwd:  t.TempDir(),
	})

	if len(res.Fire) != 1 || res.Fire[0].Attestor != Name {
		t.Fatalf("expected buildpacks to fire pre-gate, got %+v", res.Fire)
	}

	// Without --report-output-dir there is no report.toml to attest, so the
	// warning must fire and its suggested command must add the flag.
	if len(res.Warnings) != 1 || res.Warnings[0].Code != "BUILDPACKS_NO_REPORT" {
		t.Fatalf("expected BUILDPACKS_NO_REPORT warning, got %+v", res.Warnings)
	}
	want := []string{"pack", "build", "--report-output-dir=./out", "demo-app", "--builder", "heroku/builder:24"}
	got := res.Warnings[0].SuggestedCommand
	if !argvEqual(got, want) {
		t.Errorf("suggested_command = %v, want %v", got, want)
	}
}

func TestDetectorSuppressesWarningWithReportFlag(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"pack", "build", "demo-app", "--report-output-dir", "./out"},
		Cwd:  t.TempDir(),
	})

	if len(res.Fire) != 1 {
		t.Fatalf("expected buildpacks to fire, got %+v", res.Fire)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warn_unless should suppress the warning, got %+v", res.Warnings)
	}
}

func TestDetectorDoesNotFireOnUnrelatedCommand(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"go", "build", "./..."},
		Cwd:  t.TempDir(),
	})
	if len(res.Fire) != 0 {
		t.Errorf("buildpacks must not fire on 'go build', got %+v", res.Fire)
	}
}

func TestDetectorFiresPostGateOnObservedExec(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	// User typed `make image` — pre-gate sees no pack.
	pre := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"make", "image"},
		Cwd:  t.TempDir(),
	})
	if len(pre.Fire) != 0 {
		t.Errorf("pre-gate should not fire on 'make image', got %+v", pre.Fire)
	}

	// But the trace shows pack build ran as a child.
	post := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       &pre,
		ExecTrace: []detection.ExecEvent{{Argv: []string{"pack", "build", "demo-app"}}},
		TraceMode: detection.TraceLight,
	})
	if len(post.Fire) != 1 || post.Fire[0].Attestor != Name {
		t.Fatalf("expected buildpacks to fire post-gate via exec_observed, got %+v", post.Fire)
	}
}

func argvEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
