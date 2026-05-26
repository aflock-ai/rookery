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

//go:build integration
// +build integration

package trivy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestTrivyDetectorAgainstRealOutput runs real trivy, captures the JSON
// report it produces, and asserts the trivy detector fires when that
// product is present in the post-gate. Validates the matcher against
// trivy's actual on-disk output, not synthetic fixtures.
func TestTrivyDetectorAgainstRealOutput(t *testing.T) {
	tv, err := exec.LookPath("trivy")
	if err != nil {
		t.Skip("trivy not installed; skipping integration test")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "trivy-report.json")
	// trivy fs scan a tiny dir (the test's own tempdir) — fast, no
	// network image-pull required.
	cmd := exec.Command(tv, "fs", "--quiet", "--format", "json", "--output", out, dir)
	if err := cmd.Run(); err != nil {
		t.Skipf("trivy fs failed: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Size() == 0 {
		t.Skipf("trivy did not produce output (size=%d err=%v)", info.Size(), err)
	}

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
	res := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre: pre,
		Products: map[string]detection.ProductRef{
			"trivy-report.json": {Path: "trivy-report.json"},
		},
		TraceMode: detection.TraceLight,
		Cwd:       dir,
	})

	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("trivy detector did not fire on real trivy output: fire=%+v skip=%+v", res.Fire, res.Skip)
}

// TestTrivyDetectorOnExecOnly validates the exec_observed path — user
// invoked trivy directly, no product file yet.
func TestTrivyDetectorOnExecOnly(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
	res := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       pre,
		ExecTrace: []detection.ExecEvent{{Argv: []string{"trivy", "image", "alpine"}}},
		TraceMode: detection.TraceLight,
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("trivy detector did not fire on exec trace: %+v", res)
}
