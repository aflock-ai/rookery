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

package govulncheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestGovulncheckDetectorOnRealRun invokes govulncheck against a tiny
// Go module and asserts the detector fires (pre-gate argv + post-gate
// exec_observed both should work).
func TestGovulncheckDetectorOnRealRun(t *testing.T) {
	if _, err := exec.LookPath("govulncheck"); err != nil {
		t.Skip("govulncheck not installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	// Pre-gate: user types govulncheck directly.
	resPre := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"govulncheck", "./..."},
		Cwd:  dir,
	})
	firedPre := false
	for _, f := range resPre.Fire {
		if f.Attestor == Name {
			firedPre = true
		}
	}
	if !firedPre {
		t.Errorf("pre-gate did not fire: %+v", resPre)
	}

	// Post-gate via exec_observed (user wrapped govulncheck in make/script).
	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"make"}}}
	resPost := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       pre,
		ExecTrace: []detection.ExecEvent{{Argv: []string{"govulncheck", "./..."}}},
		TraceMode: detection.TraceLight,
		Cwd:       dir,
	})
	firedPost := false
	for _, f := range resPost.Fire {
		if f.Attestor == Name {
			firedPost = true
		}
	}
	if !firedPost {
		t.Errorf("post-gate did not fire via exec_observed: %+v", resPost)
	}
}
