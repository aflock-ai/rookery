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

package sbom

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestSBOMDetectorAgainstRealSyftOutput runs syft (skipped if not on
// PATH), produces a real SPDX JSON file, and asserts the post-gate
// matcher fires against the real product. Validates that the
// product_glob patterns actually match a file syft creates with the
// canonical extension.
func TestSBOMDetectorAgainstRealSyftOutput(t *testing.T) {
	syft, err := exec.LookPath("syft")
	if err != nil {
		t.Skip("syft not installed; skipping integration test")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "sbom.spdx.json")
	cmd := exec.Command(syft, "scan", "alpine:latest", "-o", "spdx-json="+out)
	if err := cmd.Run(); err != nil {
		t.Skipf("syft scan failed (network?): %v", err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Size() < 100 {
		t.Skipf("syft did not produce expected output (size=%d, err=%v)", info.Size(), err)
	}

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
	res := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre: pre,
		Products: map[string]detection.ProductRef{
			"sbom.spdx.json": {Path: "sbom.spdx.json"},
		},
		TraceMode: detection.TraceLight,
		Cwd:       dir,
	})

	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("sbom detector did not fire on real syft output (%d bytes): fire=%+v skip=%+v",
		info.Size(), res.Fire, res.Skip)
}
