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

package asff

import (
	"os/exec"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestASFFDetectorOnExec asserts the pre-gate argv match against the
// real `aws securityhub get-findings` invocation pattern.
func TestASFFDetectorOnExec(t *testing.T) {
	if _, err := exec.LookPath("aws"); err != nil {
		t.Skip("aws CLI not installed")
	}
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"aws", "securityhub", "get-findings"},
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("asff did not fire on aws securityhub get-findings: %+v", res)
}
