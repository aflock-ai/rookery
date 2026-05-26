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

package kubebench

import (
	"os/exec"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestKubeBenchDetectorOnRealBinary asserts the detector fires when the
// real kube-bench binary is on PATH and the user invoked it directly.
// We don't actually execute kube-bench (it requires a Kubernetes cluster)
// — we just verify the argv detector path matches the binary's name.
func TestKubeBenchDetectorOnRealBinary(t *testing.T) {
	if _, err := exec.LookPath("kube-bench"); err != nil {
		t.Skip("kube-bench not installed")
	}
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"kube-bench", "run"},
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("kube-bench detector did not fire: %+v", res)
}
