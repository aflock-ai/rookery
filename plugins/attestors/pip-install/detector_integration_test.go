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

package pipinstall

import (
	"os/exec"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestPipInstallDetectorOnRealPipBinary validates that pip-install
// fires when the user invokes `pip install` or `pip3 install`. We don't
// actually install anything (would require network) — just check the
// argv match against the real binary names on PATH.
func TestPipInstallDetectorOnRealPipBinary(t *testing.T) {
	for _, bin := range []string{"pip", "pip3"} {
		t.Run(bin, func(t *testing.T) {
			if _, err := exec.LookPath(bin); err != nil {
				t.Skipf("%s not installed", bin)
			}
			reg := detection.NewRegistry()
			reg.Register(Name, detectorYAML)
			res := detection.RunPrePlanWith(reg, detection.PrePlan{
				Argv: []string{bin, "install", "requests"},
				Cwd:  t.TempDir(),
			})
			for _, f := range res.Fire {
				if f.Attestor == Name {
					return
				}
			}
			t.Fatalf("pip-install did not fire on %s install: %+v", bin, res)
		})
	}
}
