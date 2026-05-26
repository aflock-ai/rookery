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

package falco

import (
	"os/exec"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

func TestFalcoOrFalcoctlPresent(t *testing.T) {
	cases := []string{"falco", "falcoctl"}
	any := false
	for _, name := range cases {
		if _, err := exec.LookPath(name); err == nil {
			any = true
			reg := detection.NewRegistry()
			reg.Register(Name, detectorYAML)
			res := detection.RunPrePlanWith(reg, detection.PrePlan{
				Argv: []string{name, "--version"},
				Cwd:  t.TempDir(),
			})
			fired := false
			for _, f := range res.Fire {
				if f.Attestor == Name {
					fired = true
				}
			}
			if !fired {
				t.Errorf("falco detector did not fire on argv=%s: %+v", name, res)
			}
		}
	}
	if !any {
		t.Skip("neither falco nor falcoctl installed")
	}
}
