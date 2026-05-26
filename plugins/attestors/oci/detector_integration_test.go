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

package oci

import (
	"os/exec"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestOCIDetectorOnRealOCITools fires the oci detector via pre-gate
// argv matches against each OCI-handling tool we ship a detector for
// (skopeo, crane, docker save). Only the tools that are installed get
// tested; others skip.
func TestOCIDetectorOnRealOCITools(t *testing.T) {
	type tc struct {
		tool string
		argv []string
	}
	cases := []tc{
		{"docker", []string{"docker", "save", "alpine", "-o", "img.tar"}},
		{"skopeo", []string{"skopeo", "copy", "docker://alpine", "dir:/tmp/alpine"}},
		{"crane", []string{"crane", "manifest", "alpine"}},
	}
	ran := 0
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			if _, err := exec.LookPath(c.tool); err != nil {
				t.Skipf("%s not installed", c.tool)
			}
			ran++
			reg := detection.NewRegistry()
			reg.Register(Name, detectorYAML)
			res := detection.RunPrePlanWith(reg, detection.PrePlan{
				Argv: c.argv,
				Cwd:  t.TempDir(),
			})
			for _, f := range res.Fire {
				if f.Attestor == Name {
					return
				}
			}
			t.Fatalf("oci detector did not fire on %v: %+v", c.argv, res)
		})
	}
	if ran == 0 {
		t.Skip("none of docker/skopeo/crane installed")
	}
}
