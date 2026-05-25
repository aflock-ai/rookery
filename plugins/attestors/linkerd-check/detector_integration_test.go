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

package linkerdcheck

import (
	"os/exec"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

func TestLinkerdCheckDetectorOnRealBinary(t *testing.T) {
	if _, err := exec.LookPath("linkerd"); err != nil {
		t.Skip("linkerd not installed")
	}
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"linkerd", "check"},
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("linkerd-check did not fire: %+v", res)
}

// linkerd version without `check` subcommand should NOT fire — the
// detector requires the specific "linkerd check" argv prefix.
func TestLinkerdCheckDetectorRequiresCheckSubcommand(t *testing.T) {
	if _, err := exec.LookPath("linkerd"); err != nil {
		t.Skip("linkerd not installed")
	}
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"linkerd", "version"},
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			t.Fatalf("linkerd-check should NOT fire on `linkerd version`: %+v", res)
		}
	}
}
