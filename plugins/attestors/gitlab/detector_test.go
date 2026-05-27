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

package gitlab

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
}

func TestDetectorFiresInGitLabCI(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"echo", "hi"},
		Env:  map[string]string{"GITLAB_CI": "true"},
		Cwd:  t.TempDir(),
	})
	if len(res.Fire) != 1 || res.Fire[0].Attestor != Name {
		t.Fatalf("expected gitlab to fire, got %+v", res.Fire)
	}
}
