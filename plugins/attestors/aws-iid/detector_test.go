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

package aws_iid

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}

// TestDetectorFiresOnEC2Runner injects a positive imds_reachable probe
// result and asserts aws-iid fires. The real probe (HTTP HEAD against
// 169.254.169.254) must be integration-tested on an actual EC2 instance.
// See docs/detection-integration-tests.md.
func TestDetectorFiresOnEC2Runner(t *testing.T) {
	detection.ResetProbeCache()
	detection.InjectProbeResult("imds_reachable", true)
	defer detection.ResetProbeCache()

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"echo", "hi"},
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("expected aws-iid to fire when imds is reachable, got fire=%+v skip=%+v", res.Fire, res.Skip)
}

// TestDetectorSkipsOffEC2 injects a negative probe result and asserts
// aws-iid is correctly skipped.
func TestDetectorSkipsOffEC2(t *testing.T) {
	detection.ResetProbeCache()
	detection.InjectProbeResult("imds_reachable", false)
	defer detection.ResetProbeCache()

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"echo", "hi"},
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			t.Fatalf("expected aws-iid to skip off-EC2, but it fired: %+v", f)
		}
	}
}
