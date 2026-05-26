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

package gcpiit

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}

// TestDetectorFiresOnGCPRunner injects a positive gcp_metadata_reachable
// probe result and asserts the gcp-iit detector fires. The real network
// probe is integration-test territory — it must run on a GCE instance
// and lives outside this unit test. See docs/detection-integration-tests.md.
func TestDetectorFiresOnGCPRunner(t *testing.T) {
	detection.ResetProbeCache()
	detection.InjectProbeResult("gcp_metadata_reachable", true)
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
	t.Fatalf("expected gcp-iit to fire when probe is true, got fire=%+v skip=%+v", res.Fire, res.Skip)
}

// TestDetectorSkipsOffGCP injects a negative probe result and asserts
// gcp-iit is correctly skipped — the user is not on GCP.
func TestDetectorSkipsOffGCP(t *testing.T) {
	detection.ResetProbeCache()
	detection.InjectProbeResult("gcp_metadata_reachable", false)
	defer detection.ResetProbeCache()

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"echo", "hi"},
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			t.Fatalf("expected gcp-iit to skip off-GCP, but it fired: %+v", f)
		}
	}
}
