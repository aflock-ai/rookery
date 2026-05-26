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

package github_review

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}

// Pre-gate uses AND of (.git/HEAD present, GITHUB_TOKEN|GH_TOKEN|
// GITHUB_ACTIONS set). The shared helpers exercise one leaf at a
// time, so we set the env leaf and rely on the helper's tempdir not
// having .git → asserts the AND short-circuits (no fire).
//
// We do NOT positively test the full AND firing here because the
// helper takes either a file OR an env, not both. The integration-
// test attestor harness validates the happy path end-to-end via
// scripts/test-catalog-tools.py.
func TestDetectorSkipsWithoutGit(t *testing.T) {
	detectiontest.AssertPreGateSkipsCleanly(t, Name, detectorYAML, []string{"echo", "hi"})
}
