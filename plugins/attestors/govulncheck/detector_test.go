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

package govulncheck

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}

func TestDetectorPreGateFiresOnArgv(t *testing.T) {
	detectiontest.AssertPreGateFiresOnArgv(t, Name, detectorYAML, []string{"govulncheck"})
}

func TestDetectorPostGateFiresOnExec(t *testing.T) {
	detectiontest.AssertPostGateFiresOnExec(t, Name, detectorYAML, []string{"govulncheck"})
}

// Note: govulncheck's other post-gate branch is all_of(file_exists:go.mod,
// product_glob:govulncheck*.json). Exercising it would need both inputs;
// the exec_observed test above already proves the registration + matcher
// path. A compound-branch integration test belongs in a higher-level
// suite once cilock run is wired to detection.
