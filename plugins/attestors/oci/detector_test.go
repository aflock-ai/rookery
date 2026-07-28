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

package oci

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}

func TestDetectorPostGateFiresOnExec(t *testing.T) {
	detectiontest.AssertPostGateFiresOnExec(t, Name, detectorYAML, []string{"docker", "save"})
}

func TestDetectorPostGateFiresOnProduct(t *testing.T) {
	detectiontest.AssertPostGateFiresOnProduct(t, Name, detectorYAML, "index.json")
}

// TestDetectorGatesCoverEveryTrustedPushForm pins detector.yaml to
// isRegistryPushCommand: every push invocation the registry-digest parser
// trusts must also select the oci attestor via BOTH the pre gate (argv) and
// the post gate (observed exec). A form the parser accepts but the detector
// misses — `docker image push` was exactly that — means a push-only run never
// runs this attestor and silently produces no registrydigest evidence at all.
func TestDetectorGatesCoverEveryTrustedPushForm(t *testing.T) {
	for _, argv := range [][]string{
		{"docker", "push", "registry.example.com/app:v1"},
		{"docker", "image", "push", "registry.example.com/app:v1"},
		{"crane", "push", "app.tar", "registry.example.com/app:v1"},
		{"crane", "copy", "src.example.com/app:v1", "dst.example.com/app:v1"},
		{"crane", "cp", "src.example.com/app:v1", "dst.example.com/app:v1"},
	} {
		if !isRegistryPushCommand(argv) {
			t.Fatalf("test premise broken: %v is not a trusted push command", argv)
		}
		detectiontest.AssertPreGateFiresOnArgv(t, Name, detectorYAML, argv)
		detectiontest.AssertPostGateFiresOnExec(t, Name, detectorYAML, argv)
	}
}
