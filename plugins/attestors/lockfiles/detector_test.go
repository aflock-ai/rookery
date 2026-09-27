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

package lockfiles

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}

func TestDetectorPreGateFiresOnFile(t *testing.T) {
	detectiontest.AssertPreGateFiresOnFile(t, Name, detectorYAML, "package-lock.json")
}

// The pre-gate must fire for every lockfile the attestor captures; a name
// the attestor knows but detection does not is a lockfile never suggested.
func TestDetectorPreGateFiresOnEveryCapturedLockfile(t *testing.T) {
	for _, name := range lockfilePatterns() {
		t.Run(name, func(t *testing.T) {
			detectiontest.AssertPreGateFiresOnFile(t, Name, detectorYAML, name)
		})
	}
}
