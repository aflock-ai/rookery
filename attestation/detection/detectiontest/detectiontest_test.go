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

package detectiontest

import "testing"

// smokeYAML is a minimal valid detector.yaml used to exercise each
// helper. The helpers don't care about the predicate semantics — they
// just want to confirm the wrapped Run*Plan calls produce expected
// fire/skip decisions.
var smokeYAML = []byte(`
apiVersion: cilock.detection/v0.1
name: smoke
description: "smoke-test detector used by detectiontest's own unit tests"
pre:
  match:
    any_of:
      - argv_prefix: ["smoke"]
      - env_set: SMOKE_TEST
      - file_exists: smoke.txt
post:
  match:
    any_of:
      - exec_observed:
          argv_prefix: ["smoke-tool"]
      - product_glob: ["*.smoke"]
`)

func TestHelpersExerciseTheirOwnHappyPaths(t *testing.T) {
	// Each helper should pass against an input that matches the smoke
	// detector. If any helper regressed, this test fails first.
	AssertParses(t, "smoke", smokeYAML)
	AssertPreGateFiresOnArgv(t, "smoke", smokeYAML, []string{"smoke", "run"})
	AssertPreGateFiresInEnv(t, "smoke", smokeYAML, "SMOKE_TEST", "1")
	AssertPreGateFiresOnFile(t, "smoke", smokeYAML, "smoke.txt")
	AssertPreGateSkipsCleanly(t, "smoke", smokeYAML, []string{"echo", "unrelated"})
	AssertPostGateFiresOnExec(t, "smoke", smokeYAML, []string{"smoke-tool", "--run"})
	AssertPostGateFiresOnProduct(t, "smoke", smokeYAML, "out.smoke")
	AssertPostGateTraceUnavailable(t, "smoke", smokeYAML)
}
