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

// jade:ring local

package cli

import "testing"

// The CI-marker reads used to go through Viper bindings. They read the process
// environment directly now; these pin that a variable set (or cleared) after
// process start is observed, including the ones no init() ever named.
func TestProcessEnvObservesCurrentEnvironment(t *testing.T) {
	for _, k := range []string{"GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "GITLAB_CI", "BUILDKITE", "CIRCLECI",
		"KUBERNETES_SERVICE_HOST", "CI", jenkinsURLKey} {
		t.Setenv(k, "")
		if got := processEnv(k); got != "" {
			t.Fatalf("%s cleared: got %q", k, got)
		}
		t.Setenv(k, "v-"+k)
		if got := processEnv(k); got != "v-"+k {
			t.Fatalf("%s set: got %q", k, got)
		}
	}
}

func TestInGitHubActionsIsExactlyTrue(t *testing.T) {
	for val, want := range map[string]bool{"true": true, "": false, "TRUE": false, "1": false, "false": false} {
		t.Setenv("GITHUB_ACTIONS", val)
		if got := inGitHubActions(); got != want {
			t.Errorf("GITHUB_ACTIONS=%q: got %v, want %v", val, got, want)
		}
	}
}
