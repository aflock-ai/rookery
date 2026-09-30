// jade:ring local

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

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// clearCIEnv removes every variable the CI detection reads, so the host's own
// CI (this test may run in GitHub Actions) does not leak into a case.
func clearCIEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CI", "GITLAB_CI", "GITHUB_ACTIONS", "ACTIONS_ID_TOKEN_REQUEST_URL",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "BUILDKITE", "CIRCLECI", "CI_SERVER_URL", "CI_JOB_ID",
		"CILOCK_LOGIN_ID_TOKEN", "SIGSTORE_ID_TOKEN", "CILOCK_ID_TOKEN"} {
		t.Setenv(k, "")
	}
}

// TestLoginInCINeverStartsTheBrowser is a customer demo finding: on the
// served build, `cilock login --product` in a GitLab job with no login
// id_token fell into the browser flow and hung for five minutes. In CI login
// must fail fast, name what is missing, and show the exact stanza to add.
func TestLoginInCINeverStartsTheBrowser(t *testing.T) {
	const url = "https://platform.example.com"
	for name, c := range map[string]struct {
		env  map[string]string
		args []string
		want []string
	}{
		"gitlab job, no login id_token": {
			env:  map[string]string{"CI": "true", "GITLAB_CI": "true", "CI_SERVER_URL": "https://gitlab.example", "CI_JOB_ID": "7"},
			args: []string{"--product", "hello-api"},
			want: []string{"id_tokens:", "CILOCK_LOGIN_ID_TOKEN", "aud: " + url + "/login"},
		},
		"gitlab job, --interactive": {
			env:  map[string]string{"CI": "true", "GITLAB_CI": "true", "CI_SERVER_URL": "https://gitlab.example", "CI_JOB_ID": "7"},
			args: []string{"--interactive"},
			want: []string{"--interactive", "CI"},
		},
		"github actions without id-token: write": {
			env:  map[string]string{"CI": "true", "GITHUB_ACTIONS": "true"},
			want: []string{"permissions:", "id-token: write"},
		},
		"any other CI": {
			env:  map[string]string{"CI": "true"},
			want: []string{"--token"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			isolateCLIConfig(t)
			clearCIEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			cmd := LoginCmd()
			cmd.SetArgs(append([]string{"--platform-url", url}, c.args...))
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			done := make(chan error, 1)
			go func() { done <- cmd.Execute() }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("login in CI with no identity must fail")
				}
				for _, w := range c.want {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("error must name %q:\n%v", w, err)
					}
				}
			case <-time.After(10 * time.Second):
				t.Fatal("login in CI blocked: it started an interactive flow")
			}
		})
	}
}
