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

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A browser ceremony is refused where nobody can finish it: in CI with no
// terminal, or when --no-browser says so. A terminal, or no CI marker, lets
// it run (an agent in a non-TTY shell on a laptop still has a human and a
// browser).
func TestBrowserBlockedReason(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		tty       bool
		noBrowser bool
		blocked   bool
	}{
		{"laptop terminal", nil, true, false, false},
		{"agent shell, no CI", nil, false, false, false},
		{"CI=true, no terminal", map[string]string{"CI": "true"}, false, false, true},
		{"CI=1, no terminal", map[string]string{"CI": "1"}, false, false, true},
		{"CI=false is not CI", map[string]string{"CI": "false"}, false, false, false},
		{"GitLab, no terminal", map[string]string{"GITLAB_CI": "true"}, false, false, true},
		{"Jenkins, no terminal", map[string]string{"JENKINS_URL": "https://ci.example"}, false, false, true},
		{"GitHub Actions, no terminal", map[string]string{"GITHUB_ACTIONS": "true"}, false, false, true},
		{"CI with a terminal (debug shell)", map[string]string{"CI": "true"}, true, false, false},
		{"--no-browser on a laptop", nil, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := browserBlockedReason(envOf(c.env), c.tty, c.noBrowser)
			require.Equal(t, c.blocked, got != "", "reason %q", got)
		})
	}
}

// In CI, `cilock login` fails at once with the headless remedy instead of
// opening a browser and waiting five minutes for a callback nobody will make.
// decideLoginTierCI owns this refusal; the test pins that it stays fast.
func TestLoginInCIRefusesTheBrowserFast(t *testing.T) {
	isolateAgentConfig(t)
	t.Setenv("CI", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("BROWSER", "none")

	start := time.Now()
	err := executeCmd("login")
	require.Error(t, err)
	require.Less(t, time.Since(start), 10*time.Second, "the refusal must not wait for a callback")
	require.Contains(t, err.Error(), "--token", "the refusal names the way out")
	require.True(t, strings.Contains(err.Error(), "CI"), "the refusal says why: %v", err)
}

// --no-browser refuses outside CI too, and `cilock use` honours it.
func TestNoBrowserFlagRefuses(t *testing.T) {
	isolateAgentConfig(t)
	t.Setenv("CI", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("BROWSER", "none")
	for _, args := range [][]string{{"login", "--no-browser"}, {"use", "--no-browser"}} {
		err := executeCmd(args...)
		require.Error(t, err, "%v", args)
		require.Contains(t, err.Error(), "--no-browser", "%v", args)
	}
}
