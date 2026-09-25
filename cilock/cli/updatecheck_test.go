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
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/stretchr/testify/require"
)

func TestStartUpdateCheckEvidenceDefaults(t *testing.T) {
	version, profile, budget := Version, config.DefaultEvidenceProfile, config.DefaultProductInlineBytes
	t.Cleanup(func() {
		Version, config.DefaultEvidenceProfile, config.DefaultProductInlineBytes = version, profile, budget
	})
	Version = "4.0.0" // A real release stamp prevents a dev-build skip masking the gate.
	t.Setenv(skipVersionCheckEnv, "")
	for _, tt := range []struct {
		profile, budget string
		invalid         bool
	}{
		{"compact", "131072", false},
		{"legacy", "131072", false},
		{"unknown", "131072", true},
		{"", "131072", true},
		{"compact", "-1", true},
		{"compact", "invalid", true},
		{"legacy", "2147483648", true},
	} {
		t.Run(tt.profile+"/"+tt.budget, func(t *testing.T) {
			config.DefaultEvidenceProfile, config.DefaultProductInlineBytes = tt.profile, tt.budget
			cache := t.TempDir()
			t.Setenv("HOME", cache)
			t.Setenv("XDG_CACHE_HOME", cache)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, `{"latest":"v4.0.1"}`)
			}))
			defer server.Close()
			t.Setenv("CILOCK_DIST_BASE", server.URL)
			check := startUpdateCheck([]string{"run", "--", "true"})
			notice := check.Notice() // Also waits for a mistakenly-started check in the red test.
			if tt.invalid {
				require.Nil(t, check, "invalid compiled defaults must not start the background worker")
				require.Empty(t, notice)
				require.Zero(t, requests.Load())
			} else {
				require.NotNil(t, check)
				require.Contains(t, notice, "4.0.1")
				require.Equal(t, int32(1), requests.Load(), "valid profiles must retain the update check")
			}
		})
	}
}

func TestStartUpdateCheckExplicitOffline(t *testing.T) {
	version := Version
	t.Cleanup(func() { Version = version })
	Version = "4.0.0"
	t.Setenv(skipVersionCheckEnv, "")
	for _, args := range [][]string{
		{"verify", "artifact", "--platform-url", "", "--enable-archivista=false"},
		{"verify", "artifact", "--platform-url=", "--enable-archivista=false"},
		{"verify", "artifact", "--offline", "--enable-archivista=false"},
	} {
		t.Run(args[2]+args[3], func(t *testing.T) {
			cache := t.TempDir()
			t.Setenv("HOME", cache)
			t.Setenv("XDG_CACHE_HOME", cache)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, `{"latest":"v4.0.1"}`)
			}))
			defer server.Close()
			t.Setenv("CILOCK_DIST_BASE", server.URL)
			check := startUpdateCheck(args)
			_ = check.Notice()
			require.Nil(t, check)
			require.Zero(t, requests.Load(), "explicit offline verify must not fetch the update manifest")
		})
	}
}

func TestInvalidEvidenceDefaultsPreserveHelpAndVersion(t *testing.T) {
	defer log.SetLogger(log.GetLogger())
	profile := config.DefaultEvidenceProfile
	t.Cleanup(func() { config.DefaultEvidenceProfile = profile })
	config.DefaultEvidenceProfile = "invalid"
	t.Setenv("CILOCK_NO_TELEMETRY", "1")
	for _, args := range [][]string{{"--help"}, {"run", "--help"}, {"version"}} {
		cmd := New()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		require.NoError(t, cmd.ExecuteContext(t.Context()), "diagnostic command %v must remain usable", args)
	}
}

func TestSkipUpdateCheckForArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"bare invocation", nil, true},
		{"help word", []string{"help"}, true},
		{"help flag only", []string{"--help"}, true},
		{"completion", []string{"completion", "bash"}, true},
		// Cobra allows persistent flags before the subcommand — the guard
		// must not be defeated by a flag-prefixed invocation.
		{"completion after flags", []string{"--log-level", "debug", "completion", "bash"}, true},
		{"hidden complete after flags", []string{"--log-level", "debug", "__complete", "run", ""}, true},
		{"hidden complete", []string{"__complete", "run", ""}, true},
		{"hidden complete nodesc", []string{"__completeNoDesc", "run", ""}, true},
		{"normal command", []string{"verify", "artifact"}, false},
		{"offline split", []string{"verify", "--platform-url", ""}, true},
		{"offline equals", []string{"verify", "--platform-url="}, true},
		{"offline alias", []string{"verify", "--offline"}, true},
		{"offline alias true", []string{"verify", "--offline=true"}, true},
		{"offline alias false", []string{"verify", "--offline=false"}, false},
		{"offline alias override", []string{"verify", "--offline", "--offline=false"}, false},
		{"explicit online", []string{"verify", "--platform-url=https://example.test"}, false},
		{"last platform wins online", []string{"verify", "--platform-url=", "--platform-url", "https://example.test"}, false},
		{"last platform wins offline", []string{"verify", "--platform-url=https://example.test", "--platform-url", ""}, true},
		{"archivista alone is not offline", []string{"verify", "--enable-archivista=false"}, false},
		{"wrapped offline flags", []string{"run", "--", "tool", "--platform-url", ""}, false},
		// --help/-h anywhere before "--" is help rendering, not real work.
		{"subcommand help flag", []string{"verify", "--help"}, true},
		{"subcommand short help", []string{"verify", "-h"}, true},
		{"subcommand advanced help", []string{"run", "--help-advanced"}, true},
		{"normal command after flags", []string{"--log-level", "debug", "verify"}, false},
		// Tokens after "--" are the wrapped command's argv, not subcommands.
		{"run wrapping sensitive word", []string{"run", "--", "help"}, false},
		{"run wrapping completion", []string{"run", "-s", "build", "--", "make", "completion"}, false},
		// `cilock skill` promises no network I/O.
		{"skill is local", []string{"skill", "install", "--agent", "codex"}, true},
		{"skill after flags", []string{"--log-level", "debug", "skill", "show"}, true},
		{"run wrapping skill", []string{"run", "--", "skill"}, false},
	}
	for _, tc := range cases {
		if got := skipUpdateCheckForArgs(tc.args); got != tc.want {
			t.Errorf("%s: skipUpdateCheckForArgs(%v) = %v, want %v", tc.name, tc.args, got, tc.want)
		}
	}
}
