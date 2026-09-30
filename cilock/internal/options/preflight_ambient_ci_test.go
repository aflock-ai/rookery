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

package options

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// testGitLabJWT is an unsigned compact JWT carrying GitLab ID token claims for
// job 10 of https://gitlab.example. Selection reads claims only.
func testGitLabJWT(aud any, jobID string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]string{"alg": "RS256"}) + "." +
		enc(map[string]any{"iss": "https://gitlab.example", "aud": aud, "job_id": jobID}) + "." + enc("sig")
}

// setGitLabJob makes this process a GitLab CI job (job 10) with no ID tokens.
func setGitLabJob(t *testing.T) {
	t.Helper()
	for _, other := range []string{"BUILDKITE", "CIRCLECI", "GITHUB_ACTIONS", "SIGSTORE_ID_TOKEN", "CILOCK_LOGIN_ID_TOKEN", "CILOCK_ARCHIVISTA_ID_TOKEN"} {
		t.Setenv(other, "")
	}
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.example")
	t.Setenv("CI_JOB_ID", "10")
}

// TestPreflightIdentity_AmbientNonGitHubCI: on GitLab CI, Buildkite and
// CircleCI, a keyless run with no `cilock login` signs with the job's own OIDC
// token, so the first-run gate must stand down exactly as it does for GitHub
// Actions. Before, it only knew GitHub's token endpoint and refused the path
// ResolvePlatformDefaults had just chosen with "not signed in ... run 'cilock
// login' first" (GitLab CE 19.4.1, 2026-09-29, pipeline 3 job 3).
func TestPreflightIdentity_AmbientNonGitHubCI(t *testing.T) {
	for _, ci := range []string{"BUILDKITE", "CIRCLECI"} {
		t.Run(ci, func(t *testing.T) {
			isolateCredentialStore(t)
			clearAmbientOIDC(t)
			// GITHUB_ACTIONS too: GitHub's own runners set it, and it outranks
			// Buildkite and CircleCI in provider detection.
			for _, other := range []string{"GITLAB_CI", "GITHUB_ACTIONS", "BUILDKITE", "CIRCLECI"} {
				t.Setenv(other, "")
			}
			t.Setenv(ci, "true")
			cmd, ro := newRunCmd(t)
			if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			ro.ResolvePlatformDefaults(cmd)
			if err := ro.PreflightIdentity(cmd); err != nil {
				t.Fatalf("%s job with its own OIDC path must NOT be gated, got %v", ci, err)
			}
		})
	}

	t.Run("GITLAB_CI with a sigstore id_token", func(t *testing.T) {
		isolateCredentialStore(t)
		clearAmbientOIDC(t)
		setGitLabJob(t)
		t.Setenv("SIGSTORE_ID_TOKEN", testGitLabJWT("sigstore", "10"))
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err != nil {
			t.Fatalf("a GitLab job that declared its sigstore id_token must NOT be gated, got %v", err)
		}
		if !ro.signerWorkflowIdentity {
			t.Fatal("the GitLab job token must be installed as the workflow signing identity")
		}
	})

	// A GitLab job that declared no sigstore token (or only tokens for other
	// audiences, or the pre-17 CI_JOB_JWT) cannot sign keyless. It is refused
	// BEFORE its build, naming the id_tokens entry to add; before this it was
	// either refused as "not signed in" or waved through to fail at Fulcio
	// after the build.
	for name, env := range map[string]map[string]string{
		"no id_tokens":           {},
		"only the login token":   {"CILOCK_LOGIN_ID_TOKEN": testGitLabJWT("https://platform.example.com/login", "10")},
		"multi-audience token":   {"SIGSTORE_ID_TOKEN": testGitLabJWT([]string{"sigstore", "https://platform.example.com/login"}, "10")},
		"another job's token":    {"SIGSTORE_ID_TOKEN": testGitLabJWT("sigstore", "11")},
		"pre-17 CI_JOB_JWT only": {"CI_JOB_JWT": testGitLabJWT("https://gitlab.example", "10")},
	} {
		t.Run("GITLAB_CI refused before the build: "+name, func(t *testing.T) {
			isolateCredentialStore(t)
			clearAmbientOIDC(t)
			setGitLabJob(t)
			t.Setenv("CI_JOB_JWT", "")
			for k, v := range env {
				t.Setenv(k, v)
			}
			cmd, ro := newRunCmd(t)
			if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			ro.ResolvePlatformDefaults(cmd)
			err := ro.PreflightIdentity(cmd)
			if err == nil {
				t.Fatal("a GitLab job with no sigstore ID token for itself must be refused before the build")
			}
			for _, want := range []string{"id_tokens", "SIGSTORE_ID_TOKEN", "aud: sigstore"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal must name the fix; missing %q in %v", want, err)
				}
			}
			if ro.signerWorkflowIdentity {
				t.Fatal("no token was selected, so no workflow identity may be claimed")
			}
		})
	}

	// Not a CI flag's value: "false" (or anything but "true") is not a CI job,
	// so the cold-run gate still fires.
	t.Run("GITLAB_CI=false is not a CI job", func(t *testing.T) {
		isolateCredentialStore(t)
		clearAmbientOIDC(t)
		for _, other := range []string{"BUILDKITE", "CIRCLECI"} {
			t.Setenv(other, "")
		}
		t.Setenv("GITLAB_CI", "false")
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err == nil {
			t.Fatal("no CI identity and no session must still be gated")
		}
	})
}
