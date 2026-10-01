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
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/platformauth"
)

// TestCILoginHintNamesTheJobsOwnCI is a customer demo finding: inside a
// GitLab job cilock suggested GitHub Actions snippets. The hint names the CI
// it is running in, with the exact audience for this platform.
func TestCILoginHintNamesTheJobsOwnCI(t *testing.T) {
	const url = "https://appliance.example.com"
	gl := CILoginHint(envOf(map[string]string{"GITLAB_CI": "true"}), url)
	for _, want := range []string{"id_tokens:", "CILOCK_LOGIN_ID_TOKEN:", "aud: " + url + "/login",
		"SIGSTORE_ID_TOKEN:", "aud: sigstore", "cilock login --product <product> --platform-url " + url} {
		if !strings.Contains(gl, want) {
			t.Errorf("GitLab hint lacks %q:\n%s", want, gl)
		}
	}
	for _, never := range []string{"permissions:", "id-token: write", "GitHub"} {
		if strings.Contains(gl, never) {
			t.Errorf("GitLab hint must not suggest %q:\n%s", never, gl)
		}
	}
	gh := CILoginHint(envOf(map[string]string{"GITHUB_ACTIONS": "true"}), url)
	if !strings.Contains(gh, "id-token: write") || strings.Contains(gh, "id_tokens") {
		t.Errorf("GitHub hint:\n%s", gh)
	}
	if local := CILoginHint(envOf(nil), url); !strings.Contains(local, "cilock login --product <product> --platform-url "+url) || strings.Contains(local, "id_tokens") {
		t.Errorf("local hint:\n%s", local)
	}
}

// TestCITrustHintIsTheOneTimeRecipe: in CI the way to store evidence with no
// secret is `cilock trust` once, then the job's own identity. The hint names
// the exact trust command for this job's project and host, and the job's ID
// tokens with their exact audiences (or the include that declares them); it
// never asks for a token file or an upload header (Cole, 2026-09-29: "we
// should be able to use cilock trust").
func TestCITrustHintIsTheOneTimeRecipe(t *testing.T) {
	const url = "https://appliance.example.com"
	gl := CITrustHint(envOf(map[string]string{"GITLAB_CI": "true", "CI_PROJECT_PATH": "example-org/case-api",
		"CI_SERVER_HOST": "gitlab.example-org.example"}), url)
	for _, want := range []string{"cilock trust gitlab example-org/case-api --host gitlab.example-org.example --platform-url " + url,
		"--allow-trust", "SIGSTORE_ID_TOKEN:", "aud: sigstore", "CILOCK_ARCHIVISTA_ID_TOKEN:", "aud: " + url + "/archivista",
		"CILOCK_LOGIN_ID_TOKEN:", "aud: " + url + "/login", "cilock-platform.gitlab-ci.yml"} {
		if !strings.Contains(gl, want) {
			t.Errorf("GitLab trust hint lacks %q:\n%s", want, gl)
		}
	}
	for _, never := range []string{"--signer-fulcio-token", "--archivista-headers", "id-token: write"} {
		if strings.Contains(gl, never) {
			t.Errorf("the trust hint must not ask for %q:\n%s", never, gl)
		}
	}
	com := CITrustHint(envOf(map[string]string{"GITLAB_CI": "true", "CI_PROJECT_PATH": "acme/app", "CI_SERVER_HOST": "gitlab.com"}), url)
	if strings.Contains(com, "--host") {
		t.Errorf("gitlab.com needs no --host:\n%s", com)
	}
	gh := CITrustHint(envOf(map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/widget"}), url)
	if !strings.Contains(gh, "cilock trust github acme/widget") || !strings.Contains(gh, "id-token: write") || strings.Contains(gh, "id_tokens") {
		t.Errorf("GitHub trust hint:\n%s", gh)
	}
	if local := CITrustHint(envOf(nil), url); !strings.Contains(local, "cilock login") {
		t.Errorf("outside CI there is no job identity to trust; the hint is login:\n%s", local)
	}
}

// TestBindingGateNamesTrustWhenTheIdentityIsNotTrusted is pipeline 27 on the
// real CE (project 8, no trust credential): the run-start binding gate got a
// 401 from resolve-binding and said "Fix the configuration, or pass
// --no-product-binding". The fix is `cilock trust` once, and the refusal says
// so, for this project and host. It still fails closed.
func TestBindingGateNamesTrustWhenTheIdentityIsNotTrusted(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_PATH", "example-org/case-api")
	t.Setenv("CI_SERVER_HOST", "gitlab-wp-test.previews.testifysec.io")
	err := classifyBindingGateError("https://appliance.example.com",
		&platformauth.IdentityNotTrustedError{Status: 401, Msg: "resolve-binding: https://appliance.example.com/api/auth/resolve-binding returned 401: {}"})
	if err == nil {
		t.Fatal("an untrusted identity must fail closed")
	}
	for _, want := range []string{"not trusted", "cilock trust gitlab example-org/case-api --host gitlab-wp-test.previews.testifysec.io"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "Fix the configuration") {
		t.Errorf("the refusal must name the fix, not a generic one:\n%v", err)
	}
}

// TestRepoNotMappedInGitLabNamesTheProject: the zero-product failure in a
// GitLab job names the project id (not github_repository_id) and the
// product-bound login.
func TestRepoNotMappedInGitLabNamesTheProject(t *testing.T) {
	env := envOf(map[string]string{"GITLAB_CI": "true", "CI_PROJECT_PATH": "example-org/hello-api", "CI_PROJECT_ID": "3"})
	msg := repoNotMappedMessageEnv(env, "https://appliance.example.com",
		&platformauth.RepositoryNotMappedError{TenantName: "example-org", TenantID: "t1"})
	for _, want := range []string{"example-org/hello-api", "project_id=3", "id_tokens:", "--product <product>"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "github") {
		t.Errorf("a GitLab message must not name GitHub:\n%s", msg)
	}
	amb := ambiguousProductMessageEnv(env, "https://appliance.example.com", &platformauth.AmbiguousProductError{TenantName: "example-org"})
	if !strings.Contains(amb, "example-org/hello-api") || !strings.Contains(amb, "id_tokens:") {
		t.Errorf("ambiguous message:\n%s", amb)
	}
}
