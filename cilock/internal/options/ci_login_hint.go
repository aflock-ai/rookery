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
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
)

// CILoginHint is how to sign this run in to platformURL with a product bound,
// written for the CI it runs in: a GitLab job gets `id_tokens:` entries with
// the exact audiences, a GitHub job `permissions: id-token: write`, anything
// else `cilock login`. A hint for another CI's syntax is worse than none.
func CILoginHint(getenv func(string) string, platformURL string) string {
	u := strings.TrimRight(auth.NormalizeURL(platformURL), "/")
	login := "cilock login --product <product> --platform-url " + u
	switch auth.CIProviderFromEnv(getenv) {
	case auth.CIGitLab:
		return fmt.Sprintf("in .gitlab-ci.yml, give the job its ID tokens and log in with the product:\n"+
			"  id_tokens:\n"+
			"    CILOCK_LOGIN_ID_TOKEN:\n"+
			"      aud: %s\n"+
			"    SIGSTORE_ID_TOKEN:\n"+
			"      aud: sigstore\n"+
			"  script:\n"+
			"    - %s", platformconfig.Derive(u).OIDCLoginAudience, login)
	case auth.CIGitHub:
		return "in the workflow, let the job mint its OIDC token and log in with the product:\n" +
			"  permissions:\n" +
			"    id-token: write\n" +
			"  steps:\n" +
			"    - run: " + login
	default:
		return "run: " + login
	}
}

// CITrustHint is how a CI job stores evidence with no secret: a tenant admin
// runs `cilock trust` once for the job's project, and the job signs and
// uploads with its own identity. For GitLab that is one job ID token per
// platform door, each with its fixed audience: "sigstore" (the only one
// Fulcio accepts) to sign, <platform>/archivista (what `cilock trust`
// registers) to upload, and <platform>/login so the run learns the project's
// bound product. One token cannot serve all three without the sigstore
// audience becoming an upload credential any Fulcio could replay. Outside CI
// there is no job identity to trust, so the hint is `cilock login`.
func CITrustHint(getenv func(string) string, platformURL string) string {
	u := strings.TrimRight(auth.NormalizeURL(platformURL), "/")
	admin := "a tenant admin, once: `cilock login --platform-url " + u + " --allow-trust`, then "
	switch auth.CIProviderFromEnv(getenv) {
	case auth.CIGitLab:
		project := getenv("CI_PROJECT_PATH")
		if project == "" {
			project = "<group>/<project>"
		}
		host := ""
		if h := getenv("CI_SERVER_HOST"); h != "" && h != "gitlab.com" {
			host = " --host " + h
		}
		return fmt.Sprintf("%s`cilock trust gitlab %s%s --platform-url %s`; and the job declares, in .gitlab-ci.yml "+
			"(or includes cilock-platform.gitlab-ci.yml, which declares them):\n"+
			"  id_tokens:\n"+
			"    SIGSTORE_ID_TOKEN:\n"+
			"      aud: sigstore\n"+
			"    CILOCK_ARCHIVISTA_ID_TOKEN:\n"+
			"      aud: %s/archivista\n"+
			"    CILOCK_LOGIN_ID_TOKEN:\n"+
			"      aud: %s/login", admin, project, host, u, u, u)
	case auth.CIGitHub:
		repo := getenv("GITHUB_REPOSITORY")
		if repo == "" {
			repo = "<owner>/<repo>"
		}
		return fmt.Sprintf("%s`cilock trust github %s --platform-url %s`; and the job grants:\n"+
			"  permissions:\n"+
			"    id-token: write", admin, repo, u)
	default:
		return "run: cilock login --platform-url " + u
	}
}

// ciRepoIdentifiers names the repository the way the CI it runs in does,
// preferring what the platform returned.
func ciRepoIdentifiers(getenv func(string) string, repo, repoID string) (name, idLabel, id string) {
	if auth.CIProviderFromEnv(getenv) == auth.CIGitLab {
		name, idLabel, id = getenv("CI_PROJECT_PATH"), "project_id", getenv("CI_PROJECT_ID")
	} else {
		name, idLabel, id = getenv("GITHUB_REPOSITORY"), "github_repository_id", getenv("GITHUB_REPOSITORY_ID")
	}
	if repo != "" {
		name = repo
	}
	if repoID != "" {
		id = repoID
	}
	if name == "" {
		name = "(unknown repository)"
	}
	if id == "" {
		id = "(unknown)"
	}
	return name, idLabel, id
}
