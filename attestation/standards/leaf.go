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

package standards

import (
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/sigstore/fulcio/pkg/certificate"
)

// GitHubActionsIssuer is the OIDC issuer of GitHub Actions workflow tokens.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// RunnerGitHubHosted is the Fulcio runner-environment value for a
// GitHub-hosted runner.
const RunnerGitHubHosted = "github-hosted"

// providerHostedRunners are the Fulcio runner-environment values that name a
// runner the CI provider operates (sigstore/fulcio config/identity/config.yaml:
// GitHub, GitLab and Buildkite fill runner_environment; CircleCI and
// Kubernetes report no hosted signal).
var providerHostedRunners = map[string]bool{
	RunnerGitHubHosted: true,
	"gitlab-hosted":    true,
	"buildkite-hosted": true,
}

// IsProviderHostedRunner reports whether a Fulcio runner-environment value
// names a provider-operated runner.
func IsProviderHostedRunner(env string) bool { return providerHostedRunners[env] }

// Leaf is what a signing certificate says about who signed and where.
type Leaf struct {
	Issuer            string
	BuildSignerURI    string
	RunnerEnvironment string
	Principal         string
	// CI is the CI platform the issuer names, or "" when it names none.
	CI string
}

// CIFromIssuer maps a workload OIDC issuer onto a CI platform. Only the SaaS
// issuers are recognized for GitLab (gitlab.com); a self-managed GitLab has
// its own issuer and no Fulcio mapping. Unknown issuers return "".
func CIFromIssuer(iss string) string {
	switch {
	case iss == GitHubActionsIssuer:
		return CIGitHub
	case iss == "https://gitlab.com":
		return CIGitLab
	case iss == "https://agent.buildkite.com":
		return CIBuildkite
	case iss == "https://oidc.circleci.com" || strings.HasPrefix(iss, "https://oidc.circleci.com/org/"):
		return CICircleCI
	case strings.HasPrefix(iss, "https://container.googleapis.com/v1/projects/"),
		strings.HasPrefix(iss, "https://oidc.eks.") && strings.Contains(iss, ".amazonaws.com/id/"),
		strings.HasPrefix(iss, "https://oidc.prod-aks.azure.com/"),
		strings.Contains(iss, ".oic.prod-aks.azure.com/"):
		return CIKubernetes
	}
	return ""
}

// LeafFromCertificate reads the Fulcio extensions and SANs of a signing leaf.
// A certificate without a SPIFFE URI, a workflow issuer or an email is
// PrincipalUnknown: it is never promoted to an issued principal.
func LeafFromCertificate(c *x509.Certificate) Leaf {
	var l Leaf
	if c == nil {
		return l
	}
	if exts, err := certificate.ParseExtensions(c.Extensions); err == nil {
		l.Issuer = exts.Issuer
		l.BuildSignerURI = exts.BuildSignerURI
		l.RunnerEnvironment = exts.RunnerEnvironment
	}
	l.CI = CIFromIssuer(l.Issuer)
	switch {
	case hasSPIFFE(c):
		l.Principal = PrincipalAgent
	case l.CI != "":
		l.Principal = PrincipalWorkflow
	case len(c.EmailAddresses) > 0:
		l.Principal = PrincipalHuman
	}
	return l
}

// LeafFromPEM parses the first certificate in a PEM block. Bad input is an
// empty Leaf, which observes nothing.
func LeafFromPEM(raw []byte) (Leaf, bool) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return Leaf{}, false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Leaf{}, false
	}
	return LeafFromCertificate(c), true
}

func hasSPIFFE(c *x509.Certificate) bool {
	for _, u := range c.URIs {
		if u != nil && u.Scheme == "spiffe" {
			return true
		}
	}
	return false
}

// IsTrustedBuilder reports whether the leaf's Build Signer URI names a
// builder identity from the catalog (the isolated provenance workflow). The
// match is a prefix on the full `<workflow path>@` so a sibling workflow in
// the same repository, or a lookalike path, never matches.
func (l Leaf) IsTrustedBuilder() bool {
	if l.BuildSignerURI == "" {
		return false
	}
	cats, err := Catalogs()
	if err != nil {
		return false
	}
	for _, c := range cats {
		for _, s := range c.Steps {
			if s.BuilderIdentity != "" && strings.HasPrefix(l.BuildSignerURI, s.BuilderIdentity) {
				return true
			}
		}
	}
	return false
}
