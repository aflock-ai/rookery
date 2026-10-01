// jade:ring local
// Copyright 2026 The Aflock Authors
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

package slsa

import (
	"crypto"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	v1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
	"github.com/aflock-ai/rookery/plugins/attestors/git"
	"github.com/aflock-ai/rookery/plugins/attestors/gitlab"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

const (
	gitHEAD = "1111111111111111111111111111111111111111"
	jwtSHA  = "0123456789abcdef0123456789abcdef01234567"
)

// Generic SLSA verifiers match the source by resolvedDependencies[].uri
// ("git+https://<host>/<owner>/<repo>[@<ref>]") and a gitCommit digest. The
// source entry is a claim a verifier gates on, so it comes only from the CI
// platform's own signed OIDC token (repository + sha), never from git
// remotes: a checkout's remotes are local, mutable config, and one unused
// remote naming the expected repository would otherwise vouch for any
// checkout. And the token alone is not enough: it names what TRIGGERED the
// job, and a job triggered in acme/app can check out and build anything. The
// entry is recorded only when the checkout the git attestor observed, by its
// verified commit hash, is the token's sha.
func TestSourceDependencyComesOnlyFromAuthenticatedCIClaims(t *testing.T) {
	ghClaims := func() map[string]any {
		return map[string]any{"repository": "acme/app", "ref": "refs/heads/main"}
	}
	want := []*v1.ResourceDescriptor{
		{URI: "git+https://github.com/acme/app@refs/heads/main", Digest: map[string]string{"gitCommit": jwtSHA}},
	}

	t.Run("github claims verified by GitHub's own key set, on that checkout, give the source", func(t *testing.T) {
		require.Equal(t, want, sourceDeps(runWith(t, checkout(jwtSHA, true), fakeGitHub(canonicalGitHubJWKS, ghClaims()))))
	})

	// The finding: a job triggered in acme/app that builds another revision
	// (or another repository) must not produce provenance naming acme/app.
	t.Run("a checkout at another commit than the token's sha gives no source", func(t *testing.T) {
		p := runWith(t, checkout(gitHEAD, true), fakeGitHub(canonicalGitHubJWKS, ghClaims()))
		require.Empty(t, sourceDeps(p))
		require.Equal(t, map[string]any{"uri": "git+https://github.com/acme/app@refs/heads/main", "gitCommit": jwtSHA},
			p.PbProvenance.BuildDefinition.InternalParameters["ciTrigger"], "the unbound claims are kept only as triggering context")
	})

	t.Run("no observed checkout gives no source", func(t *testing.T) {
		require.Empty(t, sourceDeps(runWith(t, fakeGitHub(canonicalGitHubJWKS, ghClaims()))))
	})

	t.Run("a checkout hash the git attestor did not verify gives no source", func(t *testing.T) {
		require.Empty(t, sourceDeps(runWith(t, checkout(jwtSHA, false), fakeGitHub(canonicalGitHubJWKS, ghClaims()))))
	})

	t.Run("the checkout binds whichever order the attestors completed in", func(t *testing.T) {
		require.Equal(t, want, sourceDeps(runWith(t, fakeGitHub(canonicalGitHubJWKS, ghClaims()), checkout(jwtSHA, true))))
	})

	t.Run("git remotes alone produce no source entry", func(t *testing.T) {
		p := runWith(t, fakeGit([]string{"https://github.com/acme/app.git", "git@github.com:acme/app.git"}))
		require.Empty(t, sourceDeps(p))
	})

	// The finding: an unrelated checkout (other/app at gitHEAD) with an unused
	// remote naming acme/app must not produce an acme/app source entry.
	t.Run("an extra remote naming another repository adds nothing", func(t *testing.T) {
		g := fakeGit([]string{"https://github.com/other/app.git", "https://github.com/acme/app.git"})
		gh := fakeGitHub(canonicalGitHubJWKS, map[string]any{"repository": "other/app", "ref": "refs/heads/main"})
		for _, d := range sourceDeps(runWith(t, g, gh)) {
			require.NotContains(t, d.URI, "acme/app", "remote-derived source leaked: %+v", d)
			require.NotEqual(t, gitHEAD, d.Digest["gitCommit"], "remote-derived commit leaked: %+v", d)
		}
	})

	t.Run("github claims verified against another key set give no source", func(t *testing.T) {
		require.Empty(t, sourceDeps(runWith(t, checkout(jwtSHA, true), fakeGitHub("https://attacker.example/jwks", ghClaims()))))
	})

	t.Run("GITHUB_SERVER_URL cannot move the source host", func(t *testing.T) {
		gh := fakeGitHub(canonicalGitHubJWKS, ghClaims())
		gh.data.CIServerUrl = "https://evil.example"
		require.Equal(t, want, sourceDeps(runWith(t, checkout(jwtSHA, true), gh)))
	})

	t.Run("gitlab claims give the source on the token's issuer", func(t *testing.T) {
		gl := fakeGitLab("https://gitlab.example:8443", "https://gitlab.example:8443/oauth/discovery/keys")
		require.Equal(t, []*v1.ResourceDescriptor{
			{URI: "git+https://gitlab.example:8443/acme/app@refs/heads/main", Digest: map[string]string{"gitCommit": jwtSHA}},
		}, sourceDeps(runWith(t, checkout(jwtSHA, true), gl)))
	})

	t.Run("gitlab claims verified against a key set not the issuer's give no source", func(t *testing.T) {
		gl := fakeGitLab("https://gitlab.example", "https://attacker.example/keys")
		require.Empty(t, sourceDeps(runWith(t, checkout(jwtSHA, true), gl)))
	})

	t.Run("no dependency is emitted under name with a sha1 digest", func(t *testing.T) {
		p := runWith(t, fakeGit([]string{"https://github.com/acme/app.git"}), fakeGitHub(canonicalGitHubJWKS, ghClaims()))
		for _, d := range p.PbProvenance.BuildDefinition.ResolvedDependencies {
			_, hasSHA1 := d.Digest["sha1"]
			require.False(t, hasSHA1, "dependency %+v", d)
		}
	})
}

// The source uri keeps the repository's full authority: a non-default port
// or an IPv6 literal names a different endpoint and must survive.
func TestSourceRepoURI(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/acme/app":           "git+https://github.com/acme/app",
		"https://github.com/acme/app.git":       "git+https://github.com/acme/app",
		"https://github.com/acme/app/":          "git+https://github.com/acme/app",
		"https://git.example:8443/acme/app.git": "git+https://git.example:8443/acme/app",
		"https://git.example:443/acme/app":      "git+https://git.example/acme/app",
		"http://git.example:8080/acme/app":      "git+http://git.example:8080/acme/app",
		"http://git.example:80/acme/app":        "git+http://git.example/acme/app",
		"https://[2001:db8::1]/acme/app":        "git+https://[2001:db8::1]/acme/app",
		"https://[2001:db8::1]:8443/acme/app":   "git+https://[2001:db8::1]:8443/acme/app",
		"https://GitHub.com/acme/app":           "git+https://github.com/acme/app",
		"https://user:pass@github.com/acme/app": "",
		"https://github.com/acme/app?x=1":       "",
		"https://github.com/acme/app#frag":      "",
		"ssh://git@github.com/acme/app":         "",
		"git@github.com:acme/app.git":           "",
		"file:///srv/mirror/app":                "",
		"/srv/mirror/app":                       "",
		"https://github.com/":                   "",
		"":                                      "",
	} {
		require.Equal(t, want, sourceRepoURI(in), "sourceRepoURI(%q)", in)
	}
}

// sourceDeps returns the resolvedDependencies that describe the source
// (every entry that carries a uri or a gitCommit digest).
func sourceDeps(p *Provenance) []*v1.ResourceDescriptor {
	var out []*v1.ResourceDescriptor
	for _, d := range p.PbProvenance.BuildDefinition.ResolvedDependencies {
		if _, ok := d.Digest["gitCommit"]; ok || d.URI != "" {
			out = append(out, d)
		}
	}
	return out
}

func runWith(t *testing.T, platform ...attestation.Attestor) *Provenance {
	t.Helper()
	p := New()
	attestors := append([]attestation.Attestor{&fakeCommandRun{}}, platform...)
	attestors = append(attestors, p)
	ctx, err := attestation.NewContext("build", attestors, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return p
}

func fakeGit(remotes []string) *fakeGitAttestor {
	return &fakeGitAttestor{data: &git.Attestor{
		CommitHash:   gitHEAD,
		CommitDigest: cryptoutil.DigestSet{{Hash: crypto.SHA1}: gitHEAD},
		Remotes:      remotes,
	}}
}

// checkout is the git attestor's view of the working tree: HEAD at sha, and
// whether it re-hashed the commit object to get it (CommitHashVerified).
func checkout(sha string, verified bool) *fakeGitAttestor {
	return &fakeGitAttestor{data: &git.Attestor{
		CommitHash:         sha,
		CommitHashVerified: verified,
		CommitDigest:       cryptoutil.DigestSet{{Hash: crypto.SHA1}: sha},
	}}
}

type fakeGitAttestor struct{ data *git.Attestor }

func (f *fakeGitAttestor) Name() string                                   { return git.Name }
func (f *fakeGitAttestor) Type() string                                   { return git.Type }
func (f *fakeGitAttestor) RunType() attestation.RunType                   { return git.RunType }
func (f *fakeGitAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fakeGitAttestor) Schema() *jsonschema.Schema                     { return nil }
func (f *fakeGitAttestor) Data() *git.Attestor                            { return f.data }
func (f *fakeGitAttestor) Subjects() map[string]cryptoutil.DigestSet      { return nil }
func (f *fakeGitAttestor) BackRefs() map[string]cryptoutil.DigestSet      { return nil }

// fakeGitLab is a GitLab job whose ID token names issuer iss and was
// verified against the key set at jwksURL.
func fakeGitLab(iss, jwksURL string) *fakeGitLabAttestor {
	return &fakeGitLabAttestor{data: &gitlab.Attestor{
		PipelineUrl: iss + "/acme/app/-/pipelines/1",
		JWT: &jwt.Attestor{
			Claims: map[string]any{
				"iss": iss, "project_path": "acme/app", "sha": jwtSHA, "ref_path": "refs/heads/main",
			},
			VerifiedBy: jwt.VerificationInfo{JWKSUrl: jwksURL},
		},
	}}
}

type fakeGitLabAttestor struct{ data *gitlab.Attestor }

func (f *fakeGitLabAttestor) Name() string                                   { return gitlab.Name }
func (f *fakeGitLabAttestor) Type() string                                   { return gitlab.Type }
func (f *fakeGitLabAttestor) RunType() attestation.RunType                   { return gitlab.RunType }
func (f *fakeGitLabAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fakeGitLabAttestor) Schema() *jsonschema.Schema                     { return nil }
func (f *fakeGitLabAttestor) Data() *gitlab.Attestor                         { return f.data }
func (f *fakeGitLabAttestor) Subjects() map[string]cryptoutil.DigestSet      { return nil }
func (f *fakeGitLabAttestor) BackRefs() map[string]cryptoutil.DigestSet      { return nil }
