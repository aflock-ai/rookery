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
	"net/url"
	"strings"

	v1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/plugins/attestors/git"
	"github.com/aflock-ai/rookery/plugins/attestors/github"
	"github.com/aflock-ai/rookery/plugins/attestors/gitlab"
)

// gitCommitDigest is the in-toto digest algorithm name for a git commit id.
const gitCommitDigest = "gitCommit"

// schemePorts are the ports an http(s) authority may omit (RFC 9110 §4.2).
// They are protocol facts, not tunable defaults.
var schemePorts = map[string]string{"https": "443", "http": "80"}

// sourceRepoURI turns an http(s) repository URL into the SLSA source form,
// "git+<scheme>://<authority>/<path>" without a trailing ".git". The
// authority keeps everything that names the endpoint: a non-default port and
// IPv6 brackets survive, only a default port is dropped and the host is
// lower-cased. It returns "" for anything else (another scheme, userinfo, a
// query or fragment, no path), so an input it cannot represent faithfully
// yields no source entry rather than a different one.
func sourceRepoURI(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return ""
	}
	schemePort, ok := schemePorts[u.Scheme]
	if !ok {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && port != schemePort {
		host += ":" + port
	}
	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	if host == "" || path == "" {
		return ""
	}
	return "git+" + u.Scheme + "://" + host + "/" + path
}

// sourceClaim is a source the CI platform's signed token names: the
// repository uri, the ref when the token says, and the commit. It names what
// triggered the job, not what the job built, so it becomes a source entry only
// once bindSources ties it to the observed checkout.
type sourceClaim struct {
	uri, ref, sha string
}

// githubSourceClaim reads the source from a GitHub Actions OIDC token, but
// only when GitHub's own key set verified it (the github attestor's JWKS URL
// can be redirected by an environment variable a build step sets). The host
// is always github.com, the only issuer that key set signs for; the
// GITHUB_SERVER_URL environment value is not consulted.
func githubSourceClaim(gh *github.Attestor) (sourceClaim, bool) {
	if gh == nil || gh.JWT == nil || gh.JWT.VerifiedBy.JWKSUrl != githubActionsJWKSURL {
		log.Warn("GitHub OIDC token not verified against GitHub's key set; no source dependency recorded")
		return sourceClaim{}, false
	}
	sha, _ := gh.JWT.Claims["sha"].(string)
	repo, _ := gh.JWT.Claims["repository"].(string)
	ref, _ := gh.JWT.Claims["ref"].(string)
	if sha == "" || repo == "" {
		log.Warn("GitHub OIDC token lacks a sha or repository claim; no source dependency recorded")
		return sourceClaim{}, false
	}
	return sourceClaim{uri: sourceRepoURI("https://github.com/" + repo), ref: ref, sha: sha}, true
}

// gitlabSourceClaim reads the source from a GitLab CI ID token, on the host
// the token's own signed `iss` claim names, and only when the token verified
// against that issuer's key set. The CI_SERVER_URL environment value is not
// consulted, and a key set elsewhere (WITNESS_GITLAB_JWKS_URL) gives nothing.
func gitlabSourceClaim(gl *gitlab.Attestor) (sourceClaim, bool) {
	if gl == nil || gl.JWT == nil {
		return sourceClaim{}, false
	}
	iss, _ := gl.JWT.Claims["iss"].(string)
	iss = strings.TrimSuffix(iss, "/")
	if iss == "" || gl.JWT.VerifiedBy.JWKSUrl != iss+"/oauth/discovery/keys" {
		log.Warn("GitLab ID token not verified against its issuer's key set; no source dependency recorded")
		return sourceClaim{}, false
	}
	sha, _ := gl.JWT.Claims["sha"].(string)
	project, _ := gl.JWT.Claims["project_path"].(string)
	if sha == "" || project == "" {
		log.Warn("GitLab ID token lacks a sha or project_path claim; no source dependency recorded")
		return sourceClaim{}, false
	}
	return sourceClaim{uri: sourceRepoURI(iss + "/" + project), ref: gitlabRef(gl.JWT.Claims), sha: sha}, true
}

// observedCheckout is the commit the git attestor saw checked out, or "" when
// it did not re-hash the commit object itself (CommitHashVerified): a hash the
// repository's storage merely claims binds nothing.
func observedCheckout(g *git.Attestor) string {
	if g == nil || !g.CommitHashVerified {
		return ""
	}
	return strings.ToLower(g.CommitHash)
}

// bindSources records each claim as a source entry only when the checkout the
// build ran on is the claimed commit. A commit id names its tree and history,
// so an equal id means the job built exactly what the token says triggered it.
// A claim that does not bind (another revision or repository checked out, or
// no verified checkout at all) is kept only as triggering context in
// internalParameters["ciTrigger"], never as a source a verifier gates on.
func bindSources(sources *sourceDependencies, claims []sourceClaim, observed string, internal map[string]interface{}) {
	for _, c := range claims {
		if c.uri == "" {
			continue
		}
		if observed != "" && strings.EqualFold(c.sha, observed) {
			sources.add(c.uri, c.ref, c.sha)
			continue
		}
		log.Warn("the CI token's commit is not the commit the git attestor observed checked out; recorded as the trigger, not as a source dependency")
		uri := c.uri
		if c.ref != "" {
			uri += "@" + c.ref
		}
		internal["ciTrigger"] = map[string]any{"uri": uri, gitCommitDigest: c.sha}
	}
}

// gitlabRef returns the full git ref from a GitLab CI ID token: ref_path
// when present, otherwise ref qualified by ref_type. It returns "" when the
// token does not say.
func gitlabRef(claims map[string]interface{}) string {
	if refPath, _ := claims["ref_path"].(string); refPath != "" {
		return refPath
	}
	ref, _ := claims["ref"].(string)
	switch refType, _ := claims["ref_type"].(string); {
	case ref == "":
		return ""
	case refType == "branch":
		return "refs/heads/" + ref
	case refType == "tag":
		return "refs/tags/" + ref
	}
	return ""
}

// sourceDependencies collects the source descriptors for a run and returns
// them deduplicated: one entry per (repository, commit). An entry that names
// the ref (from the CI platform's verified claims) replaces a ref-less entry
// for the same repository and commit.
type sourceDependencies struct {
	order   []string
	entries map[string]*v1.ResourceDescriptor
}

func (s *sourceDependencies) add(repoURI, ref, commit string) {
	if repoURI == "" || commit == "" {
		return
	}
	if s.entries == nil {
		s.entries = map[string]*v1.ResourceDescriptor{}
	}
	key := repoURI + "\x00" + commit
	uri := repoURI
	if ref != "" {
		uri += "@" + ref
	}
	if existing, ok := s.entries[key]; ok {
		if ref != "" && !strings.Contains(strings.TrimPrefix(existing.URI, repoURI), "@") {
			existing.URI = uri
		}
		return
	}
	s.order = append(s.order, key)
	s.entries[key] = &v1.ResourceDescriptor{URI: uri, Digest: map[string]string{gitCommitDigest: commit}}
}

func (s *sourceDependencies) list() []*v1.ResourceDescriptor {
	out := make([]*v1.ResourceDescriptor, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, s.entries[key])
	}
	return out
}
