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

package attestation

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"slices"
	"strings"
)

// ciOIDCCredentialEnvVars are the variables that let a process obtain a CI
// workload OIDC token: the credential cilock's keyless Fulcio signer exchanges
// for its signing certificate. A wrapped step (a command under commandrun, or
// an action under cilock-action) that inherits one can mint a certificate for
// the same workflow identity and sign forged provenance (#9822). The step
// never needs a private key to do that; the token request credential is
// enough.
//
//   - ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN: GitHub
//     Actions. Read by the Fulcio signer (plugins/signers/fulcio), the github
//     attestor and cilock's workflow-identity login.
//   - CI_JOB_JWT / CI_JOB_JWT_V2: GitLab's pre-17.0 job JWTs, the assertion
//     itself. Read by the gitlab attestor and the instruction-file signer.
//   - SIGSTORE_ID_TOKEN: the name sigstore clients (cosign) read an ambient
//     OIDC token from, and the name GitLab's `id_tokens` docs use for it.
//
// GitLab `id_tokens` may be exported under any name the pipeline chooses, so
// no name list can be complete. Those are caught by VALUE instead: any
// variable holding a JWT whose `iss` is GitHub Actions, gitlab.com, or the
// self-managed GitLab named by CI_SERVER_URL is withheld too (isCIIssuedJWT).
// What is still not caught: a token under a custom name from an issuer this
// code does not know, or one stored in a file rather than the environment.
var ciOIDCCredentialEnvVars = []string{
	"ACTIONS_ID_TOKEN_REQUEST_URL",
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"CI_JOB_JWT",
	"CI_JOB_JWT_V2",
	"SIGSTORE_ID_TOKEN",
}

// CIOIDCCredentialEnvVars returns the variable names always withheld from a
// wrapped step unless the operator opts out.
func CIOIDCCredentialEnvVars() []string {
	return slices.Clone(ciOIDCCredentialEnvVars)
}

// Values of ChildEnvRecord.CIOIDCCredentials.
const (
	// ChildEnvCIOIDCScrubbed: the wrapped step ran without any CI OIDC
	// credential (the default).
	ChildEnvCIOIDCScrubbed = "scrubbed"
	// ChildEnvCIOIDCInherited: the operator opted out and the wrapped step
	// inherited the CI OIDC credentials. A verifier must treat the step as
	// able to mint the signer's workflow identity.
	ChildEnvCIOIDCInherited = "inherited"
)

// ChildEnvRecord is the signed record of what was done to a wrapped step's
// environment. command-run carries it at _meta.childEnv and github-action at
// childEnv. Absent means the attestation predates the scrub, and the step
// inherited everything.
type ChildEnvRecord struct {
	// CIOIDCCredentials is ChildEnvCIOIDCScrubbed or ChildEnvCIOIDCInherited.
	CIOIDCCredentials string `json:"ciOidcCredentials"`
	// Scrubbed lists the variable NAMES (never values) that were withheld from
	// the step, sorted.
	Scrubbed []string `json:"scrubbed,omitempty"`
}

// ChildEnviron returns the environment for a wrapped step built from base:
// base unchanged when inherit is set, otherwise base without its CI OIDC
// credentials. The record says which, and names what was withheld. base is
// not modified.
func ChildEnviron(base []string, inherit bool) ([]string, *ChildEnvRecord) {
	if inherit {
		return base, &ChildEnvRecord{CIOIDCCredentials: ChildEnvCIOIDCInherited}
	}
	kept, removed := ScrubCIOIDCCredentials(base)
	slices.Sort(removed)
	return kept, &ChildEnvRecord{CIOIDCCredentials: ChildEnvCIOIDCScrubbed, Scrubbed: removed}
}

// Merge folds another record for the same step into r: the scrubbed names are
// unioned, and "inherited" wins, because one inheriting sub-step is enough for
// the step to hold the credential. A nil r is returned as a copy of other.
func (r *ChildEnvRecord) Merge(other *ChildEnvRecord) *ChildEnvRecord {
	if other == nil {
		return r
	}
	if r == nil {
		cp := *other
		cp.Scrubbed = slices.Clone(other.Scrubbed)
		return &cp
	}
	if other.CIOIDCCredentials == ChildEnvCIOIDCInherited {
		r.CIOIDCCredentials = ChildEnvCIOIDCInherited
	}
	for _, n := range other.Scrubbed {
		if !slices.Contains(r.Scrubbed, n) {
			r.Scrubbed = append(r.Scrubbed, n)
		}
	}
	slices.Sort(r.Scrubbed)
	return r
}

// ScrubCIOIDCCredentials returns env without the CI OIDC credential entries,
// keeping order, and the names it removed. An entry is a credential when its
// NAME is in CIOIDCCredentialEnvVars, or when its VALUE is a JWT issued by a
// CI OIDC issuer (see isCIIssuedJWT). The second rule is what catches GitLab
// `id_tokens`, which a pipeline may export under any name.
func ScrubCIOIDCCredentials(env []string) (kept, removed []string) {
	issuers := ciIssuers(env)
	kept = make([]string, 0, len(env))
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if slices.ContainsFunc(ciOIDCCredentialEnvVars, func(n string) bool { return envNameEqual(n, name) }) || isCIIssuedJWT(value, issuers) {
			if !slices.ContainsFunc(removed, func(n string) bool { return envNameEqual(n, name) }) {
				removed = append(removed, name)
			}
			continue
		}
		kept = append(kept, kv)
	}
	return kept, removed
}

// envNamesFoldCase is true where the OS resolves environment names without
// regard to case (Windows). There "actions_id_token_request_token" IS the
// token request credential, and a step reads it back through the uppercase
// name, so the scrub must fold case too. A var only so tests can exercise both
// behaviours on one host.
var envNamesFoldCase = runtime.GOOS == "windows"

// envNameEqual compares two environment variable names the way the OS does.
func envNameEqual(a, b string) bool {
	if envNamesFoldCase {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// githubActionsIssuer is GitHub's OIDC issuer. An enterprise with a customized
// issuer gets "<githubActionsIssuer>/<enterprise-slug>".
const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// ciIssuerSet is the set of CI OIDC issuers a value is matched against.
type ciIssuerSet struct {
	exact []string // compared with trailing "/" trimmed
}

// ciIssuers returns the known CI OIDC issuers: GitHub Actions, gitlab.com, and
// the self-managed GitLab named by CI_SERVER_URL in env (the issuer of a
// self-managed instance's id_tokens is its server URL; the gitlab attestor
// derives its JWKS URL from the same variable). CI_SERVER_URL is read from the
// env slice being scrubbed, so this stays a pure function of its input.
func ciIssuers(env []string) ciIssuerSet {
	s := ciIssuerSet{exact: []string{githubActionsIssuer, "https://gitlab.com"}}
	for _, kv := range env {
		if name, v, ok := strings.Cut(kv, "="); ok && envNameEqual(name, "CI_SERVER_URL") {
			if v = strings.TrimRight(strings.TrimSpace(v), "/"); v != "" {
				s.exact = append(s.exact, v)
			}
		}
	}
	return s
}

func (s ciIssuerSet) matches(iss string) bool {
	iss = strings.TrimRight(iss, "/")
	if iss == "" {
		return false
	}
	if slices.Contains(s.exact, iss) {
		return true
	}
	// GitHub customized enterprise issuer: one extra path segment.
	return strings.HasPrefix(iss, githubActionsIssuer+"/")
}

// isCIIssuedJWT reports whether value is a compact JWS whose `iss` claim is a
// known CI OIDC issuer. The signature is NOT checked: this decides what to
// withhold, never what to trust, and a forged token that names a CI issuer is
// still something the step has no business holding.
//
// False positives: a value is only withheld when it is a JWT naming a CI
// issuer, which is a CI OIDC token (or an exact copy of one) by construction.
// A step that legitimately needs one opts out, and the opt-out is signed.
func isCIIssuedJWT(value string, issuers ciIssuerSet) bool {
	// Cheap pre-filter: a JSON header always base64url-encodes to "eyJ".
	if !strings.HasPrefix(value, "eyJ") || strings.Count(value, ".") != 2 {
		return false
	}
	_, rest, _ := strings.Cut(value, ".")
	payload, _, _ := strings.Cut(rest, ".")
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload, "="))
	if err != nil {
		return false
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return false
	}
	return issuers.matches(claims.Iss)
}
