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

package commandrun

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"slices"
	"strings"
)

// ciOIDCCredentialEnvVars are the variables that let a process obtain a CI
// workload OIDC token: the credential cilock's keyless Fulcio signer exchanges
// for its signing certificate. A wrapped build step that inherits one can mint
// a certificate for the same workflow identity and sign forged provenance
// (#9822). The step never needs a private key to do that; the token request
// credential is enough.
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

// CIOIDCCredentialEnvVars returns the variable names withheld from the wrapped
// command unless WithInheritCIOIDCCredentials(true) is set.
func CIOIDCCredentialEnvVars() []string {
	return slices.Clone(ciOIDCCredentialEnvVars)
}

// Values of V02ChildEnv.CIOIDCCredentials.
const (
	// ChildEnvCIOIDCScrubbed: the wrapped command ran without any CI OIDC
	// credential variable (the default).
	ChildEnvCIOIDCScrubbed = "scrubbed"
	// ChildEnvCIOIDCInherited: the operator opted out and the wrapped command
	// inherited the CI OIDC credential variables. A verifier must treat the
	// step as able to mint the signer's workflow identity.
	ChildEnvCIOIDCInherited = "inherited"
)

// V02ChildEnv records, inside the signed predicate's _meta, what was done to
// the wrapped command's environment. Absent means the attestation predates the
// scrub, and the step inherited everything.
type V02ChildEnv struct {
	// CIOIDCCredentials is ChildEnvCIOIDCScrubbed or ChildEnvCIOIDCInherited.
	CIOIDCCredentials string `json:"ciOidcCredentials"`
	// Scrubbed lists the variable NAMES (never values) that were set in
	// cilock's environment and withheld from the child, sorted.
	Scrubbed []string `json:"scrubbed,omitempty"`
}

// WithInheritCIOIDCCredentials lets the wrapped command inherit the CI OIDC
// credential variables (see CIOIDCCredentialEnvVars). Off by default. Only for
// a step that must obtain its own OIDC token, such as cosign keyless signing
// or cloud OIDC federation. The choice is recorded in the signed predicate as
// _meta.childEnv.ciOidcCredentials = "inherited", so a policy can refuse it.
func WithInheritCIOIDCCredentials(inherit bool) Option {
	return func(cr *CommandRun) {
		cr.inheritCIOIDC = inherit
	}
}

// ChildEnv returns what was done to the wrapped command's environment, or nil
// when the command has not run (or the attestation predates the field).
func (rc *CommandRun) ChildEnv() *V02ChildEnv {
	return rc.childEnv
}

// childEnviron returns the wrapped command's environment, base minus the CI
// OIDC credentials unless the operator opted out, and records the outcome on
// rc. It never modifies cilock's own environment: the signer reads its token
// from there.
func (rc *CommandRun) childEnviron(base []string) []string {
	env := base
	if rc.inheritCIOIDC {
		rc.childEnv = &V02ChildEnv{CIOIDCCredentials: ChildEnvCIOIDCInherited}
		return env
	}
	env, removed := scrubCIOIDCCredentials(env)
	slices.Sort(removed)
	rc.childEnv = &V02ChildEnv{CIOIDCCredentials: ChildEnvCIOIDCScrubbed, Scrubbed: removed}
	return env
}

// scrubCIOIDCCredentials returns env without the CI OIDC credential entries,
// keeping order, and the names it removed. An entry is a credential when its
// NAME is in ciOIDCCredentialEnvVars, or when its VALUE is a JWT issued by a
// CI OIDC issuer (see isCIIssuedJWT). The second rule is what catches GitLab
// `id_tokens`, which a pipeline may export under any name.
func scrubCIOIDCCredentials(env []string) (kept, removed []string) {
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
// child's env slice, so this stays a pure function of what is being scrubbed.
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
// A step that legitimately needs one opts out with
// WithInheritCIOIDCCredentials, and the opt-out is signed.
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
