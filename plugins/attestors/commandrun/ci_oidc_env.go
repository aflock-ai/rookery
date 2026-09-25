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

import "github.com/aflock-ai/rookery/attestation"

// The CI OIDC credential scrub lives in the attestation package so that
// commandrun and cilock-action's action runner apply one rule
// (attestation/ci_oidc_credentials.go). These names keep commandrun's API.

// CIOIDCCredentialEnvVars returns the variable names withheld from the wrapped
// command unless WithInheritCIOIDCCredentials(true) is set.
func CIOIDCCredentialEnvVars() []string { return attestation.CIOIDCCredentialEnvVars() }

// Values of V02ChildEnv.CIOIDCCredentials.
const (
	ChildEnvCIOIDCScrubbed  = attestation.ChildEnvCIOIDCScrubbed
	ChildEnvCIOIDCInherited = attestation.ChildEnvCIOIDCInherited
)

// V02ChildEnv records, inside the signed predicate's _meta, what was done to
// the wrapped command's environment. Absent means the attestation predates the
// scrub, and the step inherited everything.
type V02ChildEnv = attestation.ChildEnvRecord

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
	env, rec := attestation.ChildEnviron(base, rc.inheritCIOIDC)
	rc.childEnv = rec
	return env
}

// scrubCIOIDCCredentials is attestation.ScrubCIOIDCCredentials.
func scrubCIOIDCCredentials(env []string) (kept, removed []string) {
	return attestation.ScrubCIOIDCCredentials(env)
}
