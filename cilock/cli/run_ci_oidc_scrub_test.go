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

// jade:ring local

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// #9822: the step `cilock run` wraps must not inherit the job's OIDC token
// request credential, or it can mint the signer's workflow identity and sign
// forged provenance. --inherit-ci-oidc-credentials is the explicit opt-out for
// steps that need their own token, and the signed record says which it was.

// childEnvRecord returns the signed command-run `_meta.childEnv` block.
func (c signedCollection) childEnvRecord(t *testing.T) map[string]any {
	t.Helper()
	for _, a := range c.Predicate.Attestations {
		if a.Type != commandRunV02 {
			continue
		}
		var cr struct {
			Meta struct {
				ChildEnv map[string]any `json:"childEnv"`
			} `json:"_meta"`
		}
		require.NoError(t, json.Unmarshal(a.Attestation, &cr))
		return cr.Meta.ChildEnv
	}
	t.Fatalf("no command-run record among %v", c.attestationTypes())
	return nil
}

func TestRunWithholdsCIOIDCCredentialsFromTheWrappedStep(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/?x=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token-0123456789")
	t.Setenv("CI_JOB_JWT_V2", "gitlab-jwt-0123456789")

	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	work := filepath.Join(dir, "work")
	require.NoError(t, os.MkdirAll(work, 0o750))

	// Exit 0 only when none of the credentials is visible to the step.
	unseen := `[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL+x}${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}${CI_JOB_JWT_V2+x}" ]`
	out := filepath.Join(dir, "scrubbed.json")
	require.NoError(t, runOffline(t, keyPath, work, out, nil, "sh", "-c", unseen),
		"the wrapped step saw a CI OIDC credential variable")
	rec := readSignedCollection(t, out).childEnvRecord(t)
	require.Equal(t, "scrubbed", rec["ciOidcCredentials"], "signed record: %v", rec)
	require.ElementsMatch(t, []any{"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "CI_JOB_JWT_V2"}, rec["scrubbed"])

	require.Equal(t, "request-token-0123456789", os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
		"cilock's own environment must keep the token: the Fulcio signer reads it from there")
}

func TestRunInheritCIOIDCCredentialsOptOutIsSigned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/?x=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token-0123456789")

	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	work := filepath.Join(dir, "work")
	require.NoError(t, os.MkdirAll(work, 0o750))

	seen := `[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL+x}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}" ]`
	out := filepath.Join(dir, "inherited.json")
	require.NoError(t, runOffline(t, keyPath, work, out, []string{"--inherit-ci-oidc-credentials"}, "sh", "-c", seen),
		"with --inherit-ci-oidc-credentials the step must see the token request variables")
	rec := readSignedCollection(t, out).childEnvRecord(t)
	require.Equal(t, "inherited", rec["ciOidcCredentials"], "the opt-out must be in the signed record so a verifier can refuse it: %v", rec)
}
