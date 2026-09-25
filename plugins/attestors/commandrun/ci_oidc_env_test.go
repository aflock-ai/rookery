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

package commandrun

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// ciOIDCTestEnv sets every CI OIDC credential variable the wrapped step must
// not see, plus one ordinary variable that must still pass through.
func ciOIDCTestEnv(t *testing.T) {
	t.Helper()
	for _, name := range CIOIDCCredentialEnvVars() {
		t.Setenv(name, "value-of-"+strings.ToLower(name)+"-0123456789")
	}
	t.Setenv("CILOCK_OIDC_SCRUB_CONTROL", "still-here")
}

// childEnvNames runs `env` under the attestor and returns the variable NAMES
// the child saw. Names only: stdout is redacted for sensitive values, and the
// question here is presence, not value.
func childEnvNames(t *testing.T, opts ...Option) (*CommandRun, map[string]bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX env(1)")
	}
	actx, err := attestation.NewContext("ci-oidc-scrub", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(append([]Option{WithCommand([]string{"env"}), WithSilent(true)}, opts...)...)
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(rc.Stdout, "\n") {
		if name, _, ok := strings.Cut(line, "="); ok {
			seen[name] = true
		}
	}
	return rc, seen
}

// The token-request variables are what lets a process mint a Fulcio-bound
// OIDC token for the job's workflow identity, the same identity cilock signs
// with. A wrapped build step that holds them can sign forged provenance
// (#9822), so the child must not inherit them by default.
func TestWrappedStepDoesNotInheritCIOIDCCredentialsByDefault(t *testing.T) {
	ciOIDCTestEnv(t)
	rc, seen := childEnvNames(t)

	for _, name := range CIOIDCCredentialEnvVars() {
		if seen[name] {
			t.Errorf("wrapped step inherited %s; it can mint the signer's OIDC identity", name)
		}
	}
	if !seen["CILOCK_OIDC_SCRUB_CONTROL"] {
		t.Fatal("control variable missing from the child: the scrub removed more than the CI OIDC credentials")
	}

	got := rc.ChildEnv()
	if got == nil || got.CIOIDCCredentials != ChildEnvCIOIDCScrubbed {
		t.Fatalf("ChildEnv() = %+v, want ciOidcCredentials=%q", got, ChildEnvCIOIDCScrubbed)
	}
	want := slices.Clone(CIOIDCCredentialEnvVars())
	slices.Sort(want)
	if !slices.Equal(got.Scrubbed, want) {
		t.Errorf("ChildEnv().Scrubbed = %v, want every set credential name %v", got.Scrubbed, want)
	}
}

// Signing reads the token from cilock's OWN environment (the Fulcio signer
// and the github attestor call os.Getenv in the parent, and cilock builds its
// signers before it starts the wrapped command). The scrub must touch only the
// child's environment, never the parent's.
func TestScrubLeavesTheSignersEnvironmentIntact(t *testing.T) {
	ciOIDCTestEnv(t)
	childEnvNames(t)

	for _, name := range CIOIDCCredentialEnvVars() {
		if os.Getenv(name) == "" {
			t.Errorf("parent lost %s after the wrapped step ran; the signer can no longer fetch its token", name)
		}
	}
}

// A step that legitimately needs the token (cosign keyless, npm provenance,
// cloud OIDC federation) opts out. The opt-out must be visible to a verifier,
// so it is recorded in the signed predicate.
func TestInheritCIOIDCCredentialsOptOutIsRecorded(t *testing.T) {
	ciOIDCTestEnv(t)
	rc, seen := childEnvNames(t, WithInheritCIOIDCCredentials(true))

	for _, name := range CIOIDCCredentialEnvVars() {
		if !seen[name] {
			t.Errorf("opt-out set but the child did not see %s", name)
		}
	}
	got := rc.ChildEnv()
	if got == nil || got.CIOIDCCredentials != ChildEnvCIOIDCInherited {
		t.Fatalf("ChildEnv() = %+v, want ciOidcCredentials=%q", got, ChildEnvCIOIDCInherited)
	}
	if len(got.Scrubbed) != 0 {
		t.Errorf("opt-out run reports scrubbed names %v", got.Scrubbed)
	}

	body, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw struct {
		Meta struct {
			ChildEnv *V02ChildEnv `json:"childEnv"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if raw.Meta.ChildEnv == nil || raw.Meta.ChildEnv.CIOIDCCredentials != ChildEnvCIOIDCInherited {
		t.Fatalf("signed predicate _meta.childEnv = %+v, want ciOidcCredentials=%q", raw.Meta.ChildEnv, ChildEnvCIOIDCInherited)
	}

	var back CommandRun
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b := back.ChildEnv(); b == nil || b.CIOIDCCredentials != ChildEnvCIOIDCInherited {
		t.Fatalf("round-trip lost the opt-out: %+v", b)
	}
}

// With no CI credential in the environment there is nothing to scrub, but the
// predicate still says the scrub was in force, so "absent" in a stored
// attestation keeps meaning "produced before this field existed".
func TestScrubIsRecordedEvenWhenNothingWasSet(t *testing.T) {
	for _, name := range CIOIDCCredentialEnvVars() {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	rc, _ := childEnvNames(t)
	got := rc.ChildEnv()
	if got == nil || got.CIOIDCCredentials != ChildEnvCIOIDCScrubbed {
		t.Fatalf("ChildEnv() = %+v, want ciOidcCredentials=%q", got, ChildEnvCIOIDCScrubbed)
	}
	if len(got.Scrubbed) != 0 {
		t.Errorf("nothing was set, but Scrubbed = %v", got.Scrubbed)
	}
}

// testJWT builds an UNSIGNED JWT carrying claims. Only the claims are ever
// parsed; nothing here verifies a signature.
func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
}

// GitLab `id_tokens` are exported under whatever name the pipeline picks, so a
// name list can never be complete. A value that is a JWT issued by a CI OIDC
// issuer is withheld whatever its name.
func TestScrubCatchesCINamedAnythingByIssuer(t *testing.T) {
	gitlab := testJWT(t, map[string]any{"iss": "https://gitlab.com", "aud": "sigstore", "sub": "project_path:g/p:ref_type:branch:ref:main"})
	github := testJWT(t, map[string]any{"iss": "https://token.actions.githubusercontent.com", "aud": "sigstore"})
	ghes := testJWT(t, map[string]any{"iss": "https://token.actions.githubusercontent.com/acme", "aud": "sigstore"})
	selfManaged := testJWT(t, map[string]any{"iss": "https://gitlab.example.com", "aud": "vault"})
	selfManagedSlash := testJWT(t, map[string]any{"iss": "https://gitlab.example.com/", "aud": "vault"})
	other := testJWT(t, map[string]any{"iss": "https://accounts.google.com", "aud": "x"})
	lookalike := testJWT(t, map[string]any{"iss": "https://gitlab.com.evil.example", "aud": "x"})
	ghLookalike := testJWT(t, map[string]any{"iss": "https://token.actions.githubusercontent.com.evil.example"})

	in := []string{
		"CI_SERVER_URL=https://gitlab.example.com",
		"MY_DEPLOY_ID_TOKEN=" + gitlab,
		"VAULT_ID_TOKEN=" + selfManaged,
		"OTHER_VAULT_TOKEN=" + selfManagedSlash,
		"GH_TOKEN_COPY=" + github,
		"GHES_TOKEN=" + ghes,
		"GOOGLE_ID_TOKEN=" + other,
		"LOOKALIKE=" + lookalike,
		"GH_LOOKALIKE=" + ghLookalike,
		"NOT_A_JWT=eyJ.not-base64!.x",
		"EMPTY_CLAIMS=" + testJWT(t, map[string]any{}),
		"PLAIN=hello",
	}
	kept, removed := scrubCIOIDCCredentials(in)

	wantRemoved := []string{"MY_DEPLOY_ID_TOKEN", "VAULT_ID_TOKEN", "OTHER_VAULT_TOKEN", "GH_TOKEN_COPY", "GHES_TOKEN"}
	if !slices.Equal(removed, wantRemoved) {
		t.Errorf("removed = %v, want %v", removed, wantRemoved)
	}
	for _, kv := range kept {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(wantRemoved, name) {
			t.Errorf("%s survived the scrub", name)
		}
	}
	for _, name := range []string{"CI_SERVER_URL", "GOOGLE_ID_TOKEN", "LOOKALIKE", "GH_LOOKALIKE", "NOT_A_JWT", "EMPTY_CLAIMS", "PLAIN"} {
		if !slices.ContainsFunc(kept, func(kv string) bool { return strings.HasPrefix(kv, name+"=") }) {
			t.Errorf("%s was removed; only CI-issued JWTs may be", name)
		}
	}
}

// Without CI_SERVER_URL there is no self-managed issuer to match, so a
// gitlab.example.com token is not a known CI token.
func TestScrubSelfManagedIssuerNeedsCIServerURL(t *testing.T) {
	selfManaged := testJWT(t, map[string]any{"iss": "https://gitlab.example.com"})
	_, removed := scrubCIOIDCCredentials([]string{"VAULT_ID_TOKEN=" + selfManaged})
	if len(removed) != 0 {
		t.Errorf("removed = %v with no CI_SERVER_URL configured", removed)
	}
}

// End to end: the custom-named token never reaches the child, and its NAME is
// recorded; with the opt-out it does reach the child.
func TestWrappedStepDoesNotSeeCustomNamedGitLabIDToken(t *testing.T) {
	ciOIDCTestEnv(t)
	t.Setenv("MY_SIGSTORE_TOKEN", testJWT(t, map[string]any{"iss": "https://gitlab.com", "aud": "sigstore"}))

	rc, seen := childEnvNames(t)
	if seen["MY_SIGSTORE_TOKEN"] {
		t.Fatal("custom-named GitLab id_token reached the wrapped step")
	}
	if !slices.Contains(rc.ChildEnv().Scrubbed, "MY_SIGSTORE_TOKEN") {
		t.Errorf("Scrubbed = %v, want it to name MY_SIGSTORE_TOKEN", rc.ChildEnv().Scrubbed)
	}

	_, seen = childEnvNames(t, WithInheritCIOIDCCredentials(true))
	if !seen["MY_SIGSTORE_TOKEN"] {
		t.Error("opt-out set but the custom-named token was withheld")
	}
}
