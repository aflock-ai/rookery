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

package gitlab

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// fakeGitLab is a self-managed GitLab's JWKS endpoint and the key that signs
// its job ID tokens, served where the attestor looks for it:
// <CI_SERVER_URL>/oauth/discovery/keys.
type fakeGitLab struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeGitLab(t *testing.T) *fakeGitLab {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGitLab{key: key}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/discovery/keys" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(g.srv.Close)
	return g
}

// token mints a GitLab 19 shaped job ID token (claims as captured from GitLab
// CE 19.4.1, pipeline 6 job 10), signed by key.
func (g *fakeGitLab) token(t *testing.T, key *rsa.PrivateKey, aud any, jobID string) string {
	t.Helper()
	return g.tokenWithIssuer(t, key, aud, jobID, g.srv.URL)
}

func (g *fakeGitLab) tokenWithIssuer(t *testing.T, key *rsa.PrivateKey, aud any, jobID, issuer string) string {
	t.Helper()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	claims := map[string]any{"iss": issuer, "aud": aud, "sub": "project_path:example-org/hello-api:ref_type:branch:ref:main",
		"job_id": jobID, "pipeline_id": "6", "project_id": "1", "project_path": "example-org/hello-api",
		"ref": "main", "ref_type": "branch", "ref_protected": "true", "iat": 1790659869, "exp": 1790663469}
	signing := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (g *fakeGitLab) job(t *testing.T) {
	t.Helper()
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", g.srv.URL)
	t.Setenv("CI_JOB_ID", "10")
	t.Setenv("WITNESS_GITLAB_JWKS_URL", "")
	for _, v := range []string{"CI_JOB_JWT", "CI_JOB_JWT_V2", "SIGSTORE_ID_TOKEN", "CILOCK_LOGIN_ID_TOKEN", "MY_TOKEN"} {
		t.Setenv(v, "")
	}
}

func attest(t *testing.T, a *Attestor) error {
	t.Helper()
	ctx, err := attestation.NewContext("gitlab-test", []attestation.Attestor{a}, attestation.WithContext(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	return a.Attest(ctx)
}

// TestAttestRecordsTheJobsIDToken: on GitLab 17+ (no CI_JOB_JWT) the attestor
// records the verified claims of the job's own id_tokens token. Before, it
// read only CI_JOB_JWT and logged "no jwt token found in environment" on
// GitLab CE 19.4.1 (pipelines 4 and 5).
func TestAttestRecordsTheJobsIDToken(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	t.Setenv("SIGSTORE_ID_TOKEN", g.token(t, g.key, "sigstore", "10"))

	a := New()
	if err := attest(t, a); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.JWT == nil || a.JWT.Claims["job_id"] != "10" || a.JWT.Claims["project_path"] != "example-org/hello-api" {
		t.Fatalf("want the verified job claims recorded, got %+v", a.JWT)
	}
	if a.JWT.VerifiedBy.JWKSUrl != g.srv.URL+"/oauth/discovery/keys" {
		t.Fatalf("claims must be verified against the self-managed JWKS, got %q", a.JWT.VerifiedBy.JWKSUrl)
	}
}

// TestAttestFindsAnyNamedIDToken: the variable name is the pipeline's choice.
func TestAttestFindsAnyNamedIDToken(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	t.Setenv("MY_TOKEN", g.token(t, g.key, "https://platform.example/login", "10"))
	a := New()
	if err := attest(t, a); err != nil || a.JWT == nil {
		t.Fatalf("want MY_TOKEN's claims recorded, got %v %+v", err, a.JWT)
	}
}

// TestAttestNeverRecordsAnotherJobsToken: a token issued to another job is
// never taken as this job's claims.
func TestAttestNeverRecordsAnotherJobsToken(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	t.Setenv("SIGSTORE_ID_TOKEN", g.token(t, g.key, "sigstore", "11"))
	a := New()
	if err := attest(t, a); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.JWT != nil {
		t.Fatalf("another job's token must not be recorded, got %+v", a.JWT.Claims)
	}
}

// TestAttestRefusesAnUnverifiableToken: a token for this job that does not
// verify against the issuer's JWKS fails the attestor; it is never recorded.
func TestAttestRefusesAnUnverifiableToken(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGSTORE_ID_TOKEN", g.token(t, other, "sigstore", "10"))
	a := New()
	if err := attest(t, a); err == nil {
		t.Fatalf("a token signed by another key must fail the attestor, recorded %+v", a.JWT)
	}
}

// TestAttestNamedVariableMustHoldThisJobsToken: a named variable that is
// empty is an error, not a silent skip.
func TestAttestNamedVariableMustHoldThisJobsToken(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	a := New(WithTokenEnvVar("MY_TOKEN"))
	err := attest(t, a)
	if err == nil || !strings.Contains(err.Error(), "MY_TOKEN") || !strings.Contains(err.Error(), "id_tokens") {
		t.Fatalf("want a refusal naming MY_TOKEN and id_tokens, got %v", err)
	}
}

// TestAttestLegacyJobJWTMustBeThisJobs: the pre-17 CI_JOB_JWT fallback obeys the same binding as the
// id_tokens scan. A valid, verifiable token another job of the same GitLab holds is never recorded,
// and a token for this job is, whether its iss is the server URL (JWT_V2 style) or the bare host.
func TestAttestLegacyJobJWTMustBeThisJobs(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	t.Setenv("CI_JOB_JWT", g.token(t, g.key, "sigstore", "11"))
	a := New()
	if err := attest(t, a); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.JWT != nil {
		t.Fatalf("another job's CI_JOB_JWT must not be recorded, got %+v", a.JWT.Claims)
	}

	t.Setenv("CI_JOB_JWT", g.token(t, g.key, "sigstore", "10"))
	b := New()
	if err := attest(t, b); err != nil || b.JWT == nil || b.JWT.Claims["job_id"] != "10" {
		t.Fatalf("this job's CI_JOB_JWT must be recorded, got %v %+v", err, b.JWT)
	}
}

// TestAttestLegacyJobJWTWithAnotherIssuerIsNotRecorded: a token for this job id issued by a different
// GitLab is not this job's.
func TestAttestLegacyJobJWTWithAnotherIssuerIsNotRecorded(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	t.Setenv("CI_SERVER_HOST", "gitlab.example.com")
	t.Setenv("CI_JOB_JWT", g.token(t, g.key, "sigstore", "10"))
	t.Setenv("CI_SERVER_URL", "https://gitlab.example.com")
	t.Setenv("WITNESS_GITLAB_JWKS_URL", g.srv.URL+"/oauth/discovery/keys")
	a := New()
	if err := attest(t, a); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.JWT != nil {
		t.Fatalf("a token from another issuer must not be recorded, got %+v", a.JWT.Claims)
	}
}

func TestAttestLegacyJobJWTWithBareHostIssuer(t *testing.T) {
	g := newFakeGitLab(t)
	g.job(t)
	host := strings.TrimPrefix(g.srv.URL, "http://")
	t.Setenv("CI_SERVER_HOST", host)
	t.Setenv("CI_JOB_JWT", g.tokenWithIssuer(t, g.key, "sigstore", "10", host))
	a := New()
	if err := attest(t, a); err != nil || a.JWT == nil || a.JWT.Claims["job_id"] != "10" || a.JWT.Claims["iss"] != host {
		t.Fatalf("this job's bare-host legacy token must be recorded, got %v %+v", err, a.JWT)
	}
}
