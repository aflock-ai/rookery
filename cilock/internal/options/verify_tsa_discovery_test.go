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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

const testTSAChainPEM = "-----BEGIN CERTIFICATE-----\nMIITESTTSA\n-----END CERTIFICATE-----\n"

// tsaDiscoveryStub serves discovery WITH a tsa_cert_chain_url, plus the chain
// itself. crossOrigin points tsa_cert_chain_url at a foreign host to prove the
// same-origin guard.
func tsaDiscoveryStub(t *testing.T, crossOrigin bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/judge-configuration":
			chainURL := srv.URL + "/api/v1/timestamp/certchain"
			if crossOrigin {
				chainURL = "https://evil.example.com/api/v1/timestamp/certchain"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"archivista_url": srv.URL + "/archivista",
				"signing": map[string]any{
					"fulcio_oidc_issuer": srv.URL + "/fulcio/oidc",
					"trust_bundle_pem":   testTrustBundlePEM,
					"tsa_cert_chain_url": chainURL,
				},
			})
		case "/api/v1/timestamp/certchain":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = io.WriteString(w, testTSAChainPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

func seedTSASession(t *testing.T, platformURL string) {
	t.Helper()
	if err := auth.Save(auth.Credential{
		PlatformURL: platformURL,
		Token:       "stored-session-credential",
		Email:       "alice@acme-corp.com",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

// TestVerifyResolvePlatformDefaults_DerivesTSAChainFromDiscovery completes the
// flagless trust story: a logged-in verify derives the platform TSA chain from
// discovery's tsa_cert_chain_url so RFC3161 tokens validate with no
// --policy-timestamp-servers file.
func TestVerifyResolvePlatformDefaults_DerivesTSAChainFromDiscovery(t *testing.T) {
	isolateCredentialStore(t)
	srv := tsaDiscoveryStub(t, false)
	defer srv.Close()
	seedTSASession(t, srv.URL)

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		t.Fatalf("ResolvePlatformDefaults: %v", err)
	}

	if string(vo.PolicyCARootsPEM) != testTrustBundlePEM {
		t.Fatalf("precondition: CA bundle should adopt, got %q", string(vo.PolicyCARootsPEM))
	}
	if string(vo.PolicyTSAChainPEM) != testTSAChainPEM {
		t.Fatalf("PolicyTSAChainPEM = %q, want the discovered TSA chain", string(vo.PolicyTSAChainPEM))
	}
}

// TestVerifyResolvePlatformDefaults_TSAExplicitFlagWins: an operator-supplied
// --policy-timestamp-servers chain always suppresses the discovered one.
func TestVerifyResolvePlatformDefaults_TSAExplicitFlagWins(t *testing.T) {
	isolateCredentialStore(t)
	srv := tsaDiscoveryStub(t, false)
	defer srv.Close()
	seedTSASession(t, srv.URL)

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL, "--policy-timestamp-servers", "/path/to/tsa-chain.pem"}); err != nil {
		t.Fatal(err)
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		t.Fatalf("ResolvePlatformDefaults: %v", err)
	}

	if len(vo.PolicyTSAChainPEM) != 0 {
		t.Fatal("explicit --policy-timestamp-servers must suppress the discovered TSA chain")
	}
}

// TestVerifyResolvePlatformDefaults_TSARidesCAGate: with NO session, neither
// the CA bundle nor the TSA chain may be adopted from the network — the
// timestamp-trust leg must never outrun the CA-trust decision (GHSA #5988).
func TestVerifyResolvePlatformDefaults_TSARidesCAGate(t *testing.T) {
	isolateCredentialStore(t) // NO stored session
	srv := tsaDiscoveryStub(t, false)
	defer srv.Close()

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		t.Fatalf("ResolvePlatformDefaults: %v", err)
	}

	if len(vo.PolicyTSAChainPEM) != 0 {
		t.Fatalf("not-logged-in verify must NOT adopt a network-sourced TSA chain, got %q", string(vo.PolicyTSAChainPEM))
	}
}

// TestVerifyResolvePlatformDefaults_TSACrossOriginRefused: a discovery document
// pointing tsa_cert_chain_url off the platform origin must not be followed —
// trust material only travels from the platform itself (#5987).
func TestVerifyResolvePlatformDefaults_TSACrossOriginRefused(t *testing.T) {
	isolateCredentialStore(t)
	srv := tsaDiscoveryStub(t, true)
	defer srv.Close()
	seedTSASession(t, srv.URL)

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		t.Fatalf("ResolvePlatformDefaults: %v", err)
	}

	if len(vo.PolicyTSAChainPEM) != 0 {
		t.Fatalf("cross-origin tsa_cert_chain_url must be refused, got %q", string(vo.PolicyTSAChainPEM))
	}
}
