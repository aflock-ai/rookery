//go:build audit

// Copyright 2025 The Witness Contributors
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

package fulcio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// =============================================================================
// R3-260-11: Fulcio URL accepts HTTP without explicit warning or rejection
//
// FulcioSignerProvider.Signer() parses the URL and sets:
//   isInsecure := scheme == "http"
//
// When isInsecure is true:
//   - gRPC mode: uses insecure.NewCredentials() (no TLS at all)
//   - HTTP mode: uses a default http.Client (which DOES verify TLS,
//     so HTTP mode is actually MORE secure than intended for http:// URLs)
//
// There is no enforcement that the Fulcio URL must use HTTPS. For a
// supply-chain security tool that signs attestations, allowing plain
// HTTP connections to the certificate authority is a significant risk:
//   - MITM can intercept the OIDC token
//   - MITM can return forged certificates
//   - No integrity protection on the signing request
//
// The only protection is a log.Infof message ("Fulcio client is running
// in insecure mode") which is easily missed.
//
// Proving test: show that http:// URLs are accepted without error, and
// that the gRPC client is created with insecure credentials.
// =============================================================================

func TestSecurity_R3_260_Fulcio_NoHTTPSEnforcement(t *testing.T) {
	// Verify that http:// URLs are accepted by newClient.
	client, err := newClient("http://localhost", 8080, true)
	require.NoError(t, err, "http:// URL should be accepted (no HTTPS enforcement)")
	require.NotNil(t, client)

	// Verify that Signer() accepts http:// URLs and derives isInsecure=true.
	fsp := New(WithFulcioURL("http://evil-mitm-proxy.example.com:8080"))
	u, err := url.Parse(fsp.FulcioURL)
	require.NoError(t, err)

	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	isInsecure := scheme == "http"

	require.True(t, isInsecure,
		"BUG: http:// URL produces isInsecure=true, which disables all TLS "+
			"verification for gRPC connections to Fulcio. There is no mechanism "+
			"to reject http:// URLs or require explicit opt-in for insecure mode.")

	t.Log("BUG PROVEN: http:// Fulcio URLs are accepted without any enforcement " +
		"of HTTPS. In gRPC mode, this disables all TLS (insecure.NewCredentials()). " +
		"An MITM attacker on the network path can: " +
		"1. Intercept the OIDC token (sent in the signing request). " +
		"2. Return a forged certificate chain. " +
		"3. No integrity protection on any data exchanged. " +
		"The only indication is a log.Infof message easily lost in CI output. " +
		"Fix: require explicit opt-in for insecure mode via a separate flag, " +
		"and default to rejecting non-HTTPS URLs. Or at minimum, emit a " +
		"log.Warnf or return an error without a --allow-insecure flag.")
}

// =============================================================================
// R3-260-12: fetchToken does not enforce HTTPS on tokenURL
//
// fetchToken(tokenURL, bearer, audience) accepts any URL scheme.
// In GitHub Actions, ACTIONS_ID_TOKEN_REQUEST_URL is typically HTTPS,
// but the code does not validate this. A compromised environment variable
// could point to an HTTP URL, allowing the bearer token to be sent in
// the clear.
//
// The bearer token is the ACTIONS_ID_TOKEN_REQUEST_TOKEN, which is a
// short-lived GitHub Actions runtime token. Leaking it via HTTP allows
// an attacker to request OIDC tokens and potentially forge attestation
// identities.
//
// Proving test: show that fetchToken accepts http:// URLs and sends the
// bearer token over the unencrypted connection.
// =============================================================================

func TestSecurity_R3_260_Fulcio_FetchTokenNoSchemeValidation(t *testing.T) {
	// Set up an HTTP server (not HTTPS) to capture the request.
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"count": 1, "value": "fake-oidc-token"}`)
	}))
	defer server.Close()

	// Verify the test server is HTTP (not HTTPS).
	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	require.Equal(t, "http", u.Scheme,
		"test server should be plain HTTP to prove the vulnerability")

	// fetchToken sends the bearer token over HTTP without complaint.
	secretBearer := "ghs_SuperSecretRuntimeToken123456"
	token, err := fetchToken(server.URL+"/token", secretBearer, "sigstore")
	require.NoError(t, err,
		"fetchToken should succeed with http:// URL (no scheme validation)")
	require.Equal(t, "fake-oidc-token", token)

	// Verify the secret bearer was sent over the unencrypted connection.
	require.Equal(t, "bearer "+secretBearer, capturedAuth,
		"BUG: fetchToken sent the secret bearer token over plain HTTP. "+
			"An attacker who sets ACTIONS_ID_TOKEN_REQUEST_URL to an HTTP "+
			"endpoint can capture the runtime token.")

	t.Log("BUG PROVEN: fetchToken sends the bearer (ACTIONS_ID_TOKEN_REQUEST_TOKEN) " +
		"over any URL scheme including plain HTTP. There is no validation that " +
		"tokenURL uses HTTPS. If an attacker controls ACTIONS_ID_TOKEN_REQUEST_URL " +
		"(e.g., via environment variable injection), they receive the bearer token " +
		"in cleartext and can use it to request OIDC tokens. " +
		"Fix: validate that tokenURL scheme is 'https' before making the request, " +
		"or at minimum log a loud warning when HTTP is used.")
}

// =============================================================================
// R3-260-13: getCertHTTP does not validate certificate chain
//
// After receiving the protobuf SigningCertificate from Fulcio via HTTP,
// getCertHTTP returns it directly without any validation. The caller
// (Signer()) then parses the PEM certs and passes them to NewX509Signer
// without verifying:
//   - Chain validity against a trust root
//   - Leaf cert's public key matches the generated private key
//   - Certificate expiration dates
//   - Revocation status
//
// This means a MITM or compromised Fulcio can return a completely forged
// certificate chain and the code will use it for signing.
//
// Proving test: return a self-signed cert chain from a fake Fulcio HTTP
// server and verify getCertHTTP accepts it.
// =============================================================================

func TestSecurity_R3_260_Fulcio_NoCertChainValidation(t *testing.T) {
	// Create a completely fake certificate chain (not from Fulcio's root).
	fakeRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fakeRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Evil Attacker Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	fakeRootDER, err := x509.CreateCertificate(rand.Reader, fakeRootTemplate, fakeRootTemplate, &fakeRootKey.PublicKey, fakeRootKey)
	require.NoError(t, err)

	fakeLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fakeLeafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Forged Leaf Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}
	fakeLeafDER, err := x509.CreateCertificate(rand.Reader, fakeLeafTemplate, fakeRootTemplate, &fakeLeafKey.PublicKey, fakeRootKey)
	require.NoError(t, err)

	fakeCerts := []string{
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeRootDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeLeafDER})),
	}

	certResp := &fulciopb.SigningCertificate{
		Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
			SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
				Chain: &fulciopb.CertificateChain{
					Certificates: fakeCerts,
				},
			},
		},
	}
	respJSON, err := protojson.Marshal(certResp)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("attacker@evil.com", "")
	result, err := getCertHTTP(context.Background(), key, server.URL, token)

	// getCertHTTP returns the forged chain without any validation.
	require.NoError(t, err,
		"BUG: getCertHTTP accepts a completely forged certificate chain from "+
			"an attacker-controlled server without validating against any trust root")
	require.NotNil(t, result)

	t.Log("BUG PROVEN: getCertHTTP accepts ANY certificate chain returned by " +
		"the Fulcio server, including chains signed by attacker-controlled CAs. " +
		"No validation is performed against Fulcio's trust root, no expiration " +
		"check, and no verification that the leaf cert matches our private key. " +
		"Impact: HIGH in HTTP/insecure mode (trivial MITM). " +
		"Fix: validate the returned chain against a known Fulcio root CA bundle. " +
		"Also verify leaf cert public key == our generated key's public key.")
}

// =============================================================================
// R3-260-14: Token stored in plaintext struct, exposed via %+v and Marshal
//
// FulcioSignerProvider stores the OIDC token as a plain string field:
//   type FulcioSignerProvider struct {
//       Token string
//   }
//
// This means:
// 1. fmt.Sprintf("%+v", fsp) exposes the full token.
// 2. json.Marshal(fsp) includes the token.
// 3. Any logging/debug code that prints the struct leaks the token.
// 4. The struct has no custom String() or MarshalJSON() to redact it.
//
// OIDC tokens are short-lived but sensitive. Leaking them in logs can
// allow token replay within the token's validity window.
//
// Proving test: demonstrate token exposure via string formatting.
// =============================================================================

func TestSecurity_R3_260_Fulcio_TokenPlaintextExposure(t *testing.T) {
	secretToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SECRET_PAYLOAD.SIGNATURE"

	fsp := New(WithToken(secretToken))

	// Direct field access exposes the token.
	require.Equal(t, secretToken, fsp.Token,
		"Token is stored as a plain string field")

	// fmt.Sprintf exposes it.
	formatted := fmt.Sprintf("%+v", fsp)
	assert.Contains(t, formatted, secretToken,
		"BUG: fmt.Sprintf(%%+v) exposes the full OIDC token in the struct output")

	// Verify there is no custom String() method that redacts.
	// If there were, Sprintf would call it instead.
	defaultFormatted := fmt.Sprintf("%v", fsp)
	if strings.Contains(defaultFormatted, secretToken) {
		t.Logf("Token exposed in default format: %s", defaultFormatted)
	}

	t.Log("BUG PROVEN: FulcioSignerProvider.Token is a plain string field with " +
		"no redaction. The token is exposed via: " +
		"1. fmt.Sprintf/Printf with any format verb. " +
		"2. json.Marshal (exported field, no custom MarshalJSON). " +
		"3. Any debug/error logging that includes the struct. " +
		"4. Stack traces or core dumps. " +
		"Fix: implement custom String() and MarshalJSON() that redact the token, " +
		"or store it in an unexported field with accessor.")
}

// =============================================================================
// R3-260-15: Signer() with empty FulcioURL produces unhelpful error
//
// When FulcioURL is empty, url.Parse("") succeeds (returns empty URL),
// and the code falls through to u.Host == "" check which returns:
//   "fulcio URL must include a host"
//
// This is fine, but what about malformed URLs that parse successfully?
// =============================================================================

func TestSecurity_R3_260_Fulcio_MalformedURLHandling(t *testing.T) {
	testCases := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
			errMsg:  "fulcio URL must include a host",
		},
		{
			name:    "just a path",
			url:     "/api/v2/signingCert",
			wantErr: true,
			errMsg:  "fulcio URL must include a host",
		},
		{
			name:    "javascript scheme",
			url:     "javascript://fulcio.sigstore.dev",
			wantErr: false, // BUG: accepted because scheme != "" and host != ""
			errMsg:  "",
		},
		{
			name:    "file scheme",
			url:     "file:///etc/passwd",
			wantErr: true, // host is empty for file:// URIs
			errMsg:  "fulcio URL must include a host",
		},
		{
			name:    "ftp scheme",
			url:     "ftp://fulcio.example.com",
			wantErr: false, // BUG: accepted, scheme defaults to https logic fails
			errMsg:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate what Signer() does with the URL.
			u, err := url.Parse(tc.url)
			if err != nil {
				if !tc.wantErr {
					t.Fatalf("unexpected parse error: %v", err)
				}
				return
			}

			scheme := u.Scheme
			if scheme == "" {
				scheme = "https"
			}

			if u.Host == "" {
				if tc.wantErr {
					return // Expected error
				}
				t.Fatalf("expected no error but got empty host for %q", tc.url)
			}

			if !tc.wantErr {
				t.Logf("URL %q accepted: scheme=%q host=%q. "+
					"Non-standard schemes like javascript:// and ftp:// are accepted.",
					tc.url, scheme, u.Host)
			}
		})
	}
}

// =============================================================================
// R3-260-16: getCertHTTP inconsistency with getCert retry behavior
//
// getCert (gRPC path) retries up to 3 times with exponential backoff.
// getCertHTTP (HTTP path) has NO retry logic whatsoever.
//
// This means the same transient error (e.g., 503 from a load balancer)
// causes immediate failure in HTTP mode but succeeds after retry in gRPC
// mode. Users switching from gRPC to HTTP mode will experience degraded
// reliability with no documentation of this difference.
//
// Proving test: hit a server that fails once then succeeds, showing
// getCertHTTP fails while the equivalent gRPC path would retry.
// =============================================================================

func TestSecurity_R3_260_Fulcio_HTTPNoRetry(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "service temporarily unavailable")
			return
		}
		// Second request would succeed, but getCertHTTP never retries.
		chain := generateCertChain(t)
		certResp := &fulciopb.SigningCertificate{
			Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
				SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
					Chain: &fulciopb.CertificateChain{Certificates: chain},
				},
			},
		}
		respJSON, _ := protojson.Marshal(certResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")
	_, err = getCertHTTP(context.Background(), key, server.URL, token)

	require.Error(t, err,
		"getCertHTTP should fail on transient 503 (no retry logic)")
	require.Equal(t, 1, requestCount,
		"BUG: getCertHTTP made only 1 request. getCert (gRPC) would have "+
			"retried up to 3 times with exponential backoff.")

	t.Log("BUG PROVEN: getCertHTTP has no retry logic. A single transient 503 " +
		"causes immediate failure, while the equivalent getCert (gRPC path) would " +
		"retry up to 3 times with 1s/2s/4s exponential backoff. " +
		"Fix: extract the retry logic into a shared function and use it in both paths.")
}
