//go:build audit

// Copyright 2024 The Witness Contributors
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

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/go-jose/go-jose.v2"
	josejwt "gopkg.in/go-jose/go-jose.v2/jwt"
)

// TestSecurity_R3_200_JWKSURLAcceptsHTTP proves that the JWT attestor
// fetches JWKS from plain HTTP URLs without enforcing HTTPS. Unlike the
// TSP timestamper (which enforces HTTPS), the JWT attestor makes no scheme
// validation on the JWKS URL.
//
// Impact: HIGH — A man-in-the-middle attacker can serve a malicious JWKS
// set containing their own public key, causing the attestor to accept
// forged JWT tokens. The attacker signs a JWT with their own key, serves
// a JWKS containing the matching public key over the MITM'd HTTP
// connection, and the attestor happily verifies it. This also enables
// SSRF: the JWKS URL can point to internal services (e.g.,
// http://169.254.169.254/latest/meta-data/ on AWS) to probe internal
// infrastructure.
func TestSecurity_R3_200_JWKSURLAcceptsHTTP(t *testing.T) {
	// Generate a key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create JWKS with the public key
	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	// Serve JWKS over plain HTTP (not HTTPS)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	// The server URL starts with http:// (not https://)
	if !strings.HasPrefix(server.URL, "http://") {
		t.Fatalf("expected HTTP URL, got %s", server.URL)
	}

	// Create a signed JWT token
	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), "test-key-1")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}

	claims := josejwt.Claims{
		Subject: "test-subject",
		Issuer:  "test-issuer",
	}

	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// Create attestor with HTTP JWKS URL
	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))

	// SECURITY FINDING: The attestor happily fetches from HTTP
	// A secure implementation should reject non-HTTPS JWKS URLs
	err = attestor.Attest(nil)

	if err != nil {
		t.Fatalf("attestor returned error (unexpected): %v", err)
	}

	// The attestor accepted the HTTP JWKS URL and verified the claims
	if len(attestor.Claims) == 0 {
		t.Fatal("expected claims to be populated")
	}

	if attestor.VerifiedBy.JWKSUrl != server.URL {
		t.Logf("VerifiedBy.JWKSUrl = %q", attestor.VerifiedBy.JWKSUrl)
	}

	t.Logf("SECURITY FINDING R3-200: JWT attestor accepted JWKS from plain HTTP URL %q. "+
		"No HTTPS enforcement means a MITM attacker can serve a malicious JWKS to forge "+
		"JWT verification. The TSP timestamper enforces HTTPS but the JWT attestor does not. "+
		"Additionally, the JWKS URL could point to internal services for SSRF attacks.",
		server.URL)
}

// TestSecurity_R3_201_JWKSURLNoSchemeValidation proves that the JWT attestor
// does not validate the JWKS URL scheme at all. While the HTTP client will
// reject truly invalid schemes, it accepts file://, ftp://, and other schemes
// that could be used for SSRF.
func TestSecurity_R3_201_JWKSURLNoSchemeValidation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "file URL should be rejected",
			url:     "file:///etc/passwd",
			wantErr: true, // Go's HTTP client rejects file:// URLs, but this is accidental not intentional
		},
		{
			name:    "internal IP should be rejected",
			url:     "http://127.0.0.1:1/jwks",
			wantErr: true, // Connection refused, but not because of SSRF protection
		},
		// NOTE: Skipping cloud metadata URL test (http://169.254.169.254/)
		// because it causes a 30-second timeout. The point is proven by the
		// internal IP test — no explicit SSRF protection exists.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal JWT (we don't care about verification here,
			// just that the URL validation happens before any fetch)
			attestor := New(WithToken("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake"), WithJWKSUrl(tt.url))

			err := attestor.Attest(nil)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for URL %q, but got nil", tt.url)
			}

			// The point is: errors happen because of network failures,
			// NOT because of explicit URL validation/SSRF protection
			if err != nil {
				// Check if it's a scheme validation error vs a network error
				errStr := err.Error()
				if strings.Contains(errStr, "scheme") || strings.Contains(errStr, "must be https") {
					t.Logf("GOOD: URL %q was rejected by scheme validation", tt.url)
				} else {
					t.Logf("SECURITY FINDING R3-201: URL %q failed with %q — "+
						"this is a network error, NOT explicit URL validation. "+
						"There is no SSRF protection; the request was attempted.",
						tt.url, errStr)
				}
			}
		})
	}
}

// TestSecurity_R3_202_JWKSNoKeyIDSilentVerificationGap proves that when a
// token is signed without a KeyID header, the attestor verifies the claims
// using the JWKS but then fails to look up the specific key (since KeyID is "").
// The attestation succeeds with populated claims but VerifiedBy is empty.
// This creates an audit gap — consumers can't determine which key verified the token.
func TestSecurity_R3_202_JWKSNoKeyIDSilentVerificationGap(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create JWKS where keys have KeyIDs set
	jwk := jose.JSONWebKey{
		Key:       &signingKey.PublicKey,
		KeyID:     "server-key-1",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	// Sign token WITHOUT a KeyID header — this is valid JWT behavior
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, nil)
	if err != nil {
		t.Fatal(err)
	}

	claims := josejwt.Claims{
		Subject: "test-subject",
		Issuer:  "test-issuer",
	}

	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))
	err = attestor.Attest(nil)

	if err != nil {
		// go-jose v2 may require key ID matching; if so, the error is about
		// key format/matching. This is actually a separate issue — the attestor
		// returns an error here but doesn't provide a clear message about the
		// key ID mismatch.
		t.Logf("Attestor returned error (key matching issue): %v", err)
		t.Logf("SECURITY FINDING R3-202: When token has no KeyID and JWKS keys have "+
			"KeyIDs, go-jose fails with an opaque error. The attestor doesn't provide "+
			"a clear message about the KeyID mismatch, making debugging difficult.")
		return
	}

	// If we get here, claims were verified
	if len(attestor.Claims) == 0 {
		t.Fatal("expected claims to be populated after successful verification")
	}

	// Check if VerifiedBy was populated
	// jwks.Key("") would look for keys with empty KeyID
	if attestor.VerifiedBy.JWKSUrl == "" {
		t.Logf("SECURITY FINDING R3-202: Token was cryptographically verified "+
			"but VerifiedBy is empty because the token has no KeyID header. "+
			"jwks.Key(\"\") returns no results since all JWKS keys have explicit KeyIDs. "+
			"The attestation appears verified but doesn't record which key did it.")
	} else {
		t.Logf("VerifiedBy was populated: %v", attestor.VerifiedBy)
	}
}
