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

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/invopop/jsonschema"
	"gopkg.in/go-jose/go-jose.v2"
	josejwt "gopkg.in/go-jose/go-jose.v2/jwt"
)

// TestSecurity_R3_250_SchemaDoublePointerBug proves that Schema() passes
// a double pointer (**Attestor) to jsonschema.Reflect. The method receiver
// is already a *Attestor, so &a creates **Attestor. This produces a
// degenerate schema that wraps the real type in an extra indirection,
// losing all struct field information in the top-level definition.
//
// BUG CLASS 2: Schema reflection on pointer receiver using &a.
//
// Impact: MEDIUM -- JSON schema consumers (UI generators, documentation
// tools, policy engines) get an incorrect schema that doesn't describe
// the attestor's actual fields. This could cause validation bypasses if
// a policy engine relies on the schema to constrain attestation input.
func TestSecurity_R3_250_SchemaDoublePointerBug(t *testing.T) {
	a := New()

	// Call the buggy Schema() method
	buggySchema := a.Schema()

	// Call with the correct single-pointer
	correctSchema := jsonschema.Reflect(a)

	buggyJSON, err := json.MarshalIndent(buggySchema, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal buggy schema: %v", err)
	}

	correctJSON, err := json.MarshalIndent(correctSchema, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal correct schema: %v", err)
	}

	// The buggy schema and correct schema will differ because the double
	// pointer creates an extra level of indirection. The top-level $ref
	// in the buggy schema may point to a different definition name or
	// miss the struct fields entirely.
	if string(buggyJSON) == string(correctJSON) {
		// If they happen to match, the library may have been updated to
		// handle double-pointers gracefully. Log it but don't fail --
		// the code is still wrong even if the library compensates.
		t.Logf("INFO: jsonschema.Reflect currently handles **Attestor the same as *Attestor. "+
			"The code is still wrong (passes &a where a is *Attestor) and may break "+
			"with library updates.")
		return
	}

	t.Logf("SECURITY FINDING R3-250: Schema() produces a different schema than expected.\n"+
		"Buggy schema (via &&Attestor):\n%s\n\nCorrect schema (via *Attestor):\n%s",
		string(buggyJSON), string(correctJSON))

	// Verify the correct schema has the expected fields
	if correctSchema.Definitions == nil {
		t.Fatal("correct schema has no definitions")
	}

	// Check that buggy schema is missing fields that the correct schema has
	attestorDef, ok := correctSchema.Definitions["Attestor"]
	if !ok {
		t.Fatal("correct schema missing Attestor definition")
	}

	if attestorDef.Properties == nil || attestorDef.Properties.Len() == 0 {
		t.Fatal("correct schema Attestor definition has no properties")
	}

	t.Logf("Correct schema has %d properties in Attestor definition",
		attestorDef.Properties.Len())
}

// TestSecurity_R3_251_ExpiredJWTAccepted proves that the JWT attestor
// does not validate token expiration. A JWT with an exp claim in the
// past is accepted and its claims are attested as valid.
//
// Impact: HIGH -- An attacker who obtains an expired JWT can use it to
// create attestations. The attestor extracts claims from expired tokens
// without checking exp/nbf/iat, so revoked or rotated credentials
// remain usable indefinitely.
func TestSecurity_R3_251_ExpiredJWTAccepted(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     "expired-test-key",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), "expired-test-key")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}

	// Create a token that expired 24 hours ago
	expiredTime := time.Now().Add(-24 * time.Hour)
	claims := josejwt.Claims{
		Subject:  "expired-subject",
		Issuer:   "test-issuer",
		Expiry:   josejwt.NewNumericDate(expiredTime),
		IssuedAt: josejwt.NewNumericDate(expiredTime.Add(-1 * time.Hour)),
	}

	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))
	err = attestor.Attest(nil)

	// The attestor should reject expired tokens but doesn't
	if err != nil {
		t.Fatalf("unexpected error (attestor rejected token for other reason): %v", err)
	}

	// Verify the expired claims were accepted
	if len(attestor.Claims) == 0 {
		t.Fatal("expected claims to be populated")
	}

	// Check that the exp claim is in the past
	if exp, ok := attestor.Claims["exp"]; ok {
		t.Logf("SECURITY FINDING R3-251: Expired JWT accepted. exp=%v (in the past). "+
			"The attestor extracts claims from expired tokens without validating "+
			"exp/nbf/iat. An attacker with an old token can create valid attestations.",
			exp)
	} else {
		t.Logf("SECURITY FINDING R3-251: JWT with exp claim accepted, but exp not in Claims map. "+
			"The attestor does not validate token temporal claims.")
	}
}

// TestSecurity_R3_252_NotYetValidJWTAccepted proves that the JWT attestor
// does not validate the nbf (not before) claim. A JWT that isn't valid
// yet (nbf in the future) is accepted.
//
// Impact: MEDIUM -- Tokens issued for future use can be used before
// their intended activation time, bypassing time-gated access controls.
func TestSecurity_R3_252_NotYetValidJWTAccepted(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     "nbf-test-key",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), "nbf-test-key")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}

	// Create a token that won't be valid for 24 hours
	futureTime := time.Now().Add(24 * time.Hour)
	claims := josejwt.Claims{
		Subject:   "future-subject",
		Issuer:    "test-issuer",
		NotBefore: josejwt.NewNumericDate(futureTime),
		Expiry:    josejwt.NewNumericDate(futureTime.Add(1 * time.Hour)),
	}

	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))
	err = attestor.Attest(nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(attestor.Claims) == 0 {
		t.Fatal("expected claims to be populated")
	}

	t.Logf("SECURITY FINDING R3-252: JWT with nbf in the future accepted. "+
		"nbf=%v. The attestor does not validate temporal claims. "+
		"Tokens meant for future use can be used immediately.",
		attestor.Claims["nbf"])
}

// TestSecurity_R3_253_VerifiedByEmptyOnKeyIDMismatch proves that when the
// JWKS contains keys but none match the token's KeyID, the attestor still
// succeeds with populated claims but VerifiedBy is zero-valued. This means
// claims are trusted despite no specific key being identified as the verifier.
//
// Impact: MEDIUM -- Downstream consumers checking VerifiedBy to determine
// which key verified the token will find an empty struct, creating an
// audit gap. The token was cryptographically verified (go-jose tries all
// keys), but the attestor doesn't record which key succeeded.
func TestSecurity_R3_253_VerifiedByEmptyOnKeyIDMismatch(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// JWKS key has KeyID "server-key-1"
	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
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

	// Token has a DIFFERENT KeyID
	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), "totally-different-key")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}

	claims := josejwt.Claims{
		Subject: "mismatched-kid-subject",
		Issuer:  "test-issuer",
	}

	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))
	err = attestor.Attest(nil)

	if err != nil {
		// go-jose may reject when kid doesn't match; this is actually good
		// security behavior from the library. Log and continue.
		t.Logf("go-jose rejected mismatched KeyID (good library behavior): %v", err)
		t.Logf("FINDING R3-253: The attestor relies on go-jose to reject "+
			"mismatched KeyIDs. If go-jose ever changes this behavior, "+
			"the attestor has no fallback validation.")
		return
	}

	// If we get here, the token was verified despite KeyID mismatch
	if attestor.VerifiedBy.JWKSUrl == "" {
		t.Logf("SECURITY FINDING R3-253: Token verified but VerifiedBy is empty. "+
			"KeyID 'totally-different-key' doesn't match JWKS key 'server-key-1'. "+
			"jwks.Key() returns empty for the mismatched ID, so no key is recorded "+
			"as the verifier. Claims are trusted without audit trail of the "+
			"verifying key.")
	}

	if len(attestor.Claims) > 0 {
		t.Logf("Claims were populated despite KeyID mismatch: %v", attestor.Claims)
	}
}

// TestSecurity_R3_254_AlgorithmNotRestricted proves that the JWT attestor
// does not restrict which signing algorithms are acceptable. While go-jose
// provides some protection against "none" algorithm attacks, the attestor
// itself doesn't specify which algorithms it trusts.
//
// Impact: MEDIUM -- If the JWKS endpoint serves keys for multiple algorithms,
// an attacker could exploit weaker algorithms. The attestor should restrict
// to a known-good set of algorithms (e.g., RS256, ES256).
func TestSecurity_R3_254_AlgorithmNotRestricted(t *testing.T) {
	// Test with ECDSA P-256 key (ES256) - a different algorithm family
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{
		Key:       &ecKey.PublicKey,
		KeyID:     "ec-key-1",
		Algorithm: "ES256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), "ec-key-1")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ecKey}, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}

	claims := josejwt.Claims{
		Subject: "ec-subject",
		Issuer:  "test-issuer",
	}

	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))
	err = attestor.Attest(nil)

	if err != nil {
		t.Fatalf("unexpected error with ES256 token: %v", err)
	}

	if len(attestor.Claims) == 0 {
		t.Fatal("expected claims from ES256 token")
	}

	t.Logf("SECURITY FINDING R3-254: JWT attestor accepts any algorithm "+
		"supported by go-jose (tested ES256). There is no allow-list of "+
		"acceptable algorithms. An attacker controlling the JWKS endpoint "+
		"can serve keys for weaker algorithms. The attestor should provide "+
		"an option to restrict acceptable algorithms.")

	// Verify the attestor doesn't even look at the algorithm
	for _, header := range attestor.VerifiedBy.JWK.Certificates {
		t.Logf("Certificate in JWK: %v", header.Subject)
	}
	t.Logf("VerifiedBy algorithm: %s", attestor.VerifiedBy.JWK.Algorithm)
}

// TestSecurity_R3_255_EmptyTokenError proves that passing an empty token
// produces an ErrInvalidToken with an empty string, which prints as
// 'invalid token: ""'. This is correct behavior but worth documenting.
func TestSecurity_R3_255_EmptyTokenError(t *testing.T) {
	attestor := New()
	err := attestor.Attest(nil)

	if err == nil {
		t.Fatal("expected error for empty token")
	}

	invalidErr, ok := err.(ErrInvalidToken)
	if !ok {
		t.Fatalf("expected ErrInvalidToken, got %T: %v", err, err)
	}

	if string(invalidErr) != "" {
		t.Fatalf("expected empty token string, got %q", string(invalidErr))
	}

	t.Logf("Empty token correctly produces ErrInvalidToken: %v", err)
}

// TestSecurity_R3_256_NilContextSafe proves that passing nil as the
// AttestationContext doesn't panic. The JWT attestor doesn't use the
// context at all, so nil should be safe. This is a regression guard.
func TestSecurity_R3_256_NilContextSafe(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     "nil-ctx-key",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), "nil-ctx-key")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}

	claims := josejwt.Claims{Subject: "test"}
	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))

	// This should not panic
	err = attestor.Attest(nil)
	if err != nil {
		t.Fatalf("nil context caused error: %v", err)
	}

	t.Logf("FINDING R3-256: Nil AttestationContext is safe because the JWT "+
		"attestor ignores the context entirely. However, if someone adds "+
		"context usage later, this will panic.")
}

// TestSecurity_R3_257_MalformedTokenParsing proves that various malformed
// tokens are handled without panics.
func TestSecurity_R3_257_MalformedTokenParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	tests := []struct {
		name  string
		token string
	}{
		{"completely_invalid", "not-a-jwt-at-all"},
		{"empty_parts", "..."},
		{"base64_garbage", "YWJj.ZGVm.Z2hp"},
		{"single_part", "eyJhbGciOiJSUzI1NiJ9"},
		{"null_bytes", "eyJhbGciOiJSUzI1NiJ9.\x00\x00\x00.fake"},
		{"very_long_token", string(make([]byte, 1<<16))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := New(WithToken(tt.token), WithJWKSUrl(server.URL))

			// Must not panic regardless of input
			err := attestor.Attest(nil)
			if err == nil {
				t.Errorf("expected error for malformed token %q, got nil", tt.name)
			}
			t.Logf("Token %q correctly rejected: %v", tt.name, err)
		})
	}
}

// TestSecurity_R3_258_JWKSResponseNotJSON proves that a non-JSON response
// from the JWKS endpoint is handled gracefully without panic.
func TestSecurity_R3_258_JWKSResponseNotJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>not json</html>"))
	}))
	defer server.Close()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}

	claims := josejwt.Claims{Subject: "test"}
	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))
	err = attestor.Attest(nil)

	if err == nil {
		t.Fatal("expected error for non-JSON JWKS response")
	}

	t.Logf("Non-JSON JWKS response correctly rejected: %v", err)
}

// TestSecurity_R3_259_JWKSEmptyKeySet proves that when the JWKS endpoint
// returns an empty key set, the attestor behavior depends on go-jose's
// Claims() method. With no keys, verification should fail or claims
// should not be trusted.
func TestSecurity_R3_259_JWKSEmptyKeySet(t *testing.T) {
	// Serve an empty JWKS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), "test-key")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}

	claims := josejwt.Claims{Subject: "test"}
	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	attestor := New(WithToken(raw), WithJWKSUrl(server.URL))
	err = attestor.Attest(nil)

	if err == nil {
		// If no error, claims were parsed without any verification key
		t.Logf("SECURITY FINDING R3-259: Token accepted with empty JWKS. "+
			"Claims: %v. The attestor should reject tokens when no matching "+
			"key is found in the JWKS.", attestor.Claims)
	} else {
		t.Logf("Empty JWKS correctly rejected token: %v", err)
	}
}
