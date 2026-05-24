// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hashivault

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

// mockVault stands up an httptest server that pretends to be Vault Transit.
// It records the body of the most recent sign/verify request so tests can
// assert on the signature_algorithm field.
type mockVault struct {
	server *httptest.Server

	mu          sync.Mutex
	keyType     string
	signReq     map[string]interface{}
	verifyReq   map[string]interface{}
	signature   string
	signCalls   int
	verifyCalls int
	keysCalls   int
}

func newMockVault(t *testing.T, keyType string) *mockVault {
	t.Helper()
	m := &mockVault{keyType: keyType, signature: "vault:v1:fakesig"}

	mux := http.NewServeMux()

	// Key metadata read: GET /v1/transit/keys/<keyPath>
	mux.HandleFunc("/v1/transit/keys/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.keysCalls++
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"type":           m.keyType,
				"latest_version": 1,
				"keys": map[string]interface{}{
					"1": map[string]interface{}{
						"public_key": "test-public-key",
					},
				},
			},
		})
	})

	// Sign: POST /v1/transit/sign/<keyPath>/<hash>
	mux.HandleFunc("/v1/transit/sign/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		m.mu.Lock()
		m.signCalls++
		m.signReq = parsed
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"signature": m.signature,
			},
		})
	})

	// Verify: POST /v1/transit/verify/<keyPath>/<hash>
	mux.HandleFunc("/v1/transit/verify/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		m.mu.Lock()
		m.verifyCalls++
		m.verifyReq = parsed
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"valid": true,
			},
		})
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func newTestClient(t *testing.T, m *mockVault) *client {
	t.Helper()
	cfg := vault.DefaultConfig()
	cfg.Address = m.server.URL
	vc, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	vc.SetToken("test-token")
	return &client{
		client:                   vc,
		keyPath:                  "mykey",
		transitSecretsEnginePath: "transit",
		keyVersion:               1,
	}
}

// TestSign_ECDSA_OmitsSignatureAlgorithm proves the bug fix: when the Vault
// key is ECDSA, the sign request must NOT carry signature_algorithm=pkcs1v15.
// Before the fix, this was hardcoded and Vault rejected ECDSA sign calls.
func TestSign_ECDSA_OmitsSignatureAlgorithm(t *testing.T) {
	ecdsaTypes := []string{"ecdsa-p256", "ecdsa-p384", "ecdsa-p521"}
	for _, kt := range ecdsaTypes {
		t.Run(kt, func(t *testing.T) {
			m := newMockVault(t, kt)
			c := newTestClient(t, m)

			sig, err := c.sign(context.Background(), []byte("12345678901234567890123456789012"), crypto.SHA256)
			if err != nil {
				t.Fatalf("sign returned error: %v", err)
			}
			if string(sig) != "vault:v1:fakesig" {
				t.Fatalf("unexpected signature: %q", sig)
			}

			if _, present := m.signReq["signature_algorithm"]; present {
				t.Errorf("BUG: signature_algorithm sent for %s key; got %v", kt, m.signReq["signature_algorithm"])
			}
			if m.keysCalls != 1 {
				t.Errorf("expected 1 key metadata lookup, got %d", m.keysCalls)
			}
		})
	}
}

// TestSign_Ed25519_OmitsSignatureAlgorithm covers the ed25519 path.
func TestSign_Ed25519_OmitsSignatureAlgorithm(t *testing.T) {
	m := newMockVault(t, "ed25519")
	c := newTestClient(t, m)

	if _, err := c.sign(context.Background(), []byte("12345678901234567890123456789012"), crypto.SHA256); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}
	if _, present := m.signReq["signature_algorithm"]; present {
		t.Errorf("BUG: signature_algorithm sent for ed25519 key; got %v", m.signReq["signature_algorithm"])
	}
}

// TestSign_RSA_KeepsPKCS1v15 verifies back-compat: existing RSA users
// continue to get pkcs1v15 by default.
func TestSign_RSA_KeepsPKCS1v15(t *testing.T) {
	rsaTypes := []string{"rsa-2048", "rsa-3072", "rsa-4096"}
	for _, kt := range rsaTypes {
		t.Run(kt, func(t *testing.T) {
			m := newMockVault(t, kt)
			c := newTestClient(t, m)

			if _, err := c.sign(context.Background(), []byte("12345678901234567890123456789012"), crypto.SHA256); err != nil {
				t.Fatalf("sign returned error: %v", err)
			}
			algo, ok := m.signReq["signature_algorithm"].(string)
			if !ok || algo != "pkcs1v15" {
				t.Errorf("expected signature_algorithm=pkcs1v15 for %s, got %v", kt, m.signReq["signature_algorithm"])
			}
		})
	}
}

// TestVerify_ECDSA_OmitsSignatureAlgorithm mirrors the sign-side test for the
// verify path.
func TestVerify_ECDSA_OmitsSignatureAlgorithm(t *testing.T) {
	m := newMockVault(t, "ecdsa-p256")
	c := newTestClient(t, m)

	if err := c.verify(context.Background(), bytes.NewReader([]byte("hello")), []byte("vault:v1:fakesig"), crypto.SHA256); err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if _, present := m.verifyReq["signature_algorithm"]; present {
		t.Errorf("BUG: signature_algorithm sent for ecdsa-p256 key on verify; got %v", m.verifyReq["signature_algorithm"])
	}
}

// TestVerify_RSA_KeepsPKCS1v15 ensures the verify path still sends pkcs1v15
// for RSA keys (back-compat).
func TestVerify_RSA_KeepsPKCS1v15(t *testing.T) {
	m := newMockVault(t, "rsa-2048")
	c := newTestClient(t, m)

	if err := c.verify(context.Background(), bytes.NewReader([]byte("hello")), []byte("vault:v1:fakesig"), crypto.SHA256); err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	algo, ok := m.verifyReq["signature_algorithm"].(string)
	if !ok || algo != "pkcs1v15" {
		t.Errorf("expected verify signature_algorithm=pkcs1v15 for rsa-2048, got %v", m.verifyReq["signature_algorithm"])
	}
}

// TestDiscoverKeyType_CachedAcrossCalls verifies the key metadata lookup
// happens once and is cached for subsequent sign/verify calls. The Vault
// keys endpoint is more expensive than sign/verify so caching matters.
func TestDiscoverKeyType_CachedAcrossCalls(t *testing.T) {
	m := newMockVault(t, "ecdsa-p256")
	c := newTestClient(t, m)

	for i := 0; i < 3; i++ {
		if _, err := c.sign(context.Background(), []byte("12345678901234567890123456789012"), crypto.SHA256); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	if err := c.verify(context.Background(), bytes.NewReader([]byte("hello")), []byte("vault:v1:fakesig"), crypto.SHA256); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if m.keysCalls != 1 {
		t.Errorf("expected key metadata to be fetched once and cached, got %d calls", m.keysCalls)
	}
	if m.signCalls != 3 {
		t.Errorf("expected 3 sign calls, got %d", m.signCalls)
	}
	if m.verifyCalls != 1 {
		t.Errorf("expected 1 verify call, got %d", m.verifyCalls)
	}
}

// TestSignatureAlgorithmFor_TableDriven documents the algorithm selection
// policy for every key type Vault Transit supports.
func TestSignatureAlgorithmFor_TableDriven(t *testing.T) {
	cases := []struct {
		keyType  string
		wantAlgo string
		wantSend bool
	}{
		{"rsa-2048", "pkcs1v15", true},
		{"rsa-3072", "pkcs1v15", true},
		{"rsa-4096", "pkcs1v15", true},
		{"ecdsa-p256", "", false},
		{"ecdsa-p384", "", false},
		{"ecdsa-p521", "", false},
		{"ed25519", "", false},
		{"", "", false}, // unknown / empty type: let Vault decide.
	}
	for _, tc := range cases {
		t.Run(tc.keyType, func(t *testing.T) {
			got, send := signatureAlgorithmFor(tc.keyType)
			if got != tc.wantAlgo || send != tc.wantSend {
				t.Errorf("signatureAlgorithmFor(%q) = (%q, %v), want (%q, %v)",
					tc.keyType, got, send, tc.wantAlgo, tc.wantSend)
			}
		})
	}
}

// TestDiscoverKeyType_VaultError surfaces errors from the Vault read so the
// caller does not silently fall back to a misconfigured signature_algorithm.
func TestDiscoverKeyType_VaultError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintln(w, `{"errors":["permission denied"]}`)
	}))
	t.Cleanup(srv.Close)

	cfg := vault.DefaultConfig()
	cfg.Address = srv.URL
	vc, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	vc.SetToken("test-token")
	c := &client{
		client:                   vc,
		keyPath:                  "mykey",
		transitSecretsEnginePath: "transit",
	}

	if _, err := c.sign(context.Background(), []byte("12345678901234567890123456789012"), crypto.SHA256); err == nil {
		t.Errorf("expected sign to fail when key metadata lookup fails")
	}
}
