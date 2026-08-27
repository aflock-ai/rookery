// Copyright 2026 The Aflock Authors
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

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	fulciosigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
	"github.com/stretchr/testify/require"
)

// fakeFulcio is an HTTP Fulcio (the /api/v2/signingCert REST shape the fulcio
// signer provider speaks with use-http) that mints a leaf certificate for the
// public key each request carries, chained to a throwaway CA, and records every
// certificate request together with an observation the test supplies at that
// instant -- typically "had the wrapped command finished yet?". It is the real
// provider end to end; only the CA is fake.
type fakeFulcio struct {
	URL string

	mu       sync.Mutex
	requests []fakeFulcioRequest
}

type fakeFulcioRequest struct {
	At       time.Time
	Observed bool
}

func newFakeFulcio(t *testing.T, observe func() bool) *fakeFulcio {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake fulcio test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	f := &fakeFulcio{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/signingCert" {
			http.NotFound(w, r)
			return
		}
		observed := observe != nil && observe()
		f.mu.Lock()
		f.requests = append(f.requests, fakeFulcioRequest{At: time.Now(), Observed: observed})
		f.mu.Unlock()

		var body struct {
			PublicKeyRequest struct {
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"publicKeyRequest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(body.PublicKeyRequest.PublicKey.Content))
		if block == nil {
			http.Error(w, "no public key PEM in request", http.StatusBadRequest)
			return
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		leaf := &x509.Certificate{
			SerialNumber:   big.NewInt(time.Now().UnixNano()),
			Subject:        pkix.Name{CommonName: "fake fulcio leaf"},
			EmailAddresses: []string{"alice@acme.com"},
			NotBefore:      time.Now().Add(-time.Minute),
			NotAfter:       time.Now().Add(10 * time.Minute),
			KeyUsage:       x509.KeyUsageDigitalSignature,
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, pub, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"signedCertificateEmbeddedSct": map[string]any{
				"chain": map[string]any{"certificates": []string{leafPEM, caPEM}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

// Requests returns a snapshot of every certificate request served so far.
func (f *fakeFulcio) Requests() []fakeFulcioRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeFulcioRequest(nil), f.requests...)
}

// unverifiedJWT builds a compact JWS carrying the given claims with a
// placeholder signature. Nothing on the cilock side verifies the token -- the
// provider reads its claims unverified and forwards it to Fulcio -- so this is
// exactly the shape a static --signer-fulcio-token arrives in.
func unverifiedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + enc(payload) + "." + enc([]byte("unverified"))
}

// staticFulcioSignerOptions builds the setter list loadSigners receives for the
// fulcio provider, closing over *token so a test (or a refresher) can swap the
// token the provider is rebuilt with -- the same pointer-to-flag-storage shape
// internal/options addFlags produces, which is what lets the deferred signer
// pick up a token installed after the signers were loaded.
func staticFulcioSignerOptions(fulcioURL string, token *string) options.SignerOptions {
	return options.SignerOptions{"fulcio": {func(sp signer.SignerProvider) (signer.SignerProvider, error) {
		fsp, ok := sp.(fulciosigner.FulcioSignerProvider)
		if !ok {
			return nil, fmt.Errorf("provided signer provider is not a fulcio signer provider")
		}
		fulciosigner.WithFulcioURL(fulcioURL)(&fsp)
		fulciosigner.WithToken(*token)(&fsp)
		fulciosigner.WithUseHTTP(true)(&fsp)
		return fsp, nil
	}}}
}

// staticFulcioTokenPathOptions is staticFulcioSignerOptions for a token read
// from a file (--signer-fulcio-token-path).
func staticFulcioTokenPathOptions(fulcioURL, tokenPath string) options.SignerOptions {
	return options.SignerOptions{"fulcio": {func(sp signer.SignerProvider) (signer.SignerProvider, error) {
		fsp, ok := sp.(fulciosigner.FulcioSignerProvider)
		if !ok {
			return nil, fmt.Errorf("provided signer provider is not a fulcio signer provider")
		}
		fulciosigner.WithFulcioURL(fulcioURL)(&fsp)
		fulciosigner.WithTokenPath(tokenPath)(&fsp)
		fulciosigner.WithUseHTTP(true)(&fsp)
		return fsp, nil
	}}}
}

var onlyFulcio = map[string]struct{}{"fulcio": {}}
