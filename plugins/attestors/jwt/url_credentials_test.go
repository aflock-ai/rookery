// jade:ring local
//
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

// The gitlab attestor builds its JWKS URL from CI_SERVER_URL, so a login in
// that URL reached verifiedBy.jwksUrl in the signed predicate. The fetch
// still uses the URL as given; only the recorded copy loses its userinfo.
func TestAttestRedactsCredentialsInRecordedJWKSURL(t *testing.T) {
	const secret = "jwks-url-pw-1234"
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &privKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
	var gotUser, gotPassword string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPassword, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "k1")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := josejwt.Signed(signer).Claims(josejwt.Claims{Subject: "s"}).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	jwksURL := strings.Replace(server.URL, "http://", "http://ci:"+secret+"@", 1) + "/oauth/discovery/keys"
	a := New(WithToken(raw), WithJWKSUrl(jwksURL))
	if err := a.Attest(nil); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if gotUser != "ci" || gotPassword != secret {
		t.Errorf("the JWKS fetch must still send the configured login; got user %q password %q", gotUser, gotPassword)
	}
	want := strings.Replace(server.URL, "http://", "http://******@", 1) + "/oauth/discovery/keys"
	if a.VerifiedBy.JWKSUrl != want {
		t.Errorf("VerifiedBy.JWKSUrl = %q, want %q", a.VerifiedBy.JWKSUrl, want)
	}
	predicate, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(predicate), secret) {
		t.Errorf("signed predicate carries a credential: %s", predicate)
	}
}

// The non-200 error text names the JWKS endpoint, and an error from an
// attestor reaches logs and the run's failure output. It carries the URL
// without its userinfo.
func TestAttestRedactsCredentialsInJWKSStatusError(t *testing.T) {
	const secret = "jwks-err-pw-5678"
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "k1")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := josejwt.Signed(signer).Claims(josejwt.Claims{Subject: "s"}).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	jwksURL := strings.Replace(server.URL, "http://", "http://ci:"+secret+"@", 1) + "/oauth/discovery/keys"
	err = New(WithToken(raw), WithJWKSUrl(jwksURL)).Attest(nil)
	if err == nil {
		t.Fatal("Attest succeeded against a JWKS endpoint that returns 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("Attest failed for another reason than the status code: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the status error carries the JWKS credential: %v", err)
	}
	if want := strings.Replace(server.URL, "http://", "http://******@", 1); !strings.Contains(err.Error(), want) {
		t.Errorf("the status error = %v, want it to name the endpoint as %s", err, want)
	}
}

// A failed fetch returns net/http's *url.Error, whose text names the URL with
// only the password taken out. A token in the username slot
// ("https://glpat-TOKEN@gitlab.example/...") would reach logs and the run's
// failure output, so the error names the endpoint without any userinfo.
func TestAttestRedactsUsernameTokenInJWKSFetchError(t *testing.T) {
	const token = "glpat-jwksfetchtoken1234"
	server := httptest.NewServer(http.NotFoundHandler())
	endpoint := server.URL
	server.Close() // nothing listens there now, so the fetch fails

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := josejwt.Signed(signer).Claims(josejwt.Claims{Subject: "s"}).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	jwksURL := strings.Replace(endpoint, "http://", "http://"+token+"@", 1) + "/oauth/discovery/keys"
	err = New(WithToken(raw), WithJWKSUrl(jwksURL)).Attest(nil)
	if err == nil {
		t.Fatal("Attest succeeded against a closed JWKS endpoint")
	}
	if !strings.Contains(err.Error(), "error fetching jwks") {
		t.Fatalf("Attest failed for another reason than the fetch: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("the fetch error carries the JWKS username token: %v", err)
	}
	if want := strings.Replace(endpoint, "http://", "http://******@", 1); !strings.Contains(err.Error(), want) {
		t.Errorf("the fetch error = %v, want it to name the endpoint as %s", err, want)
	}
	// Every parser reads this userinfo and this host, and Go dials the host
	// the redacted endpoint names, so the dial error can name nothing else
	// and is kept.
	if !strings.Contains(err.Error(), "dial tcp") {
		t.Errorf("the fetch error = %v, want it to keep the dial error", err)
	}
}

// The *url.Error a failed fetch returns wraps an error that is itself text
// taken from the URL. url.Parse quotes the bytes it refused, so
// "http://ci:SECRET/part@host/keys", whose password holds a '/', fails with
// `invalid port ":SECRET" after host`; and a dial names the host and port Go
// read, which for "http://127.0.0.1:1/SECRET@host/keys" is the user and the
// start of the password to Python's proxy parser. Naming the endpoint through
// redact.URLCredentials leaves all of that in the wrapped error, so the
// detail is withheld unless the redacted endpoint names the host Go dialed.
func TestAttestWithholdsURLDerivedDetailInJWKSFetchError(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := josejwt.Signed(signer).Claims(josejwt.Claims{Subject: "s"}).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, url, endpoint string
		leaks               []string
	}{
		{"a password holding a slash is read as a port", "http://ci:p9jwksportsecret/part@example.invalid/keys",
			`"http://******@"`, []string{"p9jwksportsecret", "part"}},
		{"a bad escape in the password", "http://ci:p9%zzjwksescape@example.invalid/keys",
			`"http://******@example.invalid/keys"`, []string{"%zz", "jwksescape"}},
		{"the dialed host is the user to another parser", "http://127.0.0.1:1/p9jwksdialsecret@example.invalid/keys",
			`"http://******@"`, []string{"127.0.0.1", "p9jwksdialsecret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := New(WithToken(raw), WithJWKSUrl(tc.url)).Attest(nil)
			if err == nil {
				t.Fatal("Attest succeeded against an endpoint that cannot be fetched")
			}
			if !strings.Contains(err.Error(), "error fetching jwks") {
				t.Fatalf("Attest failed for another reason than the fetch: %v", err)
			}
			for _, leak := range tc.leaks {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("the fetch error carries %q from the URL's userinfo: %v", leak, err)
				}
			}
			if !strings.Contains(err.Error(), tc.endpoint) {
				t.Errorf("the fetch error = %v, want it to name the endpoint as %s", err, tc.endpoint)
			}
		})
	}
}
