// Copyright 2025 The Aflock Authors
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

package ociref

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestResolveDigest_DigestRefShortCircuits verifies that when the input is
// already pinned to a digest the resolver returns immediately without
// contacting the registry.
func TestResolveDigest_DigestRefShortCircuits(t *testing.T) {
	const dgst = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	r := &Resolver{HTTPClient: failingClient(t)} // would explode if called
	got, err := r.Resolve("foo/bar@" + dgst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != dgst {
		t.Errorf("Resolve = %q, want %q", got, dgst)
	}
}

// TestResolveDigest_HappyPath verifies the HEAD-against-manifests flow:
// resolver issues HEAD /v2/<repo>/manifests/<tag>, reads Docker-Content-Digest
// from the response, returns it.
func TestResolveDigest_HappyPath(t *testing.T) {
	const wantDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		if r.URL.Path != "/v2/library/nginx/manifests/1.27" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		// Real registries advertise an Accept-Encoding list of media types;
		// the resolver should at minimum accept image manifests.
		if !strings.Contains(r.Header.Get("Accept"), "manifest") {
			t.Errorf("Accept header missing manifest media types: %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Docker-Content-Digest", wantDigest)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := &Resolver{
		HTTPClient: srv.Client(),
		HostOverride: map[string]string{
			"registry-1.docker.io": stripScheme(srv.URL),
		},
	}
	got, err := r.Resolve("nginx:1.27")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantDigest {
		t.Errorf("Resolve = %q, want %q", got, wantDigest)
	}
}

// TestResolveDigest_BearerAuth verifies the 401 → token endpoint → retry flow
// that nearly every public registry requires for anonymous reads.
func TestResolveDigest_BearerAuth(t *testing.T) {
	const wantDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	// Set up the token server first so we can embed its URL in the challenge.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("service") != "registry.example" {
			t.Errorf("unexpected service param: %q", r.URL.Query().Get("service"))
		}
		if r.URL.Query().Get("scope") != "repository:foo/bar:pull" {
			t.Errorf("unexpected scope param: %q", r.URL.Query().Get("scope"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "MY-BEARER"})
	}))
	defer tokenSrv.Close()

	// Registry: first call → 401 with WWW-Authenticate. Second call (with
	// Authorization: Bearer MY-BEARER) → 200 with digest.
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			challenge := fmt.Sprintf(`Bearer realm="%s",service="registry.example",scope="repository:foo/bar:pull"`, tokenSrv.URL)
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer MY-BEARER" {
			t.Errorf("Authorization = %q, want Bearer MY-BEARER", got)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", wantDigest)
		w.WriteHeader(http.StatusOK)
	}))
	defer registrySrv.Close()

	r := &Resolver{
		HTTPClient: registrySrv.Client(),
		HostOverride: map[string]string{
			"registry.example": stripScheme(registrySrv.URL),
		},
	}
	got, err := r.Resolve("registry.example/foo/bar:latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantDigest {
		t.Errorf("Resolve = %q, want %q", got, wantDigest)
	}
}

// TestResolveDigest_404 surfaces the registry's not-found response as an error.
func TestResolveDigest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	r := &Resolver{
		HTTPClient: srv.Client(),
		HostOverride: map[string]string{
			"gcr.io": stripScheme(srv.URL),
		},
	}
	_, err := r.Resolve("gcr.io/missing:nope")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

// TestResolveDigest_MissingDigestHeader surfaces a malformed registry response.
func TestResolveDigest_MissingDigestHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r := &Resolver{
		HTTPClient: srv.Client(),
		HostOverride: map[string]string{
			"gcr.io": stripScheme(srv.URL),
		},
	}
	_, err := r.Resolve("gcr.io/foo/bar:v1")
	if err == nil {
		t.Fatal("expected error when Docker-Content-Digest is missing")
	}
}

// failingClient returns an HTTP client whose RoundTripper unconditionally
// fails the test if invoked — used to verify the digest-ref short-circuit
// doesn't make any network calls.
func failingClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			t.Fatalf("unexpected HTTP call — digest-ref short-circuit failed")
			return nil, nil
		}),
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func stripScheme(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return u.Host
}
