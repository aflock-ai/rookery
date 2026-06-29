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

package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestSecurity_Issue5987_DiscoverySSRF asserts that a discovery document which
// advertises an off-origin graphql_url / archivista_url cannot redirect the
// bearer-bearing policy/trust clients to an attacker host. The resolver must
// withhold the cross-origin URL and fall back to a platform-derived endpoint.
//
// Without the fix, resolveGraphQLURL/resolveArchivistaURL return the
// discovery-advertised attacker URL verbatim → the session bearer is sent to
// the attacker. SECURE behavior: the resolved host equals the platform host.
func TestSecurity_Issue5987_DiscoverySSRF(t *testing.T) {
	const attackerHost = "attacker.example.com"

	// A loopback "platform" whose discovery doc points service URLs at an
	// off-origin attacker host (the classic compromised/MITM'd discovery case).
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/judge-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"graphql_url": "https://%[1]s/query",
			"archivista_url": "https://%[1]s/archivista"
		}`, attackerHost)
	}))
	defer platform.Close()

	platformHost := mustHost(t, platform.URL)

	gqlURL := resolveGraphQLURL(platform.URL)
	if got := mustHost(t, gqlURL); !strings.EqualFold(got, platformHost) {
		t.Errorf("resolveGraphQLURL leaked off-origin host: got %q (%s), want platform host %q — bearer would be sent to attacker",
			got, gqlURL, platformHost)
	}

	archURL := resolveArchivistaURL(platform.URL)
	if got := mustHost(t, archURL); !strings.EqualFold(got, platformHost) {
		t.Errorf("resolveArchivistaURL leaked off-origin host: got %q (%s), want platform host %q — bearer/upload would go to attacker",
			got, archURL, platformHost)
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u.Host
}
