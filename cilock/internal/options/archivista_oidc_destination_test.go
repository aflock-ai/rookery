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

package options

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

// ciTokenEndpoint stands in for GitHub's OIDC token endpoint: it answers with a
// token that names the audience it was minted for, so a test can see which
// audience reached which server.
func ciTokenEndpoint(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "ci-token-for:" + r.URL.Query().Get("audience")})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/token?x=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-bearer")
}

// recordingArchivista is an Archivista that records every Authorization it
// is sent.
func recordingArchivista(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"gitoid":"stored"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// TestArchivistaOIDCTokenNeverReachesAServerItDoesNotName is the leak: a job
// with `id-token: write` and --platform-url P that sets --archivista-server to
// any other server (a typo, a third-party or public Archivista, or an
// injected flag or env) used to hand that server a CI token minted for
// P/archivista, which P accepts as the repository's trusted upload
// credential; the server could replay it to upload as the repository. The
// client now refuses before any request, naming both.
func TestArchivistaOIDCTokenNeverReachesAServerItDoesNotName(t *testing.T) {
	ciTokenEndpoint(t)
	foreign, seen := recordingArchivista(t)
	o := archivistaOptionsFromFlags(t, "--archivista-oidc")
	o.Enable = true
	o.Url = foreign.URL
	o.Audience = "https://platform.example.com/archivista"

	client, err := o.Client()
	if err == nil {
		_, _ = client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	}
	for _, a := range seen() {
		require.NotContains(t, a, "platform.example.com", "a token for the platform reached another server")
	}
	require.Error(t, err, "the client must refuse to send a token whose audience names another server")
	require.ErrorContains(t, err, "https://platform.example.com/archivista")
	require.ErrorContains(t, err, foreign.URL)
}

// TestArchivistaOIDCBringYourOwnArchivista: a server that is not the
// platform, with its own audience (explicit, or the server URL itself), still
// gets a token, minted for that server.
func TestArchivistaOIDCBringYourOwnArchivista(t *testing.T) {
	for name, audience := range map[string]string{"explicit": "", "defaulted to the server URL": ""} {
		t.Run(name, func(t *testing.T) {
			ciTokenEndpoint(t)
			byo, seen := recordingArchivista(t)
			o := archivistaOptionsFromFlags(t, "--archivista-oidc")
			o.Enable = true
			o.Url = byo.URL
			o.Audience = audience
			if name == "explicit" {
				o.Audience = byo.URL + "/"
			}
			client, err := o.Client()
			require.NoError(t, err)
			_, err = client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
			require.NoError(t, err)
			got := seen()
			require.NotEmpty(t, got)
			require.True(t, strings.HasPrefix(got[0], "Bearer ci-token-for:"+byo.URL), "token %q", got[0])
		})
	}
}

// TestArchivistaAudienceNamesDestination sweeps the comparison: origin is
// scheme, host and effective port, compared without case; the path must be
// the one the server serves, trailing slash aside. Anything that is not an
// absolute URL cannot name a destination and is refused.
func TestArchivistaAudienceNamesDestination(t *testing.T) {
	const aud = "https://p.example/archivista"
	for _, c := range []struct {
		aud, dest string
		ok        bool
	}{
		{aud, "https://p.example/archivista", true},
		{aud, "https://p.example:443/archivista", true},
		{aud, "HTTPS://P.Example/archivista/", true},
		{"https://p.example:443/archivista/", "https://p.example/archivista", true},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/", true},
		{aud, "http://p.example/archivista", false},
		{aud, "http://p.example:443/archivista", false},
		{aud, "https://p.example:8443/archivista", false},
		{aud, "https://evil.example/archivista", false},
		{aud, "https://p.example.evil.example/archivista", false},
		{aud, "https://p.example/other", false},
		{aud, "https://p.example/archivista/extra", false},
		{aud, "https://p.example", false},
		{"archivista", "https://p.example/archivista", false},
		{"sigstore", "https://p.example/archivista", false},
		{"https://user@p.example/archivista", "https://p.example/archivista", false},
		{aud, "not a url", false},
	} {
		err := archivistaAudienceNamesDestination(c.aud, c.dest)
		if (err == nil) != c.ok {
			t.Errorf("audience %q to %q: err=%v, want ok=%v", c.aud, c.dest, err, c.ok)
		}
	}
	// The refusal says why: a bare audience names no server, and the fix is
	// the server's own URL.
	err := archivistaAudienceNamesDestination("archivista", "https://p.example/archivista")
	require.ErrorContains(t, err, "not an http(s) URL")
	require.ErrorContains(t, err, "--archivista-audience")
}

// TestResolvePlatformDefaults_ForeignArchivistaDoesNotInheritThePlatformAudience:
// --archivista-server elsewhere is not the platform's Archivista, so the
// platform's audience is not its default; the server's own URL is.
func TestResolvePlatformDefaults_ForeignArchivistaDoesNotInheritThePlatformAudience(t *testing.T) {
	isolateCredentialStore(t)
	clearAmbientOIDC(t)
	cmd, ro := newRunCmd(t)
	require.NoError(t, cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com",
		"--archivista-server", "https://archivista.corp.example", "-k", "key.pem"}))
	ro.ResolvePlatformDefaults(cmd)
	require.NotEqual(t, "https://platform.example.com/archivista", ro.ArchivistaOptions.Audience)
	cmd2, ro2 := newRunCmd(t)
	require.NoError(t, cmd2.ParseFlags([]string{"--platform-url", "https://platform.example.com", "-k", "key.pem"}))
	ro2.ResolvePlatformDefaults(cmd2)
	require.Equal(t, "https://platform.example.com/archivista", ro2.ArchivistaOptions.Audience,
		"the platform's own Archivista keeps the platform audience")
}
