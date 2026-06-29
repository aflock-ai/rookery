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

package archivista

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/upload", r.URL.Path)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var err error
		receivedBody, err = readBody(r)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "abc123"})
	}))
	defer server.Close()

	client := New(server.URL)
	env := dsse.Envelope{
		Payload:     []byte(`{"test": true}`),
		PayloadType: "application/vnd.in-toto+json",
	}

	gitoid, err := client.Store(context.Background(), env)
	require.NoError(t, err)
	require.Equal(t, "abc123", gitoid)
	require.NotEmpty(t, receivedBody)
}

func TestDownload(t *testing.T) {
	expectedEnv := dsse.Envelope{
		Payload:     []byte(`{"test": true}`),
		PayloadType: "application/vnd.in-toto+json",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/download/gitoid123", r.URL.Path)
		json.NewEncoder(w).Encode(expectedEnv)
	}))
	defer server.Close()

	client := New(server.URL)
	env, err := client.Download(context.Background(), "gitoid123")
	require.NoError(t, err)
	require.Equal(t, expectedEnv.PayloadType, env.PayloadType)
}

func TestSearchGitoids(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/query", r.URL.Path)

		var reqBody graphqlRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)
		require.Contains(t, reqBody.Query, "dsses")

		resp := graphqlResponse{
			Data: json.RawMessage(`{
				"dsses": {
					"edges": [
						{"node": {"gitoidSha256": "git1"}},
						{"node": {"gitoidSha256": "git2"}}
					]
				}
			}`),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	gitoids, err := client.SearchGitoids(context.Background(), SearchGitoidVariables{
		CollectionName: "test-step",
		SubjectDigests: []string{"sha256:abc"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"git1", "git2"}, gitoids)
}

func TestCustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer mytoken", r.Header.Get("Authorization"))
		require.Equal(t, "custom-value", r.Header.Get("X-Custom"))

		json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer mytoken")
	headers.Set("X-Custom", "custom-value")

	client := New(server.URL, WithHeaders(headers))
	_, err := client.Store(context.Background(), dsse.Envelope{
		Payload:     []byte(`{}`),
		PayloadType: "test",
	})
	require.NoError(t, err)
}

func TestStoreError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestGraphQLError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := graphqlResponse{
			Errors: []struct {
				Message string `json:"message"`
			}{
				{Message: "query failed"},
				{Message: "bad input"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.SearchGitoids(context.Background(), SearchGitoidVariables{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "query failed")
}

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf [4096]byte
	n, _ := r.Body.Read(buf[:])
	return buf[:n], nil
}

// TestNew_DefaultClientHasBoundedTimeout is the standard-CI regression guard for
// the unbounded-client hang: New() must install an http.Client with a positive
// Timeout (not the shared http.DefaultClient, which has none). Without it, a
// server that TCP-accepts then stalls would hang the caller forever — the
// ~20-min CI job-timeout hang this fixes.
func TestNew_DefaultClientHasBoundedTimeout(t *testing.T) {
	c := New("https://example.com")
	require.NotSame(t, http.DefaultClient, c.client,
		"default client must not be the shared http.DefaultClient")
	require.Positive(t, c.client.Timeout, "Archivista client must carry a bounded Timeout")
}

// TestStore_TimesOutOnStalledServer proves the bounded timeout actually fires:
// against a server that accepts the connection then never responds, Store()
// returns an error promptly instead of blocking forever. Uses an injected short
// timeout so the test is fast.
func TestStore_TimesOutOnStalledServer(t *testing.T) {
	block := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // accept, then stall until released
	}))
	// LIFO: close(block) runs BEFORE server.Close(), so Close() never deadlocks
	// waiting on the stalled handler goroutine.
	defer server.Close()
	defer close(block)

	c := New(server.URL, WithHTTPClient(&http.Client{Timeout: 250 * time.Millisecond}))
	done := make(chan error, 1)
	go func() {
		_, err := c.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err, "Store must fail (timeout) against a stalled server, not hang")
	case <-time.After(5 * time.Second):
		t.Fatal("Store hung past the client Timeout — the bounded-timeout fix is not in effect")
	}
}

// TestStore_RefusesCrossOriginRedirect is the standard-CI regression guard for
// the redirect-SSRF leg of #5987. The Archivista client carries the platform
// session bearer; New() must install a same-origin CheckRedirect so a
// compromised/MITM'd server cannot 302 the upload to a different origin and
// resend the bearer + DSSE bundle. Without the fix, the cross-origin redirect is
// followed silently and Store returns nil (the gap proven by the audit-tagged
// TestSecurity_R3_209). With the fix, Store returns an error and the attacker
// origin never receives the body.
func TestStore_RefusesCrossOriginRedirect(t *testing.T) {
	var attackerHit bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHit = true
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "leaked"})
	}))
	defer attacker.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cross-origin redirect to the attacker host (different scheme+host).
		http.Redirect(w, r, attacker.URL+"/upload", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	client := New(origin.URL)
	_, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.Error(t, err, "Store must refuse a cross-origin redirect (bearer would leak)")
	require.Contains(t, err.Error(), "cross-origin redirect")
	require.False(t, attackerHit, "the cross-origin redirect target must NOT receive the request body")
}

// TestStore_FollowsSameOriginRedirect proves the policy is not over-broad: a
// redirect that stays on the same origin (scheme+host) is still followed, so a
// legitimate path rewrite on the Archivista server keeps working.
func TestStore_FollowsSameOriginRedirect(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		// Same-origin redirect: /upload -> /v2/upload on the same host.
		http.Redirect(w, r, "/v2/upload", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/v2/upload", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "redirected-ok"})
	})
	server := httptest.NewServer(&mux)
	defer server.Close()

	client := New(server.URL)
	gitoid, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.NoError(t, err, "a same-origin redirect must still be followed")
	require.Equal(t, "redirected-ok", gitoid)
}
