// jade:ring local

package github

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tokenTransportFunc func(*http.Request) (*http.Response, error)

func (f tokenTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Keep the production URL checks while routing a synthetic endpoint to the test server.
func routeTokenServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	previous := tokenHTTPClient
	client := *previous
	client.Transport = tokenTransportFunc(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.URL.Scheme, copy.URL.Host = target.Scheme, target.Host
		copy.Host = target.Host
		return http.DefaultTransport.RoundTrip(copy)
	})
	tokenHTTPClient = &client
	t.Cleanup(func() { tokenHTTPClient = previous })
	server.URL = "https://vstoken.actions.githubusercontent.com"
}

func TestTokenAudienceReplacement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, []string{"witness"}, r.URL.Query()["audience"])
		assert.Equal(t, "retained", r.URL.Query().Get("other"))
		_, _ = w.Write([]byte(`{"value":"test-jwt"}`))
	}))
	defer server.Close()
	routeTokenServer(t, server)
	token, err := fetchToken(server.URL+"?audience=old&audience=second&other=retained", "test-bearer", "witness")
	require.NoError(t, err)
	require.Equal(t, "test-jwt", token)
}

func TestTokenResponseSizeBoundary(t *testing.T) {
	for _, size := range []int{maxResponseBodySize - 1, maxResponseBodySize, maxResponseBodySize + 1} {
		body, err := readResponseBody(strings.NewReader(strings.Repeat("x", size)))
		if size > maxResponseBodySize {
			require.Error(t, err)
			require.Empty(t, body)
		} else {
			require.NoError(t, err)
			require.Len(t, body, size)
		}
	}
}

func TestTokenRedirectDoesNotForwardBearer(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/capture", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"value":"redirected-jwt"}`))
	}))
	defer server.Close()
	routeTokenServer(t, server)
	token, err := fetchToken(server.URL+"/redirect", "test-bearer", "witness")
	require.Error(t, err)
	require.Empty(t, token)
	require.Equal(t, 1, requests)
}

func TestTokenEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{
		"http://vstoken.actions.githubusercontent.com/token",
		"https://attacker.test/token",
		"https://vstoken.actions.githubusercontent.com.attacker.test/token",
		"https://evilactions.githubusercontent.com/token",
		"https://user@vstoken.actions.githubusercontent.com/token",
		"https://vstoken.actions.githubusercontent.com:8443/token",
		"https://vstoken.actions.githubusercontent.com/token#fragment",
	} {
		t.Run(endpoint, func(t *testing.T) {
			previous := tokenHTTPClient
			client := *previous
			calls := 0
			client.Transport = tokenTransportFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, nil
			})
			tokenHTTPClient = &client
			t.Cleanup(func() { tokenHTTPClient = previous })
			token, err := fetchToken(endpoint, "test-bearer", "witness")
			require.ErrorContains(t, err, "invalid GitHub Actions token endpoint")
			require.Empty(t, token)
			require.Zero(t, calls)
		})
	}
}
