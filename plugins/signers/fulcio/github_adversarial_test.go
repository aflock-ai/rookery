//go:build audit

package fulcio

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Area 1: URL construction edge cases
// =============================================================================

func TestAdversarial_FetchToken_URLFragmentIdentifiers(t *testing.T) {
	// Fragment identifiers (#fragment) in HTTP URLs should not be sent to
	// the server. But url.Parse preserves them, and u.String() will
	// re-emit them. This test checks whether a fragment in the tokenURL
	// causes the audience parameter to be silently placed before the
	// fragment (which would work) or causes some other misbehavior.

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the audience parameter is present in the query
		if r.URL.Query().Get("audience") != "sigstore" {
			t.Errorf("Expected audience=sigstore in query, got: %s", r.URL.RawQuery)
			http.Error(w, "bad audience", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"count":1,"value":"token-with-fragment"}`)
	}))
	defer server.Close()

	// BUG PROBE: URL with a fragment identifier
	// Fragment identifiers are not sent to the server by the HTTP client,
	// so this should still work. But the URL construction might be surprising.
	tokenURL := server.URL + "/token#somefragment"
	token, err := fetchToken(tokenURL, "bearer-tok", "sigstore")
	require.NoError(t, err, "fetchToken should handle fragment identifiers gracefully")
	assert.Equal(t, "token-with-fragment", token)
}

func TestAdversarial_FetchToken_URLWithPercentEncodedChars(t *testing.T) {
	// Test with percent-encoded characters in the URL path and query.
	// url.Parse + url.Query() + q.Encode() might double-encode.

	var receivedPath string
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"count":1,"value":"encoded-token"}`)
	}))
	defer server.Close()

	// URL with already percent-encoded characters in path
	tokenURL := server.URL + "/token%2Fwith%2Fslashes"
	token, err := fetchToken(tokenURL, "bearer", "sigstore")
	require.NoError(t, err)
	assert.Equal(t, "encoded-token", token)

	// Check that the path was not double-encoded
	t.Logf("Received path: %s", receivedPath)
	t.Logf("Received query: %s", receivedQuery)

	// Now test with percent-encoded query parameter already present
	tokenURL = server.URL + "/token?foo=bar%20baz"
	token, err = fetchToken(tokenURL, "bearer", "sigstore")
	require.NoError(t, err)
	assert.Equal(t, "encoded-token", token)

	// Verify query parameters are properly preserved
	assert.Contains(t, receivedQuery, "audience=sigstore")
	assert.Contains(t, receivedQuery, "foo=bar+baz", // url.Values.Encode() uses + for spaces
		"Pre-existing percent-encoded query params should be preserved (though format may change)")
}

func TestAdversarial_FetchToken_AudienceMatchingExistingAudience(t *testing.T) {
	// When the URL already has audience=sigstore and we request audience=sigstore,
	// the code should NOT error because the condition is:
	//   q.Get("audience") != audience && q.Get("audience") != ""
	// If existing == requested, the first condition is false, so the whole
	// expression is false. This should succeed.

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify only one audience parameter
		audiences := r.URL.Query()["audience"]
		if len(audiences) != 1 {
			t.Errorf("Expected exactly 1 audience param, got %d: %v", len(audiences), audiences)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"count":1,"value":"matching-audience-token"}`)
	}))
	defer server.Close()

	tokenURL := server.URL + "/token?audience=sigstore"
	token, err := fetchToken(tokenURL, "bearer", "sigstore")
	require.NoError(t, err, "fetchToken should succeed when existing audience matches requested audience")
	assert.Equal(t, "matching-audience-token", token)
}

func TestAdversarial_FetchToken_AudienceConflict(t *testing.T) {
	// When the URL already has audience=different-audience and we request
	// audience=sigstore, the code should error.

	_, err := fetchToken("https://example.com/token?audience=other", "bearer", "sigstore")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tokenURL already has an audience")
}

func TestAdversarial_FetchToken_MultipleAudienceParams(t *testing.T) {
	// BUG PROBE: What if the URL has multiple audience query parameters?
	// url.Query().Get() returns the FIRST one. So if the URL has:
	//   ?audience=sigstore&audience=evil
	// Get("audience") returns "sigstore", which matches, so no error.
	// But q.Set("audience", "sigstore") replaces ALL values.
	// This is correct behavior, but worth documenting.

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		audiences := r.URL.Query()["audience"]
		t.Logf("Audiences received: %v", audiences)
		// After Set(), there should be only 1
		if len(audiences) != 1 {
			t.Errorf("Expected 1 audience after Set(), got %d", len(audiences))
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"count":1,"value":"multi-audience-token"}`)
	}))
	defer server.Close()

	// Multiple audience params, first one matches
	tokenURL := server.URL + "/token?audience=sigstore&audience=evil"
	token, err := fetchToken(tokenURL, "bearer", "sigstore")
	require.NoError(t, err, "Should succeed because Get() returns first value which matches")
	assert.Equal(t, "multi-audience-token", token)
}

// =============================================================================
// Area 3: Body truncation splitting multi-byte UTF-8 characters
// =============================================================================

func TestAdversarial_FetchToken_TruncationSplitsMultibyteUTF8(t *testing.T) {
	// BUG: The body truncation logic does bodyStr[:500] which operates on
	// bytes, not runes. If the 500th byte falls in the middle of a
	// multi-byte UTF-8 character, the resulting string will contain an
	// invalid UTF-8 sequence.
	//
	// This is a real bug because:
	// 1. The truncated string appears in error messages
	// 2. Invalid UTF-8 can cause issues with logging, JSON encoding, etc.

	// Create a response body where the 500th byte falls in the middle
	// of a multi-byte character (e.g., emoji or CJK character).
	// U+1F600 (😀) is 4 bytes in UTF-8: f0 9f 98 80
	// We need 498 ASCII bytes + the emoji to put byte 500 inside the emoji.

	// 498 ASCII chars + 4-byte emoji = position 498-501 for the emoji
	// bodyStr[:500] would cut at byte 500, which is inside the emoji (byte 3 of 4)
	body := strings.Repeat("A", 498) + "😀" + strings.Repeat("B", 100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
	require.Error(t, err)

	// The error message should contain the truncated body.
	// Check if the truncation produced invalid UTF-8.
	errMsg := err.Error()

	// Find the truncated body in the error message
	// The body appears after "body: " in the error
	bodyIdx := strings.Index(errMsg, "body: ")
	if bodyIdx >= 0 {
		truncatedPart := errMsg[bodyIdx+6:]
		// Remove the trailing "..." and wrapping
		if idx := strings.Index(truncatedPart, "..."); idx >= 0 {
			truncatedPart = truncatedPart[:idx]
		}

		// Check for valid UTF-8
		isValidUTF8 := true
		for i := 0; i < len(truncatedPart); {
			r, size := rune(truncatedPart[i]), 1
			if r >= 0x80 {
				var ok bool
				r, size = decodeRuneInString(truncatedPart[i:])
				ok = r != 0xFFFD || size != 1
				if !ok {
					isValidUTF8 = false
					break
				}
			}
			i += size
		}

		if !isValidUTF8 {
			t.Errorf("UTF-8 truncation fix failed: body truncation still produced invalid UTF-8. "+
				"Last 10 bytes of truncated: %q", truncatedPart[max(0, len(truncatedPart)-10):])
		} else {
			t.Log("FIXED: Truncation produced valid UTF-8 (rune-safe boundary)")
		}
	}
}

// decodeRuneInString is a minimal UTF-8 rune decoder for test use
func decodeRuneInString(s string) (rune, int) {
	if len(s) == 0 {
		return 0xFFFD, 0
	}
	b := s[0]
	switch {
	case b < 0x80:
		return rune(b), 1
	case b < 0xC0:
		return 0xFFFD, 1 // continuation byte at start = invalid
	case b < 0xE0:
		if len(s) < 2 {
			return 0xFFFD, 1
		}
		return rune(b&0x1F)<<6 | rune(s[1]&0x3F), 2
	case b < 0xF0:
		if len(s) < 3 {
			return 0xFFFD, 1
		}
		return rune(b&0x0F)<<12 | rune(s[1]&0x3F)<<6 | rune(s[2]&0x3F), 3
	default:
		if len(s) < 4 {
			return 0xFFFD, 1
		}
		return rune(b&0x07)<<18 | rune(s[1]&0x3F)<<12 | rune(s[2]&0x3F)<<6 | rune(s[3]&0x3F), 4
	}
}

func TestAdversarial_FetchToken_TruncationSplitsMultibyteJSON(t *testing.T) {
	// Same bug but in the JSON unmarshal error path (line 130).
	// Both truncation sites use the same bodyStr[:500] pattern.

	// Create a body that is valid-ish but not valid JSON, with multi-byte chars
	// at position 498-501 so the truncation splits them.
	body := strings.Repeat("x", 498) + "\xf0\x9f\x98\x80" + strings.Repeat("y", 100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 OK so we reach the JSON parse path
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
	require.Error(t, err)
	// If we get here without panic, at least the truncation didn't crash.
	// But the error message may contain invalid UTF-8.
	t.Logf("Error message (may contain invalid UTF-8): %q", err.Error())
}

// =============================================================================
// Area 7: Audience parameter edge cases
// =============================================================================

func TestAdversarial_FetchToken_AudienceWithSpecialChars(t *testing.T) {
	// What if the audience contains special URL characters?

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aud := r.URL.Query().Get("audience")
		t.Logf("Received audience: %q", aud)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"count":1,"value":"special-audience-token"}`)
	}))
	defer server.Close()

	// Audience with ampersand, equals, etc.
	specialAudiences := []string{
		"sig&store",
		"sig=store",
		"sig store",
		"sig+store",
		"https://audience.example.com/path?param=value",
	}

	for _, aud := range specialAudiences {
		t.Run(aud, func(t *testing.T) {
			token, err := fetchToken(server.URL+"/token", "bearer", aud)
			require.NoError(t, err, "fetchToken should handle audience with special chars: %q", aud)
			assert.Equal(t, "special-audience-token", token)
		})
	}
}

// =============================================================================
// Area 2: Retry logic edge cases
// =============================================================================

func TestAdversarial_FetchToken_RetryOnHTTP2Fallback(t *testing.T) {
	// The HTTP/2 fallback path creates a new client but doesn't check the
	// error from http.NewRequest (it reuses the same req). This is fine
	// because req is created before the fallback. But the more interesting
	// edge case: after fallback, if the retry with HTTP/1.1 also fails,
	// we continue the retry loop with the local client (not the global one).
	// On subsequent retries, the local client is still the HTTP/1.1 fallback.
	// This is correct behavior but should be documented.

	var attemptCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attemptCount, 1)
		if count < 3 {
			http.Error(w, "failing", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"count":1,"value":"retry-token"}`)
	}))
	defer server.Close()

	token, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
	require.NoError(t, err)
	assert.Equal(t, "retry-token", token)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attemptCount))
}

func TestAdversarial_FetchToken_ServerReturnsBodyThenCloses(t *testing.T) {
	// Test behavior when the server sends partial response body then closes.
	// io.ReadAll should return an error.

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// Write only a few bytes then let the handler return (connection closes)
		fmt.Fprint(w, `{"count":1,`)
		// Don't complete the response
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
	require.Error(t, err)
	t.Logf("Error from partial response: %v", err)
}

// =============================================================================
// Area 8: Race condition on githubHTTPClient
// =============================================================================

func TestAdversarial_FetchToken_ConcurrentAccess(t *testing.T) {
	// BUG PROBE: githubHTTPClient is a package-level var. Multiple
	// concurrent calls to fetchToken all read from it. The HTTP/2 fallback
	// path does `githubHTTPClient.Transport.(*http.Transport).Clone()` which
	// reads the global var. If another goroutine was modifying it at the
	// same time, that would be a data race. However, the code never writes
	// to githubHTTPClient, so this should be safe.
	//
	// BUT: The initial read `client := githubHTTPClient` on line 42 is a
	// pointer copy, so all goroutines share the same underlying client.
	// This is fine because http.Client is safe for concurrent use.
	//
	// The real concern: the type assertion on line 83:
	//   githubHTTPClient.Transport.(*http.Transport).Clone()
	// reads the global directly (not the local `client`). This is fine
	// as long as no one writes to it, but it's inconsistent with using
	// the local `client` variable everywhere else.

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"count":1,"value":"concurrent-token"}`)
	}))
	defer server.Close()

	const goroutines = 20
	var wg sync.WaitGroup
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		assert.NoError(t, err, "goroutine %d got unexpected error", i)
	}
}

// =============================================================================
// Additional adversarial edge cases for fetchToken
// =============================================================================

func TestAdversarial_FetchToken_ExtremelyLargeResponseBody(t *testing.T) {
	// BUG PROBE: io.ReadAll has no size limit. A malicious server could
	// return a very large response body, causing OOM.
	// We test with a moderately large body (not truly adversarial size
	// to avoid killing the test runner).

	// 10MB response body
	largeBody := strings.Repeat("X", 10*1024*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, largeBody)
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
	require.Error(t, err, "Should fail because large body is not valid JSON")

	// The function does NOT limit response body size. This is a potential
	// denial-of-service vector if the token endpoint is compromised.
	t.Log("NOTE: fetchToken has no response body size limit. io.ReadAll will read the entire response into memory. " +
		"A compromised or malicious token endpoint could cause OOM by returning a very large response.")
}

func TestAdversarial_FetchToken_ResponseWithNullBytes(t *testing.T) {
	// What happens when the response contains null bytes?
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{\"count\":1,\"value\":\"token\x00with\x00nulls\"}"))
	}))
	defer server.Close()

	token, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
	if err != nil {
		t.Logf("fetchToken with null bytes in value: error=%v", err)
	} else {
		// BUG PROBE: Does the token contain null bytes?
		if strings.Contains(token, "\x00") {
			t.Errorf("BUG: fetchToken returned a token containing null bytes: %q. "+
				"This could cause issues downstream when the token is used in HTTP headers.", token)
		}
	}
}

func TestAdversarial_FetchToken_InvalidURLScheme(t *testing.T) {
	// What happens with non-HTTP URL schemes?
	testCases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"ftp scheme", "ftp://example.com/token", true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"data scheme", "data:text/plain,hello", true},
		{"file scheme", "file:///etc/passwd", true},
		{"empty scheme", "://example.com/token", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetchToken(tc.url, "bearer", "sigstore")
			if tc.wantErr {
				require.Error(t, err, "fetchToken should reject URL with scheme: %s", tc.url)
			}
			t.Logf("URL=%q err=%v", tc.url, err)
		})
	}
}

func TestAdversarial_FetchToken_TokenValueWithSpecialChars(t *testing.T) {
	// Test that tokens with special characters are returned correctly
	specialTokens := []string{
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		"token with spaces",
		"token\twith\ttabs",
		"token\nwith\nnewlines",
		`token"with"quotes`,
	}

	for _, expectedToken := range specialTokens {
		t.Run(fmt.Sprintf("token=%q", expectedToken[:min(20, len(expectedToken))]), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := map[string]interface{}{
					"count": 1,
					"value": expectedToken,
				}
				json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			token, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
			require.NoError(t, err)
			assert.Equal(t, expectedToken, token)
		})
	}
}

func TestAdversarial_FetchToken_BearerTokenInjection(t *testing.T) {
	// BUG PROBE: The bearer token is concatenated into the Authorization
	// header as "bearer " + bearer. What if the bearer token contains
	// newline characters that could inject additional headers?
	// In Go's net/http, headers with newlines are rejected, so this should
	// fail safely.

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"count":1,"value":"injected-token"}`)
	}))
	defer server.Close()

	// Try to inject via newline in bearer token
	_, err := fetchToken(server.URL+"/token", "bearer\r\nX-Injected: true", "sigstore")
	if err != nil {
		t.Logf("Header injection correctly prevented: %v", err)
	} else {
		t.Error("BUG: fetchToken should reject bearer tokens containing newline characters, " +
			"or Go's HTTP client should reject them. The request succeeded, which could indicate " +
			"a header injection vulnerability.")
	}
}

func TestAdversarial_FetchToken_EmptyResponseOn200(t *testing.T) {
	// Test empty JSON object on 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
	require.Error(t, err, "Should fail because value is empty string (zero value)")
	assert.Contains(t, err.Error(), "empty token value")
}

func TestAdversarial_FetchToken_NonStringTokenValue(t *testing.T) {
	// BUG PROBE: What if value is a number or nested object instead of a string?
	testCases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"value is number", `{"count":1,"value":12345}`, true},
		{"value is null", `{"count":1,"value":null}`, true},
		{"value is bool", `{"count":1,"value":true}`, true},
		{"value is array", `{"count":1,"value":["a","b"]}`, true},
		{"value is object", `{"count":1,"value":{"nested":"obj"}}`, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()

			_, err := fetchToken(server.URL+"/token", "bearer", "sigstore")
			if tc.wantErr {
				require.Error(t, err, "fetchToken should error for body: %s", tc.body)
			}
			t.Logf("body=%s err=%v", tc.body, err)
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
