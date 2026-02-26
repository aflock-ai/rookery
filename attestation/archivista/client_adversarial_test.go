//go:build audit

package archivista

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// URL handling and injection
// ==========================================================================

// TestSecurity_R3_200_NoURLSchemeValidation proves that the Client constructor
// accepts any URL scheme without validation. A caller could accidentally
// create a client with file://, ftp://, or javascript: URLs.
//
// BUG [MEDIUM]: client.go:78-88 — New() does not validate the URL scheme.
// Unlike the timestamp package which validates HTTPS, archivista.New()
// accepts arbitrary schemes including file:// and plaintext http://.
func TestSecurity_R3_200_NoURLSchemeValidation(t *testing.T) {
	dangerousURLs := []struct {
		name string
		url  string
	}{
		{"file scheme", "file:///etc/passwd"},
		{"ftp scheme", "ftp://internal-server/data"},
		{"javascript scheme", "javascript:alert(1)"},
		{"empty string", ""},
		{"just a path", "/api/v1"},
		{"plaintext HTTP", "http://example.com"},
	}

	for _, tc := range dangerousURLs {
		t.Run(tc.name, func(t *testing.T) {
			// All of these succeed without error — there's no validation.
			c := New(tc.url)
			assert.NotNil(t, c,
				"BUG [MEDIUM]: New(%q) succeeds without URL validation. "+
					"File: client.go:78-88", tc.url)
		})
	}
}

// TestSecurity_R3_201_DownloadPathTraversal verifies that url.PathEscape
// is used on the gitoid in Download. It documents the actual server-side
// behavior after Go's HTTP stack decodes the percent-encoded path.
//
// Note: r.URL.Path on the server side is the decoded path. The wire format
// uses percent-encoding from url.PathEscape, but the server's parsed URL
// always shows the decoded version. The important thing is the server's
// HTTP router sees the gitoid as a single path segment.
func TestSecurity_R3_201_DownloadPathTraversal(t *testing.T) {
	tests := []struct {
		name   string
		gitoid string
	}{
		{"path traversal", "../../admin/secrets"},
		{"query injection", "foo?admin=true"},
		{"fragment injection", "foo#admin"},
		{"empty gitoid", ""},
		{"normal gitoid", "abc123def456"},
		{"url encoded traversal", "%2e%2e%2f%2e%2e%2fadmin"},
		{"null byte", "foo\x00bar"},
		{"backslash traversal", `foo\..\bar`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var receivedPath string
			var receivedRawPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				receivedRawPath = r.URL.RawPath
				json.NewEncoder(w).Encode(dsse.Envelope{
					Payload:     []byte("{}"),
					PayloadType: "test",
				})
			}))
			defer server.Close()

			client := New(server.URL)
			_, err := client.Download(context.Background(), tc.gitoid)
			// We don't assert on error — some gitoids may fail.
			// The key assertion is NO PANIC.
			_ = err

			// Just verify the server received something and we didn't panic.
			t.Logf("gitoid=%q -> Path=%q RawPath=%q", tc.gitoid, receivedPath, receivedRawPath)
		})
	}
}

// TestSecurity_R3_202_DownloadNewlineInGitoid proves that gitoid values
// containing newlines or CRLF sequences are properly handled and don't
// cause header injection.
func TestSecurity_R3_202_DownloadNewlineInGitoid(t *testing.T) {
	injectionGitoids := []struct {
		name   string
		gitoid string
	}{
		{"newline", "foo\nHost: evil.com"},
		{"CRLF", "foo\r\nX-Injected: true"},
		{"null byte", "foo\x00bar"},
	}

	for _, tc := range injectionGitoids {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(dsse.Envelope{
					Payload:     []byte("{}"),
					PayloadType: "test",
				})
			}))
			defer server.Close()

			client := New(server.URL)
			// Should either succeed with escaped gitoid or return error.
			// Must NOT panic.
			_, err := client.Download(context.Background(), tc.gitoid)
			_ = err // error is acceptable, panic is not
		})
	}
}

// ==========================================================================
// Response body size limits
// ==========================================================================

// TestSecurity_R3_203_DownloadUnboundedResponseBody proves that Download
// reads the entire response body without any size limit. A malicious
// archivista server could send a multi-GB JSON response causing OOM.
//
// BUG [HIGH]: client.go:141 — json.NewDecoder(resp.Body).Decode() reads
// the entire response without size limit. The Store error path uses
// readLimitedErrorBody (capped at 1MB), but the success path is unbounded.
func TestSecurity_R3_203_DownloadUnboundedResponseBody(t *testing.T) {
	// Server sends a large but valid JSON response.
	const payloadSize = 5 << 20 // 5MB
	largePayload := strings.Repeat("A", payloadSize)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send a huge envelope with a massive payload field.
		fmt.Fprintf(w, `{"payload":"%s","payloadType":"test"}`, largePayload)
	}))
	defer server.Close()

	client := New(server.URL)
	env, err := client.Download(context.Background(), "test-gitoid")

	// This succeeds and reads the entire 5MB into memory.
	assert.NoError(t, err,
		"BUG [HIGH]: Download reads entire response body with no size limit. "+
			"A malicious server can OOM the client. File: client.go:141")
	assert.Greater(t, len(env.Payload), payloadSize/2,
		"BUG [HIGH]: The entire oversized response was decoded into memory")
}

// TestSecurity_R3_204_StoreUnboundedResponseBody proves that Store's
// success path also reads without size limit.
//
// BUG [HIGH]: client.go:116 — json.NewDecoder(resp.Body).Decode() for
// the store response has no size limit on the success path.
func TestSecurity_R3_204_StoreUnboundedResponseBody(t *testing.T) {
	const junkSize = 2 << 20 // 2MB of junk after the gitoid

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The JSON decoder will stop after the first complete JSON object,
		// but the TCP connection still receives all the data.
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"gitoid":"abc123"}`)
		// Extra data after the JSON — decoder ignores it.
		w.Write([]byte(strings.Repeat("X", junkSize)))
	}))
	defer server.Close()

	client := New(server.URL)
	gitoid, err := client.Store(context.Background(), dsse.Envelope{
		Payload:     []byte(`{}`),
		PayloadType: "test",
	})

	assert.NoError(t, err)
	assert.Equal(t, "abc123", gitoid)
	t.Logf("DESIGN NOTE [MEDIUM]: Store response decoding stops at first JSON " +
		"object, but the response body is not explicitly limited. Extra data " +
		"after the JSON object is ignored but still transmitted. File: client.go:116")
}

// TestSecurity_R3_205_GraphQLUnboundedResponseBody proves that the GraphQL
// query response is also read without size limit.
//
// BUG [HIGH]: client.go:233 — json.NewDecoder(resp.Body).Decode() for
// graphql response has no size limit.
func TestSecurity_R3_205_GraphQLUnboundedResponseBody(t *testing.T) {
	// Server returns a GraphQL response with many edges.
	const edgeCount = 10000

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		edges := make([]string, edgeCount)
		for i := range edges {
			edges[i] = fmt.Sprintf(`{"node":{"gitoidSha256":"gitoid-%d"}}`, i)
		}
		fmt.Fprintf(w, `{"data":{"dsses":{"edges":[%s]}}}`, strings.Join(edges, ","))
	}))
	defer server.Close()

	client := New(server.URL)
	gitoids, err := client.SearchGitoids(context.Background(), SearchGitoidVariables{
		CollectionName: "test",
	})

	assert.NoError(t, err,
		"BUG [HIGH]: GraphQL response body has no size limit. "+
			"A malicious server can send unlimited data. File: client.go:233")
	assert.Equal(t, edgeCount, len(gitoids),
		"All %d edges were decoded without limit", edgeCount)
}

// ==========================================================================
// GraphQL security
// ==========================================================================

// TestSecurity_R3_206_GraphQLQueryIsConstant verifies that the GraphQL query
// string is a compile-time constant and user-supplied variables are passed
// as JSON parameters, not interpolated into the query string.
// This is CORRECT behavior — the test confirms it.
func TestSecurity_R3_206_GraphQLQueryIsConstant(t *testing.T) {
	var capturedBody graphqlRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Write([]byte(`{"data":{"dsses":{"edges":[]}}}`))
	}))
	defer server.Close()

	client := New(server.URL)

	// Try injection via variable values.
	maliciousVars := SearchGitoidVariables{
		CollectionName: `test" OR 1=1 --`,
		SubjectDigests: []string{`sha256:abc"; DROP TABLE dsses; --`},
		Attestations:   []string{`type1", deleteAll: true, extra: "`},
	}

	_, err := client.SearchGitoids(context.Background(), maliciousVars)
	assert.NoError(t, err) // Server accepted it

	// Verify the query is a constant — not containing any injection strings.
	assert.NotContains(t, capturedBody.Query, "DROP TABLE",
		"GraphQL query should be a constant, not contain injected values")
	assert.NotContains(t, capturedBody.Query, "OR 1=1",
		"GraphQL query should be a constant, not contain injected values")
	assert.Contains(t, capturedBody.Query, "dsses",
		"Query should be the standard search query")

	// The malicious strings should be in variables, properly parameterized.
	varsJSON, err := json.Marshal(capturedBody.Variables)
	require.NoError(t, err)
	assert.Contains(t, string(varsJSON), `OR 1=1`,
		"Malicious input is contained in variables (parameterized), not in query")
}

// TestSecurity_R3_207_GraphQLErrorLeaksInfo tests whether GraphQL errors
// from the server are propagated to the caller, potentially leaking
// server-internal information.
//
// DESIGN NOTE [LOW]: client.go:238-243 — GraphQL error messages from the
// server are joined and returned verbatim. A server could include internal
// details (table names, query plans, etc.) in error messages.
func TestSecurity_R3_207_GraphQLErrorLeaksInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := graphqlResponse{
			Errors: []struct {
				Message string `json:"message"`
			}{
				{Message: "column dsses.internal_id does not exist at /app/internal/db/postgres.go:42"},
				{Message: "user: admin@internal.corp has insufficient permissions"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.SearchGitoids(context.Background(), SearchGitoidVariables{
		CollectionName: "test",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "internal_id",
		"DESIGN NOTE [LOW]: GraphQL error messages from server are returned "+
			"verbatim, potentially leaking internal details. File: client.go:238-243")
	assert.Contains(t, err.Error(), "admin@internal.corp",
		"Server-internal email addresses leak through error messages")
}

// ==========================================================================
// HTTP client security
// ==========================================================================

// TestSecurity_R3_208_DefaultClientNoTimeout proves that the default Client
// uses http.DefaultClient which has no timeout.
//
// BUG [MEDIUM]: client.go:81 — default client is http.DefaultClient which
// has zero Timeout. Without a context deadline, requests can hang forever.
func TestSecurity_R3_208_DefaultClientNoTimeout(t *testing.T) {
	c := New("https://example.com")
	assert.Equal(t, http.DefaultClient, c.client,
		"BUG [MEDIUM]: Default client is http.DefaultClient with no timeout. "+
			"Callers must always use context deadlines. File: client.go:81")
	assert.Zero(t, c.client.Timeout,
		"http.DefaultClient has zero Timeout")
}

// TestSecurity_R3_209_DefaultClientFollowsRedirects proves that the default
// http.Client follows redirects, which could lead to SSRF.
//
// BUG [MEDIUM]: client.go:81 — http.DefaultClient follows up to 10 redirects.
// A compromised archivista server could redirect to internal services.
func TestSecurity_R3_209_DefaultClientFollowsRedirects(t *testing.T) {
	var redirectCount int

	finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "redirected"})
	}))
	defer finalServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		http.Redirect(w, r, finalServer.URL+"/upload", http.StatusTemporaryRedirect)
	}))
	defer redirectServer.Close()

	client := New(redirectServer.URL)
	gitoid, err := client.Store(context.Background(), dsse.Envelope{
		Payload:     []byte(`{}`),
		PayloadType: "test",
	})

	// The redirect is followed silently.
	assert.NoError(t, err,
		"BUG [MEDIUM]: Client follows redirects to arbitrary servers. "+
			"A compromised archivista could redirect to internal services. "+
			"File: client.go:81")
	assert.Equal(t, "redirected", gitoid)
	assert.Equal(t, 1, redirectCount,
		"At least one redirect was silently followed")
}

// ==========================================================================
// Error handling
// ==========================================================================

// TestSecurity_R3_210_ErrorBodyLeakage proves that error responses include
// up to 500 chars of the response body, which could contain sensitive data.
//
// DESIGN NOTE [LOW]: client.go:40-47 — readLimitedErrorBody returns up to
// 500 chars of the response body in error messages. A server could include
// sensitive data (tokens, keys, internal paths) in error responses.
func TestSecurity_R3_210_ErrorBodyLeakage(t *testing.T) {
	sensitiveError := "Error: authentication failed for user admin@internal.corp " +
		"with token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature " +
		"against database postgres://admin:s3cret@10.0.0.5:5432/archivista"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(sensitiveError))
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.Store(context.Background(), dsse.Envelope{
		Payload:     []byte(`{}`),
		PayloadType: "test",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin@internal.corp",
		"DESIGN NOTE [LOW]: Error body leaks sensitive information from server "+
			"response. File: client.go:40-47, readLimitedErrorBody")
	assert.Contains(t, err.Error(), "s3cret",
		"Database credentials leak through error messages")
}

// TestSecurity_R3_211_ErrorBodyTruncation verifies that very large error
// bodies are truncated to prevent OOM in error messages.
func TestSecurity_R3_211_ErrorBodyTruncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// Send 2MB error body.
		w.Write([]byte(strings.Repeat("E", 2<<20)))
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.Store(context.Background(), dsse.Envelope{
		Payload:     []byte(`{}`),
		PayloadType: "test",
	})

	require.Error(t, err)
	// readLimitedErrorBody caps at 1MB read, then truncates string to 500 chars.
	assert.Less(t, len(err.Error()), 1000,
		"Error message should be truncated, not include megabytes of data")
}

// ==========================================================================
// Concurrent safety
// ==========================================================================

// TestSecurity_R3_212_ConcurrentStoreRequests verifies that concurrent
// Store calls on the same Client don't race.
func TestSecurity_R3_212_ConcurrentStoreRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	client := New(server.URL)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := client.Store(context.Background(), dsse.Envelope{
				Payload:     []byte(fmt.Sprintf(`{"idx":%d}`, idx)),
				PayloadType: "test",
			})
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d should succeed", i)
	}
}

// TestSecurity_R3_213_ConcurrentDownloadRequests verifies that concurrent
// Download calls on the same Client don't race.
func TestSecurity_R3_213_ConcurrentDownloadRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(dsse.Envelope{
			Payload:     []byte("{}"),
			PayloadType: "test",
		})
	}))
	defer server.Close()

	client := New(server.URL)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := client.Download(context.Background(), fmt.Sprintf("gitoid-%d", idx))
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d should succeed", i)
	}
}

// TestSecurity_R3_214_ConcurrentSearchGitoids verifies that concurrent
// SearchGitoids calls on the same Client don't race.
func TestSecurity_R3_214_ConcurrentSearchGitoids(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"dsses":{"edges":[{"node":{"gitoidSha256":"g1"}}]}}}`))
	}))
	defer server.Close()

	client := New(server.URL)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := client.SearchGitoids(context.Background(), SearchGitoidVariables{
				CollectionName: fmt.Sprintf("step-%d", idx),
			})
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d should succeed", i)
	}
}

// TestSecurity_R3_215_ConcurrentHeaderModification tests whether concurrent
// requests with a shared Client that has custom headers causes a race.
//
// DESIGN NOTE [INFO]: The applyHeaders method reads c.headers which is set
// at construction time and never mutated afterward. This is safe for
// concurrent reads. But if someone mutated the original headers map
// after construction, WithHeaders clones it, so this is also safe.
func TestSecurity_R3_215_ConcurrentHeaderModification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer token123")
	headers.Set("X-Custom", "value")

	client := New(server.URL, WithHeaders(headers))

	// Mutate original headers after construction — should NOT affect client
	// because WithHeaders clones.
	headers.Set("Authorization", "Bearer MUTATED")

	const goroutines = 50
	var wg sync.WaitGroup

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = client.Store(context.Background(), dsse.Envelope{
				Payload:     []byte(`{}`),
				PayloadType: "test",
			})
		}(i)
	}
	wg.Wait()

	// If we get here without race detector complaints, the test passes.
}

// ==========================================================================
// Malformed response handling
// ==========================================================================

// TestSecurity_R3_216_StoreMalformedResponses tests Store with various
// malformed server responses.
func TestSecurity_R3_216_StoreMalformedResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
	}{
		{"valid", 200, `{"gitoid":"abc"}`, false},
		{"empty JSON", 200, `{}`, false},
		{"invalid JSON", 200, `{corrupt`, true},
		{"empty body", 200, ``, true},
		{"null", 200, `null`, false},
		{"array", 200, `[1,2,3]`, true},
		{"500 error", 500, `server error`, true},
		{"HTML login page", 200, `<html>login</html>`, true},
		{"truncated JSON", 200, `{"gitoid":"abc`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := New(server.URL)
			_, err := client.Store(context.Background(), dsse.Envelope{
				Payload:     []byte(`{}`),
				PayloadType: "test",
			})

			if tc.wantErr {
				assert.Error(t, err, "expected error for: %s", tc.name)
			} else {
				assert.NoError(t, err, "unexpected error for: %s", tc.name)
			}
		})
	}
}

// TestSecurity_R3_217_DownloadMalformedEnvelope tests Download with
// malformed DSSE envelope responses.
func TestSecurity_R3_217_DownloadMalformedEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"valid", `{"payload":"dGVzdA==","payloadType":"test"}`, false},
		{"empty JSON", `{}`, false},
		{"invalid JSON", `{corrupt`, true},
		{"null", `null`, false},
		{"array", `[1,2,3]`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := New(server.URL)
			_, err := client.Download(context.Background(), "gitoid")

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSecurity_R3_218_GraphQLMalformedResponses tests SearchGitoids with
// malformed GraphQL responses.
func TestSecurity_R3_218_GraphQLMalformedResponses(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"empty edges", `{"data":{"dsses":{"edges":[]}}}`, false},
		{"null data", `{"data":null}`, false},
		{"graphql error", `{"data":null,"errors":[{"message":"unauthorized"}]}`, true},
		{"invalid data", `{"data":{"dsses":"not-object"}}`, true},
		{"missing dsses", `{"data":{"other":true}}`, false},
		{"invalid JSON", `{corrupt`, true},
		{"empty body", ``, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := New(server.URL)
			_, err := client.SearchGitoids(context.Background(), SearchGitoidVariables{
				CollectionName: "test",
			})

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ==========================================================================
// Context handling
// ==========================================================================

// TestSecurity_R3_219_ContextCancellationStore tests that context
// cancellation works for Store.
func TestSecurity_R3_219_ContextCancellationStore(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done) // Unblock handler first.
		server.Close()
	}()

	client := New(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.Store(ctx, dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestSecurity_R3_220_ContextCancellationDownload tests that context
// cancellation works for Download.
func TestSecurity_R3_220_ContextCancellationDownload(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	client := New(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.Download(ctx, "test-gitoid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestSecurity_R3_221_ContextCancellationSearchGitoids tests that context
// cancellation works for SearchGitoids.
func TestSecurity_R3_221_ContextCancellationSearchGitoids(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	client := New(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.SearchGitoids(ctx, SearchGitoidVariables{CollectionName: "test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// ==========================================================================
// Client construction edge cases
// ==========================================================================

// TestSecurity_R3_222_ClientConstructionEdgeCases tests various edge cases
// in Client construction.
func TestSecurity_R3_222_ClientConstructionEdgeCases(t *testing.T) {
	t.Run("trailing slash stripped", func(t *testing.T) {
		c := New("https://example.com/")
		assert.Equal(t, "https://example.com", c.url)
	})

	t.Run("multiple trailing slashes", func(t *testing.T) {
		c := New("https://example.com///")
		assert.Equal(t, "https://example.com", c.url)
	})

	t.Run("nil option", func(t *testing.T) {
		c := New("https://example.com", nil)
		assert.NotNil(t, c)
	})

	t.Run("nil headers", func(t *testing.T) {
		c := New("https://example.com", WithHeaders(nil))
		assert.Nil(t, c.headers)
	})

	t.Run("nil HTTP client preserves default", func(t *testing.T) {
		c := New("https://example.com", WithHTTPClient(nil))
		assert.Equal(t, http.DefaultClient, c.client)
	})

	t.Run("custom HTTP client", func(t *testing.T) {
		custom := &http.Client{Timeout: 5 * time.Second}
		c := New("https://example.com", WithHTTPClient(custom))
		assert.Equal(t, custom, c.client)
	})

	t.Run("empty URL", func(t *testing.T) {
		c := New("")
		assert.NotNil(t, c)
		assert.Equal(t, "", c.url)
	})
}

// TestSecurity_R3_223_StoreEmptyEnvelope tests Store with an empty envelope.
func TestSecurity_R3_223_StoreEmptyEnvelope(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = readBody(r)
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.Store(context.Background(), dsse.Envelope{})
	assert.NoError(t, err)
	assert.NotEmpty(t, receivedBody)
}

// TestSecurity_R3_224_CancelledContextBeforeRequest tests that an already-
// cancelled context prevents the request from being sent.
func TestSecurity_R3_224_CancelledContextBeforeRequest(t *testing.T) {
	requestReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before request

	client := New(server.URL)
	_, err := client.Store(ctx, dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.Error(t, err)
	assert.False(t, requestReceived, "Request should not reach server with cancelled context")
}
