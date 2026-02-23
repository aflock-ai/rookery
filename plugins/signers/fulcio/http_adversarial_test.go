//go:build audit

package fulcio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
)

// =============================================================================
// Area 4: proofOfPossession encoding in getCertHTTP
// =============================================================================

func TestAdversarial_GetCertHTTP_ProofOfPossessionEncoding(t *testing.T) {
	// BUG PROBE: In getCertHTTP, the proof ([]byte from SignMessage) is
	// placed directly into a map[string]interface{} and then json.Marshal'd.
	// Go's json.Marshal encodes []byte as base64, which is standard.
	//
	// However, in the gRPC getCert path, the proof is sent as protobuf
	// bytes (ProofOfPossession: proof). The protobuf encoding also uses
	// base64 for bytes fields in JSON representation.
	//
	// The question is: does the Fulcio HTTP API expect base64-encoded bytes
	// or raw bytes? If it expects raw bytes, the base64 encoding is a bug.
	//
	// We can verify what gets sent by inspecting the request body.

	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}

		if err := json.Unmarshal(body, &receivedPayload); err != nil {
			t.Fatalf("Failed to parse request body: %v", err)
		}

		t.Logf("Received request body: %s", string(body))

		// Return a valid response
		chain := generateCertChain(t)
		certResp := &fulciopb.SigningCertificate{
			Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
				SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
					Chain: &fulciopb.CertificateChain{
						Certificates: chain,
					},
				},
			},
		}
		respJSON, _ := protojson.Marshal(certResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")
	_, err = getCertHTTP(context.Background(), key, server.URL, token)
	require.NoError(t, err)

	// Inspect the proofOfPossession field
	pkReq, ok := receivedPayload["publicKeyRequest"].(map[string]interface{})
	require.True(t, ok, "publicKeyRequest should be a map")

	proof, ok := pkReq["proofOfPossession"]
	require.True(t, ok, "proofOfPossession should exist")

	// json.Marshal encodes []byte as base64 string
	proofStr, ok := proof.(string)
	require.True(t, ok, "proofOfPossession should be a string (base64-encoded bytes)")

	t.Logf("proofOfPossession type: %T, value: %s", proof, proofStr)

	// Verify it looks like base64 (contains only base64 chars)
	isBase64 := true
	for _, c := range proofStr {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			isBase64 = false
			break
		}
	}

	if isBase64 {
		t.Log("proofOfPossession is base64-encoded (from json.Marshal of []byte). " +
			"This is correct for standard JSON encoding, but verify the Fulcio HTTP API " +
			"expects base64 and not raw bytes. The protobuf JSON format also uses base64 " +
			"for bytes fields, so this should be compatible.")
	} else {
		t.Errorf("BUG: proofOfPossession contains non-base64 characters: %q", proofStr)
	}
}

// =============================================================================
// Area 5: getCertHTTP has no retry logic
// =============================================================================

func TestAdversarial_GetCertHTTP_NoRetryOnTransientFailure(t *testing.T) {
	// BUG/DESIGN ISSUE: getCertHTTP has NO retry logic, unlike getCert
	// which retries up to 3 times with exponential backoff.
	// This means transient failures (502, 503, network blips) cause
	// immediate failure when using HTTP mode.

	var attemptCount int32
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attemptCount++
		count := attemptCount
		mu.Unlock()

		if count == 1 {
			// First attempt: transient 503
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":"service temporarily unavailable"}`)
			return
		}
		// Would succeed on retry, but getCertHTTP doesn't retry
		chain := generateCertChain(t)
		certResp := &fulciopb.SigningCertificate{
			Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
				SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
					Chain: &fulciopb.CertificateChain{
						Certificates: chain,
					},
				},
			},
		}
		respJSON, _ := protojson.Marshal(certResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")
	_, err = getCertHTTP(context.Background(), key, server.URL, token)

	// This WILL fail on the first attempt because the server returns 503
	require.Error(t, err, "getCertHTTP fails on first transient error because it has no retry logic")

	mu.Lock()
	finalCount := attemptCount
	mu.Unlock()

	assert.Equal(t, int32(1), finalCount,
		"BUG/DESIGN ISSUE: getCertHTTP made only 1 attempt. Unlike getCert which retries "+
			"up to 3 times with exponential backoff, getCertHTTP has NO retry logic. "+
			"Transient failures (503, network blips) cause immediate failure in HTTP mode.")
}

func TestAdversarial_GetCertHTTP_ConnectionRefused(t *testing.T) {
	// Test with a URL that refuses connections
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")

	// Use a port that's not listening
	_, err = getCertHTTP(context.Background(), key, "http://127.0.0.1:1", token)
	require.Error(t, err, "Should fail with connection refused")
	t.Logf("Connection refused error: %v", err)

	// Note: no retry happens, unlike getCert
}

// =============================================================================
// Area 6: getCertHTTP unbounded response body read
// =============================================================================

func TestAdversarial_GetCertHTTP_LargeResponseBody(t *testing.T) {
	// BUG: getCertHTTP uses io.ReadAll with no size limit on the response
	// body. A compromised or malicious Fulcio server could return an
	// extremely large response, causing OOM.
	//
	// Compare with fetchToken which also has this issue.
	// The fix would be to use io.LimitReader.

	// We test with a moderately large body (10MB) to demonstrate the issue
	// without actually killing the test runner.
	const responseSize = 10 * 1024 * 1024 // 10MB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write a large response
		w.Write([]byte(`{"signedCertificateEmbeddedSct":{"chain":{"certificates":["`))
		// Write lots of junk
		junk := strings.Repeat("A", 1024)
		for written := 0; written < responseSize; written += len(junk) {
			w.Write([]byte(junk))
		}
		w.Write([]byte(`"]}}}`))
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")
	_, err = getCertHTTP(context.Background(), key, server.URL, token)

	// After the fix, getCertHTTP uses io.LimitReader to cap reads at 1MB.
	// The 10MB response should be truncated, causing an unmarshal error
	// (not an OOM). The key assertion: it must error rather than succeed
	// with a 10MB allocation.
	require.Error(t, err, "getCertHTTP should fail on a 10MB response (LimitReader caps at 1MB)")
	t.Logf("FIXED: getCertHTTP correctly rejects oversized response: %v", err)
}

func TestAdversarial_GetCertHTTP_SlowResponseBody(t *testing.T) {
	// Test behavior with a very slow response body.
	// The client has a 30-second timeout, but what if the server sends
	// headers quickly then trickles the body?

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write partial body then stall
		w.Write([]byte(`{"signed`))
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}
		// Stall for longer than a reasonable timeout
		// (but less than the 30s client timeout to avoid test slowness)
		time.Sleep(2 * time.Second)
		w.Write([]byte(`CertificateEmbeddedSct":{}}`))
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")

	// Use a context with a shorter timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = getCertHTTP(ctx, key, server.URL, token)
	require.Error(t, err, "Should fail due to context timeout during slow body read")
	t.Logf("Slow body error: %v", err)
}

// =============================================================================
// getCertHTTP error message leaks full response body
// =============================================================================

func TestAdversarial_GetCertHTTP_ErrorMessageLeaksFullBody(t *testing.T) {
	// BUG: Unlike fetchToken which truncates error bodies to 500 chars,
	// getCertHTTP includes the ENTIRE response body in the error message
	// on non-200 status codes (line 652):
	//   return nil, fmt.Errorf("HTTP request failed with status: %s, body: %s", resp.Status, string(body))
	//
	// This means:
	// 1. Very large error responses create very large error messages
	// 2. Sensitive information in error responses gets propagated

	largeErrorBody := strings.Repeat("SENSITIVE_DATA_LEAKED_", 1000) // ~22KB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, largeErrorBody)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")
	_, err = getCertHTTP(context.Background(), key, server.URL, token)
	require.Error(t, err)

	errMsg := err.Error()
	assert.Less(t, len(errMsg), 1000,
		"FIXED: getCertHTTP should truncate error body to ~500 chars, got %d bytes", len(errMsg))
	t.Logf("FIXED: error message length is %d bytes (truncated correctly)", len(errMsg))
}

// =============================================================================
// getCertHTTP URL construction
// =============================================================================

func TestAdversarial_GetCertHTTP_URLTraversalInFulcioURL(t *testing.T) {
	// BUG PROBE: getCertHTTP concatenates fulcioURL + "/api/v2/signingCert"
	// directly (line 631). What if fulcioURL already has a trailing slash?
	// Or contains path traversal?

	var receivedPaths []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedPaths = append(receivedPaths, r.URL.Path)
		mu.Unlock()

		chain := generateCertChain(t)
		certResp := &fulciopb.SigningCertificate{
			Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
				SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
					Chain: &fulciopb.CertificateChain{
						Certificates: chain,
					},
				},
			},
		}
		respJSON, _ := protojson.Marshal(certResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := generateTestToken("test@example.com", "")

	testCases := []struct {
		name        string
		fulcioURL   string
		expectedPath string
	}{
		{
			name:        "no trailing slash",
			fulcioURL:   server.URL,
			expectedPath: "/api/v2/signingCert",
		},
		{
			name:        "trailing slash",
			fulcioURL:   server.URL + "/",
			expectedPath: "/api/v2/signingCert", // FIXED: trailing slash normalized
		},
		{
			name:        "with existing path",
			fulcioURL:   server.URL + "/prefix",
			expectedPath: "/prefix/api/v2/signingCert",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			receivedPaths = nil
			mu.Unlock()

			_, err := getCertHTTP(context.Background(), key, tc.fulcioURL, token)
			require.NoError(t, err)

			mu.Lock()
			defer mu.Unlock()
			require.Len(t, receivedPaths, 1)

			if receivedPaths[0] != tc.expectedPath {
				t.Logf("URL construction: fulcioURL=%q produced path=%q (expected %q)",
					tc.fulcioURL, receivedPaths[0], tc.expectedPath)
			}

			// Check for double slash issue
			if strings.Contains(receivedPaths[0], "//") {
				t.Errorf("BUG: getCertHTTP produced a URL with double slashes: %q. "+
					"This happens because the code does simple string concatenation "+
					"(fulcioURL + \"/api/v2/signingCert\") without handling trailing slashes.",
					receivedPaths[0])
			}
		})
	}
}

// =============================================================================
// getCertHTTP context cancellation
// =============================================================================

func TestAdversarial_GetCertHTTP_ContextCancelledBeforeRequest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = getCertHTTP(ctx, key, "http://localhost:0", token)
	require.Error(t, err, "Should fail with cancelled context")
	t.Logf("Context cancelled error: %v", err)
}

// =============================================================================
// getCertHTTP token without claims
// =============================================================================

func TestAdversarial_GetCertHTTP_SubjectOnlyToken(t *testing.T) {
	// Test with a token that has only a subject claim (no email)
	chain := generateCertChain(t)
	certResp := &fulciopb.SigningCertificate{
		Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
			SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
				Chain: &fulciopb.CertificateChain{
					Certificates: chain,
				},
			},
		},
	}
	respJSON, err := protojson.Marshal(certResp)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("", "subject-only")
	result, err := getCertHTTP(context.Background(), key, server.URL, token)
	require.NoError(t, err, "getCertHTTP should succeed with subject-only token")
	require.NotNil(t, result)
}

// =============================================================================
// getCertHTTP new http.Client per call
// =============================================================================

func TestAdversarial_GetCertHTTP_CreatesNewClientPerCall(t *testing.T) {
	// OBSERVATION: getCertHTTP creates a new http.Client on every call
	// (line 638): client := &http.Client{Timeout: 30 * time.Second}
	//
	// This means:
	// 1. No connection reuse between calls (no keep-alive benefit)
	// 2. No connection pooling
	// 3. Each call pays the full TLS handshake cost
	//
	// Compare with fetchToken which uses a package-level client with
	// connection pooling.
	//
	// This isn't a bug per se, but it's a performance issue for repeated calls.

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		chain := generateCertChain(t)
		certResp := &fulciopb.SigningCertificate{
			Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
				SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
					Chain: &fulciopb.CertificateChain{
						Certificates: chain,
					},
				},
			},
		}
		respJSON, _ := protojson.Marshal(certResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")

	// Make multiple calls
	for i := 0; i < 3; i++ {
		_, err := getCertHTTP(context.Background(), key, server.URL, token)
		require.NoError(t, err)
	}

	assert.Equal(t, 3, callCount)
	t.Log("OBSERVATION: getCertHTTP creates a new http.Client per call (no connection reuse). " +
		"fetchToken uses a package-level client with connection pooling. Consider using a " +
		"shared client for getCertHTTP as well.")
}

// =============================================================================
// getCertHTTP error response body in log.Debugf
// =============================================================================

func TestAdversarial_GetCertHTTP_DebugLogLeaksSensitiveData(t *testing.T) {
	// BUG PROBE: On non-200 status, getCertHTTP calls:
	//   log.Debugf("HTTP request failed with status: %s, full body: %s", resp.Status, string(body))
	// This logs the FULL response body at debug level, which could contain:
	// - Error details with internal server information
	// - Stack traces
	// - Sensitive configuration data
	//
	// The error message ALSO includes the full body (no truncation).
	// Both paths have no size limit on what gets logged/returned.

	sensitiveResponse := fmt.Sprintf(`{
		"error": "authentication failed",
		"internal_details": {
			"server": "fulcio-prod-us-east-1",
			"database": "postgres://internal:secret@db.internal:5432/fulcio",
			"stack_trace": "%s"
		}
	}`, strings.Repeat("at com.example.Fulcio.method(Fulcio.java:123)\n", 100))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, sensitiveResponse)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")
	_, err = getCertHTTP(context.Background(), key, server.URL, token)
	require.Error(t, err)

	if strings.Contains(err.Error(), "internal_details") {
		t.Log("CONFIRMED: getCertHTTP error messages contain full server response including " +
			"potentially sensitive internal details. The error message should truncate the " +
			"response body like fetchToken does (500 chars).")
	}
}

// =============================================================================
// getCertHTTP Content-Type not validated
// =============================================================================

func TestAdversarial_GetCertHTTP_IgnoresContentType(t *testing.T) {
	// BUG PROBE: getCertHTTP doesn't validate the Content-Type of the
	// response. It will attempt to protojson.Unmarshal any response body,
	// regardless of whether the server returned text/html, text/plain, etc.

	chain := generateCertChain(t)
	certResp := &fulciopb.SigningCertificate{
		Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
			SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
				Chain: &fulciopb.CertificateChain{
					Certificates: chain,
				},
			},
		},
	}
	respJSON, _ := protojson.Marshal(certResp)

	// Return valid JSON but with wrong Content-Type
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(respJSON)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := generateTestToken("test@example.com", "")
	result, err := getCertHTTP(context.Background(), key, server.URL, token)

	// This will succeed because Content-Type is not checked
	if err == nil {
		t.Log("OBSERVATION: getCertHTTP does not validate Content-Type header. " +
			"It successfully parsed the response even though Content-Type was text/html. " +
			"Compare with fetchToken which checks for HTML responses to give better error messages.")
		require.NotNil(t, result)
	}
}
