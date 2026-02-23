//go:build audit

package timestamp

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// TSPVerifier.Verify unbounded read
// ==========================================================================

// TestAdversarial_Verifier_UnboundedTSRRead tests that TSPVerifier.Verify
// will read the entire tsrData reader without any size limit.
// Compare this to TSPTimestamper.Timestamp which limits response to 1MB.
//
// BUG [HIGH]: Verify calls io.ReadAll(tsrData) at line 178 without any
// size limit. If an attacker supplies a malicious TSR reader (e.g. from
// a compromised archive), this can cause OOM. The Timestamp method
// correctly limits to 1MB (maxTSAResponseSize), but Verify has no such
// protection.
func TestAdversarial_Verifier_UnboundedTSRRead(t *testing.T) {
	v := NewVerifier(VerifyWithCerts(nil))

	// Create a reader that would return a lot of data.
	// We use a LimitReader to simulate a large but bounded input.
	// The point is: Verify will try to read ALL of it.
	const testSize = 10 << 20 // 10MB
	largeReader := io.LimitReader(newZeroReader(), testSize)

	_, err := v.Verify(context.Background(),
		largeReader,
		bytes.NewReader([]byte("signed-data")))

	// The error will come from timestamp.Parse failing on the data,
	// but the important thing is that all 10MB was read into memory first.
	require.Error(t, err)
	t.Logf("BUG [HIGH]: TSPVerifier.Verify reads entire tsrData into memory "+
		"without size limit (io.ReadAll at tsp.go:178). A malicious TSR input "+
		"can cause OOM. The Timestamp method correctly limits to 1MB "+
		"(maxTSAResponseSize at tsp.go:125), but Verify has no such protection.")
}

// TestAdversarial_Verifier_NilCertPool tests that passing nil certs
// (not empty certs) to VerifyWithCerts creates a non-nil but empty pool.
func TestAdversarial_Verifier_NilCertPool(t *testing.T) {
	v := NewVerifier(VerifyWithCerts(nil))
	// VerifyWithCerts(nil) calls x509.NewCertPool() and then iterates
	// a nil slice (no-op). So certChain is non-nil but empty.
	assert.NotNil(t, v.certChain,
		"VerifyWithCerts(nil) should create a non-nil empty pool")
}

// TestAdversarial_Verifier_NoCertsOption tests that Verify without any
// certs option returns a clear error.
func TestAdversarial_Verifier_NoCertsOption(t *testing.T) {
	v := NewVerifier() // no VerifyWithCerts

	_, err := v.Verify(context.Background(),
		bytes.NewReader([]byte("tsr")),
		bytes.NewReader([]byte("data")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate chain",
		"should give a clear error about missing cert chain")
}

// ==========================================================================
// validateURL SSRF edge cases
// ==========================================================================

// TestAdversarial_ValidateURL_SSRFVectors tests URL validation against
// SSRF attack vectors.
func TestAdversarial_ValidateURL_SSRFVectors(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		note    string
	}{
		{
			name:    "internal IP 127.0.0.1",
			url:     "https://127.0.0.1/timestamp",
			wantErr: false,
			note:    "DESIGN NOTE: localhost/loopback IPs are accepted by validateURL. No internal IP filtering.",
		},
		{
			name:    "internal IP 10.0.0.1",
			url:     "https://10.0.0.1/timestamp",
			wantErr: false,
			note:    "DESIGN NOTE: Private RFC1918 IPs are accepted.",
		},
		{
			name:    "internal IP 172.16.0.1",
			url:     "https://172.16.0.1/timestamp",
			wantErr: false,
			note:    "DESIGN NOTE: Private RFC1918 IPs are accepted.",
		},
		{
			name:    "internal IP 192.168.1.1",
			url:     "https://192.168.1.1/timestamp",
			wantErr: false,
			note:    "DESIGN NOTE: Private RFC1918 IPs are accepted.",
		},
		{
			name:    "IPv6 loopback",
			url:     "https://[::1]/timestamp",
			wantErr: false,
			note:    "DESIGN NOTE: IPv6 loopback is accepted.",
		},
		{
			name:    "metadata endpoint AWS",
			url:     "https://169.254.169.254/latest/meta-data/",
			wantErr: false,
			note:    "DESIGN NOTE [MEDIUM]: Cloud metadata endpoint is accepted. SSRF to 169.254.169.254 could leak cloud credentials.",
		},
		{
			name:    "URL with user info for SSRF",
			url:     "https://evil.com@internal-server/timestamp",
			wantErr: false,
			note:    "DESIGN NOTE: URL with userinfo is accepted.",
		},
		{
			name:    "HTTPS scheme with empty host",
			url:     "https:///path",
			wantErr: true,
		},
		{
			name:    "double scheme",
			url:     "https://https://example.com",
			wantErr: false,
			note:    "Go url.Parse treats 'https' as the host for the outer URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateURL(tc.url)
			if tc.wantErr {
				require.Error(t, err, "should reject URL %q", tc.url)
			} else {
				require.NoError(t, err, "URL %q should pass validation", tc.url)
				if tc.note != "" {
					t.Logf("%s", tc.note)
				}
			}
		})
	}
}

// ==========================================================================
// URL validation timing (construction vs request time)
// ==========================================================================

// TestAdversarial_URLValidation_HappensAtRequestTime tests that URL
// validation happens at Timestamp() call time, not at construction time.
// The doc comment on TimestampWithUrl says "validated at construction time"
// but this is inaccurate -- validation happens in Timestamp().
//
// BUG [LOW]: Doc comment on TimestampWithUrl (tsp.go:41-46) claims URL
// is "validated at construction time" but actually validateURL is called
// inside Timestamp(), not in NewTimestamper or TimestampWithUrl.
func TestAdversarial_URLValidation_HappensAtRequestTime(t *testing.T) {
	// Construct with clearly invalid URL - no error at construction time.
	ts := NewTimestamper(TimestampWithUrl("http://plaintext.example.com"))

	// The invalid URL is stored without validation.
	assert.Equal(t, "http://plaintext.example.com", ts.url,
		"BUG [LOW]: Invalid HTTP URL is accepted at construction time. "+
			"Doc comment claims validation happens at construction time "+
			"but it actually happens at Timestamp() call time. "+
			"File: tsp.go:41-46 vs tsp.go:93")

	// Validation only happens when Timestamp() is called.
	_, err := ts.Timestamp(context.Background(), bytes.NewReader([]byte("data")))
	require.Error(t, err, "should fail at Timestamp() time, not construction time")
	assert.Contains(t, err.Error(), "HTTPS")
}

// ==========================================================================
// Timestamp with empty/nil reader
// ==========================================================================

// TestAdversarial_Timestamp_NilReader tests Timestamp with a nil reader.
//
// BUG [HIGH]: Timestamp() panics with nil reader. The nil io.Reader is
// passed to timestamp.CreateRequest which dereferences it without a nil
// check. This is a crash bug if callers forget to validate their reader.
// File: tsp.go:97, called with r=nil -> timestamp.CreateRequest panics.
func TestAdversarial_Timestamp_NilReader(t *testing.T) {
	ts := NewTimestamper(TimestampWithUrl("https://example.com/ts"))

	// Confirmed: nil reader causes a panic in timestamp.CreateRequest.
	assert.Panics(t, func() {
		_, _ = ts.Timestamp(context.Background(), nil)
	}, "BUG [HIGH]: Timestamp() panics on nil reader instead of returning error. "+
		"File: tsp.go:97 -> timestamp.CreateRequest dereferences nil io.Reader")
}

// TestAdversarial_Timestamp_EmptyReader tests Timestamp with an empty reader.
func TestAdversarial_Timestamp_EmptyReader(t *testing.T) {
	ts := NewTimestamper(TimestampWithUrl("https://192.0.2.1:9999/ts"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Empty reader should still create a valid timestamp request.
	// It will fail on network, not on request creation.
	_, err := ts.Timestamp(ctx, bytes.NewReader([]byte{}))
	require.Error(t, err, "should fail on network, not request creation")
}

// ==========================================================================
// FakeTimestamper edge cases
// ==========================================================================

// TestAdversarial_FakeTimestamper_ZeroTime tests FakeTimestamper with
// zero time value.
func TestAdversarial_FakeTimestamper_ZeroTime(t *testing.T) {
	ft := FakeTimestamper{} // T is zero time

	data, err := ft.Timestamp(context.Background(), bytes.NewReader([]byte("test")))
	require.NoError(t, err)
	assert.NotEmpty(t, data, "zero time should still produce output")

	verifiedTime, err := ft.Verify(context.Background(),
		bytes.NewReader(data),
		bytes.NewReader([]byte("test")))
	require.NoError(t, err)
	assert.True(t, verifiedTime.IsZero(),
		"verified time from zero FakeTimestamper should be zero")
}

// TestAdversarial_FakeTimestamper_NilReader tests FakeTimestamper.Verify
// with a nil timestamp reader.
//
// BUG [MEDIUM]: FakeTimestamper.Verify panics on nil reader. The nil
// io.Reader is passed to io.ReadAll which panics. This is a crash bug.
// File: fake.go:33, io.ReadAll(nil) panics.
func TestAdversarial_FakeTimestamper_NilReader(t *testing.T) {
	ft := FakeTimestamper{}

	assert.Panics(t, func() {
		_, _ = ft.Verify(context.Background(), nil, bytes.NewReader([]byte("data")))
	}, "BUG [MEDIUM]: FakeTimestamper.Verify panics on nil reader. "+
		"io.ReadAll(nil) panics. File: fake.go:33")
}

// TestAdversarial_FakeTimestamper_LargeTimestampData tests Verify with
// large timestamp data (unbounded read).
func TestAdversarial_FakeTimestamper_LargeTimestampData(t *testing.T) {
	ft := FakeTimestamper{}

	// 1MB of data - FakeTimestamper.Verify also does io.ReadAll without limit.
	largeData := bytes.NewReader([]byte(strings.Repeat("x", 1<<20)))

	_, err := ft.Verify(context.Background(), largeData, bytes.NewReader([]byte("data")))
	require.Error(t, err, "mismatched data should error")
}

// ==========================================================================
// Helpers
// ==========================================================================

// zeroReader is an io.Reader that returns zero bytes indefinitely.
type zeroReader struct{}

func newZeroReader() io.Reader {
	return &zeroReader{}
}

func (z *zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
