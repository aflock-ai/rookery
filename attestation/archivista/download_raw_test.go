// jade:ring local

package archivista

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// storedEnvelopeBytes builds a DSSE envelope the way a SERVER stored it rather
// than the way Go would re-marshal it: pretty-printed, keys out of struct
// order, and carrying a member dsse.Envelope has no field for. Archivista
// content-addresses the exact bytes it was handed, so this is what a real
// stored envelope looks like relative to json.Marshal(dsse.Envelope{...}) —
// and it is why DownloadRaw has to exist at all.
func storedEnvelopeBytes(payload string) []byte {
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	return []byte(fmt.Sprintf(`{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "%s",
  "signatures": [],
  "extensions": {"storedBy": "archivista"}
}
`, b64))
}

func TestDownloadRawReturnsTheExactStoredBytes(t *testing.T) {
	stored := storedEnvelopeBytes(`{"test":true}`)
	gid := computeGitoid(stored)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/download/"+gid, r.URL.Path)
		_, _ = w.Write(stored)
	}))
	t.Cleanup(srv.Close)

	raw, err := New(srv.URL).DownloadRaw(t.Context(), gid)
	require.NoError(t, err)
	require.Equal(t, stored, raw, "DownloadRaw must return the stored bytes byte-for-byte")
	require.Equal(t, gid, computeGitoid(raw), "re-hashing the returned bytes must reproduce the gitoid")

	// The whole point: the decoded-then-re-marshalled envelope does NOT
	// reproduce the stored bytes, so it cannot be saved as the attestation.
	env, err := New(srv.URL).Download(t.Context(), gid)
	require.NoError(t, err)
	remarshalled, err := json.Marshal(env)
	require.NoError(t, err)
	require.NotEqual(t, stored, remarshalled, "if these were equal the raw path would be pointless")
	require.NotEqual(t, gid, computeGitoid(remarshalled), "a re-marshalled envelope must not content-address to the gitoid")
}

func TestDownloadRawRefusesAGitoidMismatch(t *testing.T) {
	stored := storedEnvelopeBytes(`{"test":true}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(stored)
	}))
	t.Cleanup(srv.Close)

	requested := computeGitoid([]byte("something else entirely"))
	raw, err := New(srv.URL).DownloadRaw(t.Context(), requested)
	require.ErrorContains(t, err, "archivista download gitoid mismatch")
	require.ErrorContains(t, err, requested, "the message must name the gitoid that was asked for")
	require.Nil(t, raw, "no bytes may escape a failed content-address check")
}

// TestDownloadAndDownloadRawShareOneVerificationPath pins that the two entry
// points cannot drift: the same server, the same wrong gitoid, the same
// refusal text. A second copy of the check is exactly what this asserts
// against.
func TestDownloadAndDownloadRawShareOneVerificationPath(t *testing.T) {
	stored := storedEnvelopeBytes(`{"test":true}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(stored)
	}))
	t.Cleanup(srv.Close)

	requested := computeGitoid([]byte("not what the server returns"))
	_, rawErr := New(srv.URL).DownloadRaw(t.Context(), requested)
	_, envErr := New(srv.URL).Download(t.Context(), requested)
	require.Error(t, rawErr)
	require.Error(t, envErr)
	require.Equal(t, envErr.Error(), rawErr.Error(), "one verification path means one message")
}

func TestDownloadRawBoundedRefusesInvalidLimitsBeforeHTTP(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL)
	for _, limit := range []int64{0, -1, MaxDownloadBytes + 1} {
		raw, err := client.DownloadRawBounded(t.Context(), "irrelevant", limit)
		require.ErrorContains(t, err, "invalid download byte limit")
		require.Nil(t, raw)
	}
	require.Zero(t, requests.Load(), "invalid bounds must be refused before any request is sent")
}

func TestDownloadRawBoundedRefusesAnOversizeBody(t *testing.T) {
	stored := storedEnvelopeBytes(`{"test":true}`)
	gid := computeGitoid(stored)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(stored)
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL)
	raw, err := client.DownloadRawBounded(t.Context(), gid, int64(len(stored)-1))
	require.ErrorContains(t, err, "byte limit")
	require.Nil(t, raw)

	raw, err = client.DownloadRawBounded(t.Context(), gid, int64(len(stored)))
	require.NoError(t, err)
	require.Equal(t, stored, raw)
}

func TestDownloadRawSurfacesAStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	raw, err := New(srv.URL).DownloadRaw(t.Context(), computeGitoid([]byte("absent")))
	var status *StatusError
	require.ErrorAs(t, err, &status)
	require.Equal(t, http.StatusNotFound, status.StatusCode)
	require.Nil(t, raw)
}

func TestDownloadRawSendsTheConfiguredCredential(t *testing.T) {
	stored := storedEnvelopeBytes(`{"test":true}`)
	gid := computeGitoid(stored)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-only-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(stored)
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL, WithAuthTokenSource(func() (string, error) { return "test-only-token", nil }))
	raw, err := client.DownloadRaw(t.Context(), gid)
	require.NoError(t, err)
	require.Equal(t, stored, raw)
}
