// jade:ring local

package archivista

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

type downloadReadCounter struct {
	io.ReadCloser
	bytes *atomic.Int64
}

func (r downloadReadCounter) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.bytes.Add(int64(n))
	return n, err
}

type downloadCountingTransport struct {
	http.RoundTripper
	bytes *atomic.Int64
}

func (t downloadCountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(req)
	if err == nil {
		resp.Body = downloadReadCounter{ReadCloser: resp.Body, bytes: t.bytes}
	}
	return resp, err
}

func TestDownloadBoundedHTTP(t *testing.T) {
	body, err := json.Marshal(dsse.Envelope{PayloadType: "application/vnd.in-toto+json", Payload: []byte(`{"test":true}`)})
	require.NoError(t, err)
	gid := computeGitoid(body)
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-only-token" {
			t.Error("bounded download lost scoped auth")
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	client := New(srv.URL, WithAuthTokenSource(func() (string, error) { return "test-only-token", nil }))
	for _, limit := range []int64{0, -1, MaxDownloadBytes + 1} {
		_, err := client.DownloadBounded(t.Context(), gid, limit)
		require.Error(t, err)
	}
	require.Zero(t, requests.Load(), "invalid bounds must be refused before HTTP")
	env, err := client.DownloadBounded(t.Context(), gid, int64(len(body)))
	require.NoError(t, err)
	require.Equal(t, []byte(`{"test":true}`), env.Payload)
	_, err = client.DownloadBounded(t.Context(), gid, int64(len(body)-1))
	require.ErrorContains(t, err, "byte limit")
	_, err = client.DownloadBounded(t.Context(), "wrong-gitoid", int64(len(body)))
	require.ErrorContains(t, err, "gitoid mismatch")
	_, err = client.Download(t.Context(), gid)
	require.NoError(t, err, "legacy Download retains its original ceiling")
}

func TestDownloadBoundedHTTPRefusesBeforeDecode(t *testing.T) {
	const limit int64 = 4096
	for _, declared := range []bool{false, true} {
		t.Run(fmt.Sprintf("content-length-%v", declared), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if declared {
					w.Header().Set("Content-Length", fmt.Sprint(limit+1))
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				// Invalid JSON: overflow must win over decoding or content-address
				// errors, without buffering this complete stream.
				chunk := bytes.Repeat([]byte("!"), int(limit))
				for i := 0; i < 32; i++ {
					if _, err := w.Write(chunk); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			t.Cleanup(srv.Close)
			var read atomic.Int64
			hc := srv.Client()
			hc.Transport = downloadCountingTransport{RoundTripper: hc.Transport, bytes: &read}
			_, err := New(srv.URL, WithHTTPClient(hc)).DownloadBounded(t.Context(), "untrusted", limit)
			require.ErrorContains(t, err, "byte limit")
			if declared {
				require.Zero(t, read.Load(), "reject declared overflow before allocating/reading body")
			} else {
				require.Equal(t, limit+1, read.Load(), "stream reads must stop at limit plus one byte")
			}
		})
	}
}

func TestDownloadBoundedHTTPCancellation(t *testing.T) {
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := New(srv.URL).DownloadBounded(ctx, "untrusted", 4096); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("download did not start")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("download ignored cancellation")
	}
}

func TestDownloadBoundedHTTPErrorBody(t *testing.T) {
	const limit int64 = 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.(http.Flusher).Flush()
		_, _ = w.Write(bytes.Repeat([]byte("!"), int(limit*4)))
	}))
	t.Cleanup(srv.Close)
	var read atomic.Int64
	hc := srv.Client()
	hc.Transport = downloadCountingTransport{RoundTripper: hc.Transport, bytes: &read}
	_, err := New(srv.URL, WithHTTPClient(hc)).DownloadBounded(t.Context(), "untrusted", limit)
	var status *StatusError
	require.ErrorAs(t, err, &status)
	require.Equal(t, http.StatusBadGateway, status.StatusCode)
	require.Equal(t, limit, read.Load(), "diagnostic reads must also honor a caller's tighter cap")
}
