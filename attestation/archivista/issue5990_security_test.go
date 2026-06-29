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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// computeGitoid replicates the git-blob-sha256 content address that Archivista
// keys envelopes on: sha256("blob <len>\0" + content), rendered as lowercase
// hex. It must match attestation/gitoid (gitoid.New + WithSha256).
func computeGitoid(content []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "blob %d\000", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// TestSecurity_Issue5990_DownloadRehashAndBound asserts the SECURE contract for
// Archivista downloads-by-gitoid:
//
//	(a) the returned bytes must content-address to the requested gitoid, else
//	    Download rejects them (content-address binding); and
//	(b) an oversized response body is refused before it is buffered into memory
//	    (OOM-DoS defense), mirroring the bounded --bundle path.
//
// Both subtests assert the fixed behavior, so they FAIL against the unbounded,
// never-re-hashed implementation.
func TestSecurity_Issue5990_DownloadRehashAndBound(t *testing.T) {
	t.Run("gitoid_mismatch_is_rejected", func(t *testing.T) {
		// The server returns a well-formed envelope, but its raw bytes
		// content-address to a gitoid different from the one requested. A
		// compromised/on-path Archivista returning wrong-scope-but-signed
		// evidence must be rejected at the content-address layer.
		body := []byte(`{"payload":"eyJ0ZXN0Ijp0cnVlfQ==","payloadType":"application/vnd.in-toto+json","signatures":[]}`)
		trueGitoid := computeGitoid(body)
		requestedGitoid := strings.Repeat("0", len(trueGitoid)) // deliberately not the true gitoid
		require.NotEqual(t, trueGitoid, requestedGitoid)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.Download(context.Background(), requestedGitoid)
		require.Error(t, err, "Download must reject an envelope whose true gitoid != requested gitoid")
	})

	t.Run("oversized_response_is_refused_before_buffering", func(t *testing.T) {
		// The server streams a syntactically valid JSON envelope whose string
		// payload is enormous. A secure client refuses once the decode crosses
		// the cap, rather than buffering multi-GiB into memory. We assert that
		// the client never reads anywhere near the full body: it must error out
		// well before the proof threshold below.
		const proofThreshold = 600 << 20 // 600 MiB — past the 512 MiB cap

		var bytesServed int64
		// Build a valid-JSON envelope prefix; the payload string is then padded
		// with 'A's far beyond the cap and never closed within the threshold.
		prefix := []byte(`{"payload":"`)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(prefix); err != nil {
				return
			}
			atomic.AddInt64(&bytesServed, int64(len(prefix)))

			flusher, _ := w.(http.Flusher)
			chunk := make([]byte, 1<<20) // 1 MiB of 'A'
			for i := range chunk {
				chunk[i] = 'A'
			}
			for atomic.LoadInt64(&bytesServed) < proofThreshold {
				n, err := w.Write(chunk)
				atomic.AddInt64(&bytesServed, int64(n))
				if err != nil {
					return // client hung up — the secure outcome
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.Download(context.Background(), "anything")
		require.Error(t, err, "Download must refuse an oversized response body")
		require.Less(t, atomic.LoadInt64(&bytesServed), int64(proofThreshold),
			"Download must refuse before consuming the full oversized body (read %d bytes)", atomic.LoadInt64(&bytesServed))
	})
}
