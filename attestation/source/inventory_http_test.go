// jade:ring local

package source

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/gitoid"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/require"
)

func inventoryHTTPCorpus(t *testing.T, invalidPrefix int) (string, []byte, []string, map[string][]byte) {
	t.Helper()
	ref, body, err := fileinventory.Encode("product", "walk", []fileinventory.Entry{{Path: "a", FileDigest: strings.Repeat("a", 64)}})
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
	require.NoError(t, err)
	ids := []string{}
	corpus := map[string][]byte{}
	for i := 0; i < 17; i++ {
		subject := ref.Digest
		if i < invalidPrefix {
			subject = strings.Repeat("0", 64)
		}
		payload, err := json.Marshal(intoto.Statement{Type: intoto.StatementType, PredicateType: fileinventory.Type, Predicate: body, Subject: []intoto.Subject{{Name: "inventory:product", Digest: map[string]string{"sha256": subject}}}})
		require.NoError(t, err)
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer))
		require.NoError(t, err)
		raw, err := json.Marshal(env)
		require.NoError(t, err)
		gid, err := gitoid.New(bytes.NewReader(raw), gitoid.WithSha256(), gitoid.WithContentLength(int64(len(raw))))
		require.NoError(t, err)
		ids = append(ids, gid.String())
		corpus[gid.String()] = raw
	}
	require.Len(t, corpus, 17, "each signed wrapper must have a distinct content address")
	return ref.Digest, body, ids, corpus
}

func inventoryHTTPClient(t *testing.T, ids []string, corpus map[string][]byte, download http.HandlerFunc) (*archivista.Client, *atomic.Int64) {
	t.Helper()
	count := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer inventory-test-only" {
			t.Error("inventory lookup changed scoped auth")
		}
		if r.URL.Path == "/query" {
			var query struct {
				Variables archivista.SearchGitoidByPredicateVariables `json:"variables"`
			}
			if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			excluded := map[string]bool{}
			for _, id := range query.Variables.ExcludeGitoids {
				excluded[id] = true
			}
			edges := []any{}
			for _, id := range ids {
				if !excluded[id] {
					edges = append(edges, map[string]any{"node": map[string]string{"gitoidSha256": id}})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"dsses": map[string]any{"edges": edges}}})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/download/") {
			count.Add(1)
			if download != nil {
				download(w, r)
				return
			}
			body, ok := corpus[strings.TrimPrefix(r.URL.Path, "/download/")]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return archivista.New(srv.URL, archivista.WithAuthTokenSource(func() (string, error) { return "inventory-test-only", nil })), count
}

func TestArchivistaInventoryHTTPBoundedSearch(t *testing.T) {
	for _, tc := range []struct {
		name          string
		invalidPrefix int
		downloads     int
		found         bool
	}{
		{"seventeen-signed-wrappers", 0, 1, true},
		{"invalid-first-valid-second", 1, 2, true},
		{"valid-sixteenth", 15, 16, true},
		{"refuse-beyond-sixteen", 16, 16, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest, body, ids, corpus := inventoryHTTPCorpus(t, tc.invalidPrefix)
			client, downloads := inventoryHTTPClient(t, ids, corpus, nil)
			src := NewArchivistaSource(client)
			got, ok := InventoryLookup(t.Context(), src)(digest)
			require.Equal(t, tc.found, ok)
			if ok {
				require.Equal(t, body, got)
			}
			require.Equal(t, int64(tc.downloads), downloads.Load())
			require.Empty(t, src.seenPredicateGitoids, "inventory resolution must not exhaust the shared predicate seen-set")
		})
	}
}

func TestArchivistaInventoryHTTPDoesNotConsumeSeenSets(t *testing.T) {
	digest, body, ids, corpus := inventoryHTTPCorpus(t, 0)
	client, downloads := inventoryHTTPClient(t, ids, corpus, nil)
	src := NewArchivistaSource(client)
	src.seenCollectionGitoids = append([]string{}, ids...)
	src.seenPredicateGitoids = append([]string{}, ids...)
	for i := 0; i < 2; i++ {
		got, ok := InventoryLookup(t.Context(), src)(digest)
		require.True(t, ok, "another query/lookup must not hide the inventory")
		require.Equal(t, body, got)
	}
	require.Equal(t, int64(2), downloads.Load())
	require.Equal(t, ids, src.seenCollectionGitoids)
	require.Equal(t, ids, src.seenPredicateGitoids)
}

func TestArchivistaInventoryHTTPEmptySourceDoesNotHideAnother(t *testing.T) {
	digest, body, ids, corpus := inventoryHTTPCorpus(t, 0)
	client, downloads := inventoryHTTPClient(t, nil, nil, nil)
	mem := NewMemorySource()
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(corpus[ids[0]], &env))
	require.NoError(t, mem.LoadEnvelope(ids[0], env))
	got, ok := InventoryLookup(t.Context(), NewMultiSource(mem, NewArchivistaSource(client)))(digest)
	require.True(t, ok)
	require.Equal(t, body, got)
	require.Zero(t, downloads.Load())
}

func TestArchivistaInventoryHTTPGenericSearchUnchanged(t *testing.T) {
	digest, _, ids, corpus := inventoryHTTPCorpus(t, 0)
	for _, tc := range []struct {
		name            string
		types, subjects []string
	}{
		{"other-type", []string{"https://example.test/other"}, []string{digest}},
		{"mixed-types", []string{fileinventory.Type, "https://example.test/other"}, []string{digest}},
		{"multiple-subjects", []string{fileinventory.Type}, []string{digest, digest}},
		{"invalid-digest", []string{fileinventory.Type}, []string{"not-a-sha256"}},
		{"uppercase-digest", []string{fileinventory.Type}, []string{strings.ToUpper(digest)}},
		{"nonhex-digest", []string{fileinventory.Type}, []string{strings.Repeat("z", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, downloads := inventoryHTTPClient(t, ids, corpus, nil)
			src := NewArchivistaSource(client)
			got, err := src.SearchByPredicateType(t.Context(), tc.types, tc.subjects)
			require.NoError(t, err)
			require.Len(t, got, 17)
			require.Equal(t, int64(17), downloads.Load())
			require.Len(t, src.seenPredicateGitoids, 17)
		})
	}
}

func TestArchivistaInventoryHTTPTransportAndCancellation(t *testing.T) {
	digest, _, ids, corpus := inventoryHTTPCorpus(t, 0)
	t.Run("oversized-declaration", func(t *testing.T) {
		limit := int64(base64.StdEncoding.EncodedLen(fileinventory.MaxBytes+4096) + (1 << 20))
		require.Equal(t, limit, MaxInventoryEnvelopeBytes)
		client, downloads := inventoryHTTPClient(t, ids[:1], corpus, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(limit+1))
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		})
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		_, err := NewArchivistaSource(client).SearchByPredicateType(ctx, []string{fileinventory.Type}, []string{digest})
		require.ErrorContains(t, err, "byte limit", "inventory source must refuse its wire ceiling before waiting for the body")
		require.NoError(t, ctx.Err(), "overflow must not wait for the caller deadline")
		require.Equal(t, int64(1), downloads.Load())
	})
	t.Run("cancel-during-first-download", func(t *testing.T) {
		entered := make(chan struct{})
		client, downloads := inventoryHTTPClient(t, ids, corpus, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			close(entered)
			<-r.Context().Done()
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := NewArchivistaSource(client).SearchByPredicateType(ctx, []string{fileinventory.Type}, []string{digest})
			done <- err
		}()
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
			t.Fatal("search ignored cancellation")
		}
		require.Equal(t, int64(1), downloads.Load())
	})
}
