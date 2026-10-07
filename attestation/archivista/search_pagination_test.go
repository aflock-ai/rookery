// jade:ring local
// Copyright 2026 The Rookery Contributors
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// relayServer serves `total` gitoids the way the Judge platform's dsses
// resolver does: a request with no `first` gets the server's cap (the
// page_clamp.go default), an oversized `first` is clamped to it, and the
// cursor is an opaque position. pageInfo is always returned.
func relayServer(t *testing.T, total, serverCap int, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var req struct {
			Query     string                     `json:"query"`
			Variables map[string]json.RawMessage `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		first := serverCap
		if raw, ok := req.Variables["first"]; ok && string(raw) != "null" {
			if err := json.Unmarshal(raw, &first); err != nil || first <= 0 {
				http.Error(w, "bad first", http.StatusBadRequest)
				return
			}
			first = min(first, serverCap)
		}
		start := 0
		if raw, ok := req.Variables["after"]; ok && string(raw) != "null" {
			var cursor string
			if err := json.Unmarshal(raw, &cursor); err != nil {
				http.Error(w, "bad after", http.StatusBadRequest)
				return
			}
			n, err := strconv.Atoi(cursor)
			if err != nil {
				http.Error(w, "bad cursor", http.StatusBadRequest)
				return
			}
			start = n + 1
		}
		end := min(start+first, total)
		type node struct {
			Gitoid string `json:"gitoidSha256"`
		}
		type edge struct {
			Node node `json:"node"`
		}
		edges := make([]edge, 0, max(end-start, 0))
		for i := start; i < end; i++ {
			edges = append(edges, edge{Node: node{Gitoid: fmt.Sprintf("gitoid-%05d", i)}})
		}
		var endCursor *string
		if end > start {
			c := strconv.Itoa(end - 1)
			endCursor = &c
		}
		data, _ := json.Marshal(map[string]any{"dsses": map[string]any{
			"edges":    edges,
			"pageInfo": map[string]any{"hasNextPage": end < total, "endCursor": endCursor},
		}})
		_ = json.NewEncoder(w).Encode(graphqlResponse{Data: data})
	}))
}

func wantGitoids(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("gitoid-%05d", i)
	}
	return out
}

// THE LOAD-BEARING TEST (#11485): a subject with more candidates than the
// server returns per request must yield EVERY candidate, for each of the three
// gitoid searches. Before pagination the client sent no `first` and read no
// pageInfo, so it silently received the server's first 1000 and stopped.
func TestGitoidSearchesPaginateToExhaustion(t *testing.T) {
	const serverCap = 1000
	const total = 2*serverCap + 501 // above the cap, not a multiple of it

	searches := map[string]func(*Client) ([]string, error){
		"SearchGitoids": func(c *Client) ([]string, error) {
			return c.SearchGitoids(context.Background(), SearchGitoidVariables{
				CollectionName: "image", SubjectDigests: []string{"abc"},
			})
		},
		"SearchGitoidsBySubjects": func(c *Client) ([]string, error) {
			return c.SearchGitoidsBySubjects(context.Background(), []string{"abc"}, nil)
		},
		"SearchGitoidsByPredicate": func(c *Client) ([]string, error) {
			return c.SearchGitoidsByPredicate(context.Background(), SearchGitoidByPredicateVariables{
				PredicateTypes: []string{"https://slsa.dev/provenance/v1"}, SubjectDigests: []string{"abc"},
			})
		},
	}
	for name, search := range searches {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			srv := relayServer(t, total, serverCap, &requests)
			defer srv.Close()

			got, err := search(New(srv.URL))
			require.NoError(t, err)
			require.Equal(t, wantGitoids(total), got,
				"every candidate past the server's page cap must be returned, in server order")
			require.EqualValues(t, 3, requests.Load(), "2501 candidates at 1000 per page is exactly three requests")
		})
	}
}

// A server that clamps below SearchPageSize still yields every candidate: the
// page size is a request, never a result cap.
func TestGitoidSearchFollowsCursorWhenServerClampsLower(t *testing.T) {
	var requests atomic.Int32
	srv := relayServer(t, 23, 5, &requests)
	defer srv.Close()

	got, err := New(srv.URL).SearchGitoids(context.Background(), SearchGitoidVariables{CollectionName: "image"})
	require.NoError(t, err)
	require.Equal(t, wantGitoids(23), got)
	require.EqualValues(t, 5, requests.Load())
}

// At or under one page the search costs exactly one request, as before.
func TestGitoidSearchSinglePageIsOneRequest(t *testing.T) {
	var requests atomic.Int32
	srv := relayServer(t, SearchPageSize, SearchPageSize, &requests)
	defer srv.Close()

	got, err := New(srv.URL).SearchGitoids(context.Background(), SearchGitoidVariables{CollectionName: "image"})
	require.NoError(t, err)
	require.Len(t, got, SearchPageSize)
	require.EqualValues(t, 1, requests.Load())
}

// A next page that cannot be reached must fail the search, never return the
// pages read so far as if they were the whole answer.
func TestGitoidSearchRefusesUnprogressablePagination(t *testing.T) {
	cases := map[string]string{
		"no end cursor":   `{"dsses":{"edges":[{"node":{"gitoidSha256":"a"}}],"pageInfo":{"hasNextPage":true,"endCursor":null}}}`,
		"empty cursor":    `{"dsses":{"edges":[{"node":{"gitoidSha256":"a"}}],"pageInfo":{"hasNextPage":true,"endCursor":""}}}`,
		"empty next page": `{"dsses":{"edges":[],"pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}`,
		"repeated cursor": `{"dsses":{"edges":[{"node":{"gitoidSha256":"a"}}],"pageInfo":{"hasNextPage":true,"endCursor":"same"}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) > 10 {
					http.Error(w, "client did not stop", http.StatusTeapot)
					return
				}
				_ = json.NewEncoder(w).Encode(graphqlResponse{Data: json.RawMessage(body)})
			}))
			defer srv.Close()

			got, err := New(srv.URL).SearchGitoids(context.Background(), SearchGitoidVariables{CollectionName: "image"})
			require.Error(t, err)
			require.Nil(t, got)
			require.Contains(t, err.Error(), "refusing")
			require.LessOrEqual(t, requests.Load(), int32(2), "the client must stop at the first page that cannot progress")
		})
	}
}

// The pagination variables travel alongside the caller's own search variables
// in one JSON object, and the query declares them.
func TestGitoidSearchSendsPaginationVariables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Contains(t, req.Query, "first: $first")
		require.Contains(t, req.Query, "after: $after")
		require.Contains(t, req.Query, "pageInfo")
		require.EqualValues(t, SearchPageSize, req.Variables["first"])
		require.Equal(t, "image", req.Variables["collectionName"])
		require.Equal(t, []any{"abc"}, req.Variables["subjectDigests"])
		_ = json.NewEncoder(w).Encode(graphqlResponse{Data: json.RawMessage(`{"dsses":{"edges":[]}}`)})
	}))
	defer srv.Close()

	got, err := New(srv.URL).SearchGitoids(context.Background(), SearchGitoidVariables{
		CollectionName: "image", SubjectDigests: []string{"abc"},
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, got)
}
