// jade:ring local
// Copyright 2026 TestifySec, Inc.
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

package source

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #9816: subject matching ignored the digest algorithm. A subject
// digest under one algorithm matched a seed produced under another whenever
// the value strings were equal. These tests run the same cases against every
// Sourcer that decides a subject match.

var (
	algoTestHex64 = strings.Repeat("9e", 32) // a sha256-shaped value
	algoTestHex40 = strings.Repeat("7c", 20) // a git-commit-shaped value
)

type algoCase struct {
	name    string
	subject map[string]string // algorithm -> value on the signed subject
	seeds   []string
	want    bool
}

func algoCases() []algoCase {
	return []algoCase{
		{
			// The #9816 repro: a gitoid:sha256 subject whose value is 64 hex
			// must not satisfy a sha256 seed of the same string.
			name:    "gitoid:sha256 value does not match bare sha256 seed",
			subject: map[string]string{"gitoid:sha256": algoTestHex64},
			seeds:   []string{algoTestHex64},
			want:    false,
		},
		{
			name:    "gitoid:sha256 value does not match explicit sha256 seed",
			subject: map[string]string{"gitoid:sha256": algoTestHex64},
			seeds:   []string{"sha256:" + algoTestHex64},
			want:    false,
		},
		{
			// A dirHash subject carrying a commit-shaped value must not stand
			// in for a git commit seed: that would bypass the hardened-git
			// SHA-1 gate entirely.
			name:    "dirHash with 40-hex value does not match commit seed",
			subject: map[string]string{"dirHash": algoTestHex40},
			seeds:   []string{algoTestHex40},
			want:    false,
		},
		{
			name:    "dirHash with 40-hex value does not match explicit sha1 seed",
			subject: map[string]string{"dirHash": algoTestHex40},
			seeds:   []string{"sha1:" + algoTestHex40},
			want:    false,
		},
		{
			name:    "same algorithm matches (bare sha256 seed)",
			subject: map[string]string{"sha256": algoTestHex64},
			seeds:   []string{algoTestHex64},
			want:    true,
		},
		{
			name:    "same algorithm matches (keyed sha256 seed)",
			subject: map[string]string{"sha256": algoTestHex64},
			seeds:   []string{"sha256:" + algoTestHex64},
			want:    true,
		},
		{
			name:    "same algorithm matches (keyed gitoid:sha256 seed)",
			subject: map[string]string{"gitoid:sha256": "gitoid:blob:sha256:" + algoTestHex64},
			seeds:   []string{"gitoid:sha256:gitoid:blob:sha256:" + algoTestHex64},
			want:    true,
		},
		{
			// A bare gitoid URI names its own algorithm.
			name:    "same algorithm matches (bare gitoid URI seed)",
			subject: map[string]string{"gitoid:sha256": "gitoid:blob:sha256:" + algoTestHex64},
			seeds:   []string{"gitoid:blob:sha256:" + algoTestHex64},
			want:    true,
		},
		{
			name:    "same algorithm matches (dirHash)",
			subject: map[string]string{"dirHash": "h1:abc="},
			seeds:   []string{"h1:abc="},
			want:    true,
		},
		{
			// An explicit key for the WRONG algorithm never matches, even
			// when the value is identical.
			name:    "explicit dirHash seed does not match sha256 subject",
			subject: map[string]string{"sha256": algoTestHex64},
			seeds:   []string{"dirHash:" + algoTestHex64},
			want:    false,
		},
	}
}

func TestMemorySource_SubjectMatchIsAlgorithmAware(t *testing.T) {
	for _, tc := range algoCases() {
		t.Run(tc.name, func(t *testing.T) {
			src := loadCollectionWithSubject(t, tc.subject)
			got, err := src.Search(context.Background(), "build", tc.seeds, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.want, len(got) == 1, "matches=%d", len(got))

			byPred, err := src.SearchByPredicateType(context.Background(), []string{"https://aflock.ai/attestation-collection/v0.1"}, tc.seeds)
			require.NoError(t, err)
			assert.Equal(t, tc.want, len(byPred) == 1, "SearchByPredicateType matches=%d", len(byPred))
		})
	}
}

func TestVerifiedSource_SubjectMatchIsAlgorithmAware(t *testing.T) {
	for _, tc := range algoCases() {
		t.Run(tc.name, func(t *testing.T) {
			var algo, value string
			for a, v := range tc.subject {
				algo, value = a, v
			}
			ce, verifier := signedCollectionForSubject(t, "ref1", "build", algo, value)
			vs := NewVerifiedSource(&lyingSourcer{env: ce}, dsse.VerifyWithVerifiers(verifier))
			results, err := vs.Search(context.Background(), "build", tc.seeds, nil)
			require.NoError(t, err)
			require.Len(t, results, 1)
			accepted := len(results[0].Verifiers) > 0 && len(results[0].Errors) == 0
			assert.Equal(t, tc.want, accepted, "errors=%v", results[0].Errors)
		})
	}
}

// TestArchivistaSource_SubjectMatchIsAlgorithmAware covers the remote store.
// Archivista's GraphQL index is value-keyed, so the source must send the VALUE
// half of each key (a "sha256:..." string would match nothing), and the
// (algorithm, value) decision is made by VerifiedSource on the signed payload.
func TestArchivistaSource_SubjectMatchIsAlgorithmAware(t *testing.T) {
	for _, tc := range algoCases() {
		t.Run(tc.name, func(t *testing.T) {
			var algo, value string
			for a, v := range tc.subject {
				algo, value = a, v
			}
			ce, verifier := signedCollectionForSubject(t, "ignored", "build", algo, value)
			body, err := json.Marshal(ce.Envelope)
			require.NoError(t, err)
			gid := envelopeGitoid(t, body)

			var mu sync.Mutex
			var sent []string
			mux := http.NewServeMux()
			mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				var req struct {
					Variables struct {
						SubjectDigests []string `json:"subjectDigests"`
					} `json:"variables"`
				}
				_ = json.Unmarshal(raw, &req)
				mu.Lock()
				sent = append(sent, req.Variables.SubjectDigests...)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{"dsses": map[string]interface{}{
						"edges": []map[string]interface{}{{"node": map[string]string{"gitoidSha256": gid}}},
					}},
				})
			})
			mux.HandleFunc("/download/", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			vs := NewVerifiedSource(NewArchivistaSource(archivista.New(srv.URL)), dsse.VerifyWithVerifiers(verifier))
			results, err := vs.Search(context.Background(), "build", tc.seeds, nil)
			require.NoError(t, err)
			accepted := false
			for _, r := range results {
				if len(r.Verifiers) > 0 && len(r.Errors) == 0 {
					accepted = true
				}
			}
			assert.Equal(t, tc.want, accepted)

			mu.Lock()
			defer mu.Unlock()
			for _, s := range sent {
				_, _, isKey := cryptoutil.ParseSubjectDigestKey(s)
				assert.False(t, isKey, "archivista must receive digest VALUES, got key %q", s)
			}
		})
	}
}
