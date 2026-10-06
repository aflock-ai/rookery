// jade:ring local

// Copyright 2026 The Aflock Authors
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

package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func notFoundServer(hits *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
}

// A path-shaped -p that does not exist is a missing file, not a gitoid: the
// Archivista 404 used to mask the real cause.
func TestLoadPolicy_MissingPathShapedArgNeverReachesArchivista(t *testing.T) {
	var hits atomic.Int32
	srv := notFoundServer(&hits)
	defer srv.Close()
	ac := archivista.New(srv.URL)

	missing := filepath.Join(t.TempDir(), "policy.json")
	_, err := LoadPolicy(context.Background(), missing, ac)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy file not found: "+missing)
	assert.Zero(t, hits.Load())
}

func TestLoadPolicy_BareGitoidStillFallsBackToArchivista(t *testing.T) {
	var hits atomic.Int32
	srv := notFoundServer(&hits)
	defer srv.Close()
	ac := archivista.New(srv.URL)

	_, err := LoadPolicy(context.Background(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ac)
	require.Error(t, err)
	assert.NotZero(t, hits.Load())
}
