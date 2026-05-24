// Copyright 2025 The Aflock Authors
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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockArchivista returns a minimal HTTP server emulating the Archivista
// GraphQL + download endpoints for SearchByPredicateType tests.
//
// gitoidToEnvelope maps gitoidSha256 -> DSSE envelope returned by /download.
// graphqlGitoids is the list returned by the GraphQL dsses query; pass nil
// for "empty result", or set graphqlError to simulate a GraphQL error.
func mockArchivista(t *testing.T, gitoidToEnvelope map[string]dsse.Envelope, graphqlGitoids []string, graphqlError string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if graphqlError != "" {
			// GraphQL returns 200 with errors array, per spec.
			resp := map[string]interface{}{
				"errors": []map[string]interface{}{{"message": graphqlError}},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		edges := make([]map[string]interface{}, 0, len(graphqlGitoids))
		for _, g := range graphqlGitoids {
			edges = append(edges, map[string]interface{}{"node": map[string]string{"gitoidSha256": g}})
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"dsses": map[string]interface{}{"edges": edges},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		gitoid := strings.TrimPrefix(r.URL.Path, "/download/")
		env, ok := gitoidToEnvelope[gitoid]
		if !ok {
			http.Error(w, fmt.Sprintf("gitoid %s not found", gitoid), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	})

	return httptest.NewServer(mux)
}

// mockArchivistaDownloadFailure returns a server that always succeeds on
// /query but returns 500 on /download — used to exercise the download-failure
// path (envelopes are skipped entirely).
func mockArchivistaDownloadFailure(t *testing.T, graphqlGitoids []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		edges := make([]map[string]interface{}, 0, len(graphqlGitoids))
		for _, g := range graphqlGitoids {
			edges = append(edges, map[string]interface{}{"node": map[string]string{"gitoidSha256": g}})
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{"dsses": map[string]interface{}{"edges": edges}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	return httptest.NewServer(mux)
}

func buildStatementEnvelope(t *testing.T, predicateType string, subjectDigest string, predicate json.RawMessage) dsse.Envelope {
	t.Helper()
	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: predicateType,
		Subject: []intoto.Subject{
			{Name: "pkg:example/artifact", Digest: map[string]string{"sha256": subjectDigest}},
		},
		Predicate: predicate,
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	return dsse.Envelope{Payload: payload, PayloadType: intoto.PayloadType}
}

// TestArchivistaSource_SearchByPredicateType_HappyPath_Typed exercises a
// typed SLSA-v1 envelope: Archivista returns 1 gitoid, the download endpoint
// returns a valid envelope, and the factory registered for the predicate
// type yields a structured Attestor (never RawAttestation).
func TestArchivistaSource_SearchByPredicateType_HappyPath_Typed(t *testing.T) {
	const (
		predicateType = "https://slsa.dev/provenance/v1"
		subjectDigest = "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebab0"
		gitoid        = "gitoid-slsa-v1-typed"
	)

	// Register a test factory for the predicate type so the typed path fires.
	// Use RegisterAttestationWithTypes to avoid polluting the name registry.
	type fakeSLSA struct {
		BuildDefinition map[string]interface{} `json:"buildDefinition"`
	}
	factory := func() attestation.Attestor {
		return &archivistaTestAttestor{predicateType: predicateType, data: &fakeSLSA{}}
	}
	attestation.RegisterAttestation("archivista-test-slsa-v1", predicateType, attestation.VerifyRunType, factory)
	t.Cleanup(func() { unregisterTestAttestation(predicateType) })

	env := buildStatementEnvelope(t, predicateType, subjectDigest, json.RawMessage(`{
        "buildDefinition": {"buildType": "https://example.com/build/v1"},
        "runDetails": {"builder": {"id": "https://example.com/builder"}}
    }`))

	srv := mockArchivista(t, map[string]dsse.Envelope{gitoid: env}, []string{gitoid}, "")
	defer srv.Close()

	client := archivista.New(srv.URL)
	src := NewArchivistaSource(client)
	got, err := src.SearchByPredicateType(context.Background(), []string{predicateType}, []string{subjectDigest})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, gitoid, got[0].Reference)
	assert.Equal(t, predicateType, got[0].Statement.PredicateType)
	require.NotNil(t, got[0].Attestor)
	// Confirm the typed path was taken (not RawAttestation) — factory returns
	// archivistaTestAttestor, RawAttestation comes from attestation package.
	_, isRaw := got[0].Attestor.(*attestation.RawAttestation)
	assert.False(t, isRaw, "should use typed factory, not RawAttestation")
}

// TestArchivistaSource_SearchByPredicateType_HappyPath_UnknownFalsbackToRaw
// covers the branch where no factory is registered for the predicate type —
// the source must fall back to RawAttestation preserving the raw predicate
// bytes.
func TestArchivistaSource_SearchByPredicateType_HappyPath_UnknownFalsbackToRaw(t *testing.T) {
	const (
		predicateType = "https://example.com/totally-unregistered/v1"
		subjectDigest = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
		gitoid        = "gitoid-unknown-predicate"
	)

	env := buildStatementEnvelope(t, predicateType, subjectDigest, json.RawMessage(`{"arbitrary":"payload","n":42}`))
	srv := mockArchivista(t, map[string]dsse.Envelope{gitoid: env}, []string{gitoid}, "")
	defer srv.Close()

	client := archivista.New(srv.URL)
	src := NewArchivistaSource(client)
	got, err := src.SearchByPredicateType(context.Background(), []string{predicateType}, []string{subjectDigest})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.NotNil(t, got[0].Attestor)
	raw, ok := got[0].Attestor.(*attestation.RawAttestation)
	require.True(t, ok, "unknown predicate type should fall back to RawAttestation, got %T", got[0].Attestor)
	assert.Equal(t, predicateType, raw.Type())
	// MarshalJSON on RawAttestation returns the raw predicate bytes verbatim.
	b, err := json.Marshal(raw)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"arbitrary":"payload"`)
}

// TestArchivistaSource_SearchByPredicateType_EmptyResult asserts the
// empty-list return shape when Archivista reports no matching gitoids.
func TestArchivistaSource_SearchByPredicateType_EmptyResult(t *testing.T) {
	srv := mockArchivista(t, nil, []string{}, "")
	defer srv.Close()

	client := archivista.New(srv.URL)
	src := NewArchivistaSource(client)
	got, err := src.SearchByPredicateType(context.Background(), []string{"https://slsa.dev/provenance/v1"}, []string{"anything"})
	require.NoError(t, err)
	assert.Empty(t, got, "empty gitoid list from Archivista should yield zero StatementEnvelopes")
}

// TestArchivistaSource_SearchByPredicateType_GraphQLError asserts that a
// GraphQL error from Archivista propagates as an error to the caller.
func TestArchivistaSource_SearchByPredicateType_GraphQLError(t *testing.T) {
	srv := mockArchivista(t, nil, nil, "schema does not support predicateIn")
	defer srv.Close()

	client := archivista.New(srv.URL)
	src := NewArchivistaSource(client)
	got, err := src.SearchByPredicateType(context.Background(), []string{"https://slsa.dev/provenance/v1"}, []string{"anything"})
	require.Error(t, err, "GraphQL errors must propagate, not be swallowed")
	assert.Contains(t, err.Error(), "predicateIn")
	assert.Nil(t, got)
}

// TestArchivistaSource_SearchByPredicateType_DownloadFailureSkips asserts
// that when Archivista returns a gitoid but /download fails, the envelope
// is skipped (not returned, not an error) — matching the existing Search
// pattern that logs and continues.
func TestArchivistaSource_SearchByPredicateType_DownloadFailureSkips(t *testing.T) {
	srv := mockArchivistaDownloadFailure(t, []string{"failing-gitoid-1", "failing-gitoid-2"})
	defer srv.Close()

	client := archivista.New(srv.URL)
	src := NewArchivistaSource(client)
	got, err := src.SearchByPredicateType(context.Background(), []string{"https://slsa.dev/provenance/v1"}, []string{"anything"})
	require.NoError(t, err, "download failure must not bubble up — it should skip the bad gitoid")
	assert.Empty(t, got)
}

// archivistaTestAttestor is a typed attestor for archivista tests. It's
// defined here rather than as an anonymous struct because
// attestation.Attestor is an interface that needs Name/Type/RunType methods.
type archivistaTestAttestor struct {
	predicateType string
	data          interface{}
}

func (a *archivistaTestAttestor) Name() string                                   { return "archivista-test" }
func (a *archivistaTestAttestor) Type() string                                   { return a.predicateType }
func (a *archivistaTestAttestor) RunType() attestation.RunType                   { return attestation.VerifyRunType }
func (a *archivistaTestAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *archivistaTestAttestor) Schema() *jsonschema.Schema                     { return nil }
func (a *archivistaTestAttestor) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &a.data)
}
func (a *archivistaTestAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.data)
}

// unregisterTestAttestation removes the test-registered factory so
// subsequent tests don't collide. The registry package doesn't expose an
// unregister method, so we can only best-effort clear the type index.
// This is test-only hygiene.
func unregisterTestAttestation(_ string) {
	// no-op for now; factories are process-global in the attestation
	// package. Tests use unique predicate-type URIs to avoid collisions.
	_ = io.EOF // ensure io import is consumed if we refactor later
}
