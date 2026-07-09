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

package options

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bindingsServer answers the policyBindings query with bindingsJSON and the
// policyReleases (latest-release fallback) query with releasesJSON.
func bindingsServer(t *testing.T, bindingsJSON, releasesJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		switch {
		case strings.Contains(req.Query, "policyBindings("):
			_, _ = io.WriteString(w, bindingsJSON)
		case strings.Contains(req.Query, "policyReleases("):
			_, _ = io.WriteString(w, releasesJSON)
		default:
			t.Errorf("unexpected query: %s", req.Query)
		}
	}))
}

// TestResolveBoundPolicy_PinnedRelease is the happy path a flagless verify
// takes: one binding with a pinned release resolves straight to the release's
// policy-envelope gitoid, carrying full provenance (who bound it, when).
func TestResolveBoundPolicy_PinnedRelease(t *testing.T) {
	srv := bindingsServer(t, `{"data":{"policyBindings":{"edges":[{"node":{
		"id":"bind-1","createdAt":"2026-07-09T15:04:05Z",
		"createdBy":{"name":"Alice","email":"alice@uat.test"},
		"policyDefinition":{"id":"def-1","name":"supply-chain"},
		"policyRelease":{"id":"rel-1","tag":"v1.0.0","dsse":{"gitoidSha256":"gitoid-policy-1"}}
	}}]}}}`, `{}`)
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	bp, err := c.ResolveBoundPolicy(context.Background(), "prod-1")
	if err != nil {
		t.Fatalf("ResolveBoundPolicy: %v", err)
	}
	if bp == nil {
		t.Fatal("want a bound policy, got nil")
	}
	if bp.Gitoid != "gitoid-policy-1" {
		t.Fatalf("gitoid = %q, want gitoid-policy-1", bp.Gitoid)
	}
	if bp.DefinitionName != "supply-chain" || bp.ReleaseTag != "v1.0.0" {
		t.Fatalf("provenance = %q/%q, want supply-chain/v1.0.0", bp.DefinitionName, bp.ReleaseTag)
	}
	if bp.BoundBy != "Alice <alice@uat.test>" {
		t.Fatalf("BoundBy = %q, want Alice <alice@uat.test>", bp.BoundBy)
	}
	if bp.BoundAt != "2026-07-09T15:04:05Z" {
		t.Fatalf("BoundAt = %q", bp.BoundAt)
	}
}

// TestResolveBoundPolicy_UnpinnedFallsBackToLatestRelease covers a binding
// created without --release/--tag: the definition's latest release applies.
func TestResolveBoundPolicy_UnpinnedFallsBackToLatestRelease(t *testing.T) {
	srv := bindingsServer(t, `{"data":{"policyBindings":{"edges":[{"node":{
		"id":"bind-1","createdAt":"2026-07-09T15:04:05Z",
		"createdBy":{"name":"","email":"alice@uat.test"},
		"policyDefinition":{"id":"def-1","name":"supply-chain"},
		"policyRelease":null
	}}]}}}`, `{"data":{"policyReleases":{"edges":[{"node":{
		"id":"rel-9","tag":"v2.1.0","dsse":{"gitoidSha256":"gitoid-latest"}
	}}]}}}`)
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	bp, err := c.ResolveBoundPolicy(context.Background(), "prod-1")
	if err != nil {
		t.Fatalf("ResolveBoundPolicy: %v", err)
	}
	if bp == nil || bp.Gitoid != "gitoid-latest" || bp.ReleaseTag != "v2.1.0" {
		t.Fatalf("got %+v, want the definition's latest release gitoid-latest/v2.1.0", bp)
	}
	if bp.BoundBy != "alice@uat.test" {
		t.Fatalf("BoundBy = %q, want the email-only fallback", bp.BoundBy)
	}
}

// TestResolveBoundPolicy_NoBindingReturnsNil: no binding is NOT an error at
// this layer — the caller owns the actionable "run cilock policy bind" message.
func TestResolveBoundPolicy_NoBindingReturnsNil(t *testing.T) {
	srv := bindingsServer(t, `{"data":{"policyBindings":{"edges":[]}}}`, `{}`)
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	bp, err := c.ResolveBoundPolicy(context.Background(), "prod-1")
	if err != nil {
		t.Fatalf("ResolveBoundPolicy: %v", err)
	}
	if bp != nil {
		t.Fatalf("want nil for an unbound product, got %+v", bp)
	}
}

// TestResolveBoundPolicy_MultipleBindingsFailClosed: verify must never silently
// pick among several bound policies — the error names them and the -p override.
func TestResolveBoundPolicy_MultipleBindingsFailClosed(t *testing.T) {
	srv := bindingsServer(t, `{"data":{"policyBindings":{"edges":[
		{"node":{"id":"bind-1","createdAt":"2026-01-01T00:00:00Z","policyDefinition":{"id":"d1","name":"supply-chain"}}},
		{"node":{"id":"bind-2","createdAt":"2026-01-02T00:00:00Z","policyDefinition":{"id":"d2","name":"compliance"}}}
	]}}}`, `{}`)
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveBoundPolicy(context.Background(), "prod-1")
	if err == nil {
		t.Fatal("want an error for multiple bindings")
	}
	for _, want := range []string{"supply-chain", "compliance", "-p"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q should mention %q", err.Error(), want)
		}
	}
}

// TestResolveBoundPolicy_BoundDefinitionWithoutReleases names the fix when the
// bound definition has never been pushed.
func TestResolveBoundPolicy_BoundDefinitionWithoutReleases(t *testing.T) {
	srv := bindingsServer(t, `{"data":{"policyBindings":{"edges":[{"node":{
		"id":"bind-1","createdAt":"2026-07-09T15:04:05Z",
		"policyDefinition":{"id":"def-1","name":"supply-chain"},
		"policyRelease":null
	}}]}}}`, `{"data":{"policyReleases":{"edges":[]}}}`)
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveBoundPolicy(context.Background(), "prod-1")
	if err == nil {
		t.Fatal("want an error for a bound definition with no releases")
	}
	if !strings.Contains(err.Error(), "cilock policy push") || !strings.Contains(err.Error(), "supply-chain") {
		t.Fatalf("error should name the definition and the `cilock policy push` fix, got %q", err.Error())
	}
}

// TestResolveBoundPolicy_ReleaseWithoutEnvelopeFailsClosed: a release whose
// Dsse edge is missing cannot be verified against — the error names the fix
// instead of passing an empty gitoid to the policy loader.
func TestResolveBoundPolicy_ReleaseWithoutEnvelopeFailsClosed(t *testing.T) {
	srv := bindingsServer(t, `{"data":{"policyBindings":{"edges":[{"node":{
		"id":"bind-1","createdAt":"2026-07-09T15:04:05Z",
		"policyDefinition":{"id":"def-1","name":"supply-chain"},
		"policyRelease":{"id":"rel-1","tag":"v1.0.0","dsse":null}
	}}]}}}`, `{}`)
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveBoundPolicy(context.Background(), "prod-1")
	if err == nil {
		t.Fatal("want an error for a release with no stored envelope")
	}
	if !strings.Contains(err.Error(), "cilock policy push") {
		t.Fatalf("error should name the `cilock policy push` fix, got %q", err.Error())
	}
}
