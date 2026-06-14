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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gqlRequest is the parsed shape of a GraphQL POST the test server inspects.
type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// readGQL parses the request body into a gqlRequest.
func readGQL(t *testing.T, r *http.Request) gqlRequest {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var req gqlRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal body %q: %v", string(body), err)
	}
	return req
}

// inputVar pulls the "input" variable map out of a gqlRequest.
func inputVar(t *testing.T, req gqlRequest) map[string]any {
	t.Helper()
	raw, ok := req.Variables["input"]
	if !ok {
		t.Fatalf("request has no input variable: %#v", req.Variables)
	}
	m, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("input is not an object: %#v", raw)
	}
	return m
}

func TestResolveDsseIDByGitoid(t *testing.T) {
	var gotGitoid string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		if !strings.Contains(req.Query, "dsses(") || !strings.Contains(req.Query, "gitoidSha256: $gitoid") {
			t.Errorf("unexpected query: %s", req.Query)
		}
		gotGitoid, _ = req.Variables["gitoid"].(string)
		_, _ = io.WriteString(w, `{"data":{"dsses":{"edges":[{"node":{"id":"dsse-uuid-1","gitoidSha256":"gitoid-abc"}}]}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	id, err := c.ResolveDsseIDByGitoid(context.Background(), "gitoid-abc")
	if err != nil {
		t.Fatalf("ResolveDsseIDByGitoid: %v", err)
	}
	if id != "dsse-uuid-1" {
		t.Fatalf("got dsse id %q, want dsse-uuid-1", id)
	}
	if gotGitoid != "gitoid-abc" {
		t.Fatalf("server saw gitoid %q, want gitoid-abc", gotGitoid)
	}
}

func TestResolveDsseIDByGitoid_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"dsses":{"edges":[]}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	id, err := c.ResolveDsseIDByGitoid(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "" {
		t.Fatalf("got id %q, want empty (not found)", id)
	}
}

func TestResolvePolicyDefinitionByName_FoundAndMissing(t *testing.T) {
	// Found.
	found := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		if name, _ := req.Variables["name"].(string); name != "supply-chain" {
			t.Errorf("server saw name %q, want supply-chain", name)
		}
		_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-1","name":"supply-chain"}}]}}}`)
	}))
	defer found.Close()

	c := &PolicyClient{GraphQLURL: found.URL, Token: "tok"}
	def, err := c.ResolvePolicyDefinitionByName(context.Background(), "supply-chain")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if def == nil || def.ID != "def-1" {
		t.Fatalf("got %#v, want def-1", def)
	}

	// Missing → nil, no error (the create-if-missing seam).
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[]}}}`)
	}))
	defer missing.Close()
	c2 := &PolicyClient{GraphQLURL: missing.URL, Token: "tok"}
	def2, err := c2.ResolvePolicyDefinitionByName(context.Background(), "nope")
	if err != nil {
		t.Fatalf("resolve missing: %v", err)
	}
	if def2 != nil {
		t.Fatalf("got %#v, want nil for missing definition", def2)
	}
}

func TestCreatePolicyDefinition_SendsRequiredInputs(t *testing.T) {
	var input map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		if !strings.Contains(req.Query, "createPolicyDefinition(input: $input)") {
			t.Errorf("unexpected mutation: %s", req.Query)
		}
		input = inputVar(t, req)
		_, _ = io.WriteString(w, `{"data":{"createPolicyDefinition":{"id":"def-new","name":"supply-chain"}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	def, err := c.CreatePolicyDefinition(context.Background(), "tenant-9", "supply-chain", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if def.ID != "def-new" {
		t.Fatalf("got id %q, want def-new", def.ID)
	}
	// tenantID + name + description (defaulted) are required by the schema.
	if input["tenantID"] != "tenant-9" {
		t.Errorf("tenantID = %v, want tenant-9", input["tenantID"])
	}
	if input["name"] != "supply-chain" {
		t.Errorf("name = %v, want supply-chain", input["name"])
	}
	if desc, _ := input["description"].(string); desc == "" {
		t.Errorf("description must be non-empty (schema requires it); got empty")
	}
	if input["isActive"] != true {
		t.Errorf("isActive = %v, want true", input["isActive"])
	}
}

func TestCreatePolicyRelease_SendsDefinitionAndDsseAndTag(t *testing.T) {
	var input map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		if !strings.Contains(req.Query, "createPolicyRelease(input: $input)") {
			t.Errorf("unexpected mutation: %s", req.Query)
		}
		input = inputVar(t, req)
		_, _ = io.WriteString(w, `{"data":{"createPolicyRelease":{"id":"rel-1","tag":"v1.0.0"}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	rel, err := c.CreatePolicyRelease(context.Background(), "tenant-9", "def-1", "dsse-uuid-1", "v1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	if rel.ID != "rel-1" || rel.Tag != "v1.0.0" {
		t.Fatalf("got %#v, want rel-1/v1.0.0", rel)
	}
	if input["tenantID"] != "tenant-9" {
		t.Errorf("tenantID = %v, want tenant-9", input["tenantID"])
	}
	if input["tag"] != "v1.0.0" {
		t.Errorf("tag = %v, want v1.0.0", input["tag"])
	}
	if input["policyDefinitionID"] != "def-1" {
		t.Errorf("policyDefinitionID = %v, want def-1", input["policyDefinitionID"])
	}
	// The DSSE edge id (a UUID), NOT the gitoid — this is the load-bearing
	// distinction the push flow resolves before calling here.
	if input["dsseID"] != "dsse-uuid-1" {
		t.Errorf("dsseID = %v, want dsse-uuid-1 (the resolved Dsse edge id, not the gitoid)", input["dsseID"])
	}
}

func TestCreatePolicyBinding_SendsEdges(t *testing.T) {
	var input map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		if !strings.Contains(req.Query, "createPolicyBinding(input: $input)") {
			t.Errorf("unexpected mutation: %s", req.Query)
		}
		input = inputVar(t, req)
		_, _ = io.WriteString(w, `{"data":{"createPolicyBinding":{"id":"bind-1","policyDefinition":{"id":"def-1","name":"supply-chain"},"policyRelease":{"id":"rel-1","tag":"v1.0.0"},"product":{"id":"prod-1","name":"svc"}}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	bind, err := c.CreatePolicyBinding(context.Background(), "tenant-9", "def-1", "rel-1", "prod-1")
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if bind.ID != "bind-1" {
		t.Fatalf("got id %q, want bind-1", bind.ID)
	}
	if input["tenantID"] != "tenant-9" {
		t.Errorf("tenantID = %v, want tenant-9", input["tenantID"])
	}
	if input["policyDefinitionID"] != "def-1" {
		t.Errorf("policyDefinitionID = %v, want def-1", input["policyDefinitionID"])
	}
	if input["policyReleaseID"] != "rel-1" {
		t.Errorf("policyReleaseID = %v, want rel-1", input["policyReleaseID"])
	}
	if input["productID"] != "prod-1" {
		t.Errorf("productID = %v, want prod-1", input["productID"])
	}
}

func TestCreatePolicyBinding_OmitsEmptyRelease(t *testing.T) {
	var input map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input = inputVar(t, readGQL(t, r))
		_, _ = io.WriteString(w, `{"data":{"createPolicyBinding":{"id":"bind-2"}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	if _, err := c.CreatePolicyBinding(context.Background(), "t", "def-1", "", "prod-1"); err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if _, present := input["policyReleaseID"]; present {
		t.Errorf("policyReleaseID must be omitted when empty; got %v", input["policyReleaseID"])
	}
}

func TestResolveProduct_ByName_Ambiguous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		// productByID is tried first; return empty so it falls through to name.
		if strings.Contains(req.Query, "CilockProductByID") {
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[]}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"products":{"edges":[{"node":{"id":"p1","name":"svc"}},{"node":{"id":"p2","name":"svc"}}]}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil || !strings.Contains(err.Error(), "multiple products") {
		t.Fatalf("want ambiguous-name error, got %v", err)
	}
}

func TestResolveProduct_ByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		if strings.Contains(req.Query, "CilockProductByID") {
			if id, _ := req.Variables["id"].(string); id == "prod-xyz" {
				_, _ = io.WriteString(w, `{"data":{"products":{"edges":[{"node":{"id":"prod-xyz","name":"svc"}}]}}}`)
				return
			}
		}
		_, _ = io.WriteString(w, `{"data":{"products":{"edges":[]}}}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	p, err := c.ResolveProduct(context.Background(), "prod-xyz")
	if err != nil {
		t.Fatalf("resolve by id: %v", err)
	}
	if p.ID != "prod-xyz" {
		t.Fatalf("got %#v, want prod-xyz", p)
	}
}

// TestScopeDenied_HelpfulError asserts a server scope rejection (HTTP 200 with a
// GraphQL error mentioning the scope, the platform's actual shape) is rewritten
// into an actionable "run cilock login" remedy.
func TestScopeDenied_HelpfulError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"errors":[{"message":"missing required scope \"policy:write\""}]}`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.CreatePolicyRelease(context.Background(), "t", "def-1", "dsse-1", "v1")
	if err == nil {
		t.Fatal("want scope-denied error, got nil")
	}
	if !strings.Contains(err.Error(), "cilock login") {
		t.Errorf("error should steer to `cilock login`; got: %v", err)
	}
	if !strings.Contains(err.Error(), "policy:write") {
		t.Errorf("error should name policy:write; got: %v", err)
	}
}

// TestScopeDenied_HTTP403 asserts an HTTP-403 transport rejection also maps to
// the helpful remedy.
func TestScopeDenied_HTTP403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `forbidden`)
	}))
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.CreatePolicyBinding(context.Background(), "t", "def-1", "", "prod-1")
	if err == nil || !strings.Contains(err.Error(), "cilock login") {
		t.Fatalf("want helpful scope error, got %v", err)
	}
}

func TestPost_RequiresTokenAndURL(t *testing.T) {
	if _, err := (&PolicyClient{Token: "tok"}).ResolveDsseIDByGitoid(context.Background(), "g"); err == nil {
		t.Error("want error for missing GraphQL URL")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"dsses":{"edges":[]}}}`)
	}))
	defer srv.Close()
	if _, err := (&PolicyClient{GraphQLURL: srv.URL}).ResolveDsseIDByGitoid(context.Background(), "g"); err == nil {
		t.Error("want error for missing token")
	}
}
