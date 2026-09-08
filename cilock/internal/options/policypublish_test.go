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
	"fmt"
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

// --- #7566: a failed product lookup must name the products it could bind to ---
//
// The remedy the old error named ("pass the product id or exact name") was not
// obtainable from cilock: there is no product-listing subcommand, so a CLI-only
// user had nowhere to learn either the id or the exact name. These tests pin the
// listing that closes that loop, and the bounds it must respect.

// productNodeJSON builds one `{"node":{"id":..,"name":..}}` edge, JSON-escaping
// the name so a test can feed in a hostile one.
func productNodeJSON(t *testing.T, id, name string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"node": map[string]any{"id": id, "name": name}})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	return string(b)
}

// productPageJSON builds a products-connection reply.
func productPageJSON(total int, edges []string) string {
	return fmt.Sprintf(`{"data":{"products":{"totalCount":%d,"edges":[%s]}}}`,
		total, strings.Join(edges, ","))
}

// emptyPage is a connection holding nothing.
func emptyPage() (int, string) { return http.StatusOK, productPageJSON(0, nil) }

// candidateCalls records what the failure path asked the platform for.
type candidateCalls struct {
	list int
	near int
	// nearVar is the `near` variable the near lookup was made with.
	nearVar string
}

// productLookupServer serves the by-id and by-name lookups as misses and routes
// the two candidate queries to reply, which is told which one was asked ("list"
// or "near"). The returned counts let a test assert that the extra round trips
// happen only on the failure path.
func productLookupServer(t *testing.T, byName string, reply func(kind string) (int, string)) (*httptest.Server, *candidateCalls) {
	t.Helper()
	calls := &candidateCalls{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		kind := ""
		switch {
		case strings.Contains(req.Query, "CilockProductList"):
			calls.list++
			kind = "list"
		case strings.Contains(req.Query, "CilockProductNear"):
			calls.near++
			calls.nearVar, _ = req.Variables["near"].(string)
			kind = "near"
		case strings.Contains(req.Query, "CilockProductByName"):
			_, _ = io.WriteString(w, byName)
			return
		default: // CilockProductByID -- always a miss in these tests.
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[]}}}`)
			return
		}
		status, body := reply(kind)
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, body)
	}))
	return srv, calls
}

const noProductsJSON = `{"data":{"products":{"edges":[]}}}`

func TestResolveProduct_NotFound_ListsAvailableProducts(t *testing.T) {
	all := []string{
		productNodeJSON(t, "prod-1", "api-gateway"),
		productNodeJSON(t, "prod-2", "billing"),
	}
	srv, calls := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return emptyPage()
		}
		return http.StatusOK, productPageJSON(2, all)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{
		`no product found matching "svc" (pass the product id or exact name)`,
		"available products:",
		"  api-gateway  prod-1",
		"  billing      prod-2",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q; got:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "close matches") {
		t.Errorf("no near match here, so no close-match block belongs; got:\n%s", msg)
	}
	if calls.list != 1 {
		t.Errorf("list query issued %d times, want exactly 1", calls.list)
	}
}

func TestResolveProduct_NotFound_CaseNearMissIsCalledOut(t *testing.T) {
	near := []string{productNodeJSON(t, "prod-1", "svc")}
	all := []string{
		productNodeJSON(t, "prod-1", "svc"),
		productNodeJSON(t, "prod-2", "other"),
	}
	srv, calls := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return http.StatusOK, productPageJSON(1, near)
		}
		return http.StatusOK, productPageJSON(2, all)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "SVC")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "close matches") {
		t.Errorf("a case-only miss must be called out as such; got:\n%s", msg)
	}
	if !strings.Contains(msg, "  svc  prod-1") {
		t.Errorf("close-match block must name the exact spelling; got:\n%s", msg)
	}
	if calls.nearVar != "SVC" {
		t.Errorf("server saw near=%q, want SVC", calls.nearVar)
	}
}

func TestResolveProduct_NotFound_WhitespaceNearMissIsCalledOut(t *testing.T) {
	near := []string{productNodeJSON(t, "prod-1", "svc")}
	srv, calls := productLookupServer(t, noProductsJSON, func(string) (int, string) {
		return http.StatusOK, productPageJSON(1, near)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "  svc  ")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	if !strings.Contains(err.Error(), "close matches") {
		t.Errorf("a whitespace-only miss must be called out as such; got:\n%s", err)
	}
	// The near lookup must be made on the trimmed name, or a padded argument
	// can never match anything.
	if calls.nearVar != "svc" {
		t.Errorf("server saw near=%q, want the trimmed \"svc\"", calls.nearVar)
	}
}

// TestResolveProduct_NotFound_UnrelatedNearRowIsDropped pins that the close-match
// block is re-checked locally: a server that ignores the fold predicate must not
// have its answer repeated back to the user as a "close match".
func TestResolveProduct_NotFound_UnrelatedNearRowIsDropped(t *testing.T) {
	rows := []string{productNodeJSON(t, "prod-9", "totally-different")}
	srv, _ := productLookupServer(t, noProductsJSON, func(string) (int, string) {
		return http.StatusOK, productPageJSON(1, rows)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	if strings.Contains(err.Error(), "close matches") {
		t.Errorf("a row that is not a near miss must not be shown as one; got:\n%s", err)
	}
}

// TestResolveProduct_NotFound_NearFailureStillLists pins the reason the close
// match is a second round trip rather than a second alias: a platform that
// cannot serve the fold predicate must still get the user their product list.
func TestResolveProduct_NotFound_NearFailureStillLists(t *testing.T) {
	all := []string{
		productNodeJSON(t, "prod-1", "api-gateway"),
		productNodeJSON(t, "prod-2", "billing"),
	}
	srv, calls := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return http.StatusOK, `{"errors":[{"message":"Unknown argument \"nameEqualFold\""}]}`
		}
		return http.StatusOK, productPageJSON(2, all)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "  api-gateway  prod-1") {
		t.Errorf("a failed close-match hint must not cost the user the listing; got:\n%s", msg)
	}
	if strings.Contains(msg, "could not list products") {
		t.Errorf("the listing succeeded, so it must not be reported as failed; got:\n%s", msg)
	}
	if calls.near != 1 || calls.list != 1 {
		t.Errorf("want one list and one near call, got list=%d near=%d", calls.list, calls.near)
	}
}

func TestResolveProduct_NotFound_TruncatesWithExactRemainder(t *testing.T) {
	const page = 20
	edges := make([]string, 0, page)
	for i := range page {
		edges = append(edges, productNodeJSON(t, fmt.Sprintf("prod-%d", i), fmt.Sprintf("p%d", i)))
	}
	srv, _ := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return emptyPage()
		}
		return http.StatusOK, productPageJSON(137, edges)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "... and 117 more") {
		t.Errorf("truncation must state the exact remainder (137-20); got:\n%s", msg)
	}
	if rows := strings.Count(msg, "  prod-"); rows != page {
		t.Errorf("listed %d product rows, want the %d-row cap; got:\n%s", rows, page, msg)
	}
}

// TestResolveProduct_NotFound_OverLongPageIsStillBounded pins that the cap is
// enforced locally too: a server that ignores `first` cannot flood the terminal,
// and the remainder it implies is still stated.
func TestResolveProduct_NotFound_OverLongPageIsStillBounded(t *testing.T) {
	edges := make([]string, 0, 50)
	for i := range 50 {
		edges = append(edges, productNodeJSON(t, fmt.Sprintf("prod-%d", i), fmt.Sprintf("p%d", i)))
	}
	srv, _ := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return emptyPage()
		}
		// totalCount under-reports on purpose: the page itself proves there are 50.
		return http.StatusOK, productPageJSON(0, edges)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	if rows := strings.Count(msg, "  prod-"); rows != 20 {
		t.Errorf("listed %d product rows, want 20; got:\n%s", rows, msg)
	}
	if !strings.Contains(msg, "... and 30 more") {
		t.Errorf("a silent truncation is the bug; want \"... and 30 more\", got:\n%s", msg)
	}
}

func TestResolveProduct_NotFound_ListFailureKeepsOriginalError(t *testing.T) {
	srv, calls := productLookupServer(t, noProductsJSON, func(string) (int, string) {
		return http.StatusInternalServerError, "boom"
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("a failed listing must not turn a not-found into a success")
	}
	msg := err.Error()
	if !strings.Contains(msg, `no product found matching "svc" (pass the product id or exact name)`) {
		t.Errorf("the original not-found error must survive; got:\n%s", msg)
	}
	if !strings.Contains(msg, "could not list products") {
		t.Errorf("the listing failure must be noted, not swallowed; got:\n%s", msg)
	}
	if strings.Contains(msg, "\navailable products:") {
		t.Errorf("no listing was obtained, so none may be claimed; got:\n%s", msg)
	}
	if calls.near != 0 {
		t.Errorf("a failed listing should not go on to fetch a hint for it; near called %d times", calls.near)
	}
}

func TestResolveProduct_NotFound_NoProductsVisible(t *testing.T) {
	srv, _ := productLookupServer(t, noProductsJSON, func(string) (int, string) {
		return emptyPage()
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	if !strings.Contains(err.Error(), "no products are visible to this session") {
		t.Errorf("an empty tenant must be said plainly; got:\n%s", err)
	}
}

// TestResolveProduct_NotFound_EscapesHostileNames pins that a product name is
// treated as untrusted text: a newline in it would forge a row in the listing
// and an ANSI escape would rewrite the terminal.
func TestResolveProduct_NotFound_EscapesHostileNames(t *testing.T) {
	hostile := "evil\n  spoofed  prod-999\x1b[2J"
	all := []string{productNodeJSON(t, "prod-1", hostile)}
	srv, _ := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return emptyPage()
		}
		return http.StatusOK, productPageJSON(1, all)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, hostile) {
		t.Errorf("hostile name pasted through verbatim; got:\n%q", msg)
	}
	if strings.Contains(msg, "\x1b") {
		t.Errorf("ANSI escape reached the terminal; got:\n%q", msg)
	}
	if !strings.Contains(msg, `\n`) || !strings.Contains(msg, `\x1b`) {
		t.Errorf("hostile name should be shown escaped, not dropped; got:\n%q", msg)
	}
}

func TestResolveProduct_ExactMatch_IssuesNoListQuery(t *testing.T) {
	byName := `{"data":{"products":{"edges":[{"node":{"id":"prod-1","name":"svc"}}]}}}`
	srv, calls := productLookupServer(t, byName, func(string) (int, string) {
		return emptyPage()
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	p, err := c.ResolveProduct(context.Background(), "svc")
	if err != nil {
		t.Fatalf("exact name must still resolve: %v", err)
	}
	if p == nil || p.ID != "prod-1" {
		t.Fatalf("got %#v, want prod-1", p)
	}
	if calls.list != 0 || calls.near != 0 {
		t.Errorf("the listing is a failure-path cost only; list=%d near=%d", calls.list, calls.near)
	}
}

// TestResolveProduct_NotFound_VisibleButUnlisted pins the case where the
// connection reports products the page did not carry. Saying "no products are
// visible" there would be false, so the count is reported instead.
func TestResolveProduct_NotFound_VisibleButUnlisted(t *testing.T) {
	srv, _ := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return emptyPage()
		}
		return http.StatusOK, productPageJSON(4, nil)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, "no products are visible to this session") {
		t.Errorf("the connection reported 4 products, so claiming none is false; got:\n%s", msg)
	}
	if !strings.Contains(msg, "4 products are visible to this session") {
		t.Errorf("want the reported count surfaced; got:\n%s", msg)
	}
}

// TestResolveProduct_NotFound_ManyCloseMatchesAreBounded pins that the
// close-match block obeys its own cap -- here against a server that ignores
// `first` and returns the whole set -- and states the remainder exactly.
func TestResolveProduct_NotFound_ManyCloseMatchesAreBounded(t *testing.T) {
	// Eight products fold-match "svc". The query asks for five; this server
	// returns all eight anyway, so the cap has to hold locally.
	rows := make([]string, 0, 8)
	for i := range 8 {
		rows = append(rows, productNodeJSON(t, fmt.Sprintf("near-%d", i), "SVC"))
	}
	srv, _ := productLookupServer(t, noProductsJSON, func(string) (int, string) {
		return http.StatusOK, productPageJSON(8, rows)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	// Five rows in the capped close-match block, eight in the available block
	// (which is under its own cap of 20).
	if rows := strings.Count(msg, "  near-"); rows != 5+8 {
		t.Errorf("listed %d rows total, want 5 close matches + 8 available; got:\n%s", rows, msg)
	}
	if n := strings.Count(msg, "... and 3 more"); n != 1 {
		t.Errorf("the close-match block must state the exact remainder (8-5); saw %d such lines in:\n%s", n, msg)
	}
}

// TestResolveProduct_NotFound_ListIsSortedByName pins that the rows are ordered
// for a human. The platform returns products in id order, which is stable but
// unreadable, and the connection has no NAME field to order by, so the sort
// happens client-side over the page that came back.
func TestResolveProduct_NotFound_ListIsSortedByName(t *testing.T) {
	// Deliberately returned in neither id nor name order.
	all := []string{
		productNodeJSON(t, "prod-3", "zebra"),
		productNodeJSON(t, "prod-1", "Mango"),
		productNodeJSON(t, "prod-2", "apple"),
	}
	srv, _ := productLookupServer(t, noProductsJSON, func(kind string) (int, string) {
		if kind == "near" {
			return emptyPage()
		}
		return http.StatusOK, productPageJSON(3, all)
	})
	defer srv.Close()

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	_, err := c.ResolveProduct(context.Background(), "svc")
	if err == nil {
		t.Fatal("want not-found error, got nil")
	}
	msg := err.Error()
	apple, mango, zebra := strings.Index(msg, "apple"), strings.Index(msg, "Mango"), strings.Index(msg, "zebra")
	if apple < 0 || mango < 0 || zebra < 0 {
		t.Fatalf("every product must be listed; got:\n%s", msg)
	}
	// Case-insensitive, so Mango sorts between apple and zebra rather than
	// ahead of both on its capital M.
	if !(apple < mango && mango < zebra) {
		t.Errorf("rows must be name-sorted case-insensitively (apple, Mango, zebra); got:\n%s", msg)
	}
}
