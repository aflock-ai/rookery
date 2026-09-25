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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ListProductBindings feeds the platform door's EVERY-binding verdict, so it
// must be exact: a page cap that silently dropped a binding would drop a policy
// from the gate and turn "all bound policies passed" into a lie. These tests
// pin pagination to exhaustion, deterministic order, and the refusals.

// doorMultiPagedServer answers the policyBindings query from pages keyed by
// the `after` cursor ("" is the first page) and counts the requests.
func doorMultiPagedServer(t *testing.T, pages map[string]string, calls *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readGQL(t, r)
		if !strings.Contains(req.Query, "policyBindings(") {
			t.Errorf("unexpected query: %s", req.Query)
			return
		}
		*calls++
		after, _ := req.Variables["after"].(string)
		body, ok := pages[after]
		if !ok {
			t.Errorf("no page for cursor %q", after)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func doorMultiPage(hasNext bool, endCursor string, nodes ...string) string {
	return fmt.Sprintf(`{"data":{"policyBindings":{"pageInfo":{"hasNextPage":%t,"endCursor":%q},"edges":[%s]}}}`,
		hasNext, endCursor, strings.Join(nodes, ","))
}

func doorMultiNode(id, def, tag string) string {
	rel := "null"
	if tag != "" {
		rel = fmt.Sprintf(`{"id":"rel-%s","tag":%q,"dsse":{"gitoidSha256":"g-%s"}}`, id, tag, id)
	}
	return fmt.Sprintf(`{"node":{"id":%q,"createdAt":"2026-09-01T00:00:00Z","createdBy":{"name":"","email":"a@b.test"},"policyDefinition":{"id":"d-%s","name":%q},"policyRelease":%s}}`,
		id, id, def, rel)
}

func TestDoorMultiListProductBindings_PaginatesToExhaustionAndSorts(t *testing.T) {
	calls := 0
	srv := doorMultiPagedServer(t, map[string]string{
		"":   doorMultiPage(true, "c1", doorMultiNode("bind-z", "zeta-gate", "v2"), doorMultiNode("bind-a", "alpha-gate", "")),
		"c1": doorMultiPage(false, "c2", doorMultiNode("bind-m", "alpha-gate", "v1")),
	}, &calls)

	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	got, err := c.ListProductBindings(context.Background(), "prod-1")
	if err != nil {
		t.Fatalf("ListProductBindings: %v", err)
	}
	if calls != 2 {
		t.Fatalf("want 2 page requests (the second page holds a binding), got %d", calls)
	}
	ids := make([]string, 0, len(got))
	for _, b := range got {
		ids = append(ids, b.BindingID)
	}
	// Sorted by definition name, then binding id: independent of server order.
	if want := "bind-a,bind-m,bind-z"; strings.Join(ids, ",") != want {
		t.Fatalf("order = %v, want %s", ids, want)
	}
	if got[0].ReleaseTag != "" || got[0].Gitoid != "" {
		t.Fatalf("an unpinned binding must not claim a release the client never resolved: %+v", got[0])
	}
	if got[2].ReleaseTag != "v2" || got[2].DefinitionName != "zeta-gate" || got[2].BoundBy != "a@b.test" {
		t.Fatalf("pinned binding provenance lost: %+v", got[2])
	}
}

func TestDoorMultiListProductBindings_NoBindingsIsEmptyNotError(t *testing.T) {
	calls := 0
	srv := doorMultiPagedServer(t, map[string]string{"": doorMultiPage(false, "")}, &calls)
	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	got, err := c.ListProductBindings(context.Background(), "prod-1")
	if err != nil {
		t.Fatalf("ListProductBindings: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no bindings, got %+v", got)
	}
}

// A server that claims another page but never advances its cursor would loop
// forever; it is refused rather than truncated (truncation would drop policies).
func TestDoorMultiListProductBindings_StuckCursorRefused(t *testing.T) {
	calls := 0
	srv := doorMultiPagedServer(t, map[string]string{
		"":   doorMultiPage(true, "c1", doorMultiNode("bind-1", "p", "v1")),
		"c1": doorMultiPage(true, "c1", doorMultiNode("bind-2", "q", "v1")),
	}, &calls)
	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	if _, err := c.ListProductBindings(context.Background(), "prod-1"); err == nil {
		t.Fatal("a non-advancing cursor must be an error, not a truncated list")
	}
	if calls > 3 {
		t.Fatalf("stuck cursor must be detected promptly, took %d calls", calls)
	}
}

// A duplicate binding id across pages is collapsed: evaluating one binding
// twice would double-count it, and it must not mask a missing one.
func TestDoorMultiListProductBindings_DuplicateIDsCollapsed(t *testing.T) {
	calls := 0
	srv := doorMultiPagedServer(t, map[string]string{
		"":   doorMultiPage(true, "c1", doorMultiNode("bind-1", "p", "v1")),
		"c1": doorMultiPage(false, "", doorMultiNode("bind-1", "p", "v1"), doorMultiNode("bind-2", "q", "v1")),
	}, &calls)
	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	got, err := c.ListProductBindings(context.Background(), "prod-1")
	if err != nil {
		t.Fatalf("ListProductBindings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 distinct bindings, got %+v", got)
	}
}

func TestDoorMultiListProductBindings_TransportErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
	if _, err := c.ListProductBindings(context.Background(), "prod-1"); err == nil {
		t.Fatal("a failed listing must be an error: never read as 'no bindings'")
	}
}
