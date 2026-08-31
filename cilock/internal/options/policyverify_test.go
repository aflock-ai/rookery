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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The platform verify door's client half. The contract under test: anchors are
// REQUIRED before a request is even built (an anchorless verify is unaskable,
// not merely rejected server-side), the variables carry exactly what the
// caller holds, and the answer is surfaced whole — including the VSA gitoid,
// which is the half that makes the verdict portable evidence.

func verifyStubServer(t *testing.T, respond func(vars map[string]any) any) (*httptest.Server, *map[string]any) {
	t.Helper()
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		captured = req.Variables
		if err := json.NewEncoder(w).Encode(map[string]any{"data": respond(req.Variables)}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

func TestVerifyComplianceSync(t *testing.T) {
	t.Run("refuses with no anchor BEFORE any request is made", func(t *testing.T) {
		c := &PolicyClient{GraphQLURL: "http://127.0.0.1:1/query", Token: "tok"}
		_, err := c.VerifyComplianceSync(context.Background(), "bind-1", "", nil, false)
		if err == nil {
			t.Fatal("an anchorless verify must be refused client-side")
		}
		// The refusal is the anchor rule, not a transport error — the bogus
		// URL above would have produced a dial error had a request been sent.
		if got := err.Error(); !strings.Contains(got, "no anchor") {
			t.Fatalf("the refusal must state the anchor rule, got: %s", got)
		}
	})

	t.Run("refuses with no binding id", func(t *testing.T) {
		c := &PolicyClient{GraphQLURL: "http://127.0.0.1:1/query", Token: "tok"}
		_, err := c.VerifyComplianceSync(context.Background(), "", "abc123", nil, false)
		if err == nil {
			t.Fatal("a verify with no binding id must be refused")
		}
	})

	t.Run("sends the anchors it was handed and surfaces the whole answer", func(t *testing.T) {
		srv, captured := verifyStubServer(t, func(map[string]any) any {
			return map[string]any{"verifyComplianceSync": map[string]any{
				"id":              "eval-1",
				"result":          "PASSED",
				"reasons":         []string{},
				"vsaGitoidSha256": "deadbeef",
				"commitHash":      "abc123",
			}}
		})
		c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
		eval, err := c.VerifyComplianceSync(context.Background(), "bind-1", "abc123", []string{"sha256:ffff"}, false)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !eval.Passed() {
			t.Errorf("status 'passed' must report Passed(): %+v", eval)
		}
		if eval.VsaGitoidSha256 != "deadbeef" {
			t.Errorf("the VSA gitoid is the portable half of the answer and must survive: %+v", eval)
		}
		vars := *captured
		if vars["bindingID"] != "bind-1" || vars["commitHash"] != "abc123" {
			t.Errorf("anchors must ride the request verbatim, got vars: %v", vars)
		}
		subs, _ := vars["subjectDigests"].([]any)
		if len(subs) != 1 || subs[0] != "sha256:ffff" {
			t.Errorf("subject anchors must ride the request verbatim, got: %v", vars["subjectDigests"])
		}
	})

	t.Run("a failed verdict is an answer, not an error — reasons and VSA intact", func(t *testing.T) {
		srv, _ := verifyStubServer(t, func(map[string]any) any {
			return map[string]any{"verifyComplianceSync": map[string]any{
				"id":              "eval-2",
				"result":          "FAILED",
				"reasons":         []string{"step build: no matching collection"},
				"vsaGitoidSha256": "cafef00d",
			}}
		})
		c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
		eval, err := c.VerifyComplianceSync(context.Background(), "bind-1", "abc123", nil, false)
		if err != nil {
			t.Fatalf("a FAILED verdict must come back as data, not as a client error: %v", err)
		}
		if eval.Passed() {
			t.Error("failed must not read as passed")
		}
		if len(eval.Reasons) != 1 || eval.VsaGitoidSha256 != "cafef00d" {
			t.Errorf("deny reasons and the failure VSA are the auditable half: %+v", eval)
		}
	})

	t.Run("a null row is an error, never a silent pass", func(t *testing.T) {
		srv, _ := verifyStubServer(t, func(map[string]any) any {
			return map[string]any{"verifyComplianceSync": nil}
		})
		c := &PolicyClient{GraphQLURL: srv.URL, Token: "tok"}
		if _, err := c.VerifyComplianceSync(context.Background(), "bind-1", "abc123", nil, false); err == nil {
			t.Fatal("no row must be an error — absence is never read as a verdict")
		}
	})
}
