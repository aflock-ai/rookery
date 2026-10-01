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

package gitlab_review

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApprovalPolicyChangesWhileReadingAreLoud(t *testing.T) {
	s := loadScenario(t)
	for _, changed := range []string{"rules", "settings", "both", "unavailable"} {
		t.Run(changed, func(t *testing.T) {
			routes := ultimateRoutes(s, s.H)
			if changed == "unavailable" {
				routes["/version"] = `inline:{"version":"19.4.1","revision":"r","enterprise":false}`
				routes["/projects/87019852/approvals"] = "status:404"
				routes["/projects/87019852/merge_requests/1/approval_state"] = "status:404"
			}
			inner := fakeGitLab(t, routes)
			stateReads, settingReads := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/api/v4/projects/87019852/merge_requests/1/approval_state":
					stateReads++
					if stateReads > 1 && (changed == "rules" || changed == "both" || changed == "unavailable") {
						body := fixture(t, "mr-approval-state-merged")
						_, _ = w.Write([]byte(strings.ReplaceAll(string(body), `"approvals_required": 1`, `"approvals_required": 2`)))
						return
					}
				case "/api/v4/projects/87019852/approvals":
					settingReads++
					// The first read probes the tier; the second records settings.
					if (settingReads > 2 && changed == "settings") || (settingReads > 1 && changed == "both") {
						body := fixture(t, routes["/projects/87019852/approvals"])
						_, _ = w.Write([]byte(strings.ReplaceAll(string(body), `"reset_approvals_on_push": true`, `"reset_approvals_on_push": false`)))
						return
					}
				}
				proxy, err := http.NewRequest(req.Method, inner.URL+req.URL.RequestURI(), http.NoBody)
				if err != nil {
					t.Error(err)
					return
				}
				proxy.Header = req.Header
				resp, err := http.DefaultClient.Do(proxy)
				if err != nil {
					t.Error(err)
					return
				}
				defer resp.Body.Close()
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, resp.Body)
			}))
			t.Cleanup(srv.Close)
			if _, err := attest(t, srv, s.H); err == nil || !strings.Contains(err.Error(), "changed while") {
				t.Fatalf("policy changed without changing approvers: want a loud refusal, got %v", err)
			}
		})
	}
}

func TestCommitStatusRequiresAllowFailure(t *testing.T) {
	s := loadScenario(t)
	for _, field := range []string{"", `,"allow_failure":null`, `,"allow_failure":"false"`} {
		t.Run(field, func(t *testing.T) {
			r := ultimateRoutes(s, s.H)
			r["/projects/87019852/repository/commits/"+s.H+"/statuses"] =
				`inline:[{"id":1,"sha":"` + s.H + `","name":"check","status":"success"` + field + `}]`
			if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil {
				t.Fatal("missing, null or nonboolean allow_failure must fail collection")
			}
		})
	}
	for _, value := range []string{"true", "false"} {
		t.Run(value, func(t *testing.T) {
			r := ultimateRoutes(s, s.H)
			r["/projects/87019852/repository/commits/"+s.H+"/statuses"] =
				`inline:[{"id":1,"sha":"` + s.H + `","name":"check","status":"success","allow_failure":` + value + `}]`
			a, err := attest(t, fakeGitLab(t, r), s.H)
			if err != nil {
				t.Fatal(err)
			}
			statuses := a.MergeRequests[0].CommitStatuses
			if len(statuses) != 1 || statuses[0].AllowFailure != (value == "true") {
				t.Fatalf("allow_failure must preserve the observed boolean: %+v", statuses)
			}
		})
	}
}

func TestTierProbesRejectMalformedEvidence(t *testing.T) {
	s := loadScenario(t)
	for _, body := range []string{"null", "{}", "<html>login</html>", "[{}]"} {
		t.Run(body, func(t *testing.T) {
			r := ultimateRoutes(s, s.H)
			r["/projects/87019852/external_status_checks"] = "inline:" + body
			if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil {
				t.Fatal("malformed probe evidence must not establish Ultimate tier")
			}
		})
	}
	t.Run("valid service", func(t *testing.T) {
		r := ultimateRoutes(s, s.H)
		r["/projects/87019852/external_status_checks"] = `inline:[{"id":1,"project_id":87019852,"name":"Compliance","external_url":"https://example.com/check"}]`
		a, err := attest(t, fakeGitLab(t, r), s.H)
		if err != nil {
			t.Fatal(err)
		}
		if a.Tier.Plan != planUltimate {
			t.Fatalf("valid service list must establish Ultimate tier: %+v", a.Tier)
		}
	})
}

// A thread is resolved only when every resolvable note in it is. A resolved
// first note followed by an unresolved resolvable reply is an open thread.
func TestAThreadWithAnUnresolvedReplyIsUnresolved(t *testing.T) {
	s := loadScenario(t)
	r := ultimateRoutes(s, s.H)
	r["/projects/87019852/merge_requests/1/discussions"] = `inline:[` +
		`{"id":"d-mixed","notes":[{"id":1,"resolvable":true,"resolved":true},{"id":2,"resolvable":true,"resolved":false}]},` +
		`{"id":"d-reply-only","notes":[{"id":3,"resolvable":false,"resolved":null},{"id":4,"resolvable":true,"resolved":false}]},` +
		`{"id":"d-done","notes":[{"id":5,"resolvable":true,"resolved":true},{"id":6,"resolvable":true,"resolved":true}]}]`
	a, err := attest(t, fakeGitLab(t, r), s.H)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	d := a.MergeRequests[0].Discussions
	if d.Resolvable != 3 || d.Resolved != 1 || len(d.Unresolved) != 2 {
		t.Fatalf("want 3 resolvable, 1 resolved, 2 unresolved; got %+v", d)
	}
	if d.Unresolved[0] != (UnresolvedThread{DiscussionID: "d-mixed", NoteID: 2}) ||
		d.Unresolved[1] != (UnresolvedThread{DiscussionID: "d-reply-only", NoteID: 4}) {
		t.Fatalf("unresolved threads must name their first open note: %+v", d.Unresolved)
	}
}

// A 200 whose body lacks what the attestor records is missing evidence, never
// an observed empty or false value.
func TestAnIncompleteResponseIsLoud(t *testing.T) {
	s := loadScenario(t)
	p := "/projects/87019852"
	mr := p + "/merge_requests/1"
	for name, c := range map[string]struct{ route, body string }{
		"approval_state {}":         {mr + "/approval_state", `inline:{}`},
		"approval_state rules null": {mr + "/approval_state", `inline:{"approval_rules_overwritten":false,"rules":null}`},
		"project approvals {}":      {p + "/approvals", `inline:{}`},
		"mr approvals {}":           {mr + "/approvals", `inline:{}`},
		"mr {}":                     {mr, `inline:{}`},
		"versions null":             {mr + "/versions", `inline:null`},
		"pipelines null":            {p + "/pipelines", `inline:null`},
		"discussions null":          {mr + "/discussions", `inline:null`},
		"a version without head":    {mr + "/versions", `inline:[{"id":1,"created_at":"2026-09-29T08:00:00.000Z"}]`},
		"version {}":                {"/version", `inline:{}`},
		// Nested fields (Codex, #10782 round 2): an element missing a field it
		// records is missing evidence too.
		"a note without an id":               {mr + "/discussions", `inline:[{"id":"d","notes":[{"resolvable":true,"resolved":false}]}]`},
		"a resolvable note without resolved": {mr + "/discussions", `inline:[{"id":"d","notes":[{"id":1,"resolvable":true}]}]`},
		"a note with a null id":              {mr + "/discussions", `inline:[{"id":"d","notes":[{"id":null,"resolvable":true,"resolved":false}]}]`},
		"rules [{}]":                         {mr + "/approval_state", `inline:{"approval_rules_overwritten":false,"rules":[{}]}`},
		"a rule without approvals_required":  {mr + "/approval_state", `inline:{"approval_rules_overwritten":false,"rules":[{"id":1,"name":"r","rule_type":"regular","report_type":null,"approved":true,"overridden":false,"approved_by":[{"id":7}],"eligible_approvers":[{"id":7}]}]}`},
		"a rule approver without an id":      {mr + "/approval_state", `inline:{"approval_rules_overwritten":false,"rules":[{"id":1,"name":"r","rule_type":"regular","report_type":null,"approvals_required":1,"approved":true,"overridden":false,"approved_by":[{}],"eligible_approvers":[{"id":7}]}]}`},
		"an approval without approved_at":    {mr + "/approvals", `inline:{"approved":true,"approved_by":[{"user":{"id":7,"username":"a"}}]}`},
		// Codex, #10782 round 3: an author or user reference must name a real user.
		"a rule approver with id 0": {mr + "/approval_state", `inline:{"approval_rules_overwritten":false,"rules":[{"id":1,"name":"r","rule_type":"regular","report_type":null,"approvals_required":1,"approved":true,"overridden":false,"approved_by":[{"id":0}],"eligible_approvers":[]}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			r := ultimateRoutes(s, s.H)
			r[c.route] = c.body
			_, err := attest(t, fakeGitLab(t, r), s.H)
			if err == nil {
				t.Fatalf("%s answered %s: want a loud error, got a record", c.route, c.body)
			}
			if msg := err.Error(); !strings.Contains(msg, "missing") && !strings.Contains(msg, "null") &&
				!strings.Contains(msg, "not a positive integer") {
				t.Fatalf("error must say what was missing: %v", err)
			}
		})
	}
}

// A fork MR's head lives in the source project; its pipelines and commit
// statuses are read there too, not only in the target project.
func TestAForkMRReadsCIFromTheSourceProject(t *testing.T) {
	s := loadScenario(t)
	r := ultimateRoutes(s, s.H)
	mr := "/projects/87019852/merge_requests/1"
	var m map[string]any
	if err := json.Unmarshal(fixture(t, r[mr]), &m); err != nil {
		t.Fatal(err)
	}
	m["source_project_id"] = 5550001
	body, _ := json.Marshal(m)
	r[mr] = "inline:" + string(body)
	fork := "/projects/5550001"
	r[fork+"/pipelines"] = `inline:[{"id":91,"iid":1,"project_id":5550001,"sha":"` + s.H + `","ref":"feature","status":"success","source":"push","created_at":"2026-09-29T08:00:00.000Z"}]`
	r[fork+"/repository/commits/"+s.H+"/statuses"] = `inline:[{"id":92,"sha":"` + s.H + `","name":"fork-check","status":"success","allow_failure":false}]`

	a, err := attest(t, fakeGitLab(t, r), s.H)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	got := a.MergeRequests[0]
	var forkPipeline, forkStatus bool
	for _, pl := range got.Pipelines {
		forkPipeline = forkPipeline || (pl.ID == 91 && pl.ProjectID == 5550001)
	}
	for _, st := range got.CommitStatuses {
		forkStatus = forkStatus || (st.ID == 92 && st.ProjectID == 5550001)
	}
	if !forkPipeline || !forkStatus {
		t.Fatalf("fork CI missing: pipelines %+v statuses %+v", got.Pipelines, got.CommitStatuses)
	}

	// A fork the token cannot read is loud, never an empty CI inventory.
	delete(r, fork+"/pipelines")
	if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil {
		t.Fatal("an unreadable fork's pipelines must fail loudly")
	}
}

// The control for the nested checks: a complete rule and a non-resolvable note
// without resolved (GitLab omits it) are accepted.
func TestCompleteNestedResponsesAreAccepted(t *testing.T) {
	s := loadScenario(t)
	mr := "/projects/87019852/merge_requests/1"
	r := ultimateRoutes(s, s.H)
	r[mr+"/approval_state"] = `inline:{"approval_rules_overwritten":false,"rules":[{"id":1,"name":"r","rule_type":"regular","report_type":null,"approvals_required":1,"approved":true,"overridden":false,"approved_by":[{"id":7}],"eligible_approvers":[{"id":7}]}]}`
	r[mr+"/discussions"] = `inline:[{"id":"d","notes":[{"id":1,"resolvable":false}]}]`
	a, err := attest(t, fakeGitLab(t, r), s.H)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	st := a.MergeRequests[0].ApprovalState
	if st == nil || len(st.Rules) != 1 || st.Rules[0].ApprovalsRequired != 1 || len(st.Rules[0].ApprovedByIDs) != 1 {
		t.Fatalf("rule not recorded: %+v", st)
	}
}

// Codex, #10782 round 3: an MR whose author is empty, null or id 0 would sign
// author_id 0, which invents an identity and defeats an author-exclusion rule
// that compares ids.
func TestAnMRWithoutARealAuthorIsLoud(t *testing.T) {
	s := loadScenario(t)
	mr := "/projects/87019852/merge_requests/1"
	for _, author := range []any{map[string]any{}, map[string]any{"id": nil}, map[string]any{"id": 0}, nil} {
		r := ultimateRoutes(s, s.H)
		var m map[string]any
		if err := json.Unmarshal(fixture(t, r[mr]), &m); err != nil {
			t.Fatal(err)
		}
		m["author"] = author
		body, _ := json.Marshal(m)
		r[mr] = "inline:" + string(body)
		if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil || !strings.Contains(err.Error(), "author") {
			t.Fatalf("author %v: want a loud error naming the author, got %v", author, err)
		}
	}
}

// Codex, #10782 round 3: credentials in the API URL would be copied into the
// signed instance.api_url. They are refused, and the error does not repeat them.
func TestAnAPIURLCarryingCredentialsIsRefused(t *testing.T) {
	for _, base := range []string{
		"https://user:s3cr3t-pw@gitlab.example.invalid/api/v4",
		"https://s3cr3t-pw@gitlab.example.invalid/api/v4",
		"https://gitlab.example.invalid/api/v4?private_token=s3cr3t-pw",
		"https://gitlab.example.invalid/api/v4#s3cr3t-pw",
	} {
		env := map[string]string{"CI_API_V4_URL": base, "CI_PROJECT_ID": "1", "CI_COMMIT_SHA": "0123456789abcdef0123456789abcdef01234567", DefaultTokenEnv: "test-token"}
		a := New(withEnv(func(k string) string { return env[k] }))
		_, err := a.client()
		if err == nil {
			t.Fatalf("%s: want a refusal", base)
		}
		if strings.Contains(err.Error(), "s3cr3t-pw") {
			t.Fatalf("the refusal repeats the credential: %v", err)
		}
		if a.Instance.APIURL != "" {
			t.Fatalf("instance.api_url recorded %q", a.Instance.APIURL)
		}
	}
}

// Repository-controlled content must never be mistaken for GitLab's API,
// even when it is served by the expected GitLab host.
func TestAPIBaseMustBeCanonical(t *testing.T) {
	for _, base := range []string{
		"https://gitlab.com/attacker/repo/-/raw/main",
		"https://gitlab.example.invalid/attacker/repo/-/raw/main/api/v4",
		"https://gitlab.com/api/v4/../attacker/repo/-/raw/main",
		"https://gitlab.com/%61pi/v4",
		"https://gitlab.com",
		"https:///api/v4",
		"ftp://localhost/api/v4",
	} {
		t.Run(base, func(t *testing.T) {
			a := New(withEnv(func(k string) string {
				if k == "CI_API_V4_URL" {
					return base
				}
				return "test-token"
			}))
			if _, err := a.client(); err == nil {
				t.Fatal("noncanonical API root was accepted")
			}
			if a.Instance.APIURL != "" {
				t.Fatal("refused API root was recorded in the predicate")
			}
		})
	}
	for _, base := range []string{
		"https://gitlab.com/api/v4",
		"https://gitlab.example.invalid/api/v4/",
		"http://127.0.0.1:1234/api/v4",
		"http://localhost:1234", // HTTP fixture replay uses a root-mounted API.
	} {
		t.Run(base, func(t *testing.T) {
			a := New(withEnv(func(k string) string {
				if k == "CI_API_V4_URL" {
					return base
				}
				return "test-token"
			}))
			if _, err := a.client(); err != nil {
				t.Fatalf("canonical API root was refused: %v", err)
			}
		})
	}
}
