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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) { detectiontest.AssertParses(t, Name, detectorYAML) }

// fixture returns the recorded gitlab.com response for name.
func fixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gitlab-com", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Response
}

type scenario struct {
	ProjectID int64 `json:"project_id"`
	IID       int64 `json:"iid"`
	P, H      string
}

func loadScenario(t *testing.T) scenario {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gitlab-com", "scenario.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s scenario
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// fakeGitLab serves recorded gitlab.com answers by path; routes maps a path
// (without query) to a fixture name, or to a status with "status:404".
func fakeGitLab(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "test-token" {
			w.WriteHeader(401)
			return
		}
		name, ok := routes[strings.TrimPrefix(r.URL.Path, "/api/v4")]
		switch {
		case !ok:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":"404 Not Found"}`))
		case strings.HasPrefix(name, "status:"):
			code := map[string]int{"status:404": 404, "status:403": 403, "status:500": 500}[name]
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"message":"x"}`))
		case strings.HasPrefix(name, "inline:"):
			_, _ = w.Write([]byte(strings.TrimPrefix(name, "inline:")))
		case name == "[]":
			_, _ = w.Write([]byte(`[]`))
		default:
			_, _ = w.Write(fixture(t, name))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ultimateRoutes(s scenario, t string) map[string]string {
	p := "/projects/87019852"
	mr := p + "/merge_requests/1"
	r := map[string]string{
		"/version":                    "version",
		p + "/approvals":              "project-approvals",
		p + "/external_status_checks": "cp-external-status-checks",
		p + "/pipelines":              "project-pipelines-head",
		mr + "/discussions":           "mr-discussions",
		mr + "/notes":                 "mr-notes",
		p + "/repository/commits/" + s.H + "/statuses": "[]",
	}
	if t == s.H {
		r[p+"/repository/commits/"+s.H+"/merge_requests"] = "commit-mrs-head"
		r[mr] = "mr-open"
		r[mr+"/versions"] = "mr-versions-after-push"
		r[mr+"/approvals"] = "mr-approvals-after-push"
		r[mr+"/approval_state"] = "mr-approval-state-after-push"
	} else {
		r[p+"/repository/commits/"+t+"/merge_requests"] = "merge-commit-mrs"
		r[mr] = "mr-merged"
		r[mr+"/versions"] = "mr-versions-merged"
		r[mr+"/approvals"] = "mr-approvals-merged"
		r[mr+"/approval_state"] = "mr-approval-state-merged"
	}
	return r
}

func attest(t *testing.T, srv *httptest.Server, sha string, opts ...Option) (*Attestor, error) {
	t.Helper()
	env := map[string]string{"CI_API_V4_URL": srv.URL + "/api/v4", "CI_PROJECT_ID": "87019852",
		"CI_COMMIT_SHA": sha, DefaultTokenEnv: "test-token"}
	a := New(append([]Option{withEnv(func(k string) string { return env[k] })}, opts...)...)
	ctx, err := attestation.NewContext("gitlab-review-test", []attestation.Attestor{a}, attestation.WithContext(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	return a, a.Attest(ctx)
}

// TestParentShaApprovalOnRealGitLabComDoesNotBindToTheHead replays the
// gitlab.com Ultimate sandbox MR read a second after the head was pushed: the
// approval given on the parent is still listed and GitLab's rule says
// approved. The attestor binds that approval to the parent, so a verifier
// counting approvals bound to the head counts none.
func TestParentShaApprovalOnRealGitLabComDoesNotBindToTheHead(t *testing.T) {
	s := loadScenario(t)
	// A single clock declared (0): the approval binds to the parent. The
	// default guard leaves it unbound instead (next test); neither counts it
	// for the head.
	a, err := attest(t, fakeGitLab(t, ultimateRoutes(s, s.H)), s.H, WithClockSkewMillis(0))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.Tier.Plan != "ultimate" {
		t.Fatalf("tier %+v", a.Tier)
	}
	if len(a.MergeRequests) != 1 {
		t.Fatalf("merge requests: %d", len(a.MergeRequests))
	}
	mr := a.MergeRequests[0]
	if mr.HeadSHA != s.H || mr.Relation != "head" || len(mr.Approvals) != 1 {
		t.Fatalf("mr %+v", mr)
	}
	ap := mr.Approvals[0]
	if ap.BoundHeadSHA == nil || *ap.BoundHeadSHA != s.P {
		t.Fatalf("the approval given on the parent must bind to %s, got %v", s.P, ap.BoundHeadSHA)
	}
	if mr.ApprovalState == nil || len(mr.ApprovalState.Rules) != 1 || !mr.ApprovalState.Rules[0].Approved {
		t.Fatal("GitLab's own view (rule approved) must be recorded as observed, and not used")
	}
	for k := range a.Subjects() {
		if strings.Contains(k, "<") {
			t.Fatalf("subject %q carries a sanitized placeholder; subjects must be ids", k)
		}
	}
}

// TestMergedMRBindsTheHeadApproval: the merge commit is attested; the
// approval given after the head's version binds to the head.
func TestMergedMRBindsTheHeadApproval(t *testing.T) {
	s := loadScenario(t)
	var merged struct {
		MergeCommitSHA string `json:"merge_commit_sha"`
	}
	if err := json.Unmarshal(fixture(t, "mr-merged"), &merged); err != nil {
		t.Fatal(err)
	}
	a, err := attest(t, fakeGitLab(t, ultimateRoutes(s, merged.MergeCommitSHA)), merged.MergeCommitSHA)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	mr := a.MergeRequests[0]
	if mr.Relation != "merge_commit" || mr.MergedAt == "" || mr.MergeUser == nil || mr.ProjectID != 87019852 ||
		mr.AuthorID == 0 || mr.BaseSHA == "" || mr.TargetBranch != "main" || mr.MergeCommitSHA != merged.MergeCommitSHA {
		t.Fatalf("merged mr %+v", mr)
	}
	if len(mr.Approvals) != 1 || mr.Approvals[0].BoundHeadSHA == nil || *mr.Approvals[0].BoundHeadSHA != s.H {
		t.Fatalf("the head approval must bind to %s: %+v", s.H, mr.Approvals)
	}
	subjects := a.Subjects()
	for _, want := range []string{"commitsha:" + merged.MergeCommitSHA, "mrhead:" + s.H, "project:", "mergerequest:", "approver:"} {
		found := false
		for k := range subjects {
			found = found || strings.HasPrefix(k, want)
		}
		if !found {
			t.Errorf("missing subject %s", want)
		}
	}
}

// TestTierDegradation: on CE (free) the paid reads are recorded as
// unavailable with the reason; on a detected Premium or Ultimate the same 404
// is loud; a 403 is always loud.
func TestTierDegradation(t *testing.T) {
	s := loadScenario(t)
	t.Run("free: unavailable, collected", func(t *testing.T) {
		r := ultimateRoutes(s, s.H)
		r["/version"] = `inline:{"version":"19.4.1","revision":"191678a3764","enterprise":false}`
		delete(r, "/projects/87019852/approvals")
		delete(r, "/projects/87019852/merge_requests/1/approval_state")
		srv := fakeGitLab(t, r)
		a, err := attest(t, srv, s.H)
		if err != nil {
			t.Fatalf("a missing paid tier must not fail the attestor: %v", err)
		}
		mr := a.MergeRequests[0]
		if a.Tier.Plan != "free" || mr.ApprovalState != nil || len(mr.Unavailable) != 2 {
			t.Fatalf("tier %+v unavailable %+v", a.Tier, mr.Unavailable)
		}
		for _, u := range mr.Unavailable {
			if u.Tier != "free" || u.Status != 404 || u.Request == "" {
				t.Fatalf("reason must name tier, request and status: %+v", u)
			}
		}
	})
	t.Run("ultimate: a 404 on approval_state is loud", func(t *testing.T) {
		r := ultimateRoutes(s, s.H)
		delete(r, "/projects/87019852/merge_requests/1/approval_state")
		if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil {
			t.Fatal("a route the detected tier has must not degrade to unavailable")
		}
	})
	t.Run("a 403 is loud, never a tier gap", func(t *testing.T) {
		r := ultimateRoutes(s, s.H)
		r["/projects/87019852/merge_requests/1/approval_state"] = "status:403"
		if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("want a loud 403, got %v", err)
		}
	})
	t.Run("no merge request brought the commit in: nothing recorded", func(t *testing.T) {
		r := ultimateRoutes(s, s.H)
		r["/projects/87019852/repository/commits/"+s.H+"/merge_requests"] = "[]"
		if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil {
			t.Fatal("an empty review record must not be attested")
		}
	})
	t.Run("CI_JOB_TOKEN is refused", func(t *testing.T) {
		if _, err := attest(t, fakeGitLab(t, ultimateRoutes(s, s.H)), s.H, WithTokenEnv("CI_JOB_TOKEN")); err == nil {
			t.Fatal("the job token must be refused")
		}
	})
}

// TestDefaultClockGuardRefusesAnApprovalNearAPush is the design review's H1:
// approved_at and a version's created_at are stamped by different nodes on a
// multi-node GitLab, so an approval stamped seconds from a push can sit on
// either side of it. The default guard (60 s) leaves the gitlab.com parent
// approval, stamped 4.9 s before the head's version, bound to nothing; only an
// operator who declares a single clock (0) gets it bound to the parent.
func TestDefaultClockGuardRefusesAnApprovalNearAPush(t *testing.T) {
	s := loadScenario(t)
	a, err := attest(t, fakeGitLab(t, ultimateRoutes(s, s.H)), s.H)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.ClockSkewMs != DefaultClockSkewMillis {
		t.Fatalf("clock_skew_ms %d, want the default %d recorded", a.ClockSkewMs, DefaultClockSkewMillis)
	}
	if ap := a.MergeRequests[0].Approvals[0]; ap.BoundHeadSHA != nil || ap.Binding != "unbound" {
		t.Fatalf("an approval 4.9 s from a push must be unbound under the default guard: %+v", ap)
	}
	for _, bad := range []string{"-1", "x", "1.5", ""} {
		if _, err := parseClockSkew(bad); err == nil {
			t.Errorf("clock-skew-ms %q must be refused", bad)
		}
	}
	if _, err := attest(t, fakeGitLab(t, ultimateRoutes(s, s.H)), s.H, WithClockSkewMillis(-1)); err == nil {
		t.Fatal("a negative guard silently disables the guard; it must be refused")
	}
}

// TestApprovalWithoutAUserIsLoud: a deleted user comes back with no id; two
// of them would collapse into one approver, and one would count as user 0.
func TestApprovalWithoutAUserIsLoud(t *testing.T) {
	s := loadScenario(t)
	r := ultimateRoutes(s, s.H)
	r["/projects/87019852/merge_requests/1/approvals"] = `inline:{"approved":true,"approved_by":[{"approved_at":"2026-09-29T08:06:55.000Z","user":null}]}`
	if _, err := attest(t, fakeGitLab(t, r), s.H); err == nil || !strings.Contains(err.Error(), "no user id") {
		t.Fatalf("want a loud refusal of an approval with no user, got %v", err)
	}
}

// TestReviewChangedWhileReadingIsLoud is design doc section 2.4: the MR and
// its approvals are read again after everything else; a change in between
// (here an unapprove) fails the attestor instead of recording a mix.
func TestReviewChangedWhileReadingIsLoud(t *testing.T) {
	s := loadScenario(t)
	inner := fakeGitLab(t, ultimateRoutes(s, s.H))
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v4/projects/87019852/merge_requests/1/approvals" {
			calls++
			if calls > 1 {
				_, _ = w.Write([]byte(`{"approved":false,"approved_by":[]}`))
				return
			}
		}
		proxy, err := http.NewRequest(req.Method, inner.URL+req.URL.RequestURI(), nil)
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
		t.Fatalf("want a loud refusal of a review that changed mid-read, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("approvals read %d times, want 2 (read, then re-read)", calls)
	}
}

// retargetRoutes serves the gitlab.com retarget probe (project 87022414, MR
// !1): an MR feature -> dev, approved on its head H, then retargeted to main
// with no push. GitLab made a second version with the same head and left the
// system note "changed target branch from `dev` to `main`". GitLab itself
// reset the approval 5 s later; the approvals served here are the ones read
// BEFORE the retarget (rt-approvals-before), which is what a collector reading
// inside the reset window sees, as with the parent-approval window.
func retargetRoutes(approvals string) (map[string]string, string) {
	p := "/projects/87022414"
	mr := p + "/merge_requests/1"
	const h = "f47646583195e87b365e39ccb77a9d2ea440def1"
	return map[string]string{
		"/version":                    "version",
		p + "/approvals":              "project-approvals",
		p + "/external_status_checks": "cp-external-status-checks",
		p + "/pipelines":              "[]",
		p + "/repository/commits/" + h + "/statuses":       "[]",
		p + "/repository/commits/" + h + "/merge_requests": "rt-commit-mrs-head",
		mr:                     "rt-mr-after",
		mr + "/versions":       "rt-versions-after",
		mr + "/approvals":      approvals,
		mr + "/approval_state": "rt-approval-state-after",
		mr + "/notes":          "rt-notes-after",
		mr + "/discussions":    "[]",
	}, h
}

func attestProject(t *testing.T, srv *httptest.Server, project, sha string, opts ...Option) (*Attestor, error) {
	t.Helper()
	env := map[string]string{"CI_API_V4_URL": srv.URL + "/api/v4", "CI_PROJECT_ID": project,
		"CI_COMMIT_SHA": sha, DefaultTokenEnv: "test-token"}
	a := New(append([]Option{withEnv(func(k string) string { return env[k] })}, opts...)...)
	ctx, err := attestation.NewContext("gitlab-review-test", []attestation.Attestor{a}, attestation.WithContext(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	return a, a.Attest(ctx)
}

// TestApprovalBeforeARetargetDoesNotBind is the design review's M3 on real
// gitlab.com data: versions are keyed on the head alone, so without a
// retarget check an approval given while the MR targeted dev binds to H and
// counts for a merge into main. With a guard of 0 (so the clock guard is not
// what refuses it) the approval is before_retarget, bound to nothing, and the
// retarget is recorded.
func TestApprovalBeforeARetargetDoesNotBind(t *testing.T) {
	routes, h := retargetRoutes("rt-approvals-before")
	server := fakeGitLab(t, routes)
	a, err := attestProject(t, server, "87022414", h, WithClockSkewMillis(0))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if want := strings.TrimPrefix(server.URL, "http://"); a.Instance.Host != want {
		t.Fatalf("instance host %q, want the API origin's host %q", a.Instance.Host, want)
	}
	mr := a.MergeRequests[0]
	if len(mr.Approvals) != 1 {
		t.Fatalf("approvals %+v", mr.Approvals)
	}
	if ap := mr.Approvals[0]; ap.BoundHeadSHA != nil || ap.Binding != "before_retarget" {
		t.Fatalf("an approval given before the retarget must bind to nothing: %+v", ap)
	}
	if len(mr.Retargets) != 1 || mr.Retargets[0].From != "dev" || mr.Retargets[0].To != "main" || mr.Retargets[0].At == "" {
		t.Fatalf("retargets %+v", mr.Retargets)
	}
}

// TestSameHeadVersionIsAResetEvenWithoutTheNote: the note's wording is
// GitLab's to change, so a version that repeats the previous version's head
// (no push made it) is also a reset boundary. Served without the notes, the
// approval is still refused.
func TestSameHeadVersionIsAResetEvenWithoutTheNote(t *testing.T) {
	routes, h := retargetRoutes("rt-approvals-before")
	routes["/projects/87022414/merge_requests/1/notes"] = "[]"
	a, err := attestProject(t, fakeGitLab(t, routes), "87022414", h, WithClockSkewMillis(0))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if ap := a.MergeRequests[0].Approvals[0]; ap.BoundHeadSHA != nil || ap.Binding != "before_retarget" {
		t.Fatalf("a same-head version must reset the binding: %+v", ap)
	}
}

// TestRetargetNoteAloneResets: the note and the same-head version are two
// independent signals; either alone is enough. Served with the versions read
// before the retarget (one version) and the notes read after it, the window
// where GitLab has written the note but not yet the version, the approval is
// still refused.
func TestRetargetNoteAloneResets(t *testing.T) {
	routes, h := retargetRoutes("rt-approvals-before")
	routes["/projects/87022414/merge_requests/1/versions"] = "rt-versions-before"
	a, err := attestProject(t, fakeGitLab(t, routes), "87022414", h, WithClockSkewMillis(0))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if ap := a.MergeRequests[0].Approvals[0]; ap.BoundHeadSHA != nil || ap.Binding != "before_retarget" {
		t.Fatalf("the retarget note alone must reset the binding: %+v", ap)
	}
}

// TestResetBoundaryEdges: the reset boundary is the retarget note at
// 09:00:21.589Z (later than the same-head version at 21.112). An approval
// stamped exactly then, or within the clock guard after it (the note and the
// approval come from different nodes' clocks), is before_retarget.
func TestResetBoundaryEdges(t *testing.T) {
	for name, c := range map[string]struct {
		at   string
		skew int64
	}{
		"at the boundary, guard 0":        {"2026-09-29T09:00:21.589Z", 0},
		"30 s after, inside a 60 s guard": {"2026-09-29T09:00:51.589Z", 60000},
	} {
		t.Run(name, func(t *testing.T) {
			routes, h := retargetRoutes(`inline:{"approved":true,"approved_by":[{"approved_at":"` + c.at + `","user":{"id":7000016,"username":"approver"}}]}`)
			a, err := attestProject(t, fakeGitLab(t, routes), "87022414", h, WithClockSkewMillis(c.skew))
			if err != nil {
				t.Fatalf("Attest: %v", err)
			}
			if ap := a.MergeRequests[0].Approvals[0]; ap.Binding != "before_retarget" {
				t.Fatalf("approval at %s with guard %d: %+v", c.at, c.skew, ap)
			}
		})
	}
}

// TestTargetBranchPushIsNotAReset is the foil for the same-head rule, on
// gitlab.com (project 87022579): two commits landed on main after the head
// was approved, GitLab made no new version and kept the approval, and so
// does the collector (with guard 0, the approval binds to the head).
func TestTargetBranchPushIsNotAReset(t *testing.T) {
	p := "/projects/87022579"
	mr := p + "/merge_requests/1"
	const h = "5ffa45bf970b6ecf664ba129f8d5265f5c2ac10d"
	routes := map[string]string{
		"/version":                    "version",
		p + "/approvals":              "project-approvals",
		p + "/external_status_checks": "cp-external-status-checks",
		p + "/pipelines":              "[]",
		p + "/repository/commits/" + h + "/statuses":       "[]",
		p + "/repository/commits/" + h + "/merge_requests": "tp-commit-mrs-head",
		mr:                     "tp-mr",
		mr + "/versions":       "tp-versions-after-2",
		mr + "/approvals":      "tp-approvals-after-2",
		mr + "/approval_state": "rt-approval-state-after",
		mr + "/notes":          "tp-notes-after-2",
		mr + "/discussions":    "[]",
	}
	a, err := attestProject(t, fakeGitLab(t, routes), "87022579", h, WithClockSkewMillis(0))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	m := a.MergeRequests[0]
	if len(m.Retargets) != 0 || len(m.Approvals) != 1 || m.Approvals[0].BoundHeadSHA == nil || *m.Approvals[0].BoundHeadSHA != h {
		t.Fatalf("a target-branch push must not reset the binding: retargets %+v approvals %+v", m.Retargets, m.Approvals)
	}
}

// TestDeclaredTier is the design review's M2: the plan is an operator input
// the policy can pin. A declared plan below the instance's records the paid
// reads as unavailable without attempting them (they never satisfy anything);
// a paid plan declared on CE, or an unknown plan, is refused.
func TestDeclaredTier(t *testing.T) {
	s := loadScenario(t)
	r := ultimateRoutes(s, s.H)
	r["/projects/87019852/merge_requests/1/approval_state"] = "status:500"
	r["/projects/87019852/approvals"] = "status:500"
	a, err := attest(t, fakeGitLab(t, r), s.H, WithTier("free"))
	if err != nil {
		t.Fatalf("a declared free plan must not read paid routes: %v", err)
	}
	if a.Tier.Plan != "free" || a.Tier.DetectedBy != "operator" {
		t.Fatalf("tier %+v", a.Tier)
	}
	mr := a.MergeRequests[0]
	if mr.ApprovalState != nil || mr.ApprovalSetting != nil || len(mr.Unavailable) != 2 {
		t.Fatalf("unavailable %+v", mr.Unavailable)
	}
	for _, u := range mr.Unavailable {
		if u.Status != 0 || u.Reason == "" {
			t.Fatalf("a read not attempted records status 0 and why: %+v", u)
		}
	}
	ce := ultimateRoutes(s, s.H)
	ce["/version"] = `inline:{"version":"19.4.1","revision":"191678a3764","enterprise":false}`
	if _, err := attest(t, fakeGitLab(t, ce), s.H, WithTier("ultimate")); err == nil {
		t.Fatal("a paid plan declared on CE must be refused")
	}
	if _, err := attest(t, fakeGitLab(t, ultimateRoutes(s, s.H)), s.H, WithTier("gold")); err == nil {
		t.Fatal("an unknown plan must be refused")
	}
}
