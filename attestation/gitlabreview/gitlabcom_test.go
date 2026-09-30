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

package gitlabreview

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadGitLabCom(t *testing.T, name string, v any) {
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
	if name == "scenario" {
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := json.Unmarshal(f.Response, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func ms(t *testing.T, s string) int64 {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm.UnixMilli()
}

// TestExactShaOnARealGitLabComTimeline replays a real gitlab.com Ultimate
// merge request (sandbox testifysec/judge-parity-sandbox, 2026-09-29): the
// approver approved on the parent sha P, then H was pushed. Read a second
// after the push, GitLab still listed that approval and its approval_state
// called the rule approved for the MR now at H, although the project resets
// approvals on push: the reset had not run yet. The exact-sha rule binds the
// approval to P and counts nothing for H. The approval given after H's
// version counts, and the MR merged at H.
func TestExactShaOnARealGitLabComTimeline(t *testing.T) {
	var sc struct{ P, H string }
	loadGitLabCom(t, "scenario", &sc)
	var rawVersions []struct {
		HeadCommitSHA string `json:"head_commit_sha"`
		CreatedAt     string `json:"created_at"`
	}
	loadGitLabCom(t, "mr-versions-merged", &rawVersions)
	vs := make([]Version, 0, len(rawVersions))
	for _, v := range rawVersions {
		vs = append(vs, Version{Head: v.HeadCommitSHA, CreatedAt: ms(t, v.CreatedAt)})
	}
	type approvals struct {
		ApprovedBy []struct {
			ApprovedAt string `json:"approved_at"`
			User       struct {
				ID int64 `json:"id"`
			} `json:"user"`
		} `json:"approved_by"`
	}
	toApprovals := func(a approvals) []Approval {
		out := make([]Approval, 0, len(a.ApprovedBy))
		for _, x := range a.ApprovedBy {
			out = append(out, Approval{User: x.User.ID, ApprovedAt: ms(t, x.ApprovedAt)})
		}
		return out
	}
	var merged struct {
		SHA      string `json:"sha"`
		MergedAt string `json:"merged_at"`
	}
	loadGitLabCom(t, "mr-merged", &merged)
	if merged.SHA != sc.H {
		t.Fatalf("the MR merged at %s, the scenario's head is %s", merged.SHA, sc.H)
	}
	mergedAt := ms(t, merged.MergedAt)

	var afterPush approvals
	loadGitLabCom(t, "mr-approvals-after-push", &afterPush)
	var gitlabState struct {
		Rules []struct {
			Approved bool `json:"approved"`
		} `json:"rules"`
	}
	loadGitLabCom(t, "mr-approval-state-after-push", &gitlabState)
	if len(afterPush.ApprovedBy) != 1 || len(gitlabState.Rules) != 1 || !gitlabState.Rules[0].Approved {
		t.Fatal("the fixture no longer shows GitLab counting the parent approval after the push")
	}
	parent := toApprovals(afterPush)
	if head, ok := BoundHead(0, vs, parent[0].ApprovedAt); !ok || head != sc.P {
		t.Fatalf("the approval given before H's version must bind to the parent %s, got %q %v", sc.P, head, ok)
	}
	if n := CountFor(0, vs, parent, mergedAt, sc.H, nil); n != 0 {
		t.Fatalf("an approval on the parent sha counted %d for the head (GitLab's rule said approved)", n)
	}

	var final approvals
	loadGitLabCom(t, "mr-approvals-merged", &final)
	if n := CountFor(0, vs, toApprovals(final), mergedAt, sc.H, nil); n != 1 {
		t.Fatalf("the approval given on H must count once, got %d", n)
	}
}
