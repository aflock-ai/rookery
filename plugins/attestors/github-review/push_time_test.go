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

package github_review

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

func newAttestorAgainst(t *testing.T, srv *httptest.Server, sha string) (*Attestor, *attestation.AttestationContext) {
	t.Helper()
	a := New(WithRepo("o/r"), WithSHA(sha), WithAPIBaseURL(srv.URL), WithToken("stub-not-a-real-token"))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	return a, ctx
}

// allPRsApproved is the shape of the rule this attestor's evidence exists to
// answer — "every PR associated with this commit is approved". It is written
// here exactly as a rego author would write it, INCLUDING the vacuous-truth
// bug an empty list hands them: a universal quantifier over an empty set is
// true.
//
// The point of the tests below is NOT that this rule is well written. It is
// that no signed github-review attestation may ever reach it carrying an empty
// PR list that was never observed.
func allPRsApproved(predicate []byte) bool {
	var p struct {
		PRs []struct {
			Reviews []struct {
				State string `json:"state"`
			} `json:"reviews"`
		} `json:"prs"`
	}
	if err := json.Unmarshal(predicate, &p); err != nil {
		return false
	}
	for _, pr := range p.PRs {
		approved := false
		for _, r := range pr.Reviews {
			if r.State == "APPROVED" {
				approved = true
			}
		}
		if !approved {
			return false
		}
	}
	return true // vacuously true when len(p.PRs) == 0
}

// TestCommitNotOnGitHubEmitsNoAttestationAtAll is the security property.
//
// At push time the commit under attestation has, by construction, not reached
// GitHub, so GET /repos/{r}/commits/{sha}/pulls answers 422 "No commit found
// for SHA". There is no review state to observe.
//
// A previous iteration recorded that as a DetectionError carrying prs=[] under
// the UNCHANGED github-review/v0.1 predicate type. That is unsafe: a
// DetectionError payload is KEPT in the signed collection (see
// attestation.EvidenceIsRecordable), so an "all PRs approved" rule written
// against v0.1 passes it vacuously. The non-zero exit of `cilock run` does not
// help — it gates the RUN, while the signed attestation is verified later, by
// someone else, long after that exit code is gone.
//
// attestation/context.go states the rule this restores: DetectionError is ONLY
// for "an operator-configured verdict on a successful observation. If the
// attestor could not look, return a plain error." Commit-not-on-GitHub is the
// second case, so the payload must be DROPPED while the run still fails.
func TestCommitNotOnGitHubEmitsNoAttestationAtAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/repos/o/r/commits/abc123/pulls", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"No commit found for SHA: abc123","documentation_url":"https://docs.github.com/rest"}`))
	}))
	defer srv.Close()

	a, ctx := newAttestorAgainst(t, srv, "abc123")
	err := a.Attest(ctx)

	require.Error(t, err, "commit-not-yet-on-GitHub must never be a success")
	require.False(t, attestation.IsSoftError(err), "must stay a fatal leg so cilock run exits non-zero")

	// THE property: the workflow must not put this payload in the signed
	// collection. Asserted against the exported predicate the workflow itself
	// applies, not a copy of it.
	require.False(t, attestation.EvidenceIsRecordable(err),
		"payload must be DROPPED from the signed collection; a recorded prs=[] passes 'all PRs approved' vacuously")
	require.False(t, attestation.IsDetectionError(err),
		"commit-not-found is 'could not observe', not an operator-configured verdict")

	// The operator still learns exactly why, from the error itself.
	require.Contains(t, err.Error(), "No commit found for SHA")
	require.Contains(t, err.Error(), "abc123")
}

// TestVacuousApprovalIsUnreachableForAnUnseenCommit demonstrates the harm the
// test above prevents: IF such a predicate were ever signed, the natural "all
// PRs approved" rule would pass it. So the predicate must never exist.
func TestVacuousApprovalIsUnreachableForAnUnseenCommit(t *testing.T) {
	// Guard assumption: an empty PR list does satisfy "all PRs approved".
	require.True(t, allPRsApproved([]byte(`{"prs":[]}`)),
		"guard assumption: an empty PR list satisfies 'all PRs approved' vacuously")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"No commit found for SHA: abc123"}`))
	}))
	defer srv.Close()

	a, ctx := newAttestorAgainst(t, srv, "abc123")
	err := a.Attest(ctx)
	require.Error(t, err)
	require.False(t, attestation.EvidenceIsRecordable(err),
		"the only defence is that this payload is never recorded")
}

// TestOtherAPIFailuresStayFatal: a 404 (wrong repo, no access) also means we
// could not observe, and must not be recorded as a clean empty review set.
func TestOtherAPIFailuresStayFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	a, ctx := newAttestorAgainst(t, srv, "abc123")
	err := a.Attest(ctx)
	require.Error(t, err)
	require.False(t, attestation.EvidenceIsRecordable(err))
}

// TestPredicateShapeIsUnchangedOnTheHappyPath: dropping the not-found payload
// means the v0.1 predicate keeps exactly the fields it always had, so evidence
// recorded before this change round-trips byte-identically and no consumer has
// to learn a new field.
func TestPredicateShapeIsUnchangedOnTheHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	a, ctx := newAttestorAgainst(t, srv, "abc123")
	require.NoError(t, a.Attest(ctx))
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "commit_not_found")
	require.Contains(t, string(raw), `"prs":[]`)
}
