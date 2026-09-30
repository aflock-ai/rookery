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

// Package gitlabreview binds GitLab merge request approvals to the exact
// commit they approved, for the gitlab-review attestor and the verifier that
// counts its approvals (docs/design/gitlab-api-attestors.md, section 3.3).
//
// GitLab records no sha per approval. An approval binds to the head of the
// newest diff version created strictly before it; a tie, a time within the
// clock guard of any version, an approval older than every version, or two
// versions created at the newest instant with different heads bind to
// nothing. An approval counts for head H only when it is bound to exactly H
// and was given no later than the merge (Cole, 2026-09-29: exact sha, no
// patch-id equivalence).
//
// The model is Lean `CilockCi.Review` (subtrees/rookery/formal/cilock-ci,
// CilockCi/Review.lean); formal_differential_test.go runs both.
package gitlabreview

// Version is one MR diff version: GET .../merge_requests/:iid/versions
// head_commit_sha and created_at (milliseconds since the epoch).
type Version struct {
	Head      string
	CreatedAt int64
}

// Approval is one approval: the approver's user id (never a username) and
// approved_at (milliseconds since the epoch).
type Approval struct {
	User       int64
	ApprovedAt int64
}

func near(skew, a, b int64) bool { return a <= b+skew && b <= a+skew }

// BoundHead is the head the approval given at t binds to, or "" and false.
// skew is the clock guard in milliseconds (0 only on an install with one
// clock). A negative guard would disable the guard, so it binds nothing (the
// model's skew is a natural number).
func BoundHead(skew int64, vs []Version, t int64) (string, bool) {
	if skew < 0 {
		return "", false
	}
	for _, v := range vs {
		if near(skew, t, v.CreatedAt) {
			return "", false
		}
	}
	newest, found := int64(0), false
	for _, v := range vs {
		if v.CreatedAt < t && (!found || v.CreatedAt > newest) {
			newest, found = v.CreatedAt, true
		}
	}
	if !found {
		return "", false
	}
	head, have := "", false
	for _, v := range vs {
		if v.CreatedAt != newest {
			continue
		}
		if have && v.Head != head {
			return "", false
		}
		head, have = v.Head, true
	}
	return head, true
}

// Counts reports whether approval a counts for head h of an MR merged at
// mergedAt: bound to exactly h, and given no later than the merge.
func Counts(skew int64, vs []Version, mergedAt int64, h string, a Approval) bool {
	b, ok := BoundHead(skew, vs, a.ApprovedAt)
	return ok && b == h && a.ApprovedAt <= mergedAt
}

// CountFor is the number of distinct approvers with a counted approval for
// head h, excluding author when it is non-nil.
func CountFor(skew int64, vs []Version, as []Approval, mergedAt int64, h string, author *int64) int {
	seen := map[int64]bool{}
	for _, a := range as {
		if !Counts(skew, vs, mergedAt, h, a) || seen[a.User] {
			continue
		}
		if author != nil && a.User == *author {
			continue
		}
		seen[a.User] = true
	}
	return len(seen)
}
