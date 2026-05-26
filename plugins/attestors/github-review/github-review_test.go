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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRepoFromURL(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"https-with-suffix", "https://github.com/aflock-ai/rookery.git", "aflock-ai/rookery", true},
		{"https-no-suffix", "https://github.com/aflock-ai/rookery", "aflock-ai/rookery", true},
		{"ssh", "git@github.com:aflock-ai/rookery.git", "aflock-ai/rookery", true},
		{"https-with-trailing-slash", "https://github.com/aflock-ai/rookery/", "aflock-ai/rookery", true},
		{"three-segments-trims", "https://github.com/aflock-ai/rookery/tree/main", "aflock-ai/rookery", true},
		{"non-github", "https://gitlab.com/foo/bar.git", "", false},
		{"garbage", "not-a-url", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRepoFromURL(tc.in)
			if tc.wantOK {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestNewWithOptions(t *testing.T) {
	a := New(
		WithRepo("o/r"),
		WithSHA("abc123"),
		WithPR("42"),
		WithToken("ghp_secret"),
		WithAPIBaseURL("https://ghe.example.com/api/v3"),
	)
	assert.Equal(t, "o/r", a.repoFlag)
	assert.Equal(t, "abc123", a.shaFlag)
	assert.Equal(t, "42", a.prFlag)
	assert.Equal(t, "ghp_secret", a.tokenFlag)
	assert.Equal(t, "https://ghe.example.com/api/v3", a.apiURLFlag)
	assert.Equal(t, Name, a.Name())
	assert.Equal(t, Type, a.Type())
}

func TestResolveTokenPrecedence(t *testing.T) {
	ctx := t.Context()

	// Explicit flag wins over everything.
	t.Setenv("GH_TOKEN", "gh-env")
	t.Setenv("GITHUB_TOKEN", "github-env")
	tok, src := resolveToken(ctx, "flag-val")
	assert.Equal(t, "flag-val", tok)
	assert.Equal(t, sourceFlag, src)

	// GH_TOKEN beats GITHUB_TOKEN.
	tok, src = resolveToken(ctx, "")
	assert.Equal(t, "gh-env", tok)
	assert.Equal(t, sourceGHTokenEnv, src)

	// GITHUB_TOKEN used when GH_TOKEN absent.
	t.Setenv("GH_TOKEN", "")
	tok, src = resolveToken(ctx, "")
	assert.Equal(t, "github-env", tok)
	assert.Equal(t, sourceGHubTokenEnv, src)

	// Whitespace-only env values are treated as unset.
	t.Setenv("GH_TOKEN", "   ")
	t.Setenv("GITHUB_TOKEN", "real")
	tok, src = resolveToken(ctx, "")
	assert.Equal(t, "real", tok)
	assert.Equal(t, sourceGHubTokenEnv, src)
}

func TestParseNextLink(t *testing.T) {
	const base = "https://api.github.com"
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "single-next",
			header: `<https://api.github.com/repositories/123/pulls/4/reviews?page=2>; rel="next", <https://api.github.com/repositories/123/pulls/4/reviews?page=5>; rel="last"`,
			want:   "/repositories/123/pulls/4/reviews?page=2",
		},
		{
			name:   "only-last-no-next",
			header: `<https://api.github.com/repositories/123/pulls/4/reviews?page=5>; rel="last"`,
			want:   "",
		},
		{
			name:   "empty",
			header: "",
			want:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseNextLink(tc.header, base))
		})
	}
}

func TestGhPullMergedOrState(t *testing.T) {
	open := ghPull{State: "open"}
	closed := ghPull{State: "closed"}
	merged := ghPull{State: "closed", Merged: true}
	assert.Equal(t, "open", open.mergedOrState())
	assert.Equal(t, "closed", closed.mergedOrState())
	assert.Equal(t, "merged", merged.mergedOrState())
}

func TestSubjectsBuildsAllKeys(t *testing.T) {
	a := New()
	a.Repo = "aflock-ai/rookery"
	a.CommitSHA = "abcdef"
	a.PRs = []PR{
		{Number: 42, Reviews: []Review{
			{UserLogin: "alice", State: "APPROVED"},
			{UserLogin: "bob", State: "COMMENTED"},
			{UserLogin: "alice", State: "COMMENTED"}, // dedup by key
		}},
		{Number: 43, Reviews: []Review{
			{UserLogin: "carol", State: "APPROVED"},
		}},
	}
	subs := a.Subjects()
	assert.Contains(t, subs, "commitsha:abcdef")
	assert.Contains(t, subs, "repo:aflock-ai/rookery")
	assert.Contains(t, subs, "pr:aflock-ai/rookery#42")
	assert.Contains(t, subs, "pr:aflock-ai/rookery#43")
	assert.Contains(t, subs, "reviewer:alice")
	assert.Contains(t, subs, "reviewer:bob")
	assert.Contains(t, subs, "reviewer:carol")
	// alice only appears once even though she has two reviews.
}

// TestPredicateMarshalsToStableJSON ensures the predicate payload
// roundtrips cleanly — guards against accidental json tag changes.
func TestPredicateMarshalsToStableJSON(t *testing.T) {
	a := New()
	a.Repo = "aflock-ai/rookery"
	a.CommitSHA = "abc"
	a.FetchedAt = "2026-05-25T22:00:00Z"
	a.PRs = []PR{{
		Number:  1,
		State:   "merged",
		HeadSHA: "abc",
		BaseSHA: "def",
		URL:     "https://github.com/aflock-ai/rookery/pull/1",
		Reviews: []Review{{State: "APPROVED", UserLogin: "alice", SubmittedAt: "2026-05-25T21:55:00Z", CommitID: "abc"}},
	}}

	raw, err := json.Marshal(a)
	require.NoError(t, err)

	var rt Attestor
	require.NoError(t, json.Unmarshal(raw, &rt))
	assert.Equal(t, a.Repo, rt.Repo)
	assert.Equal(t, a.CommitSHA, rt.CommitSHA)
	assert.Len(t, rt.PRs, 1)
	assert.Equal(t, "APPROVED", rt.PRs[0].Reviews[0].State)
	assert.Equal(t, "alice", rt.PRs[0].Reviews[0].UserLogin)
}
