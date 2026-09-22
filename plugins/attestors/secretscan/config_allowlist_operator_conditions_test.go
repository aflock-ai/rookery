// jade:ring local

// Copyright 2026 The Rookery Contributors
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

package secretscan

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Removing a path text gitleaks ships from an operator's allowlist entry may
// change what the entry admits only by that path. gitleaks joins an "AND"
// entry's non-empty checks into one conjunction (detect/detect.go,
// checkFindingAllowed), so an entry that keeps a path of the operator's own
// keeps every other check beside it; one whose only paths were built-in would
// lose its path conjunct and exempt everywhere, so it is dropped instead.
func TestBuiltinPathRemovalKeepsTheOperatorsOwnConditions(t *testing.T) {
	const fixtureKey = "fixture-key "
	files := map[string]string{
		"fixtures/allowed.txt":         "key " + e3Allowed + "\n",
		"fixtures/other.txt":           "key " + e3Other + "\n",
		"fixtures/line.txt":            fixtureKey + e3Other + "\n",
		"src/allowed.txt":              "key " + e3Allowed + "\n",
		"src/other.txt":                "key " + e3Other + "\n",
		"node_modules/pkg/allowed.txt": "key " + e3Allowed + "\n",
		"node_modules/pkg/other.txt":   "key " + e3Other + "\n",
	}
	all := []string{
		"file:fixtures/allowed.txt",
		"file:fixtures/line.txt",
		"file:fixtures/other.txt",
		"file:node_modules/pkg/allowed.txt",
		"file:node_modules/pkg/other.txt",
		"file:src/allowed.txt",
		"file:src/other.txt",
	}
	without := func(exempt ...string) []string {
		out := []string{}
		for _, f := range all {
			keep := true
			for _, e := range exempt {
				if f == "file:"+e {
					keep = false
				}
			}
			if keep {
				out = append(out, f)
			}
		}
		return out
	}

	cases := []struct {
		name   string
		config string
		want   []string
	}{
		{
			name:   "control: no allowlist",
			config: e3Rule,
			want:   all,
		},
		{
			name: "AND with a built-in and an own path keeps the own path and the regex",
			config: e3Rule + `
[[allowlists]]
condition = "AND"
paths = ['''node_modules''', '''^fixtures/''']
regexes = ['''ALLOWEDALLOWED''']
`,
			want: without("fixtures/allowed.txt"),
		},
		{
			name: "rule-level AND with a built-in and an own path, inline",
			config: e3Rule + `
[[rules.allowlists]]
condition = "AND"
paths = ['''node_modules''', '''^fixtures/''']
regexes = ['''ALLOWEDALLOWED''']
`,
			want: without("fixtures/allowed.txt"),
		},
		{
			name: "rule-level AND with a built-in and an own path, by targetRules",
			config: e3Rule + `
[[allowlists]]
targetRules = ["e3-probe"]
condition = "AND"
paths = ['''node_modules''', '''^fixtures/''']
regexes = ['''ALLOWEDALLOWED''']
`,
			want: without("fixtures/allowed.txt"),
		},
		{
			name: "AND with a built-in and an own path keeps its stopwords",
			config: e3Rule + `
[[allowlists]]
condition = "AND"
paths = ['''node_modules''', '''^fixtures/''']
stopwords = ["allowedallowed"]
`,
			want: without("fixtures/allowed.txt"),
		},
		{
			name: "AND with a built-in and an own path keeps its regexTarget",
			config: e3Rule + `
[[allowlists]]
condition = "AND"
regexTarget = "line"
paths = ['''node_modules''', '''^fixtures/''']
regexes = ['''^fixture-key ''']
`,
			want: without("fixtures/line.txt"),
		},
		{
			name: "AND whose only path is built-in is dropped, not widened to the regex alone",
			config: e3Rule + `
[[allowlists]]
condition = "AND"
paths = ['''node_modules''']
regexes = ['''ALLOWEDALLOWED''']
`,
			want: all,
		},
		{
			name: "AND whose only check is a built-in path is dropped",
			config: e3Rule + `
[[allowlists]]
condition = "AND"
paths = ['''node_modules''']
`,
			want: all,
		},
		{
			name: "OR whose only check is a built-in path is dropped",
			config: e3Rule + `
[[allowlists]]
paths = ['''node_modules''']
`,
			want: all,
		},
		{
			name: "OR with a built-in and an own path keeps the own path and the regex",
			config: e3Rule + `
[[allowlists]]
paths = ['''node_modules''', '''^fixtures/''']
regexes = ['''ALLOWEDALLOWED''']
`,
			want: without("fixtures/allowed.txt", "fixtures/other.txt", "fixtures/line.txt", "src/allowed.txt", "node_modules/pkg/allowed.txt"),
		},
		{
			name: "OR whose only path is built-in keeps its regex",
			config: e3Rule + `
[[allowlists]]
paths = ['''node_modules''']
regexes = ['''ALLOWEDALLOWED''']
`,
			want: without("fixtures/allowed.txt", "src/allowed.txt", "node_modules/pkg/allowed.txt"),
		},
		{
			name: "stopwords only is untouched",
			config: e3Rule + `
[[allowlists]]
stopwords = ["allowedallowed"]
`,
			want: without("fixtures/allowed.txt", "src/allowed.txt", "node_modules/pkg/allowed.txt"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, treeScanWithConfig(t, files, tc.config))
		})
	}
}

// TestRebuiltEntryCarriesEveryOperatorField pins the rebuild field by field,
// including commits, which a tree scan never carries and so cannot exercise.
func TestRebuiltEntryCarriesEveryOperatorField(t *testing.T) {
	re := regexp.MustCompile
	const sha = "0123456789abcdef0123456789abcdef01234567"
	for _, cond := range []config.AllowlistMatchCondition{config.AllowlistMatchOr, config.AllowlistMatchAnd} {
		t.Run(cond.String(), func(t *testing.T) {
			orig := &config.Allowlist{
				Description:    "operator entry",
				MatchCondition: cond,
				Commits:        []string{sha},
				Paths:          []*regexp.Regexp{re(`node_modules`), re(`^fixtures/`)},
				RegexTarget:    "line",
				Regexes:        []*regexp.Regexp{re(`ALLOWEDALLOWED`)},
				StopWords:      []string{"placeholder"},
			}
			require.NoError(t, orig.Validate())
			commitsOnly := &config.Allowlist{MatchCondition: cond, Commits: []string{sha}}
			require.NoError(t, commitsOnly.Validate())

			var dropped int
			got := withoutBuiltinPaths([]*config.Allowlist{orig, commitsOnly}, map[string]struct{}{`node_modules`: {}}, &dropped)
			require.Equal(t, 1, dropped)
			require.Len(t, got, 2)
			k := got[0]
			require.Equal(t, orig.Description, k.Description)
			require.Equal(t, cond, k.MatchCondition)
			require.Equal(t, orig.Commits, k.Commits)
			require.Equal(t, []string{`^fixtures/`}, patterns(k.Paths))
			require.Equal(t, "line", k.RegexTarget)
			require.Equal(t, []string{`ALLOWEDALLOWED`}, patterns(k.Regexes))
			require.Equal(t, orig.StopWords, k.StopWords)
			ok, _ := k.CommitAllowed(sha)
			require.True(t, ok)
			require.True(t, k.PathAllowed("fixtures/x"))
			require.False(t, k.PathAllowed("node_modules/x"))
			require.Same(t, commitsOnly, got[1], "an entry with no path is untouched")
		})
	}
}
