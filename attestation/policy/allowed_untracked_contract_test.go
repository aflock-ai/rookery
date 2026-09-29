// jade:ring local
// Copyright 2026 The Aflock Authors
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

package policy

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowedUntrackedGrammarPatterns is every pattern of up to three characters
// over the glob syntax that gobwas's parser accepts, the set of patterns the
// allowedUntracked field accepted before #10376.
func allowedUntrackedGrammarPatterns() []string {
	alphabet := []string{"a", "*", "?", "/", "{", "}", ",", "[", "]", "!", "-", "\\"}
	var out []string
	var grow func(prefix string, n int)
	grow = func(prefix string, n int) {
		if prefix != "" {
			if _, err := glob.Compile(prefix, '/'); err == nil {
				out = append(out, prefix)
			}
		}
		if n == 0 {
			return
		}
		for _, c := range alphabet {
			grow(prefix+c, n-1)
		}
	}
	grow("", 3)
	return out
}

// A pattern gobwas accepted but the RE2 translation cannot compile (an
// unclosed '{', an inverted range) fails CLOSED at every layer: the policy is
// refused at load and at verify, AllowsUntracked errors, and the artifact
// check rejects the collection even when allowedUntracked is only warned
// about. It is never read as "matches nothing" and dropped.
func TestAllowedUntrackedPatternsRE2RefusesFailClosed(t *testing.T) {
	var refused []string
	for _, p := range allowedUntrackedGrammarPatterns() {
		if _, err := compileAllowedUntracked([]string{p}); err != nil {
			refused = append(refused, p)
		}
	}
	require.NotEmpty(t, refused, "the enumeration must reach the patterns gobwas accepted and RE2 refuses")
	t.Logf("%d gobwas-valid patterns are refused by the RE2 translation, e.g. %q", len(refused), refused[:min(5, len(refused))])

	prev := Hardening()
	t.Cleanup(func() { SetHardening(prev) })
	warn := prev
	warn.EnforceAllowedUntracked = false
	SetHardening(warn)

	for _, p := range refused {
		step := Step{Name: "build", ArtifactsFrom: []string{"src"}, AllowedUntracked: []string{"vendor/**", p}}
		pol := Policy{Steps: map[string]Step{
			"src":   {Name: "src"},
			"build": step,
		}}
		err := pol.Validate()
		require.Error(t, err, "Validate must refuse allowedUntracked %q", p)
		assert.Contains(t, err.Error(), "allowedUntracked[1]", p)

		_, err = step.AllowsUntracked("vendor/a.go")
		require.Error(t, err, "AllowsUntracked must refuse %q, not match nothing", p)

		err = checkAllowedUntracked(step, map[string]cryptoutil.DigestSet{"vendor/a.go": {}}, map[string]struct{}{})
		var failed ErrVerifyArtifactsFailed
		require.True(t, errors.As(err, &failed), "%q: an unusable pattern rejects the collection even when untracked materials are only warned about, got %v", p, err)
	}

	// The whole verify refuses before any evidence is searched.
	verifier, keyID := newECDSAVerifier(t)
	step := validNoopStep(keyID)
	step.AllowedUntracked = []string{refused[0]}
	pol := Policy{Expires: futureExpiry(), Steps: map[string]Step{"noop": step}}
	ms := &stepAwareVerifiedSource{byStep: map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(verifier)}}}
	pass, _, _, err := pol.VerifyWithExternals(context.Background(), WithVerifiedSource(ms), WithSubjectDigests([]string{"sha256:artifact"}))
	require.Error(t, err)
	assert.False(t, pass)
	assert.Contains(t, err.Error(), "allowedUntracked")
}

// The allowedUntracked contract is gobwas's documented grammar with '/' as the
// separator (policy-schema.md, "gobwas/glob syntax"). From gobwas's Compile
// doc:
//
//	`**`   matches any sequence of characters
//	`{` pattern-list `}`   pattern alternatives
//	pattern-list: pattern { `,` pattern }
//	pattern: { term }
//
// So a run of three or more '*' is a '**' next to a '*', which together match
// any sequence, and '{}' is one empty alternative, which matches the empty
// string. The RE2 matcher admits exactly that. gobwas's own matcher did not,
// inconsistently: it matched "a" for "a**" and "a****" but not for "a***",
// matched "" for "{}" alone but not "a" for "*{}", and panicked on "a{}"
// (safeUntrackedMatch read the panic as no match). Those refusals were matcher
// defects, not the contract, and these metamorphic checks pin the contract:
// every pattern must answer exactly as its normal form does.
func TestAllowedUntrackedMatchesTheGrammarNormalForm(t *testing.T) {
	runs := regexp.MustCompile(`\*{3,}`)
	normal := func(p string) string {
		// Drop empty groups, then collapse star runs, until nothing changes. A
		// '{}' preceded by an odd number of '\' is an escaped '{' and stays.
		for {
			q := runs.ReplaceAllString(p, "**")
			q = strings.ReplaceAll(q, "{}", "\x00")
			q = regexp.MustCompile(`(^|[^\\])((?:\\\\)*)\x00`).ReplaceAllString(q, "$1$2")
			q = strings.ReplaceAll(q, "\x00", "{}")
			if q == p {
				return p
			}
			p = q
		}
	}
	vals := []string{""}
	for frontier := []string{""}; len(frontier[0]) < 4; {
		var next []string
		for _, v := range frontier {
			for _, c := range []string{"a", "b", "/", "}", ","} {
				next = append(next, v+c)
			}
		}
		vals = append(vals, next...)
		frontier = next
	}
	pats := allowedUntrackedGrammarPatterns()
	pats = append(pats, "a***", "a****", "vendor/***/x.go", "a{}", "*{}", "{}vendor/**", "a{,}", "cilock{,.exe}{}")
	checked := 0
	for _, p := range pats {
		n := normal(p)
		if n == p {
			continue
		}
		if n == "" {
			// An empty pattern is refused outright; a pattern that normalises
			// to it ("{}", "{}{}") matches only the empty path, which never
			// matches. It must admit nothing.
			mp, err := compileAllowedUntracked([]string{p})
			if err == nil {
				for _, v := range vals {
					require.False(t, mp.matches(v), "%q admits nothing, but matched %q", p, v)
				}
			}
			continue
		}
		mp, errP := compileAllowedUntracked([]string{p})
		mn, errN := compileAllowedUntracked([]string{n})
		require.Equal(t, errP == nil, errN == nil, "%q and its normal form %q must compile alike", p, n)
		if errP != nil {
			continue
		}
		for _, v := range vals {
			if v != "" && path.Clean(v) != v {
				continue
			}
			require.Equal(t, mn.matches(v), mp.matches(v), "%q must answer %q exactly as %q does", p, v, n)
			checked++
		}
	}
	require.Positive(t, checked)

	for _, c := range []struct {
		pattern, value string
		want           bool
	}{
		{"a***", "a", true},     // gobwas: false (defect), "a**" and "a****": true
		{"a***", "a/b/c", true}, // crosses separators, as '**' does
		{"a*{}", "a/b", false},  // '*' still stays in a segment
		{"*{}", "a", true},      // gobwas: false (defect)
		{"a{}", "a", true},      // gobwas: panic
		{"a{,}", "a", true},     // gobwas: panic
		{"cilock{,.exe}", "cilock", true},
		{"a{}b", "a/b", false},
	} {
		m, err := compileAllowedUntracked([]string{c.pattern})
		require.NoError(t, err, c.pattern)
		assert.Equal(t, c.want, m.matches(c.value), "%q vs %q", c.pattern, c.value)
	}
}
