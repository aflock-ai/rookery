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

package policy

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/glob"
	"github.com/stretchr/testify/require"
)

// #9826: gobwas counts '?' in bytes in some positions, so a multibyte value
// was refused by a pattern that plainly matches it.
func TestCertGlob_QuestionMarkCountsRunes(t *testing.T) {
	for _, c := range []struct{ pattern, value string }{
		{"ßς?😀", "ßς?😀"},
		{"ßς?😀", "ßςx😀"},
		{"?b", "ßb"},
		{"a?b", "aßb"},
		{"x?y?", "xßyß"},
		{"?", "😀"},
		{"{ß,x}?", "ßß"},
		{"[ß]?", "ßß"},
	} {
		require.NoError(t, checkCertConstraintGlob("common name", c.pattern, c.value), "%q vs %q", c.pattern, c.value)
	}
	for _, c := range []struct{ pattern, value string }{
		{"??", "ß"},   // one rune, two '?'
		{"?", "ßx"},   // two runes, one '?'
		{"a?b", "ab"}, // '?' needs a rune
	} {
		require.Error(t, checkCertConstraintGlob("common name", c.pattern, c.value), "%q vs %q", c.pattern, c.value)
	}
}

// gobwas let a literal prefix and suffix overlap in the value, on plain and
// brace/class/escape syntax alike, and accepted "..a.." for "{?,aa}..*",
// which neither alternative matches. Each of these was a gobwas false accept.
func TestCertGlob_NoGobwasFalseAccepts(t *testing.T) {
	for _, c := range []struct{ pattern, value string }{
		{"a*a", "a"},
		{".*.", "."},
		{":*:/", ":/"},
		{"acme*acme", "acme"},
		{"{a}*a", "a"},
		{"[a]*a", "a"},
		{"a*{a}", "a"},
		{"a*[a]", "a"},
		{`\a*a`, "a"},
		{"{ab}*b", "ab"},
		{"{?,aa}..*", "..a.."},
	} {
		g, err := glob.Compile(c.pattern)
		require.NoError(t, err)
		require.True(t, g.Match(c.value), "precondition: gobwas accepts %q for %q", c.value, c.pattern)
		require.Error(t, checkCertConstraintGlob("common name", c.pattern, c.value), "%q vs %q", c.pattern, c.value)
	}
	require.NoError(t, checkCertConstraintGlob("common name", "a*a", "aa"))
	require.NoError(t, checkCertConstraintGlob("common name", "{a}*a", "aa"))
	require.NoError(t, checkCertConstraintGlob("common name", "[ab]*a", "ba"))
}

// The syntax corners, pinned. gobwas's grammar: '\' escapes anywhere, a class
// is one range or a list, and ',' and '}' are literal outside braces.
func TestCertGlob_SyntaxCorners(t *testing.T) {
	for _, c := range []struct {
		pattern, value string
		want           bool
	}{
		{`\*`, "*", true},
		{`\*`, "a", false},
		{`\?`, "?", true},
		{`\?`, "a", false},
		{`\{a,b\}`, "{a,b}", true},
		{`\[a\]`, "[a]", true},
		{`a\`, "a", true}, // a trailing escape is dropped, as gobwas does
		{"a,b", "a,b", true},
		{"a}b", "a}b", true},
		{"a]b", "a]b", true},
		{"**", "abc", true},
		{"[a-c]", "b", true},
		{"[a-c]", "d", false},
		{"[!a-c]", "d", true},
		{"[!a-c]", "b", false},
		{"[ab-]", "-", true}, // '-' is a list member unless it follows the first rune
		{`[\]]`, "]", true},
		{"[!ab]", "c", true},
		{"[!ab]", "a", false},
		{"{a,{b,c}}x", "cx", true},
		{"{a,{b,c}}x", "dx", false},
		{"{,a}b", "b", true},
		{"{}b", "b", true},
		{"a.b", "axb", false}, // '.' is literal, never a regexp wildcard
		{"a+", "aa", false},   // '+' is literal
		{"(a|b)", "(a|b)", true},
		{"^$", "^$", true},
	} {
		g, err := compileCertGlob(c.pattern)
		require.NoError(t, err, "pattern %q", c.pattern)
		require.Equal(t, c.want, g.Match(c.value), "pattern %q value %q", c.pattern, c.value)
	}
}

// A pattern gobwas refuses is still refused, so no constraint that failed to
// compile before starts matching now.
func TestCertGlob_InvalidPatternsStillRefused(t *testing.T) {
	for _, p := range []string{"[unclosed", "[a-", "[a-bc]", "[a-b"} {
		_, gobwasErr := glob.Compile(p)
		require.Error(t, gobwasErr, "precondition: gobwas refuses %q", p)
		_, err := compileCertGlob(p)
		require.Error(t, err, "pattern %q", p)
	}
	// gobwas accepts these; the translator refuses them, so they fail closed:
	// an inverted range (RE2 refuses it) and an unclosed alternation.
	for _, p := range []string{"[z-a]", "{a", "a{b,c"} {
		_, err := compileCertGlob(p)
		require.Error(t, err, "pattern %q", p)
	}
}

// leanGlobMatch transcribes globMatch from the cilock-policy Lean model
// (formal/cilock-policy Trust.lean) clause for clause, fuel included. It is
// exponential and exists only as the reference for the differential tests.
func leanGlobMatch(n int, p, s []rune) bool {
	switch {
	case n == 0:
		return false
	case len(p) == 0:
		return len(s) == 0
	case p[0] == '*' && len(s) == 0:
		return leanGlobMatch(n-1, p[1:], s)
	case p[0] == '*':
		return leanGlobMatch(n-1, p[1:], s) || leanGlobMatch(n-1, p, s[1:])
	case len(s) == 0:
		return false
	case p[0] == '?':
		return leanGlobMatch(n-1, p[1:], s[1:])
	default:
		return p[0] == s[0] && leanGlobMatch(n-1, p[1:], s[1:])
	}
}

func leanGlob(p, s string) bool {
	pr, sr := []rune(p), []rune(s)
	return leanGlobMatch(len(pr)+len(sr)+1, pr, sr)
}

func randomString(r *rand.Rand, alphabet []rune, maxLen int) string {
	n := r.Intn(maxLen + 1)
	out := make([]rune, n)
	for i := range out {
		out[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(out)
}

// On the Lean model's own domain (literals, '*', '?', multibyte runes) the
// matcher is exactly globMatch, except that only "*" admits an empty value.
func TestCertGlob_AgreesWithLeanModel(t *testing.T) {
	r := rand.New(rand.NewSource(9826)) //nolint:gosec // deterministic test corpus
	alpha := []rune{'a', 'ß', '😀', '?', '*', '.'}
	for i := 0; i < 50000; i++ {
		p := randomString(r, alpha, 7)
		s := randomString(r, []rune{'a', 'ß', '😀', '?', '*', '.'}, 7)
		g, err := compileCertGlob(p)
		require.NoError(t, err, "pattern %q", p)
		want := leanGlob(p, s)
		if s == "" {
			want = p == AllowAllConstraint
		}
		require.Equal(t, want, g.Match(s), "pattern %q value %q", p, s)
	}
}

// globCase is a generated pattern together with its expansion into plain
// '*'/'?'/literal patterns, built independently of the translator under test.
type globCase struct {
	text      string
	expansion []string
}

var valueAlphabet = []rune{'a', 'b', '.', '-', ','}

func cross(xs, ys []string) []string {
	out := make([]string, 0, len(xs)*len(ys))
	for _, x := range xs {
		for _, y := range ys {
			out = append(out, x+y)
		}
	}
	return out
}

// genPiece builds one glob element. inAlt excludes ',' so a literal comma
// never meets alternation, and depth bounds nesting.
func genPiece(r *rand.Rand, inAlt bool, depth int) globCase {
	lits := []string{"a", "b", ".", "-", ","}
	if inAlt {
		lits = lits[:4]
	}
	switch k := r.Intn(10); {
	case k < 4:
		l := lits[r.Intn(len(lits))]
		return globCase{l, []string{l}}
	case k == 4:
		return globCase{"*", []string{"*"}}
	case k == 5:
		return globCase{"?", []string{"?"}}
	case k == 6:
		l := []string{"a", "b", "."}[r.Intn(3)]
		return globCase{`\` + l, []string{l}}
	case k == 7:
		// Class: a list or the one range, optionally negated, expanded to
		// its members over the value alphabet.
		var members map[rune]bool
		var body string
		if r.Intn(3) == 0 {
			body, members = "a-b", map[rune]bool{'a': true, 'b': true}
		} else {
			members = map[rune]bool{}
			for _, c := range []rune{'a', 'b', '.'} {
				if r.Intn(2) == 0 {
					members[c] = true
					body += string(c)
				}
			}
			if body == "" {
				body, members = "a", map[rune]bool{'a': true}
			}
		}
		negate := r.Intn(2) == 0
		text := "[" + body + "]"
		if negate {
			text = "[!" + body + "]"
		}
		var exp []string
		for _, c := range valueAlphabet {
			if members[c] != negate {
				exp = append(exp, string(c))
			}
		}
		return globCase{text, exp}
	default:
		if depth >= 2 {
			return globCase{"a", []string{"a"}}
		}
		alts := make([]string, 1+r.Intn(3))
		var exp []string
		for i := range alts {
			seq := genSeq(r, r.Intn(3), true, depth+1)
			alts[i] = seq.text
			exp = append(exp, seq.expansion...)
		}
		return globCase{"{" + strings.Join(alts, ",") + "}", exp}
	}
}

func genSeq(r *rand.Rand, n int, inAlt bool, depth int) globCase {
	out := globCase{"", []string{""}}
	for ; n > 0; n-- {
		p := genPiece(r, inAlt, depth)
		out.text += p.text
		out.expansion = cross(out.expansion, p.expansion)
	}
	return out
}

// The full grammar against an independent oracle: every generated pattern is
// expanded (alternatives into separate patterns, classes into their member
// runes) and the Lean globMatch judges the expansions. The translator must
// agree on every non-empty value. gobwas's disagreements with the same oracle
// are counted, which is the evidence for replacing its matcher.
func TestCertGlob_FullSyntaxAgreesWithExpansionOracle(t *testing.T) {
	r := rand.New(rand.NewSource(99)) //nolint:gosec // deterministic test corpus
	checked, gobwasAccepts, gobwasRejects := 0, 0, 0
	for i := 0; i < 40000; i++ {
		c := genSeq(r, 1+r.Intn(5), false, 0)
		if len(c.expansion) > 64 {
			continue
		}
		s := randomString(r, valueAlphabet, 6)
		if s == "" {
			continue
		}
		want := false
		for _, e := range c.expansion {
			if leanGlob(e, s) {
				want = true
				break
			}
		}
		g, err := compileCertGlob(c.text)
		require.NoError(t, err, "pattern %q", c.text)
		require.Equal(t, want, g.Match(s), "pattern %q value %q (expansion %q)", c.text, s, c.expansion)
		checked++

		old, err := glob.Compile(c.text)
		require.NoError(t, err, "gobwas refused generated pattern %q", c.text)
		if got, _ := safeGlobMatch(old, s); got != want {
			if got {
				gobwasAccepts++
			} else {
				gobwasRejects++
			}
		}
	}
	require.Greater(t, checked, 20000)
	t.Logf("%d cases: gobwas disagreed with the oracle %d times (%d false accepts, %d false rejects); the translator 0",
		checked, gobwasAccepts+gobwasRejects, gobwasAccepts, gobwasRejects)
}

// RE2 does not backtrack: patterns that are exponential for a backtracking
// glob stay well inside the constraint engine's own match deadline.
func TestCertGlob_PathologicalPatternsStayFast(t *testing.T) {
	long := strings.Repeat("a", 10000)
	for _, p := range []string{
		"*a*a*a*a*b",
		strings.Repeat("*a", 20) + "*b",
		strings.Repeat("?", 50) + "*b",
		"{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}*a*a*a*a*a*a*a*a*a*a*b",
	} {
		g, err := compileCertGlob(p)
		require.NoError(t, err)
		start := time.Now()
		require.False(t, g.Match(long))
		require.Less(t, time.Since(start), globMatchTimeout, "pattern %q", p)
	}
}
