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
	"fmt"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
)

// certGlob is the matcher every cert-constraint glob goes through (#9826).
//
// gobwas/glob v0.2.3 is kept only to decide which patterns are valid. Its
// matcher is not used, because on this constraint language it:
//
//   - matched the EMPTY string for patterns that reduce to one-rune matchers
//     ("?", "[!a]", "{a,?}"), so a constraint meant as "exactly one
//     character" accepted a certificate whose field was absent;
//   - let a literal prefix and suffix overlap ("a*a", "{a}*a" and "[a]*a"
//     all matched "a", and "{?,aa}..*" matched "..a..");
//   - counted '?' in bytes in some positions ("?b" refused "ßb", and
//     "ßς?😀" refused itself);
//   - panicked on some brace patterns.
//
// Instead the pattern is translated into an anchored RE2 regular expression,
// which matches runes, never backtracks, and runs in time linear in the value
// for a fixed pattern. On literals, '*' and '?' it is the cilock-policy Lean
// model's globMatch (formal/cilock-policy Trust.lean); see the differential
// tests in certglob_test.go.
//
// Separately, a pattern other than the explicit AllowAllConstraint ("*")
// never matches an empty value, even one that could match it in glob terms
// ("{,a}"): an absent certificate field must not satisfy a constraint that
// names something. That is the fail-open shape
// RejectEmptyConstraintEmptyField exists to prevent.
type certGlob struct {
	re         *regexp.Regexp
	allowEmpty bool
}

func (g certGlob) Match(s string) bool {
	if s == "" {
		return g.allowEmpty
	}
	return g.re.MatchString(s)
}

// compileCertGlob compiles a cert-constraint glob pattern. Callers pass the
// pattern already normalized (case-folded) where their path requires it. A
// pattern gobwas refuses is refused here too, so the set of accepted
// constraints is unchanged.
func compileCertGlob(pattern string) (glob.Glob, error) {
	if _, err := glob.Compile(pattern); err != nil {
		return nil, err
	}
	expr, err := globToRegexp(pattern)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("glob %q: %w", pattern, err)
	}
	return certGlob{re: re, allowEmpty: pattern == AllowAllConstraint}, nil
}

// globToRegexp translates the gobwas glob grammar, compiled without
// separators, into RE2 syntax:
//
//   - and **      any run of runes, including none
//     ?              exactly one rune
//     \c             the rune c, literally
//     [abc] [!abc]   one rune in / not in the listed runes (escapes allowed)
//     [a-z] [!a-z]   one rune in / not in the range (one range per class)
//     {x,y,...}      any one alternative; alternatives nest
//
// Outside an alternation ',' and '}' are literal, and ']' is always literal
// outside a class, as in gobwas's lexer. The translator refuses anything it
// does not recognise; compileCertGlob only calls it on patterns gobwas
// accepted.
func globToRegexp(pattern string) (string, error) {
	t := globTranslator{p: []rune(pattern)}
	t.b.WriteString(`\A(?s:`)
	for t.i = 0; t.i < len(t.p); t.i++ {
		if err := t.step(); err != nil {
			return "", fmt.Errorf("glob %q: %w", pattern, err)
		}
	}
	if t.depth != 0 {
		return "", fmt.Errorf("glob %q: unclosed alternation", pattern)
	}
	t.b.WriteString(`)\z`)
	return t.b.String(), nil
}

// globTranslator holds globToRegexp's position, output and alternation depth.
type globTranslator struct {
	p     []rune
	i     int
	depth int
	b     strings.Builder
}

// step translates the element that starts at p[i], leaving i on its last rune.
func (t *globTranslator) step() error {
	switch r := t.p[t.i]; r {
	case '*':
		t.b.WriteString(`.*`)
		for t.i+1 < len(t.p) && t.p[t.i+1] == '*' {
			t.i++
		}
	case '?':
		t.b.WriteString(`.`)
	case '\\':
		if t.i+1 < len(t.p) {
			t.i++
			writeLiteral(&t.b, t.p[t.i])
		}
	case '[':
		end, class, err := globClass(t.p, t.i)
		if err != nil {
			return err
		}
		t.b.WriteString(class)
		t.i = end
	default:
		t.alternation(r)
	}
	return nil
}

// alternation handles '{', ',' and '}' (literal outside braces) and literals.
func (t *globTranslator) alternation(r rune) {
	switch {
	case r == '{':
		t.depth++
		t.b.WriteString(`(?:`)
	case r == ',' && t.depth > 0:
		t.b.WriteString(`|`)
	case r == '}' && t.depth > 0:
		t.depth--
		t.b.WriteString(`)`)
	default:
		writeLiteral(&t.b, r)
	}
}

// globClass translates the class that opens at p[open] and returns the index
// of its closing ']'.
func globClass(p []rune, open int) (int, string, error) {
	i := open + 1
	negate := false
	if i < len(p) && p[i] == '!' {
		negate = true
		i++
	}
	var items strings.Builder
	switch {
	case i+2 < len(p) && p[i+1] == '-':
		// A range is exactly lo-hi, read raw (no escapes), then ']'. An
		// inverted range fails regexp.Compile, so it is refused.
		fmt.Fprintf(&items, `\x{%x}-\x{%x}`, p[i], p[i+2])
		i += 3
	default:
		for i < len(p) && p[i] != ']' {
			if p[i] == '\\' {
				i++
				if i >= len(p) {
					break
				}
			}
			fmt.Fprintf(&items, `\x{%x}`, p[i])
			i++
		}
	}
	if i >= len(p) || p[i] != ']' {
		return 0, "", fmt.Errorf("unclosed character class")
	}
	switch {
	case items.Len() == 0 && negate:
		return i, `.`, nil // "[!]" excludes nothing: any one rune
	case items.Len() == 0:
		return i, `[^\x00-\x{10FFFF}]`, nil // "[]" admits no rune
	case negate:
		return i, `[^` + items.String() + `]`, nil
	default:
		return i, `[` + items.String() + `]`, nil
	}
}

func writeLiteral(b *strings.Builder, r rune) {
	b.WriteString(regexp.QuoteMeta(string(r)))
}
