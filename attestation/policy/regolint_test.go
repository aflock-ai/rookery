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
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// lintRow is one deny body. firesOnMissing is what the real evaluator does on
// an empty predicate; the table asserts it, so a row whose engine behaviour
// changes (an OPA upgrade) fails here instead of silently desynchronising the
// lint from the engine.
type lintRow struct {
	name           string
	module         string
	wantRefs       []string
	firesOnMissing bool
	// exempt names why the row is excused from "the lint flags exactly the
	// rows the engine does not fire on": a field read positively before the
	// negation (the author chose "deny only when present"), or a finding that
	// is real on a different predicate than {}.
	exempt string
	// wantUndecided are findings the lint reports as undecided: a use it does
	// not model sits between deny and the negation, so its warning says it
	// cannot tell. A row with one is excused from the engine agreement.
	wantUndecided []string
	// guarded marks a row whose finding sits behind a bare reference to a
	// prefix of its path (`input.a` before `not f(input.a.b)`): on {} the
	// guard is what fails, which is the author's explicit "only when
	// present", so the admit stands.
	guarded bool
}

func v0Deny(body string, extra ...string) string {
	return "package lintrow\n\ndeny[msg] {\n" + body + "\n\tmsg := \"denied\"\n}\n" + strings.Join(extra, "\n")
}

var lintRows = []lintRow{
	{name: "builtin over a field", module: v0Deny(`	not startswith(input.reftype, "tag")`), wantRefs: []string{"input.reftype"}},
	{name: "type check over a field", module: v0Deny(`	not is_string(input.x)`), wantRefs: []string{"input.x"}},
	{name: "hoisted through an intermediate call", module: v0Deny(`	not count(input.a.b) > 0`), wantRefs: []string{"input.a.b"}},
	{name: "nested path", module: v0Deny(`	not startswith(input.jwt.claims.ref_type, "tag")`), wantRefs: []string{"input.jwt.claims.ref_type"}},
	{name: "user function over a field", module: v0Deny(`	not tagged(input.ref)`, `tagged(r) { startswith(r, "refs/tags/") }`), wantRefs: []string{"input.ref"}},
	{name: "prefix read does not cover a longer path", module: v0Deny("\tinput.a\n\tnot startswith(input.a.b, \"x\")"), wantRefs: []string{"input.a.b"}, guarded: true},
	{name: "rego v1 syntax", module: "package lintrow\n\nimport rego.v1\n\ndeny contains msg if {\n\tnot startswith(input.x, \"a\")\n\tmsg := \"denied\"\n}\n", wantRefs: []string{"input.x"}},
	{name: "negated equality is not hoisted", module: v0Deny(`	not input.x == "a"`), firesOnMissing: true},
	{name: "negated bare ref", module: v0Deny(`	not input.x`), firesOnMissing: true},
	{name: "helper rule (the safe pattern)", module: v0Deny(`	not ok`, `ok { startswith(input.x, "a") }`), firesOnMissing: true},
	{name: "object.get default", module: v0Deny(`	not startswith(object.get(input, "x", ""), "a")`), firesOnMissing: true},
	{name: "explicit positive read first", module: v0Deny("\tinput.x\n\tnot startswith(input.x, \"a\")"), exempt: "positive read first"},
	{name: "user-bound variable", module: v0Deny("\tx := input.x\n\tnot startswith(x, \"a\")"), exempt: "positive read first"},
	// The shape Pushgate's generated drafts use: a type check first, with a
	// separate readable_* rule denying absence.
	{name: "type-checked before the negation", module: v0Deny("\tis_string(input.commithash)\n\tnot regex.match(\"^[0-9a-f]{40}$\", input.commithash)"), exempt: "positive read first"},

	// Polarity. A helper that deny consumes as `not ok` fails CLOSED when its
	// hoisted read is undefined: ok is undefined, so `not ok` is true.
	{name: "negation inside a helper deny negates", module: v0Deny(`	not ok`, `ok { not startswith(input.ref, "refs/heads/evil") }`), firesOnMissing: true},
	{name: "negation inside a function deny negates", module: v0Deny(`	not f(1)`, `f(n) { not startswith(input.ref, "refs/heads/evil") }`), firesOnMissing: true},
	{name: "helper reached through two negations is positive", module: v0Deny(`	not a`, `a { not b }`, `b { not startswith(input.x, "a") }`), wantRefs: []string{"input.x"}},
	{name: "helper consumed positively", module: v0Deny("\tbad\n", `bad { not startswith(input.x, "a") }`), wantRefs: []string{"input.x"}},
	{name: "helper consumed both ways", module: v0Deny(`	not ok`, `ok { not startswith(input.x, "a") }`, `deny[msg] { ok; input.q == 1; msg := "q" }`), wantRefs: []string{"input.x"}, firesOnMissing: true,
		exempt: "the positive path admits {x: missing, q: 1}; {} is caught by the negative path"},
	// Inside a closure an undefined helper empties the collection instead of
	// failing the body, so the `not` around it does not make it fail closed.
	// (count([1 | bad]) would be hoisted out of the `not`; a bare comparison
	// keeps the comprehension inside the negated expression.)
	{name: "helper inside a comprehension under not", module: v0Deny("\tnot [1 | bad] == []", `bad { not startswith(input.x, "a") }`), wantRefs: []string{"input.x"}},
	{name: "rule deny never reaches", module: "package lintrow\n\ndeny[msg] {\n\tinput.z == 1\n\tmsg := \"z\"\n}\n\nunused { not startswith(input.x, \"a\") }\n",
		exempt: "the != style miss on input.z is the probe's to report, not the lint's"},

	// A bound parent covers the parent, not a sub-field read later.
	{name: "bound parent then hoisted sub-field", module: v0Deny("\tc := input.jwt.claims\n\tnot startswith(c.ref, \"refs/tags/\")"), wantRefs: []string{"input.jwt.claims.ref"}},
	// A read inside a comprehension is not a precondition: the comprehension
	// is empty, not undefined, when the field is missing.
	{name: "read inside a comprehension does not cover", module: v0Deny("\tcount([1 | input.reftype]) >= 0\n\tnot startswith(input.reftype, \"tag\")"), wantRefs: []string{"input.reftype"}},

	// Boolean comparisons. A hoisted read that is undefined leaves the rule
	// at its default (or its next else, or undefined), so a consumer that
	// compares by value can hold on the fallback: `ok == false` with
	// `default ok = false` fires when the field is missing. Each form below
	// has a fail-closed arrangement (no finding) and a fail-open one.
	{name: "review: ok == false over a false default", module: reviewBooleanComparison, firesOnMissing: true},
	{name: "ok == false over a true default", module: v0Deny("\tok == false", openDefaultTrue...), wantRefs: []string{"input.x"}},
	{name: "false == ok over a false default", module: v0Deny("\tfalse == ok", closedDefaultFalse...), firesOnMissing: true},
	{name: "false == ok over a true default", module: v0Deny("\tfalse == ok", openDefaultTrue...), wantRefs: []string{"input.x"}},
	{name: "ok != true over a false default", module: v0Deny("\tok != true", closedDefaultFalse...), firesOnMissing: true},
	{name: "ok != true over a true default", module: v0Deny("\tok != true", openDefaultTrue...), wantRefs: []string{"input.x"}},
	{name: "not ok over a true default", module: v0Deny("\tnot ok", openDefaultTrue...), wantRefs: []string{"input.x"}},
	{name: "ok == true with no default", module: v0Deny("\tok == true", `ok { not startswith(input.x, "a") }`), wantRefs: []string{"input.x"}},
	{name: "ok == true over a false default", module: v0Deny("\tok == true", closedDefaultFalse...), wantRefs: []string{"input.x"}},
	{name: "ok == true over a true default", module: v0Deny("\tok == true", openDefaultTrue...), firesOnMissing: true},
	{name: "ok != false over a false default", module: v0Deny("\tok != false", closedDefaultFalse...), wantRefs: []string{"input.x"}},
	{name: "ok != false over a true default", module: v0Deny("\tok != false", openDefaultTrue...), firesOnMissing: true},
	{name: "bare ok over a true default", module: v0Deny("\tok", openDefaultTrue...), firesOnMissing: true},
	{name: "equality through a local variable, false default", module: v0Deny("\tv := ok\n\tv == false", closedDefaultFalse...), firesOnMissing: true},
	{name: "equality through a local variable, true default", module: v0Deny("\tv := ok\n\tv == false", openDefaultTrue...), wantRefs: []string{"input.x"}},
	{name: "inequality through a local variable, false default", module: v0Deny("\tv := ok\n\tv != true", closedDefaultFalse...), firesOnMissing: true},
	{name: "inequality through a local variable, true default", module: v0Deny("\tv := ok\n\tv != true", openDefaultTrue...), wantRefs: []string{"input.x"}},
	{name: "function output compared, else false", module: v0Deny("\tf(1) == false", `f(n) { not startswith(input.x, "a") } else = false { true }`), firesOnMissing: true},
	{name: "function output compared, else true", module: v0Deny("\tf(1) == false", `f(n) = false { not startswith(input.x, "a") } else = true { true }`), wantRefs: []string{"input.x"}},
	{name: "negation in a rule whose else is false", module: v0Deny("\tok == false", `ok { not startswith(input.x, "a") } else = false { true }`), firesOnMissing: true},
	{name: "negation in a rule whose else is true", module: v0Deny("\tok == false", `ok = false { not startswith(input.x, "a") } else = true { true }`), wantRefs: []string{"input.x"}},
	{name: "negated comparison over an else branch", module: v0Deny("\tnot ok == false", `ok { not startswith(input.x, "a") } else = false { true }`), wantRefs: []string{"input.x"}},
	{name: "negated comparison with no else", module: v0Deny("\tnot ok == false", `ok { not startswith(input.x, "a") }`), firesOnMissing: true},
	{name: "comparison inside an else branch, false default", module: v0Deny("\tbad", append([]string{elseConsumer}, closedDefaultFalse...)...), firesOnMissing: true},
	{name: "comparison inside an else branch, true default", module: v0Deny("\tbad", append([]string{elseConsumer}, openDefaultTrue...)...), wantRefs: []string{"input.x"}},

	// A comparison with an input value can go either way, like a helper
	// consumed both ways: {want: true} admits a missing x that x = "b" denies.
	{name: "compared with an input value", module: v0Deny("\tok == input.want", closedDefaultFalse...), wantRefs: []string{"input.x"}},
	{name: "ordered comparison that the default fails", module: v0Deny("\tn > 0", `default n = 0`, `n = 1 { not startswith(input.x, "a") }`), wantRefs: []string{"input.x"}},
	{name: "ordered comparison with the constant on the left", module: v0Deny("\t0 < n", `default n = 0`, `n = 1 { not startswith(input.x, "a") }`), wantRefs: []string{"input.x"}},
	{name: "ordered comparison that the default meets", module: v0Deny("\tn < 1", `default n = 0`, `n = 1 { not startswith(input.x, "a") }`), firesOnMissing: true},

	// Another definition of the rule is a fallback too: with y = 1 and x
	// missing, ok is "b" rather than "a", and deny does not fire.
	{name: "another definition is a fallback", module: v0Deny("\tok != \"b\"", `default ok = "none"`, `ok = "a" { not startswith(input.x, "a") }`, `ok = "b" { input.y == 1 }`), wantRefs: []string{"input.x"}, firesOnMissing: true,
		exempt: "real on {y: 1}, not on {}"},

	// Forms the lint cannot decide: its warning says so. The first is
	// fail-closed (want is false), so a decided finding would be wrong.
	{name: "compared with another rule", module: v0Deny("\tok == want", append([]string{`want = false { true }`}, closedDefaultFalse...)...), wantUndecided: []string{"input.x"}, firesOnMissing: true},
	{name: "non-constant rule value", module: v0Deny("\tok == \"yes\"", `ok = v { v := lower("YES"); not startswith(input.x, "a") }`), wantUndecided: []string{"input.x"}},
	// An undecided path does not hide a decided positive one.
	{name: "undecided and positive paths", module: v0Deny("\tok == want", append([]string{`want = false { true }`, `deny[msg] { ok; msg := "ok" }`}, closedDefaultFalse...)...), wantRefs: []string{"input.x"}, firesOnMissing: true,
		exempt: "{} is caught by the undecided path; the positive one admits {want: true} with x missing"},

	// Function calls. Each distinct call is its own value: f("a") and f("b")
	// read different fields, so one can fall back while the other fires.
	// Calls with the same argument are one value, so their tests combine.
	{name: "review: distinct calls to one function", module: reviewDistinctCalls, wantRefs: []string{"input[_]"}},
	{name: "an input argument and a constant argument", module: v0Deny("\tf(input.name)\n\tnot f(\"b\")", elseFalseFunc), wantRefs: []string{"input[_]"}},
	{name: "a constant argument and an input argument", module: v0Deny("\tf(\"a\")\n\tnot f(input.name)", elseFalseFunc), wantRefs: []string{"input[_]", "input.name"}},
	{name: "two different bound arguments", module: v0Deny("\ta := input.a\n\tb := input.b\n\tf(a)\n\tnot f(b)", elseFalseFunc), wantRefs: []string{"input[_]"}},
	{name: "nested calls with different arguments", module: v0Deny("\tf(g(\"a\"))\n\tnot f(g(\"b\"))", elseFalseFunc, identityFunc), wantRefs: []string{"input[_]"}},
	{name: "else-chained function compared twice by value", module: v0Deny("\tf(\"a\") == true\n\tf(\"b\") == false", elseFalseFunc), wantRefs: []string{"input[_]"}},
	{name: "function output bound, another call negated", module: v0Deny("\tv := f(\"a\")\n\tv == true\n\tnot f(\"b\")", elseFalseFunc), wantRefs: []string{"input[_]"}},
	{name: "else-chained function compared twice, both fail closed", module: v0Deny("\tf(\"a\") == false\n\tf(\"b\") == false", elseFalseFunc), firesOnMissing: true},
	{name: "the same constant argument both ways", module: v0Deny("\tf(\"a\")\n\tnot f(\"a\")", elseFalseFunc), exempt: contradictoryBody},
	{name: "the same input argument both ways", module: v0Deny("\tf(input.a)\n\tnot f(input.a)", elseFalseFunc), exempt: contradictoryBody},
	{name: "the same input through two names", module: v0Deny("\ta := input.a\n\tb := input.a\n\tf(a)\n\tnot f(b)", elseFalseFunc), exempt: contradictoryBody},
	{name: "the same variable argument both ways", module: v0Deny("\tsome k\n\tinput.keys[k]\n\tf(k)\n\tnot f(k)", elseFalseFunc), exempt: contradictoryBody},
	{name: "nested calls with the same argument", module: v0Deny("\tf(g(\"a\"))\n\tnot f(g(\"a\"))", elseFalseFunc, identityFunc), exempt: contradictoryBody},

	// Comprehensions. A helper that stops firing empties a comprehension
	// rather than failing the body, so the direction depends on what the body
	// tests about the collection: count(...) == 0 holds on the empty one
	// (fail-closed), count(...) > 0 fails on it (fail-open).
	{name: "review: a helper counted as empty", module: reviewCountedHelper, firesOnMissing: true},
	{name: "helper counted as non-empty", module: v0Deny("\tcount([1 | ok]) > 0", okHelper), wantRefs: []string{"input.x"}},
	{name: "helper counted at least once", module: v0Deny("\tcount([1 | ok]) >= 1", okHelper), wantRefs: []string{"input.x"}},
	{name: "helper counted below one", module: v0Deny("\tcount([1 | ok]) < 1", okHelper), firesOnMissing: true},
	{name: "set comprehension counted as empty", module: v0Deny("\tcount({1 | ok}) == 0", okHelper), firesOnMissing: true},
	{name: "set comprehension counted as non-empty", module: v0Deny("\tcount({1 | ok}) > 0", okHelper), wantRefs: []string{"input.x"}},
	{name: "object comprehension counted as empty", module: v0Deny("\tcount({\"k\": 1 | ok}) == 0", okHelper), firesOnMissing: true},
	{name: "object comprehension counted as non-empty", module: v0Deny("\tcount({\"k\": 1 | ok}) != 0", okHelper), wantRefs: []string{"input.x"}},
	{name: "comprehension compared with empty", module: v0Deny("\t[1 | ok] == []", okHelper), firesOnMissing: true},
	{name: "comprehension body negates, counted as empty", module: v0Deny("\tcount([1 | not ok]) == 0", okHelper), wantRefs: []string{"input.x"}},
	{name: "comprehension body negates, counted as non-empty", module: v0Deny("\tcount([1 | not ok]) > 0", okHelper), firesOnMissing: true},
	{name: "comprehension bound, counted, formatted into the message", module: "package lintrow\n\ndeny[msg] {\n\tc := [1 | ok]\n\tcount(c) == 0\n\tmsg := sprintf(\"%v\", [c])\n}\n" + okHelper, firesOnMissing: true},
	{name: "comprehension bound, counted as non-empty, formatted", module: "package lintrow\n\ndeny[msg] {\n\tc := [1 | ok]\n\tcount(c) > 0\n\tmsg := sprintf(\"%v\", [c])\n}\n" + okHelper, wantRefs: []string{"input.x"}},
	{name: "rule bound outside, read inside a comprehension", module: v0Deny("\tv := ok\n\tcount([1 | v]) == 0", closedDefaultFalse...), firesOnMissing: true},
	{name: "element-dependent negated helper, counted as non-empty", module: v0Deny("\tcount([s | s := [\"a\", \"b\"][_]; not g(s)]) > 0", elementHelper), firesOnMissing: true},
	{name: "element-dependent helper, counted as non-empty", module: v0Deny("\tcount([s | s := [\"a\", \"b\"][_]; g(s)]) > 0", elementHelper), wantRefs: []string{"input.x"}},
	// count(...) != 1 is not monotone: dropping one of two elements fails it,
	// dropping both holds it. g's negation reads input.x, not its argument,
	// so every element stops together (fail-closed); a callee reading
	// input[v] would stop per element (fail-open on {a: "x"}). The call site
	// cannot tell which, so it is undecided.
	{name: "element-dependent helper, a test that is not monotone", module: v0Deny("\tcount([s | s := [\"a\", \"b\"][_]; g(s)]) != 1", elementHelper), wantUndecided: []string{"input.x"}, firesOnMissing: true},
	{name: "nested comprehensions", module: v0Deny("\tcount([1 | count([2 | ok]) == 0]) > 0", okHelper), firesOnMissing: true},
	{name: "some over a comprehension", module: v0DenyKeywords("\tsome y in [1 | ok]\n\ty > 0", okHelper), wantRefs: []string{"input.x"}},
	{name: "membership in a comprehension", module: v0DenyKeywords("\t1 in [1 | ok]", okHelper), wantRefs: []string{"input.x"}},
	{name: "negated membership in a comprehension", module: v0DenyKeywords("\tnot 1 in [1 | ok]", okHelper), firesOnMissing: true},
	{name: "every over a comprehension", module: v0DenyKeywords("\tevery y in [1 | ok] { y > 1 }", okHelper), firesOnMissing: true},
	{name: "helper inside an every body", module: v0DenyKeywords("\tevery y in [1, 2] { y > 0; ok }", okHelper), wantRefs: []string{"input.x"}},
	{name: "negated helper inside an every body", module: v0DenyKeywords("\tevery y in [1, 2] { y > 0; not ok }", okHelper), firesOnMissing: true},
	// A comparison with an empty literal of another kind never holds, so
	// `!=` always does, whatever ok is.
	{name: "comprehension compared with an empty literal of another kind", module: v0Deny("\t[1 | ok] != set()", okHelper), firesOnMissing: true},
	// A use of the collection the lint does not model is undecided. This
	// one is fail-closed (sum([]) is 0).
	{name: "a comprehension consumed in a way the lint does not model", module: v0Deny("\tsum([1 | ok]) == 0", okHelper), wantUndecided: []string{"input.x"}, firesOnMissing: true},

	// The same closures with the negation written inline. The hoisted read
	// stays inside the comprehension, so a missing field empties it.
	{name: "inline negation in a comprehension counted as empty", module: v0Deny("\tcount([1 | not startswith(input.x, \"a\")]) == 0"), firesOnMissing: true},
	{name: "inline negation in a comprehension counted as non-empty", module: v0Deny("\tcount([1 | not startswith(input.x, \"a\")]) > 0"), wantRefs: []string{"input.x"}},
	{name: "element-dependent inline negation counted as empty", module: v0DenyKeywords("\tcount([k | some k in [\"a\", \"b\"]; not startswith(input[k], \"a\")]) == 0"), firesOnMissing: true},
	{name: "element-dependent inline negation counted as non-empty", module: v0DenyKeywords("\tcount([k | some k in [\"a\", \"b\"]; not startswith(input[k], \"a\")]) > 0"), wantRefs: []string{"input[_]"}},
	// Written inline, the negation reads input[k] itself, so each element
	// stops on its own: {a: "x"} leaves one element, and != 1 fails.
	{name: "element-dependent inline negation, a test that is not monotone", module: v0DenyKeywords("\tcount([k | some k in [\"a\", \"b\"]; not startswith(input[k], \"a\")]) != 1"), wantRefs: []string{"input[_]"}, firesOnMissing: true,
		exempt: "real on {a: \"x\"}, not on {}"},
	{name: "inline negation inside an every body", module: v0DenyKeywords("\tevery k in [\"a\"] { not startswith(input.z, k) }"), wantRefs: []string{"input.z"}},
	{name: "inline negation in a comprehension the lint does not model", module: v0Deny("\tsum([1 | not startswith(input.x, \"a\")]) == 0"), wantUndecided: []string{"input.x"}, firesOnMissing: true},

	// Review round 5. A partial rule read whole is a collection its bodies
	// fill: when they stop firing it is empty, not undefined. The lint does
	// not model that collection, so it cannot decide.
	{name: "review: a partial set counted as empty", module: reviewCountedPartialSet, wantUndecided: []string{"input.ref"}, firesOnMissing: true},
	{name: "partial set counted as non-empty", module: v0Deny("\tcount(allowed) > 0", `allowed[true] { not startswith(input.x, "a") }`), wantUndecided: []string{"input.x"}},
	{name: "partial set indexed", module: v0Deny("\tallowed[true]", `allowed[true] { not startswith(input.x, "a") }`), wantRefs: []string{"input.x"}},
	{name: "partial object counted as empty", module: v0Deny("\tcount(allowed) == 0", `allowed[k] = 1 { k := "k"; not startswith(input.x, "a") }`), wantUndecided: []string{"input.x"}, firesOnMissing: true},
	{name: "rule read through its parent path", module: v0Deny("\tcount(allowed) == 0", `allowed["k"] = 1 { not startswith(input.x, "a") }`), wantUndecided: []string{"input.x"}, firesOnMissing: true},
	// A negation that stops firing moves the body that holds it one way and
	// every rule that negates that body the other way: here it empties the
	// comprehension, which makes ok hold, which makes `not ok` fail.
	{name: "review: a comprehension counted as empty under not", module: reviewNegatedCountedComprehension, wantRefs: []string{"input.ref"}},
	{name: "a comprehension counted as non-empty under not", module: v0Deny("\tnot ok", `ok { count([1 | not startswith(input.x, "a")]) > 0 }`), firesOnMissing: true},
	{name: "an unmodelled comprehension under not", module: v0Deny("\tnot ok", `ok { sum([1 | not startswith(input.x, "a")]) == 0 }`), wantUndecided: []string{"input.x"}},
}

// Review round 5, finding 1, verbatim: fail-closed. A missing ref leaves the
// partial set allowed empty, so count(allowed) == 0 holds and deny fires.
const reviewCountedPartialSet = `package p
allowed[true] { not startswith(input.ref, "evil") }
deny["bad ref"] { count(allowed) == 0 }
`

// Review round 5, finding 2, verbatim: fail-open. A missing ref empties the
// comprehension, so ok holds, `not ok` fails, and deny never fires.
const reviewNegatedCountedComprehension = `package p
ok { count([1 | not startswith(input.ref, "trusted")]) == 0 }
deny["bad ref"] { not ok }
`

// Review round 4, finding 1, verbatim: f("a") and not f("b") test two values.
// {"a": "good", "b": "bad"} denies; omitting a leaves f("a") false, and admits.
const reviewDistinctCalls = `package p
f(k) { not startswith(input[k], "bad") } else = false { true }
deny["bad"] { f("a"); not f("b") }
`

// Review round 4, finding 2, verbatim: fail-closed. A missing ref leaves ok
// undefined, the comprehension empty, and count(...) == 0 true.
const reviewCountedHelper = `package p
ok { not startswith(input.ref, "evil") }
deny["bad ref"] { count([1 | ok]) == 0 }
`

const (
	elseFalseFunc     = `f(k) { not startswith(input[k], "bad") } else = false { true }`
	identityFunc      = `g(x) = x { true }`
	okHelper          = `ok { not startswith(input.x, "a") }`
	elementHelper     = `g(v) { not startswith(input.x, v) }`
	contradictoryBody = "deny's body tests one value both ways, so it never fires on any input"
)

func v0DenyKeywords(body string, extra ...string) string {
	return strings.Replace(v0Deny(body, extra...), "package lintrow\n", "package lintrow\n\nimport future.keywords.every\nimport future.keywords.in\n", 1)
}

// The review's reproduction, verbatim: fail-closed, because a missing ref
// leaves ok at its default and ok == false holds.
const reviewBooleanComparison = `package p
default ok = false
ok { not startswith(input.ref, "refs/heads/evil") }
deny["bad ref"] { ok == false }
`

var (
	closedDefaultFalse = []string{`default ok = false`, `ok { not startswith(input.x, "a") }`}
	openDefaultTrue    = []string{`default ok = true`, `ok = false { not startswith(input.x, "a") }`}
)

// bad's first body never holds on {}, so bad rests on its else branch.
const elseConsumer = `bad { input.nope == 1 } else = true { ok == false }`

func TestLintRegoFailOpenAgreesWithEngine(t *testing.T) {
	for _, row := range lintRows {
		t.Run(row.name, func(t *testing.T) {
			findings, err := LintRegoFailOpen(row.name, row.module)
			require.NoError(t, err)
			var got, undecided []string
			for _, f := range findings {
				require.NotEmpty(t, f.Rule)
				require.Positive(t, f.Row)
				if f.Undecided {
					undecided = append(undecided, f.InputRef)
					require.Contains(t, f.String(), "cannot decide")
					continue
				}
				got = append(got, f.InputRef)
			}
			require.ElementsMatch(t, row.wantRefs, got, "lint findings")
			require.ElementsMatch(t, row.wantUndecided, undecided, "undecided findings")

			admits, err := ProbeRegoEmptyPredicate([]RegoPolicy{{Name: row.name, Module: []byte(row.module)}})
			require.NoError(t, err)
			require.Equal(t, row.firesOnMissing, !admits, "engine behaviour on an empty predicate")

			if row.exempt == "" && len(row.wantUndecided) == 0 {
				require.Equal(t, len(row.wantRefs) > 0, !row.firesOnMissing,
					"the lint must flag exactly the negations the engine skips on a missing field")
			}

			// With every hardening option on, the verifier logs each finding.
			// A deny on {} is the engine's own verdict. An admit on {} that
			// rests on a finding's missing field is refused; an
			// admit with no finding is the engine's, unless a deny body read
			// a missing field, which regostrict_test.go covers.
			withHardening(t, everyHardening())
			warnings := installWarnCapture(t)
			forgetFailOpenLint(t)
			err = EvaluateRegoPolicy(&lintAttestor{}, []RegoPolicy{{Name: row.name, Module: []byte(row.module)}})
			var denied ErrPolicyDenied
			switch {
			case row.firesOnMissing:
				require.True(t, errors.As(err, &denied), "the verdict must be the engine's (deny), got %v", err)
			case len(findings) > 0 && row.guarded:
				require.NoError(t, err, "a guarded finding: the author's presence guard is what failed")
			case len(findings) > 0:
				require.ErrorContains(t, err, "#9820", "an admit on {} that rests on a finding must be refused")
				require.False(t, errors.As(err, &denied), "a refusal, not the policy's deny")
			case err != nil:
				require.ErrorContains(t, err, "#9820", "the only error an admit can become is the refusal")
			}
			for _, f := range findings {
				require.True(t, warnings.sawContaining(f.String()), "evaluation must log the finding as a warning: %s", f)
			}
		})
	}
}

// everyHardening turns on every verify-time hardening option, as the cilock
// CLI does by default, so an option that made a lint finding refuse would
// change a verdict in the table above.
func everyHardening() HardeningOptions {
	var h HardeningOptions
	v := reflect.ValueOf(&h).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Bool {
			v.Field(i).SetBool(true)
		}
	}
	return h
}

// forgetFailOpenLint empties the lint cache, so the next evaluation lints and
// logs again even under -count=N.
func forgetFailOpenLint(t *testing.T) {
	t.Helper()
	forget := func() {
		failOpenLintMu.Lock()
		clear(failOpenLintCache)
		failOpenLintMu.Unlock()
	}
	forget()
	t.Cleanup(forget)
}

// The evaluator loads every module of one attestation together, so a module
// that calls a function defined in a sibling module compiles only as a set.
// Linting each module alone turned that into a compile error, and the verifier
// then skipped the lint.
func siblingModules() []RegoPolicy {
	return []RegoPolicy{
		{Name: "caller", Module: []byte("package caller\n\ndeny[msg] {\n\tnot data.helpers.tagged(input.ref)\n\tmsg := \"untagged\"\n}\n")},
		{Name: "helpers", Module: []byte("package helpers\n\ntagged(r) { startswith(r, \"refs/tags/\") }\n\ndeny[msg] {\n\tinput.never == true\n\tmsg := \"never\"\n}\n")},
	}
}

func TestLintRegoFailOpenSetSeesSiblingModules(t *testing.T) {
	findings, err := LintRegoFailOpenSet(siblingModules())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "caller", findings[0].Module)
	require.Equal(t, "input.ref", findings[0].InputRef)
}

func TestEvaluateRegoPolicyLintsTheModuleSet(t *testing.T) {
	withHardening(t, everyHardening())
	warnings := installWarnCapture(t)
	forgetFailOpenLint(t)
	// The caller negates input.ref, which lintAttestor does not carry, so the
	// admit is refused; the finding is still logged.
	require.ErrorContains(t, EvaluateRegoPolicy(&lintAttestor{Reftype: "tag"}, siblingModules()), "#9820")
	require.True(t, warnings.sawContaining("caller:"), "want the caller's finding logged, got %v", warnings.lines)
	require.True(t, warnings.sawContaining("input.ref"), "want the caller's finding logged, got %v", warnings.lines)
	require.False(t, warnings.sawContaining("does not compile"), "the set compiles together: %v", warnings.lines)
}

// A finding is user-facing: compiler temporaries render as `_`.
func TestLintRegoFailOpenRendersGeneratedVars(t *testing.T) {
	findings, err := LintRegoFailOpen("dyn", v0Deny("\tsome k\n\tinput.keys[k]\n\tnot startswith(input[k], \"tag\")"))
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "input[_]", findings[0].InputRef)
	require.NotContains(t, findings[0].String(), "__local")
}

func TestLintRegoFailOpenReportsCompileErrors(t *testing.T) {
	_, err := LintRegoFailOpen("unsafe", v0Deny(`	not startswith(input.steps[s].x, "tag")`))
	require.Error(t, err)
	_, err = LintRegoFailOpen("syntax", "package x\ndeny[msg] {")
	require.Error(t, err)
}

func TestProbeEmptyPredicate(t *testing.T) {
	vacuous := "package p\n\ndeny[msg] {\n\tinput.repository != \"aflock-ai/rookery\"\n\tmsg := \"foreign\"\n}\n"
	admits, err := ProbeRegoEmptyPredicate([]RegoPolicy{{Name: "vacuous", Module: []byte(vacuous)}})
	require.NoError(t, err)
	require.True(t, admits, "a != over a missing field denies nothing on {}")

	safe := v0Deny(`	not input.repository == "aflock-ai/rookery"`)
	admits, err = ProbeRegoEmptyPredicate([]RegoPolicy{{Name: "safe", Module: []byte(safe)}})
	require.NoError(t, err)
	require.False(t, admits)

	// One module that denies is enough: the set is not vacuous.
	admits, err = ProbeRegoEmptyPredicate([]RegoPolicy{{Name: "vacuous", Module: []byte(vacuous)}, {Name: "safe2", Module: []byte(strings.Replace(safe, "lintrow", "other", 1))}})
	require.NoError(t, err)
	require.False(t, admits)

	admits, err = ProbeRegoEmptyPredicate(nil)
	require.NoError(t, err)
	require.False(t, admits, "no modules means nothing to probe")
}

func TestProbeEmptyPredicateReportsTimeout(t *testing.T) {
	prev := regoProbeTimeout
	regoProbeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { regoProbeTimeout = prev })
	// ~4e8 iterations with no allocation: far past the budget, so the probe
	// is cancelled rather than finishing. A module that never denies would
	// otherwise read as "admits".
	slow := v0Deny("	slow", "slow { numbers.range(1, 20000)[i]; numbers.range(1, 20000)[j]; i + j < 0 }")
	start := time.Now()
	admits, err := ProbeRegoEmptyPredicate([]RegoPolicy{{Name: "slow", Module: []byte(slow)}})
	require.Less(t, time.Since(start), 10*time.Second, "the budget must bound the probe")
	require.Error(t, err, "a probe that runs out of budget must say so, never report admits")
	require.False(t, admits)
}

type lintAttestor struct {
	Reftype string `json:"reftype,omitempty"`
}

func (a *lintAttestor) Name() string                                   { return "lint" }
func (a *lintAttestor) Type() string                                   { return "https://example.com/lint/v1" }
func (a *lintAttestor) RunType() attestation.RunType                   { return "test" }
func (a *lintAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *lintAttestor) Schema() *jsonschema.Schema                     { return nil }

// A fail-open negation is logged at evaluation and never refused: with every
// hardening option on, the verifier returns the engine's verdict. The table
// above checks the same for each row, the review modules of rounds 2 to 5
// included.
func TestEvaluateRegoPolicyWarnsOnFailOpenUnderEveryHardening(t *testing.T) {
	withHardening(t, everyHardening())
	warnings := installWarnCapture(t)
	forgetFailOpenLint(t)
	mod := []RegoPolicy{{Name: "tagged", Module: []byte(v0Deny(`	not startswith(input.reftype, "tag")`))}}

	// The attestor carries the field and satisfies the rule: the finding is
	// logged and the verdict is the engine's.
	require.NoError(t, EvaluateRegoPolicy(&lintAttestor{Reftype: "tag"}, mod), "a finding over a present field is a warning")
	require.True(t, warnings.sawContaining("never fires when input.reftype is missing"), "want the finding logged, got %v", warnings.lines)

	// On a predicate without reftype the engine admits; that admit rests on
	// the missing field, so evaluation refuses it.
	require.ErrorContains(t, EvaluateRegoPolicy(&lintAttestor{}, mod), "#9820")
}
