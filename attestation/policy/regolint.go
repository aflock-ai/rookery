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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/open-policy-agent/opa/ast"
)

// A negated rego expression that reads an input field inside a call looks
// like it fires when the field is missing, and does not. The OPA compiler
// hoists the read out of the negation:
//
//	not startswith(input.reftype, "tag")
//
// compiles to
//
//	__local1__ = input.reftype; not startswith(__local1__, "tag")
//
// so on a predicate without reftype the first expression is undefined, the
// body fails, and the deny never fires. The policy reads as "deny unless
// tagged" and behaves as "deny only when present and untagged". The lint below
// works on the compiled module, so it follows the engine's own rewrite
// instead of guessing at it from the source text.
//
// The lint is an authoring aid: every finding is logged at evaluation and
// reported by `cilock policy validate`. Evaluation refuses an admit when a
// finding's field is missing from that input (regostrict.go, #9820), and
// object.get with a default is how an author declares a missing field fine.

// RegoFailOpenFinding is one negated expression whose input read the compiler
// hoisted out of the negation.
type RegoFailOpenFinding struct {
	Module   string `json:"module"`
	Rule     string `json:"rule"`
	Row      int    `json:"row"`
	InputRef string `json:"input_ref"`
	Expr     string `json:"expr"`
	// Undecided marks a finding in a rule deny reaches only through a use
	// the lint does not model, so it cannot tell whether a missing field
	// admits or denies.
	Undecided bool `json:"undecided,omitempty"`
}

func (f RegoFailOpenFinding) String() string {
	if f.Undecided {
		return fmt.Sprintf("%s:%d rule %s: `%s` never fires when %s is missing, and the lint cannot decide whether that admits or denies: between deny and this negation sits a use it does not model (a comparison against another rule or a computed value, a rule whose value is not a constant, a partial rule read whole, or a comprehension used other than by its size); check by hand that a missing %s denies",
			f.Module, f.Row, f.Rule, f.Expr, f.InputRef, f.InputRef)
	}
	return fmt.Sprintf("%s:%d rule %s: `%s` never fires when %s is missing, because the compiler reads %s outside the `not`; read %s positively first, use object.get with a default, or move the negation into a helper rule that deny consumes as `not helper`",
		f.Module, f.Row, f.Rule, f.Expr, f.InputRef, f.InputRef, f.InputRef)
}

// LintRegoFailOpen lints one module on its own. See LintRegoFailOpenSet.
func LintRegoFailOpen(name, module string) ([]RegoFailOpenFinding, error) {
	return LintRegoFailOpenSet([]RegoPolicy{{Name: name, Module: []byte(module)}})
}

// LintRegoFailOpenSet compiles a module set together, as the evaluator loads
// it, and reports every negated expression that reads an input path only
// through a compiler-generated temporary, with no earlier positive read of
// that path (or a longer one) in the same body.
//
// A negation is reported when its failing makes deny fire less. A hoisted
// read that is undefined makes its body undefined, so the rule falls back to
// its next else, its default, or undefined. That admits when deny consumes
// the rule positively, and denies when deny consumes it as `not rule` or
// compares it to the value it falls back to (`ok == false` over
// `default ok = false`). Inside a comprehension the failing body drops an
// element instead, which can make the enclosing body fire more, and then a
// rule deny negates fires less. regopolarity.go follows the direction through
// every rule reference and every distinct function call, and regoclosure.go
// through comprehensions and `every`. A rule the deny query never reaches
// cannot change the verdict. A negation reached through a use the lint does
// not model is reported with Undecided set.
//
// A set that does not parse or compile returns the compiler's error.
func LintRegoFailOpenSet(policies []RegoPolicy) ([]RegoFailOpenFinding, error) {
	compiled, names, err := compileRegoSet(policies)
	if err != nil {
		return nil, err
	}
	idx := newRuleIndex(compiled)
	reached := idx.polarities(compiled)
	var findings []RegoFailOpenFinding
	for i, m := range compiled {
		for _, top := range m.Rules {
			for _, rule := range withElse(top) {
				if len(reached[rule]) == 0 {
					continue
				}
				findings = append(findings, idx.lintRule(names[i], rule, reached[rule])...)
			}
		}
	}
	return findings, nil
}

// compileRegoSet compiles the modules together and returns them in input
// order with their names.
func compileRegoSet(policies []RegoPolicy) ([]*ast.Module, []string, error) {
	modules := make(map[string]*ast.Module, len(policies))
	keys := make([]string, 0, len(policies))
	names := make([]string, 0, len(policies))
	for i, p := range policies {
		key := p.Name
		if _, dup := modules[key]; dup || key == "" {
			key = fmt.Sprintf("%s#%d", p.Name, i)
		}
		parsed, err := ast.ParseModule(key, string(p.Module))
		if err != nil {
			return nil, nil, err
		}
		if parsed == nil {
			return nil, nil, fmt.Errorf("rego module %q is empty", p.Name)
		}
		modules[key] = parsed
		keys = append(keys, key)
		names = append(names, p.Name)
	}
	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, nil, compiler.Errors
	}
	compiled := make([]*ast.Module, 0, len(keys))
	for _, k := range keys {
		compiled = append(compiled, compiler.Modules[k])
	}
	return compiled, names, nil
}

func dataRefs(x interface{}, skipClosures bool) []ast.Ref {
	var refs []ast.Ref
	walkRefs(x, skipClosures, func(ref ast.Ref) {
		if ref.HasPrefix(ast.DefaultRootRef) {
			refs = append(refs, ref)
		}
	})
	return refs
}

// walkRefs visits every Ref under x, optionally without descending into
// comprehensions and `every`, whose bodies do not make the outer expression
// undefined.
func walkRefs(x interface{}, skipClosures bool, f func(ast.Ref)) {
	ast.NewGenericVisitor(func(v interface{}) bool {
		switch v := v.(type) {
		case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension, *ast.Every:
			return skipClosures
		case ast.Ref:
			f(v)
		}
		return false
	}).Walk(x)
}

// bodyLint walks one compiled body in order. hoisted maps each variable a
// compiler-generated expression bound to the input paths it carries; alias
// maps each variable a user expression bound to an input path; positive
// holds the input paths user-written, non-negated expressions have read.
type bodyLint struct {
	module, rule string
	hoisted      map[ast.Var][]ast.Ref
	alias        map[ast.Var][]ast.Ref
	positive     []ast.Ref
	seen         map[string]bool
	findings     []bodyFinding
}

// bodyFinding is a finding with the input path it reads, unrendered, so a
// closure can tell whether the path depends on its element.
type bodyFinding struct {
	RegoFailOpenFinding
	ref ast.Ref
}

func lintBody(module, rule string, body ast.Body) []bodyFinding {
	l := &bodyLint{module: module, rule: rule, hoisted: map[ast.Var][]ast.Ref{}, alias: map[ast.Var][]ast.Ref{}, seen: map[string]bool{}}
	for _, expr := range body {
		vars := exprVars(expr)
		switch {
		case expr.Generated:
			l.recordHoist(expr, vars)
		case expr.Negated:
			l.checkNegation(expr, vars)
		default:
			l.positive = append(l.positive, l.inputRefs(expr)...)
			l.positive = append(l.positive, l.refsOf(vars)...)
			l.recordAlias(expr)
		}
	}
	return l.findings
}

func (l *bodyLint) refsOf(vars []ast.Var) []ast.Ref {
	var refs []ast.Ref
	for _, v := range vars {
		refs = append(refs, l.hoisted[v]...)
	}
	return refs
}

// recordHoist propagates input paths through a generated expression, so a
// chain like `__2 = input.a.b; count(__2, __1); not gt(__1, 0)` still traces
// the negation back to input.a.b. A user-bound variable read here is a
// source, not a target: `c := input.jwt.claims; not startswith(c.ref, "x")`
// hoists c.ref, and c itself stays bound to the parent the author read.
func (l *bodyLint) recordHoist(expr *ast.Expr, vars []ast.Var) {
	refs := append(l.inputRefs(expr), l.refsOf(vars)...)
	if len(refs) == 0 {
		return
	}
	for _, v := range vars {
		if _, ok := l.hoisted[v]; ok {
			continue
		}
		if _, ok := l.alias[v]; ok {
			continue
		}
		l.hoisted[v] = refs
	}
}

// recordAlias remembers `x := input.a` (compiled to an equality with a
// variable on one side), so a later read of x.b resolves to input.a.b.
func (l *bodyLint) recordAlias(expr *ast.Expr) {
	if !expr.IsEquality() && !expr.IsAssignment() {
		return
	}
	ops := expr.Operands()
	if len(ops) != 2 {
		return
	}
	for i, side := range ops {
		v, ok := side.Value.(ast.Var)
		if !ok {
			continue
		}
		other := ops[1-i]
		if _, isRef := other.Value.(ast.Ref); !isRef {
			continue
		}
		if refs := l.inputRefs(other); len(refs) > 0 {
			l.alias[v] = refs
		}
	}
}

func (l *bodyLint) checkNegation(expr *ast.Expr, vars []ast.Var) {
	for _, ref := range l.refsOf(vars) {
		key := fmt.Sprintf("%d|%s", exprRow(expr), ref)
		if l.seen[key] || coveredByPositiveRead(l.positive, ref) {
			continue
		}
		l.seen[key] = true
		l.findings = append(l.findings, bodyFinding{RegoFailOpenFinding{
			Module: l.module, Rule: l.rule, Row: exprRow(expr),
			InputRef: renderRef(ref), Expr: exprText(expr),
		}, ref})
	}
}

// inputRefs returns the input paths x reads outside any comprehension or
// `every`, resolving a path rooted at a user-bound alias to the input path
// under it. Bare `input` is always defined when the verifier supplies input,
// so it is not a finding. A read inside a comprehension is not a precondition:
// the comprehension is empty, not undefined, when the field is missing.
func (l *bodyLint) inputRefs(x interface{}) []ast.Ref {
	var refs []ast.Ref
	walkRefs(x, true, func(ref ast.Ref) {
		if len(ref) >= 2 && ref[0].Equal(ast.InputRootDocument) {
			refs = append(refs, ref)
			return
		}
		v, ok := ref[0].Value.(ast.Var)
		if !ok || len(ref) < 2 {
			return
		}
		for _, base := range l.alias[v] {
			refs = append(refs, base.Concat(ref[1:]))
		}
	})
	return refs
}

// renderRef prints a path for a user: compiler temporaries become `_`.
func renderRef(ref ast.Ref) string {
	out := ref.Copy()
	for i, t := range out {
		if v, ok := t.Value.(ast.Var); ok && i > 0 && v.IsGenerated() {
			out[i] = ast.VarTerm("_")
		}
	}
	return out.String()
}

func exprVars(expr *ast.Expr) []ast.Var {
	vis := ast.NewVarVisitor().WithParams(ast.VarVisitorParams{SkipClosures: true})
	vis.Walk(expr)
	out := make([]ast.Var, 0, len(vis.Vars()))
	for v := range vis.Vars() {
		if v.Equal(ast.InputRootDocument.Value) || v.Equal(ast.DefaultRootDocument.Value) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// coveredByPositiveRead reports whether an earlier positive expression read
// ref or a path under it, which makes the field's presence an explicit
// precondition the author wrote.
func coveredByPositiveRead(positive []ast.Ref, ref ast.Ref) bool {
	for _, p := range positive {
		if p.HasPrefix(ref) {
			return true
		}
	}
	return false
}

func exprRow(expr *ast.Expr) int {
	if expr.Location == nil {
		return 0
	}
	return expr.Location.Row
}

func exprText(expr *ast.Expr) string {
	if expr.Location != nil && len(expr.Location.Text) > 0 {
		return string(expr.Location.Text)
	}
	return expr.String()
}

// regoProbeTimeout bounds ProbeRegoEmptyPredicate. A var so a test can force
// the timeout path.
var regoProbeTimeout = 2 * time.Second

// ProbeRegoEmptyPredicate evaluates a module set against an empty predicate
// ({}) with the verifier's own evaluator. admits is true when no module
// denies: every rule then depends on a field being present to fire, so a
// predicate that omits the fields passes. Any error other than a policy
// denial (including running out of the budget) is returned, and admits is
// false: a probe that did not finish proves nothing either way.
func ProbeRegoEmptyPredicate(policies []RegoPolicy) (admits bool, err error) {
	if len(policies) == 0 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), regoProbeTimeout)
	defer cancel()
	err = evaluateRegoInput(ctx, map[string]interface{}{}, policies, "empty-predicate probe", "")
	if err == nil {
		return true, nil
	}
	var denied ErrPolicyDenied
	if errors.As(err, &denied) {
		return false, nil
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("empty-predicate probe did not finish within %s: %w", regoProbeTimeout, err)
	}
	return false, err
}

// failOpenLintCache memoises lint results by the digest of the module set.
// EvaluateRegoPolicy runs once per candidate collection, so compiling every
// set on every call would repeat the same work many times per verify.
// Bounded: past the cap the lint still runs, it just is not stored.
var (
	failOpenLintMu    sync.Mutex
	failOpenLintCache = map[[sha256.Size]byte][]RegoFailOpenFinding{}
)

const failOpenLintCacheMax = 1024

// warnRegoFailOpen lints the module set before evaluation, compiled together
// the way the evaluator loads it, and logs each finding once per distinct
// set. Logging never changes the verdict; regostrict.go uses the same
// findings to refuse an admit on a missing field. A set that does not compile is logged once and left to the evaluator, which fails on
// the same error.
func warnRegoFailOpen(policies []RegoPolicy) {
	findings, first := lintCached(policies)
	if !first {
		return
	}
	for _, f := range findings {
		log.Warnf("%s", f)
	}
}

func lintSetKey(policies []RegoPolicy) [sha256.Size]byte {
	h := sha256.New()
	for _, p := range policies {
		// Length-prefixed, so no name/module split can collide with another.
		_, _ = fmt.Fprintf(h, "%d:%s%d:", len(p.Name), p.Name, len(p.Module))
		h.Write(p.Module)
	}
	var key [sha256.Size]byte
	copy(key[:], h.Sum(nil))
	return key
}

func lintCached(policies []RegoPolicy) (findings []RegoFailOpenFinding, first bool) {
	key := lintSetKey(policies)
	failOpenLintMu.Lock()
	cached, ok := failOpenLintCache[key]
	failOpenLintMu.Unlock()
	if ok {
		return cached, false
	}
	findings, err := LintRegoFailOpenSet(policies)
	failOpenLintMu.Lock()
	defer failOpenLintMu.Unlock()
	if _, raced := failOpenLintCache[key]; raced {
		return findings, false
	}
	// Past the cap nothing is stored and nothing is logged again, so a
	// long-lived verifier cannot turn the warning into a per-call flood.
	if len(failOpenLintCache) >= failOpenLintCacheMax {
		return findings, false
	}
	if err != nil {
		log.Warnf("rego fail-open negation lint did not run, the module set does not compile: %v", err)
		findings = nil
	}
	failOpenLintCache[key] = findings
	return findings, true
}
