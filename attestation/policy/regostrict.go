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
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// A deny body that reads a field the attestor did not emit is undefined, so
// the deny never fires and the step passes (#9820 E1). The engine is
// deny-only, so that silence reads exactly like a clean pass. When the engine
// admits, refuseUndefinedDenyReads asks Rego itself whether any read the
// admit depended on was undefined, for the bindings the body actually had:
//
//   - every input read a deny body makes in a comparison, call or
//     assignment, outside comprehensions and `every` (whose bodies are
//     empty, not undefined, on a missing field), including reads through a
//     variable bound to input (`c := input.jwt.claims; c.ref`, `some it in
//     input.items; it.status`); and
//   - every read inside a negation the fail-open lint (regolint.go) reports,
//     including one in a helper rule that deny reaches.
//
// For each such read R of expression j, a probe rule is added to the
// module: the body's expressions before j, then "R is undefined". Variables
// in R that nothing before j binds (the `_` in input.items[_].status) are
// iterated over the collection that exists, so one element missing the
// field is caught even when another has it, and a dynamic key
// (input.values[input.required], or a key bound earlier) is judged for the
// key the body actually used. A probe that fires turns the admit into an
// error that names the read.
//
// A bare reference is a condition, not a read: `input.x` alone denies only
// when the field is present, and it guards later reads of the same path
// because a probe's body copies it. `not input.x` tests absence and is not
// probed. Helper rules may read optional fields positively; that is how the
// shipped policies tell input shapes apart. An optional field read in a deny
// body belongs in object.get with a default.
//
// There is no warn mode: a policy that trips this has to be fixed.

const (
	strictProbeRule = "__cilock_strict_probe"
	strictGuardVar  = "__cilock_strict_guard"
	strictValueVar  = "__cilock_strict_value"
	strictMsgVar    = "__cilock_strict_msg"
)

// strictProbes is the augmented module set for one policy set: the parsed
// modules with probe rules added, and the query that collects every probe.
type strictProbes struct {
	modules []*ast.Module
	query   string
	static  []staticRead
	err     error
}

var (
	strictProbesMu    sync.Mutex
	strictProbesCache = map[[32]byte]*strictProbes{}
)

// refuseUndefinedDenyReads is called only after the engine admitted input.
func refuseUndefinedDenyReads(ctx context.Context, policies []RegoPolicy, input interface{}) error {
	probes := strictProbesCached(policies)
	if probes.err != nil {
		return fmt.Errorf("rego: cannot build the missing-field check (%v); refusing (#9820)", probes.err)
	}
	missing, err := probes.eval(ctx, input)
	if err != nil {
		return err
	}
	for _, s := range probes.static {
		if !everyBindingResolves(input, s.ref[1:]) {
			missing = append(missing, s.msg)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("rego %s, which this attestation does not carry for the values the deny read, so the deny cannot fire and the policy admits by default; refusing (#9820). Read an optional field with object.get and a default, or test for its absence with `not`", missing[0])
}

// eval runs every probe against input and returns what they report.
func (p *strictProbes) eval(ctx context.Context, input interface{}) ([]string, error) {
	if p.query == "" {
		return nil, nil
	}
	opts := []func(*rego.Rego){
		rego.Input(input),
		rego.Capabilities(restrictedCapabilities()),
		rego.StrictBuiltinErrors(true),
		rego.Query(p.query),
	}
	for _, m := range p.modules {
		opts = append(opts, rego.ParsedModule(m.Copy()))
	}
	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrRegoEvaluationRefused{Code: "timeout", cause: err}
		}
		return nil, fmt.Errorf("rego: missing-field check failed to evaluate (%v); refusing (#9820)", err)
	}
	var missing []string
	for _, r := range rs {
		for _, e := range r.Expressions {
			if set, ok := e.Value.([]interface{}); ok {
				for _, m := range set {
					missing = append(missing, fmt.Sprint(m))
				}
			}
		}
	}
	return missing, nil
}

// staticRead is a lint finding no probe could reproduce: its negation sits in
// a function body (whose parameters a probe cannot bind), a comprehension or
// an `every`. It is checked against input without bindings, fail closed:
// every element of a collection it iterates must carry the path.
type staticRead struct {
	ref ast.Ref
	msg string
}

// everyBindingResolves reports whether rest resolves in cur for every
// binding of its variable terms. An empty array is nothing to iterate, so it
// resolves; an empty object has no key a computed lookup could find, so it
// does not.
func everyBindingResolves(cur interface{}, rest ast.Ref) bool {
	if len(rest) == 0 {
		return true
	}
	switch key := rest[0].Value.(type) {
	case ast.String:
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return false
		}
		next, ok := obj[string(key)]
		return ok && everyBindingResolves(next, rest[1:])
	case ast.Number:
		arr, ok := cur.([]interface{})
		idx, isInt := key.Int()
		if !ok || !isInt || idx < 0 || idx >= len(arr) {
			return false
		}
		return everyBindingResolves(arr[idx], rest[1:])
	default:
		return everyChild(cur, rest[1:])
	}
}

func everyChild(cur interface{}, rest ast.Ref) bool {
	var children []interface{}
	switch c := cur.(type) {
	case map[string]interface{}:
		if len(c) == 0 {
			return false
		}
		for _, child := range c {
			children = append(children, child)
		}
	case []interface{}:
		children = c
	default:
		return false
	}
	for _, child := range children {
		if !everyBindingResolves(child, rest) {
			return false
		}
	}
	return true
}

func strictProbesCached(policies []RegoPolicy) *strictProbes {
	key := lintSetKey(policies)
	strictProbesMu.Lock()
	cached, ok := strictProbesCache[key]
	strictProbesMu.Unlock()
	if ok {
		return cached
	}
	built := buildStrictProbes(policies)
	strictProbesMu.Lock()
	defer strictProbesMu.Unlock()
	if len(strictProbesCache) < failOpenLintCacheMax {
		strictProbesCache[key] = built
	}
	return built
}

// buildStrictProbes parses each module the way the evaluator does and adds
// the probe rules. A module that does not parse gets none: the evaluator has
// already refused it. Lint findings no probe covers become static reads.
func buildStrictProbes(policies []RegoPolicy) *strictProbes {
	findings, _ := lintCached(policies)
	lintRows := map[string]map[int]bool{}
	for _, f := range findings {
		if lintRows[f.Module] == nil {
			lintRows[f.Module] = map[int]bool{}
		}
		lintRows[f.Module][f.Row] = true
	}
	out := &strictProbes{}
	covered := map[string]map[int]bool{}
	var queries []string
	seenPkg := map[string]bool{}
	for _, p := range policies {
		mod, err := ast.ParseModule(p.Name, string(p.Module))
		if err != nil || mod == nil {
			continue
		}
		b := &probeBuilder{module: p.Name, mod: mod, lintRows: lintRows[p.Name], covered: map[int]bool{}}
		if err := b.build(); err != nil {
			out.err = fmt.Errorf("module %q: %w", p.Name, err)
			return out
		}
		covered[p.Name] = b.covered
		out.modules = append(out.modules, mod)
		pkg := mod.Package.Path.String()
		if b.probes > 0 && !seenPkg[pkg] {
			seenPkg[pkg] = true
			queries = append(queries, pkg+"."+strictProbeRule)
		}
	}
	out.query = strings.Join(queries, "\n")
	out.static, out.err = uncoveredFindings(findings, covered)
	return out
}

// uncoveredFindings turns each lint finding no probe reproduced into a
// static read.
func uncoveredFindings(findings []RegoFailOpenFinding, covered map[string]map[int]bool) ([]staticRead, error) {
	var out []staticRead
	for _, f := range findings {
		if covered[f.Module][f.Row] {
			continue
		}
		ref, err := ast.ParseRef(f.InputRef)
		if err != nil {
			return nil, fmt.Errorf("finding %s:%d reads %s, which cannot be checked: %w", f.Module, f.Row, f.InputRef, err)
		}
		out = append(out, staticRead{ref: ref, msg: fmt.Sprintf("%s:%d rule %s: `%s` reads %s", f.Module, f.Row, f.Rule, f.Expr, f.InputRef)})
	}
	return out, nil
}

// probeBuilder adds probe rules to one parsed module.
type probeBuilder struct {
	module   string
	mod      *ast.Module
	lintRows map[int]bool
	covered  map[int]bool
	probes   int
}

func (b *probeBuilder) build() error {
	rules := append([]*ast.Rule(nil), b.mod.Rules...)
	for _, rule := range rules {
		// A function body's parameters are not in scope in a probe, so its
		// findings are left to the static check.
		if rule.Default || len(rule.Head.Args) > 0 {
			continue
		}
		deny := isDenyRule(rule)
		if !deny && len(b.lintRows) == 0 {
			continue
		}
		if err := b.body(rule.Body, deny); err != nil {
			return err
		}
	}
	return nil
}

// bodyState tracks, while walking a body in order, the variables bound to
// input and the variables any earlier expression binds.
type bodyState struct {
	aliases map[ast.Var]bool
	bound   ast.VarSet
}

func (b *probeBuilder) body(body ast.Body, deny bool) error {
	st := &bodyState{aliases: map[ast.Var]bool{}, bound: ast.NewVarSet()}
	for j, expr := range body {
		if b.probeable(expr, deny) {
			refs := st.inputRefs(expr)
			for _, ref := range refs {
				if err := b.addProbes(body[:j], ref, st.bound, exprRow(expr)); err != nil {
					return err
				}
			}
			if expr.Negated && len(refs) > 0 {
				b.covered[exprRow(expr)] = true
			}
		}
		st.record(expr)
	}
	return nil
}

// probeable reports whether expr's reads are checked: a positive, non-bare
// expression in a deny body, or a negation the fail-open lint reported.
func (b *probeBuilder) probeable(expr *ast.Expr, deny bool) bool {
	if expr.Negated {
		return b.lintRows[exprRow(expr)]
	}
	if _, isSome := expr.Terms.(*ast.SomeDecl); isSome {
		return deny
	}
	return deny && !isRefTerm(expr)
}

// inputRefs returns the refs in expr, outside closures, rooted at input or at
// a variable bound to input.
func (st *bodyState) inputRefs(expr *ast.Expr) []ast.Ref {
	var out []ast.Ref
	walkRefs(expr, true, func(ref ast.Ref) {
		if len(ref) < 2 {
			return
		}
		if ref[0].Equal(ast.InputRootDocument) {
			out = append(out, ref)
			return
		}
		if v, ok := ref[0].Value.(ast.Var); ok && st.aliases[v] {
			out = append(out, ref)
		}
	})
	return out
}

// record updates the aliases and bound variables after expr.
func (st *bodyState) record(expr *ast.Expr) {
	if some, ok := expr.Terms.(*ast.SomeDecl); ok {
		for _, sym := range some.Symbols {
			st.recordSomeIn(sym)
		}
		return
	}
	if expr.Negated {
		return
	}
	st.recordAlias(expr)
	vis := ast.NewVarVisitor().WithParams(ast.VarVisitorParams{SkipClosures: true, SkipRefHead: true})
	vis.Walk(expr)
	for v := range vis.Vars() {
		st.bound.Add(v)
	}
}

// recordSomeIn binds the variables of `some k, v in coll`; v aliases input
// when coll does. A bare `some x` declares and binds nothing.
func (st *bodyState) recordSomeIn(sym *ast.Term) {
	call, ok := sym.Value.(ast.Call)
	if !ok || len(call) < 3 {
		return
	}
	input := st.rootedAtInput(call[len(call)-1])
	elem := call[len(call)-2]
	for _, arg := range call[1 : len(call)-1] {
		v, ok := arg.Value.(ast.Var)
		if !ok {
			continue
		}
		st.bound.Add(v)
		if input && arg == elem {
			st.aliases[v] = true
		}
	}
}

// recordAlias remembers `x := input.a` (or `=`), so later reads of x.b are
// reads of input.
func (st *bodyState) recordAlias(expr *ast.Expr) {
	if !(expr.IsAssignment() || expr.IsEquality()) || len(expr.Operands()) != 2 {
		return
	}
	ops := expr.Operands()
	for i, side := range ops {
		if v, ok := side.Value.(ast.Var); ok && st.rootedAtInput(ops[1-i]) {
			st.aliases[v] = true
		}
	}
}

func (st *bodyState) rootedAtInput(t *ast.Term) bool {
	ref, ok := t.Value.(ast.Ref)
	if !ok || len(ref) == 0 {
		return false
	}
	if ref[0].Equal(ast.InputRootDocument) {
		return true
	}
	v, ok := ref[0].Value.(ast.Var)
	return ok && st.aliases[v]
}

// addProbes adds one probe per unbound-variable boundary of ref. For
// input.items[_].status (with _ unbound) that is "input.items is undefined"
// and "for some existing input.items[i], input.items[i].status is
// undefined".
func (b *probeBuilder) addProbes(prefix ast.Body, ref ast.Ref, bound ast.VarSet, row int) error {
	var cuts []int
	for k := 1; k < len(ref); k++ {
		if v, ok := ref[k].Value.(ast.Var); ok && !bound.Contains(v) {
			cuts = append(cuts, k)
		}
	}
	var guard ast.Ref
	for s := 0; s <= len(cuts); s++ {
		target := ref
		if s < len(cuts) {
			target = ref[:cuts[s]]
		}
		if len(target) >= 2 {
			if err := b.addProbe(prefix, guard, target, row); err != nil {
				return err
			}
		}
		if s < len(cuts) {
			guard = ref[:cuts[s]+1]
		}
	}
	return nil
}

func (b *probeBuilder) addProbe(prefix ast.Body, guard, target ast.Ref, row int) error {
	rule, err := parseTemplateRule(strictProbeRule + "[" + strictMsgVar + "] { true }")
	if err != nil {
		return err
	}
	body := make(ast.Body, 0, len(prefix)+3)
	for _, e := range prefix {
		body = append(body, e.Copy())
	}
	if guard != nil {
		// Unifying with a fresh variable binds the guard's own variables,
		// iterating the part of the collection that exists.
		body = append(body, ast.Equality.Expr(ast.VarTerm(strictGuardVar), ast.RefTerm(guard.Copy()...)))
	}
	// count([1 | v = target]) == 0 holds exactly when target is undefined for
	// the current bindings. A negated call would not work: the compiler reads
	// target outside the `not`, so an undefined target fails the whole body.
	defined := ast.ArrayComprehensionTerm(ast.IntNumberTerm(1),
		ast.NewBody(ast.Equality.Expr(ast.VarTerm(strictValueVar), ast.RefTerm(target.Copy()...))))
	body = append(body, ast.Equal.Expr(ast.CallTerm(ast.RefTerm(ast.VarTerm("count")), defined), ast.IntNumberTerm(0)))
	msg := fmt.Sprintf("%s:%d: deny reads %s", b.module, row, renderRef(target))
	body = append(body, ast.Equality.Expr(ast.VarTerm(strictMsgVar), ast.StringTerm(msg)))
	for i, e := range body {
		e.Index = i
	}
	rule.Body = body
	rule.Module = b.mod
	b.mod.Rules = append(b.mod.Rules, rule)
	b.probes++
	return nil
}

// parseTemplateRule parses one v0 rule in a scratch package.
func parseTemplateRule(src string) (*ast.Rule, error) {
	m, err := ast.ParseModule("cilock-strict-template", "package cilock_strict_template\n"+src+"\n")
	if err != nil {
		return nil, err
	}
	if len(m.Rules) != 1 {
		return nil, fmt.Errorf("template %q parsed to %d rules", src, len(m.Rules))
	}
	return m.Rules[0], nil
}

// isRefTerm reports whether expr is a bare reference used as a condition.
func isRefTerm(expr *ast.Expr) bool {
	term, ok := expr.Terms.(*ast.Term)
	if !ok {
		return false
	}
	_, isRef := term.Value.(ast.Ref)
	return isRef
}

func isDenyRule(rule *ast.Rule) bool {
	ref := rule.Head.Ref()
	return len(ref) > 0 && ref[0].Value.Compare(ast.Var("deny")) == 0
}
