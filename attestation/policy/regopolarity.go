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
	"github.com/open-policy-agent/opa/ast"
)

// Polarity answers one question for each rule body the deny query can reach:
// when this body stops firing, does deny fire less (positive), more
// (negative), or can the lint not tell (undecided)?
//
// A body that stops firing does not make its rule undefined. The rule falls
// back to the next branch of its else chain, then to its default, and only
// then to undefined. So the direction depends on how the consumer reads the
// rule. `ok` and `ok == true` fail on the fallback; `not ok` holds on it;
// `ok == false` holds on it when the fallback is `default ok = false`, and
// fails when there is no default. The lint evaluates the consumer's own
// expressions on the value the body produces and on each fallback value, and
// the direction is whichever way the consumer changes.
//
// Each call to a function is its own value: f("a") and f("b") can fall back
// independently, so `f("a"); not f("b")` reaches f positively through the
// first call. Calls whose arguments are the same term (after following the
// variables the body bound them through) are one value, and their tests
// combine. A reference inside a comprehension or an `every` body follows the
// closure model in regoclosure.go.

type polarity uint8

const (
	polPositive polarity = iota
	polNegative
	polUndecided
)

// then composes the polarity a rule is reached with and the polarity of one
// reference it makes.
func (p polarity) then(edge polarity) polarity {
	switch {
	case p == polUndecided || edge == polUndecided:
		return polUndecided
	case edge == polNegative && p == polPositive:
		return polNegative
	case edge == polNegative:
		return polPositive
	}
	return p
}

type polarityState struct {
	rule *ast.Rule
	pol  polarity
}

// polarities walks rule references from each package's deny rules, which
// are what the evaluator queries (rego.go evaluateRegoInput). Each branch of
// an else chain is its own node. It returns every polarity each reached
// branch is reached with.
func (idx *ruleIndex) polarities(modules []*ast.Module) map[*ast.Rule][]polarity {
	var queue []polarityState
	for _, m := range modules {
		for _, r := range idx.resolve(m.Package.Path.Append(ast.StringTerm("deny"))) {
			idx.queried[r] = true
			queue = append(queue, polarityState{r, polPositive})
		}
	}
	visited := map[polarityState]bool{}
	reached := map[*ast.Rule][]polarity{}
	for len(queue) > 0 {
		st := queue[0]
		queue = queue[1:]
		if visited[st] {
			continue
		}
		visited[st] = true
		reached[st.rule] = append(reached[st.rule], st.pol)
		queue = append(queue, idx.successors(st)...)
	}
	return reached
}

type ruleEntry struct {
	path  ast.Ref
	rules []*ast.Rule // a rule and its else chain share a path
}

type chainPos struct{ entry, pos int }

type ruleIndex struct {
	entries []ruleEntry
	at      map[*ast.Rule]chainPos
	scans   map[*ast.Rule]*ruleScan
	// queried holds the deny rules the evaluator queries.
	queried map[*ast.Rule]bool
}

func newRuleIndex(modules []*ast.Module) *ruleIndex {
	idx := &ruleIndex{at: map[*ast.Rule]chainPos{}, scans: map[*ast.Rule]*ruleScan{}, queried: map[*ast.Rule]bool{}}
	for _, m := range modules {
		for _, rule := range m.Rules {
			chain := withElse(rule)
			for i, r := range chain {
				idx.at[r] = chainPos{len(idx.entries), i}
			}
			idx.entries = append(idx.entries, ruleEntry{path: m.Package.Path.Extend(rule.Head.Ref().GroundPrefix()), rules: chain})
		}
	}
	return idx
}

// resolve returns the rules a data reference can read: those at or under it
// (`data.p` reads every rule in p) and the one it indexes into.
func (idx *ruleIndex) resolve(ref ast.Ref) []*ast.Rule {
	prefix := ref.GroundPrefix()
	var out []*ast.Rule
	for _, e := range idx.entries {
		if ref.HasPrefix(e.path) || e.path.HasPrefix(prefix) {
			out = append(out, e.rules...)
		}
	}
	return out
}

func (idx *ruleIndex) scan(rule *ast.Rule) *ruleScan {
	sc, ok := idx.scans[rule]
	if !ok {
		sc = scanRuleUses(idx, rule)
		idx.scans[rule] = sc
	}
	return sc
}

func (idx *ruleIndex) successors(st polarityState) []polarityState {
	var out []polarityState
	for _, u := range idx.scan(st.rule).uses {
		for _, target := range idx.resolve(u.ref) {
			for _, p := range idx.usePolarities(u, target) {
				out = append(out, polarityState{target, st.pol.then(p)})
			}
		}
	}
	return out
}

// fillsCollection reports whether a rule adds one element to a collection at
// its path: a partial set (`p[x] { ... }`) or a partial object
// (`p[k] = v { ... }`).
func fillsCollection(r *ast.Rule) bool {
	return r.Head.RuleKind() == ast.MultiValue || !r.Head.Ref().IsGround()
}

func withElse(rule *ast.Rule) []*ast.Rule {
	var out []*ast.Rule
	for r := rule; r != nil; r = r.Else {
		out = append(out, r)
	}
	return out
}

// regoValue is a rule's value as its consumer sees it: undefined, or a
// constant term.
type regoValue struct {
	undefined bool
	term      *ast.Term
}

// constValue returns the value a rule branch produces when its body fires,
// and false when it is not a constant (a partial set, a computed value).
func constValue(r *ast.Rule) (regoValue, bool) {
	h := r.Head
	if h.RuleKind() != ast.SingleValue || !h.Ref().IsGround() || h.Value == nil || !ast.IsConstant(h.Value.Value) {
		return regoValue{}, false
	}
	return regoValue{term: h.Value}, true
}

// fallbacks returns what a rule branch falls back to when its body does not
// fire: each later else branch up to the first that always fires, then the
// default (or undefined). Another definition of the same rule may fire
// instead, so its values are fallbacks too. ok is false when any of them is
// not a constant.
func (idx *ruleIndex) fallbacks(r *ast.Rule) (out []regoValue, ok bool) {
	at := idx.at[r]
	entry := idx.entries[at.entry]
	out, ok, final := elseFallbacks(entry.rules[at.pos+1:])
	if !ok {
		return nil, false
	}
	var fallback *regoValue
	if !final {
		fallback = &regoValue{undefined: true}
	}
	for i, e := range idx.entries {
		if i == at.entry || !e.path.Equal(entry.path) {
			continue
		}
		for _, sibling := range e.rules {
			v, isConst := constValue(sibling)
			if !isConst {
				return nil, false
			}
			if sibling.Default {
				if !final {
					fallback = &v
				}
				continue
			}
			out = append(out, v)
		}
	}
	if fallback != nil {
		out = append(out, *fallback)
	}
	return out, true
}

// elseFallbacks returns the values of the else branches after a failed one,
// up to the first that always fires (final).
func elseFallbacks(rest []*ast.Rule) (out []regoValue, ok, final bool) {
	for _, next := range rest {
		v, isConst := constValue(next)
		if !isConst {
			return nil, false, false
		}
		out = append(out, v)
		if alwaysFires(next.Body) {
			return out, true, true
		}
	}
	return out, true, false
}

func alwaysFires(body ast.Body) bool {
	if len(body) != 1 || body[0].Negated {
		return false
	}
	t, ok := body[0].Terms.(*ast.Term)
	return ok && t.Value.Compare(ast.Boolean(true)) == 0
}

// usePolarities is the direction of one reference to one target branch.
func (idx *ruleIndex) usePolarities(u refUse, target *ast.Rule) []polarity {
	switch {
	case u.through != nil:
		return idx.closurePolarities(u, target)
	case u.undecided:
		return []polarity{polUndecided}
	case u.either:
		return []polarity{polPositive, polNegative}
	case u.fixed != nil:
		return u.fixed
	}
	pos := idx.at[target]
	path := idx.entries[pos.entry].path
	if len(u.ref) < len(path) || len(u.ref) == len(path) && fillsCollection(target) {
		// Read whole, a partial rule (or any rule under the path read) is
		// part of a collection, which is empty, not undefined, when the
		// body stops firing: count(allowed) == 0 then holds. The lint does
		// not model that collection.
		return []polarity{polUndecided}
	}
	if !u.ref.Equal(path) || u.opaque {
		return u.fallback()
	}
	fire, fireConst := constValue(target)
	alts, altsConst := idx.fallbacks(target)
	if !fireConst || !altsConst {
		return u.fallback()
	}
	holds := u.holds(fire)
	for _, alt := range alts {
		if u.holds(alt) == holds {
			continue
		}
		if holds {
			return []polarity{polPositive}
		}
		return []polarity{polNegative}
	}
	return nil // the consumer reads the same on every fallback
}

type useKind uint8

// The comparison builtins the compiler emits for ==, !=, <, >, <= and >=.
const (
	opEq    = "eq"
	opEqual = "equal"
	opNeq   = "neq"
	opLt    = "lt"
	opGt    = "gt"
	opLte   = "lte"
	opGte   = "gte"
)

const (
	useTruthy  useKind = iota // `r`, `f(x)`: holds when defined and not false
	useDefined                // `v := r`, `f(x, v)`: holds when defined
	useCompare                // `r == c`, `r != c`, `r < c`: against a constant
)

// valueUse is one expression's test of a rule's value.
type valueUse struct {
	kind    useKind
	op      string // eq, neq, lt, gt, lte, gte, with the rule on the left
	c       *ast.Term
	negated bool
}

func (x valueUse) holds(v regoValue) bool {
	return x.test(v) != x.negated
}

func (x valueUse) test(v regoValue) bool {
	if v.undefined {
		return false
	}
	switch x.kind {
	case useTruthy:
		return v.term.Value.Compare(ast.Boolean(false)) != 0
	case useDefined:
		return true
	}
	c := v.term.Value.Compare(x.c.Value)
	switch x.op {
	case opNeq:
		return c != 0
	case opLt:
		return c < 0
	case opGt:
		return c > 0
	case opLte:
		return c <= 0
	case opGte:
		return c >= 0
	}
	return c == 0
}

// refUse is everything one rule body does with one data reference, or with
// one call to a function.
type refUse struct {
	ref ast.Ref
	// vars are the variables in the reference or in the call's arguments, so
	// a closure can tell whether the use depends on its element.
	vars []ast.Var
	// fixed is set for a head term, whose direction does not depend on the
	// target's value (positive).
	fixed []polarity
	uses  []valueUse
	// direct holds the negation of each expression naming ref directly,
	// the direction when the value model does not apply.
	direct []bool
	// opaque: some expression reads the rule in a way the value model does
	// not cover (an argument to a call, a path into it).
	opaque bool
	// either: compared with an input value, which can take any value, so a
	// fallback can move the comparison both ways.
	either bool
	// undecided: compared with something the lint cannot evaluate.
	undecided bool
	// inner and through: a use inside a closure body, and how the enclosing
	// body consumes that closure (regoclosure.go).
	inner   *refUse
	through *closureSite
}

func (u refUse) holds(v regoValue) bool {
	for _, x := range u.uses {
		if !x.holds(v) {
			return false
		}
	}
	return true
}

// fallback is the direction when the value model does not apply: the
// negation of each expression naming the rule, as for a bare reference. A
// comparison is not a bare reference, so it makes the reference undecided.
func (u refUse) fallback() []polarity {
	for _, x := range u.uses {
		if x.kind == useCompare {
			return []polarity{polUndecided}
		}
	}
	var pos, neg bool
	for _, negated := range u.direct {
		neg = neg || negated
		pos = pos || !negated
	}
	return polarities(pos, neg)
}

func polarities(pos, neg bool) []polarity {
	var out []polarity
	if pos {
		out = append(out, polPositive)
	}
	if neg {
		out = append(out, polNegative)
	}
	return out
}

// subject is what an expression reads: a rule (key: its path), or one call
// to a function (key: the call with its arguments in canonical form).
type subject struct {
	ref  ast.Ref
	key  string
	vars []ast.Var
}

func refSubject(ref ast.Ref) subject {
	return subject{ref: ref, key: ref.String(), vars: varsIn(ref)}
}

// ruleScan is what one rule body does with the rules it references, and how
// it consumes each closure in it.
type ruleScan struct {
	uses  []refUse
	sites map[interface{}]*closureSite
}

// useScan walks one body in order, tracking local variables bound to a
// rule's value (`v := ok`, and the compiler's own `__local0__ = data.p.ok`
// for `ok != true`) and the term each variable was bound to (canon), so two
// spellings of one call argument give one key.
type useScan struct {
	idx   *ruleIndex
	seen  map[ast.Var]bool
	bound map[ast.Var]subject
	canon map[ast.Var]*ast.Term
	fixed []refUse
	byKey map[string]*refUse
	order []string
	// The closure model (regoclosure.go): variables that hold a
	// comprehension or a value derived from one, the closures seen, and the
	// head variables the body has not bound yet.
	track    map[ast.Var]tracked
	sites    map[interface{}]*closureSite
	headOnly map[ast.Var]bool
	denyKey  map[ast.Var]bool
}

func newUseScan(idx *ruleIndex, sites map[interface{}]*closureSite) *useScan {
	return &useScan{
		idx: idx, seen: map[ast.Var]bool{}, bound: map[ast.Var]subject{}, canon: map[ast.Var]*ast.Term{},
		byKey: map[string]*refUse{}, track: map[ast.Var]tracked{}, sites: sites,
		headOnly: map[ast.Var]bool{}, denyKey: map[ast.Var]bool{},
	}
}

func scanRuleUses(idx *ruleIndex, rule *ast.Rule) *ruleScan {
	s := newUseScan(idx, map[interface{}]*closureSite{})
	for _, t := range append([]*ast.Term{rule.Head.Key, rule.Head.Value}, rule.Head.Args...) {
		if t == nil {
			continue
		}
		for _, ref := range dataRefs(t, false) {
			s.fixed = append(s.fixed, refUse{ref: ref, fixed: []polarity{polPositive}})
		}
		s.markSeen(t)
	}
	s.markHead(rule)
	for _, expr := range rule.Body {
		s.scanExpr(expr)
	}
	return &ruleScan{uses: s.uses(), sites: s.sites}
}

func (s *useScan) uses() []refUse {
	out := append([]refUse(nil), s.fixed...)
	for _, k := range s.order {
		out = append(out, *s.byKey[k])
	}
	return out
}

func (s *useScan) group(sub subject) *refUse {
	g, ok := s.byKey[sub.key]
	if !ok {
		g = &refUse{ref: sub.ref, vars: sub.vars}
		s.byKey[sub.key] = g
		s.order = append(s.order, sub.key)
	}
	return g
}

func (s *useScan) markSeen(x interface{}) {
	for _, v := range varsIn(x) {
		s.seen[v] = true
	}
}

func (s *useScan) scanExpr(expr *ast.Expr) {
	s.consumeTracked(expr)
	s.recordCanon(expr)
	s.scanClosures(expr)
	handled := map[string]bool{}
	call := s.classify(expr, handled)
	for _, ref := range dataRefs(expr, true) {
		sub := refSubject(ref)
		if call != nil && ref.Equal(call.ref) {
			sub = *call
		}
		g := s.group(sub)
		g.direct = append(g.direct, expr.Negated)
		g.opaque = g.opaque || !handled[sub.key]
	}
	for _, v := range exprVars(expr) {
		if sub, ok := s.bound[v]; ok && !handled[sub.key] {
			s.group(sub).opaque = true
		}
	}
	s.markSeen(expr)
	for _, v := range varsIn(expr) {
		delete(s.headOnly, v)
	}
}

// recordCanon remembers the term a fresh variable is bound to: `v = t`, or a
// call's output (`f(x, v)` binds v to the call f(x)).
func (s *useScan) recordCanon(expr *ast.Expr) {
	if !expr.IsCall() {
		return
	}
	ops := expr.Operands()
	if expr.Operator().String() == opEq && len(ops) == 2 {
		for i := range ops {
			if v, ok := ops[i].Value.(ast.Var); ok && !s.seen[v] && !mentions(ops[1-i], v) {
				s.canon[v] = ops[1-i]
				return
			}
		}
		return
	}
	n := s.arity(expr.Operator())
	if n < 0 || len(ops) != n+1 {
		return
	}
	if v, ok := ops[n].Value.(ast.Var); ok && !s.seen[v] {
		s.canon[v] = ast.CallTerm(append([]*ast.Term{ast.NewTerm(expr.Operator())}, ops[:n]...)...)
	}
}

// maxCanonDepth bounds how many bindings canonical follows through.
const maxCanonDepth = 8

// canonical replaces each variable in t with the term it was bound to.
func (s *useScan) canonical(t *ast.Term) *ast.Term {
	out := t.Copy()
	for depth := 0; depth < maxCanonDepth; depth++ {
		changed := false
		x, err := ast.TransformVars(out, func(v ast.Var) (ast.Value, error) {
			b, ok := s.canon[v]
			if !ok {
				return v, nil
			}
			changed = true
			return b.Copy().Value, nil
		})
		value, isValue := x.(ast.Value)
		if err != nil || !isValue || !changed {
			break
		}
		out = ast.NewTerm(value)
	}
	return out
}

// invocation is the subject of one call to a function.
func (s *useScan) invocation(op ast.Ref, args []*ast.Term) subject {
	call := make([]*ast.Term, 0, len(args)+1)
	call = append(call, ast.NewTerm(op))
	for _, a := range args {
		call = append(call, s.canonical(a))
	}
	t := ast.CallTerm(call...)
	return subject{ref: op, key: t.String(), vars: varsIn(t)}
}

// arity is the number of arguments a user function or a builtin takes, or -1.
func (s *useScan) arity(op ast.Ref) int {
	if n := s.userArity(op); n >= 0 {
		return n
	}
	b, ok := ast.BuiltinMap[op.String()]
	if !ok || b.Decl == nil || b.Decl.FuncArgs().Variadic != nil {
		return -1
	}
	return len(b.Decl.FuncArgs().Args)
}

func (s *useScan) userArity(op ast.Ref) int {
	for _, r := range s.idx.resolve(op) {
		if len(r.Head.Args) > 0 && s.idx.entries[s.idx.at[r].entry].path.Equal(op) {
			return len(r.Head.Args)
		}
	}
	return -1
}

// subject returns what a term is exactly the value of: a ground data
// reference, or a variable bound to a rule or a call.
func (s *useScan) subject(t *ast.Term) (subject, bool) {
	switch v := t.Value.(type) {
	case ast.Ref:
		if v.HasPrefix(ast.DefaultRootRef) && v.IsGround() {
			return refSubject(v), true
		}
	case ast.Var:
		sub, ok := s.bound[v]
		return sub, ok
	}
	return subject{}, false
}

func (s *useScan) fresh(t *ast.Term) (ast.Var, bool) {
	v, ok := t.Value.(ast.Var)
	if !ok || s.seen[v] {
		return "", false
	}
	_, isBound := s.bound[v]
	return v, !isBound
}

// classify records the value tests expr makes, and returns the subject of
// the call expr makes to a user function, if any.
func (s *useScan) classify(expr *ast.Expr, handled map[string]bool) *subject {
	if t, ok := expr.Terms.(*ast.Term); ok {
		if sub, ok := s.subject(t); ok {
			s.group(sub).uses = append(s.group(sub).uses, valueUse{kind: useTruthy, negated: expr.Negated})
			handled[sub.key] = true
		}
		return nil
	}
	if !expr.IsCall() {
		return nil
	}
	op, ops := expr.Operator(), expr.Operands()
	name := op.String()
	switch name {
	case opEq, opEqual, opNeq, opLt, opGt, opLte, opGte:
		if len(ops) == 2 {
			s.classifyComparison(name, ops, expr.Negated, handled)
		}
		return nil
	}
	if op.HasPrefix(ast.DefaultRootRef) {
		return s.classifyCall(op, ops, expr.Negated, handled)
	}
	return nil
}

// mirrored is the operator with its operands swapped, so the rule reads on
// the left.
var mirrored = map[string]string{opEq: opEq, opEqual: opEq, opNeq: opNeq, opLt: opGt, opGt: opLt, opLte: opGte, opGte: opLte}

func (s *useScan) classifyComparison(name string, ops []*ast.Term, negated bool, handled map[string]bool) {
	for i := range ops {
		sub, ok := s.subject(ops[i])
		if !ok {
			continue
		}
		handled[sub.key] = true
		g, other := s.group(sub), ops[1-i]
		op := name
		if name == opEqual {
			op = opEq
		}
		if i == 1 {
			op = mirrored[name]
		}
		if v, isFresh := s.fresh(other); isFresh && name == opEq {
			g.uses = append(g.uses, valueUse{kind: useDefined, negated: negated})
			s.bound[v] = sub
			continue
		}
		switch {
		case ast.IsConstant(other.Value):
			g.uses = append(g.uses, valueUse{kind: useCompare, op: op, c: other, negated: negated})
		case readsInput(other):
			g.either = true
		default:
			g.undecided = true
		}
	}
}

// classifyCall handles a call to a user function: `f(x)` tests its value,
// and `f(x, v)` (the compiler's form of `f(x) == c`) binds it to v. Each
// distinct call is its own subject.
func (s *useScan) classifyCall(op ast.Ref, ops []*ast.Term, negated bool, handled map[string]bool) *subject {
	arity := s.userArity(op)
	if arity < 0 || len(ops) < arity {
		return nil
	}
	sub := s.invocation(op, ops[:arity])
	g := s.group(sub)
	switch len(ops) {
	case arity:
		g.uses = append(g.uses, valueUse{kind: useTruthy, negated: negated})
	case arity + 1:
		v, isFresh := s.fresh(ops[arity])
		if !isFresh {
			return &sub
		}
		g.uses = append(g.uses, valueUse{kind: useDefined, negated: negated})
		s.bound[v] = sub
	default:
		return &sub
	}
	handled[sub.key] = true
	return &sub
}

func readsInput(t *ast.Term) bool {
	found := false
	walkRefs(t, false, func(ref ast.Ref) {
		found = found || ref[0].Equal(ast.InputRootDocument)
	})
	return found
}

// varsIn returns every variable under x, closures included.
func varsIn(x interface{}) []ast.Var {
	vis := ast.NewVarVisitor()
	vis.Walk(x)
	out := make([]ast.Var, 0, len(vis.Vars()))
	for v := range vis.Vars() {
		out = append(out, v)
	}
	return out
}

func mentions(x interface{}, v ast.Var) bool {
	for _, w := range varsIn(x) {
		if w.Equal(v) {
			return true
		}
	}
	return false
}
