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
	"math"

	"github.com/open-policy-agent/opa/ast"
)

// Closures. A body inside a comprehension that stops firing does not fail
// the enclosing body: it drops elements from the collection, and the
// enclosing body then tests the collection. count([1 | ok]) == 0 holds on the
// empty collection, so a missing field under ok denies there (fail-closed);
// count([1 | ok]) > 0 fails on it, so the same field admits (fail-open).
//
// The lint follows the tests it can evaluate on the collection's size:
// count(c) against a constant, c compared with an empty literal, `x in c`
// and `some x in c` (both need an element), and `every x in c` (holds on the
// empty collection). Formatting c into a deny message with sprintf is not a
// test. Any other use of a comprehension makes it undecided. An `every` body
// is simpler: every holds only when its body holds for each element, so a
// body that stops holding stops the every.
//
// The same model applies to a rule referenced inside the closure (through
// regopolarity.go) and to a negation written inside it (through lintRule).

type role uint8

const (
	roleCollection role = iota // holds the comprehension
	roleCount                  // count(c)
	roleDerived                // sprintf over c: formatted, not tested
	roleIndex                  // k in c[k] from `some v in c`: depends on order
)

type tracked struct {
	coll *collection
	role role
}

type collKind uint8

const (
	kindArray collKind = iota
	kindSet
	kindObject
)

// sizeTest is one test of a collection's size, possibly negated. opNever
// holds for no size: a comparison with an empty literal of another kind.
type sizeTest struct {
	op      string
	k       float64
	negated bool
}

const opNever = "never"

func (t sizeTest) holds(n int) bool {
	v := float64(n)
	var r bool
	switch t.op {
	case opEq:
		r = v == t.k
	case opNeq:
		r = v != t.k
	case opLt:
		r = v < t.k
	case opGt:
		r = v > t.k
	case opLte:
		r = v <= t.k
	case opGte:
		r = v >= t.k
	}
	return r != t.negated
}

// collection is what one body does with one comprehension's value.
type collection struct {
	kind      collKind
	tests     []sizeTest
	undecided bool
}

func (c *collection) holds(n int) bool {
	for _, t := range c.tests {
		if !t.holds(n) {
			return false
		}
	}
	return true
}

// maxSizeConst bounds the constants the model enumerates sizes up to.
const maxSizeConst = 64

func (c *collection) span() (int, bool) {
	n := 2
	for _, t := range c.tests {
		if t.op == opNever {
			continue
		}
		if math.IsNaN(t.k) || math.Abs(t.k) > maxSizeConst {
			return 0, false
		}
		n = max(n, int(math.Ceil(t.k))+2)
	}
	return n, true
}

// change is how a collection moves when the thing inside the closure stops
// firing (fallback) compared with when it fires.
type change uint8

const (
	fallbackEmpties change = iota // the same for every element: stopping empties the collection
	fireEmpties                   // the same, negated inside: firing empties it
	fallbackShrinks               // depends on the element: stopping drops some elements
	fallbackGrows                 // depends on the element, negated: stopping adds some
)

func (ch change) allows(fire, fallback int) bool {
	switch ch {
	case fallbackEmpties:
		return fallback == 0
	case fireEmpties:
		return fire == 0
	case fallbackShrinks:
		return fallback <= fire
	}
	return fallback >= fire
}

// direction is positive when some pair of sizes the change allows holds when
// firing and fails on the fallback, and negative for the opposite.
func (c *collection) direction(ch change) []polarity {
	n, ok := c.span()
	if c.undecided || !ok {
		return []polarity{polUndecided}
	}
	var pos, neg bool
	for fire := 0; fire <= n; fire++ {
		for fb := 0; fb <= n; fb++ {
			if !ch.allows(fire, fb) {
				continue
			}
			hf, hb := c.holds(fire), c.holds(fb)
			pos = pos || hf && !hb
			neg = neg || !hf && hb
		}
	}
	return polarities(pos, neg)
}

// closureSite is one closure in a body: how the body consumes it (coll is
// nil for an every body), and the variables bound outside it.
type closureSite struct {
	coll  *collection
	known map[ast.Var]bool
}

func (site *closureSite) local(vars []ast.Var) bool {
	for _, v := range vars {
		if !site.known[v] {
			return true
		}
	}
	return false
}

// outer maps a direction inside the closure body to the enclosing body.
// perElement: each element can stop on its own (a negation over input[k]
// with k the element), so any subset of elements drops; otherwise every
// element stops together.
func (site *closureSite) outer(inner polarity, perElement bool) []polarity {
	if inner == polUndecided {
		return []polarity{polUndecided}
	}
	if site.coll == nil {
		return []polarity{inner}
	}
	ch := fallbackEmpties
	switch {
	case inner == polNegative && perElement:
		ch = fallbackGrows
	case inner == polNegative:
		ch = fireEmpties
	case perElement:
		ch = fallbackShrinks
	}
	return site.coll.direction(ch)
}

// outerUse is outer for a reference. A call whose arguments depend on the
// element may still stop for every element together, because the callee's
// negation need not read the argument. Every element stopping together is
// always possible (a predicate missing every field), so its directions are
// decided; any further direction the per-element reading adds is undecided.
func (site *closureSite) outerUse(inner polarity, local bool) []polarity {
	together := site.outer(inner, false)
	if !local || samePolarities(together, site.outer(inner, true)) {
		return together
	}
	return append(together, polUndecided)
}

func samePolarities(a, b []polarity) bool {
	var inA, inB [polUndecided + 1]bool
	for _, p := range a {
		inA[p] = true
	}
	for _, p := range b {
		inB[p] = true
	}
	return inA == inB
}

func (idx *ruleIndex) closurePolarities(u refUse, target *ast.Rule) []polarity {
	local := u.through.local(u.inner.vars)
	out := make([]polarity, 0, 2)
	for _, p := range idx.usePolarities(*u.inner, target) {
		out = append(out, u.through.outerUse(p, local)...)
	}
	return out
}

// markHead records the head variables. Unifying a collection with one hands
// it to the rule's consumers, which the model does not follow, except for
// the key of a deny set: the evaluator only asks whether deny has an element.
func (s *useScan) markHead(rule *ast.Rule) {
	for _, t := range []*ast.Term{rule.Head.Key, rule.Head.Value} {
		if t != nil {
			for _, v := range varsIn(t) {
				s.headOnly[v] = true
			}
		}
	}
	if rule.Head.Key != nil && s.idx.queried[rule] && rule.Head.RuleKind() == ast.MultiValue {
		for _, v := range varsIn(rule.Head.Key) {
			s.denyKey[v] = true
		}
	}
}

func closuresIn(expr *ast.Expr) []interface{} {
	var found []interface{}
	ast.NewGenericVisitor(func(x interface{}) bool {
		switch x.(type) {
		case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension, *ast.Every:
			found = append(found, x)
			return true
		}
		return false
	}).Walk(expr)
	return found
}

func closureBody(c interface{}) ast.Body {
	switch c := c.(type) {
	case *ast.ArrayComprehension:
		return c.Body
	case *ast.SetComprehension:
		return c.Body
	case *ast.ObjectComprehension:
		return c.Body
	case *ast.Every:
		return c.Body
	}
	return nil
}

func kindOf(c interface{}) collKind {
	switch c.(type) {
	case *ast.SetComprehension:
		return kindSet
	case *ast.ObjectComprehension:
		return kindObject
	}
	return kindArray
}

// scanClosures scans each closure in expr as a child body, and wraps each use
// it makes in how expr consumes the closure.
func (s *useScan) scanClosures(expr *ast.Expr) {
	found := closuresIn(expr)
	if len(found) == 0 {
		return
	}
	known := make(map[ast.Var]bool, len(s.seen))
	for v := range s.seen {
		known[v] = true
	}
	for _, v := range exprVars(expr) {
		known[v] = true
	}
	for _, c := range found {
		site := &closureSite{known: known}
		if _, isEvery := c.(*ast.Every); !isEvery {
			site.coll = s.consumeLiteral(expr, c)
		}
		s.sites[c] = site
		child := s.child()
		for _, e := range closureBody(c) {
			child.scanExpr(e)
		}
		for _, u := range child.uses() {
			inner := u
			s.fixed = append(s.fixed, refUse{ref: u.ref, vars: u.vars, inner: &inner, through: site})
		}
	}
}

func (s *useScan) child() *useScan {
	c := newUseScan(s.idx, s.sites)
	for v := range s.seen {
		c.seen[v] = true
	}
	for v, sub := range s.bound {
		c.bound[v] = sub
	}
	for v, t := range s.canon {
		c.canon[v] = t
	}
	return c
}

// consumeLiteral is the collection for a comprehension written in expr:
// bound to a fresh variable (tested by later expressions), or compared with
// an empty literal here.
func (s *useScan) consumeLiteral(expr *ast.Expr, c interface{}) *collection {
	coll := &collection{kind: kindOf(c)}
	if !expr.IsCall() || len(expr.Operands()) != 2 {
		coll.undecided = true
		return coll
	}
	name, ops := expr.Operator().String(), expr.Operands()
	for i, t := range ops {
		if t.Value != c {
			continue
		}
		other := ops[1-i]
		if v, isFresh := s.fresh(other); isFresh && name == opEq {
			s.track[v] = tracked{coll: coll}
			return coll
		}
		if sink, harmless := s.headSink(name, other); sink {
			coll.undecided = !harmless
			return coll
		}
		coll.undecided = !emptyTest(name, other, expr.Negated, coll)
		return coll
	}
	coll.undecided = true
	return coll
}

// consumeTracked classifies each read of a tracked variable in expr. A read
// the model does not cover, including any read inside a closure of expr,
// makes the collection undecided.
func (s *useScan) consumeTracked(expr *ast.Expr) {
	if len(s.track) == 0 {
		return
	}
	outer := map[ast.Var]bool{}
	for _, v := range exprVars(expr) {
		outer[v] = true
	}
	type read struct {
		v ast.Var
		t tracked
	}
	var reads []read
	for _, v := range varsIn(expr) {
		if t, ok := s.track[v]; ok {
			reads = append(reads, read{v, t})
		}
	}
	for _, r := range reads {
		if !outer[r.v] || !s.consume(expr, r.v, r.t) {
			r.t.coll.undecided = true
		}
	}
}

func (s *useScan) consume(expr *ast.Expr, v ast.Var, t tracked) bool {
	if every, ok := expr.Terms.(*ast.Every); ok {
		if t.role != roleCollection || !isVar(every.Domain, v) {
			return false
		}
		t.coll.tests = append(t.coll.tests, sizeTest{op: opEq})
		return true
	}
	if !expr.IsCall() || t.role == roleIndex {
		return false
	}
	name, ops := expr.Operator().String(), expr.Operands()
	if handled, ok := s.aliasOrSink(name, ops, v, t); handled {
		return ok
	}
	if name == ast.Sprintf.Name && len(ops) == 3 {
		out, isFresh := s.fresh(ops[2])
		if isFresh {
			s.track[out] = tracked{coll: t.coll, role: roleDerived}
		}
		return isFresh
	}
	switch t.role {
	case roleCount:
		return countTest(name, ops, v, expr.Negated, t.coll)
	case roleCollection:
		return s.collectionTest(name, ops, v, expr.Negated, t.coll)
	}
	return false
}

// aliasOrSink handles `w = v`: a fresh w is another name for v; a head
// variable hands v to the rule's consumers.
func (s *useScan) aliasOrSink(name string, ops []*ast.Term, v ast.Var, t tracked) (handled, ok bool) {
	if name != opEq || len(ops) != 2 {
		return false, false
	}
	for i := range ops {
		if !isVar(ops[i], v) {
			continue
		}
		if w, isFresh := s.fresh(ops[1-i]); isFresh {
			s.track[w] = t
			return true, true
		}
		if sink, harmless := s.headSink(name, ops[1-i]); sink {
			return true, harmless
		}
	}
	return false, false
}

func (s *useScan) headSink(name string, t *ast.Term) (sink, harmless bool) {
	v, ok := t.Value.(ast.Var)
	if !ok || name != opEq || !s.headOnly[v] {
		return false, false
	}
	return true, s.denyKey[v]
}

func countTest(name string, ops []*ast.Term, v ast.Var, negated bool, coll *collection) bool {
	if _, isCmp := mirrored[name]; !isCmp || len(ops) != 2 {
		return false
	}
	for i := range ops {
		if !isVar(ops[i], v) {
			continue
		}
		n, isNum := ops[1-i].Value.(ast.Number)
		if !isNum {
			return false
		}
		k, exact := n.Float64()
		if !exact {
			return false
		}
		op := name
		if op == opEqual {
			op = opEq
		}
		if i == 1 {
			op = mirrored[name]
		}
		coll.tests = append(coll.tests, sizeTest{op: op, k: k, negated: negated})
		return true
	}
	return false
}

func (s *useScan) collectionTest(name string, ops []*ast.Term, v ast.Var, negated bool, coll *collection) bool {
	switch {
	case name == ast.Count.Name && len(ops) == 2 && isVar(ops[0], v):
		n, isFresh := s.fresh(ops[1])
		if isFresh {
			s.track[n] = tracked{coll: coll, role: roleCount}
		}
		return isFresh
	case name == ast.Member.Name && len(ops) == 2 && isVar(ops[1], v) && !mentions(ops[0], v):
		coll.tests = append(coll.tests, sizeTest{op: opGt, negated: negated})
		return true
	case len(ops) != 2:
		return false
	case name == opEq && s.elementOf(ops, v, negated, coll):
		return true
	}
	for i := range ops {
		if isVar(ops[i], v) {
			return emptyTest(name, ops[1-i], negated, coll)
		}
	}
	return false
}

// elementOf handles `e = c[k]` with e and k fresh, the compiled form of
// `some e in c`: it holds when c has an element.
func (s *useScan) elementOf(ops []*ast.Term, v ast.Var, negated bool, coll *collection) bool {
	for i := range ops {
		ref, ok := ops[i].Value.(ast.Ref)
		if !ok || len(ref) != 2 || !isVar(ref[0], v) {
			continue
		}
		k, keyFresh := s.fresh(ref[1])
		_, elemFresh := s.fresh(ops[1-i])
		if !keyFresh || !elemFresh {
			return false
		}
		s.track[k] = tracked{coll: coll, role: roleIndex}
		coll.tests = append(coll.tests, sizeTest{op: opGt, negated: negated})
		return true
	}
	return false
}

// emptyTest handles a comparison of the collection with an empty literal.
// (mirrored normalises equal to eq, and eq and neq are symmetric.)
func emptyTest(name string, other *ast.Term, negated bool, coll *collection) bool {
	op := mirrored[name]
	if op != opEq && op != opNeq {
		return false
	}
	kind, empty := emptyLiteral(other.Value)
	if !empty {
		return false
	}
	if kind != coll.kind {
		coll.tests = append(coll.tests, sizeTest{op: opNever, negated: negated != (op == opNeq)})
		return true
	}
	coll.tests = append(coll.tests, sizeTest{op: op, negated: negated})
	return true
}

func emptyLiteral(v ast.Value) (collKind, bool) {
	switch x := v.(type) {
	case *ast.Array:
		return kindArray, x.Len() == 0
	case ast.Set:
		return kindSet, x.Len() == 0
	case ast.Object:
		return kindObject, x.Len() == 0
	}
	return kindArray, false
}

func isVar(t *ast.Term, v ast.Var) bool {
	x, ok := t.Value.(ast.Var)
	return ok && x.Equal(v)
}

// scoredFinding is a finding with the directions its negation, when it never
// fires, moves the body being linted.
type scoredFinding struct {
	finding RegoFailOpenFinding
	ref     ast.Ref
	dirs    []polarity
}

// lintRule lints one branch of an else chain (the branches after it carry
// their own polarity), including each closure body in it. A negation is
// reported when the direction it moves this body, composed with a polarity
// deny reaches the branch with, makes deny fire less: a closure consumer can
// turn the body's failure into the body firing more, and `not rule` turns
// that back into deny firing less. Undecided when either side is undecided.
func (idx *ruleIndex) lintRule(module string, rule *ast.Rule, reached []polarity) []RegoFailOpenFinding {
	sc := idx.scan(rule)
	name := rule.Head.Ref().String()
	var out []RegoFailOpenFinding
	for _, f := range sc.bodyFindings(module, name, rule.Body) {
		var decided, warn bool
		for _, p := range reached {
			for _, d := range f.dirs {
				switch p.then(d) {
				case polPositive:
					decided = true
				case polUndecided:
					warn = true
				}
			}
		}
		switch {
		case decided:
			out = append(out, f.finding)
		case warn:
			f.finding.Undecided = true
			out = append(out, f.finding)
		}
	}
	return out
}

func (sc *ruleScan) bodyFindings(module, rule string, body ast.Body) []scoredFinding {
	var out []scoredFinding
	for _, f := range lintBody(module, rule, body) {
		out = append(out, scoredFinding{finding: f.RegoFailOpenFinding, ref: f.ref, dirs: []polarity{polPositive}})
	}
	for _, expr := range body {
		for _, c := range closuresIn(expr) {
			site, ok := sc.sites[c]
			if !ok {
				site = &closureSite{coll: &collection{undecided: true}}
			}
			for _, f := range sc.bodyFindings(module, rule, closureBody(c)) {
				// The negation reads f.ref itself, so a path through the
				// element is missing per element.
				perElement := site.local(varsIn(f.ref))
				var dirs []polarity
				for _, d := range f.dirs {
					dirs = append(dirs, site.outer(d, perElement)...)
				}
				f.dirs = dirs
				out = append(out, f)
			}
		}
	}
	return out
}
