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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// STRUCTURAL CONTAINMENT for the lazy stop, in the same spirit as #7948's
// probe bound (TestDiagnosticProbeIsReachableOnlyThroughTheDepthGuard).
//
// The #7948 lesson was that a SECOND, unguarded call site is invisible in
// review. The lazy stop has the same shape of risk in three places:
//
//  1. errStepSatisfied is a control-flow escape. A second producer — a helper
//     that returns it, a source that could emit it — would silently truncate a
//     stream nobody meant to truncate.
//  2. It must be SWALLOWED. If a caller propagated it, a satisfied step would
//     surface as a verify error.
//  3. The stop must be GUARDED. A `return errStepSatisfied` not dominated by
//     the lazyStop predicate is a lazy stop with the flag off.
//
// Each is asserted below, each with a negative control so it cannot pass
// vacuously.
// ---------------------------------------------------------------------------

func TestLazyStop_SentinelHasExactlyOneProducer(t *testing.T) {
	returners := funcsReturningIdent(t, ".", "errStepSatisfied")
	assert.Equal(t, []string{"verifyStepStreamed"}, returners,
		"errStepSatisfied must be returned from exactly one function — the streamed step pipeline. "+
			"A second producer is a stream truncation that nothing in review makes visible, and the "+
			"verdict-invariance argument (stop only at a gate PASS, only when the exclusions allow it) "+
			"holds only for the one site that carries the guard.")
}

func TestLazyStop_SentinelIsSwallowedNotPropagated(t *testing.T) {
	handlers := funcsMatchingIdentPair(t, ".", "errors", "Is", "errStepSatisfied")
	assert.Equal(t, []string{"verifyStepStreamed"}, handlers,
		"errStepSatisfied must be recognised and swallowed in the same function that produces it. "+
			"If it escapes, a SATISFIED step surfaces to the caller as a verification error.")
}

func TestLazyStop_IsGuardedByTheLazyPredicate(t *testing.T) {
	guards := guardsOfReturn(t, ".", "errStepSatisfied")
	require.NotEmpty(t, guards, "found no `return errStepSatisfied` at all — the analyzer is broken or the stop was removed")
	for _, g := range guards {
		assert.Contains(t, g, "lazyStop",
			"every `return errStepSatisfied` must sit under a condition that tests the lazyStop predicate; "+
				"an unguarded one truncates the stream with the option OFF. Guard found: %q", g)
	}
}

// The demand valve is the ONLY thing that can clear a step's laziness, and the
// depth loop is the only thing that may fire it. A second caller would be a
// second, unreviewed un-truncation policy.
func TestLazyStop_DemandValveHasOneCaller(t *testing.T) {
	callers := callersOfMethodInPackage(t, ".", "demand")
	assert.Equal(t, []string{"verifySteps"}, callers,
		"demandValve.demand must be called from exactly one place — the depth loop. "+
			"The valve's soundness argument (mark on an unsatisfied verify, monotone marks, one extra "+
			"iteration per firing) is a property of that one call site.")
}

// ---------------------------------------------------------------------------
// Negative controls. Each analyzer is run over a synthetic package that HAS
// the violation, and must report it. Without these the four tests above could
// be passing because the analyzer finds nothing anywhere.
// ---------------------------------------------------------------------------

func TestLazyContainment_AnalyzersDetectViolations(t *testing.T) {
	dir := t.TempDir()
	src := `package p

import "errors"

var errStepSatisfied = errors.New("x")

func verifyStepStreamed() error {
	lazyStop := true
	if lazyStop {
		return errStepSatisfied
	}
	err := errors.New("y")
	if err != nil && !errors.Is(err, errStepSatisfied) {
		return err
	}
	return nil
}

func sneakySecondProducer() error { return errStepSatisfied }

type demandValve struct{}

func (d *demandValve) demand() bool { return true }

func verifySteps(v *demandValve) { v.demand() }

func someOtherArm(v *demandValve) { v.demand() }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o600))

	assert.Equal(t, []string{"sneakySecondProducer", "verifyStepStreamed"}, funcsReturningIdent(t, dir, "errStepSatisfied"),
		"the producer analyzer must see the second returner; if it cannot, TestLazyStop_SentinelHasExactlyOneProducer passes vacuously")
	assert.Equal(t, []string{"verifyStepStreamed"}, funcsMatchingIdentPair(t, dir, "errors", "Is", "errStepSatisfied"),
		"the swallow analyzer must find the errors.Is site")
	assert.Equal(t, []string{"someOtherArm", "verifySteps"}, callersOfMethodInPackage(t, dir, "demand"),
		"the valve-caller analyzer must see the second caller; if it cannot, TestLazyStop_DemandValveHasOneCaller passes vacuously")

	// The synthetic package has TWO returns: one guarded by lazyStop, one bare.
	// Both must be reported, and the bare one must come back with an EMPTY
	// guard — otherwise TestLazyStop_IsGuardedByTheLazyPredicate could never
	// fail on an unguarded stop.
	guards := guardsOfReturn(t, dir, "errStepSatisfied")
	require.Equal(t, []string{"", "lazyStop"}, guards,
		"the guard analyzer must report both returns, and report the unguarded one with an empty guard")
}

// ---------------------------------------------------------------------------
// Analyzers
// ---------------------------------------------------------------------------

// parseNonTestFiles parses dir's non-test Go files.
func parseNonTestFiles(t *testing.T, dir string) (*token.FileSet, []*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, perr)
		files = append(files, f)
	}
	require.NotEmpty(t, files, "parsed no non-test Go files in %s", dir)
	return fset, files
}

func lazySortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// funcsReturningIdent returns the names of top-level functions with a
// `return ... ident ...` statement naming ident.
func funcsReturningIdent(t *testing.T, dir, ident string) []string {
	t.Helper()
	_, files := parseNonTestFiles(t, dir)
	seen := map[string]struct{}{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				ret, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, res := range ret.Results {
					if id, ok := res.(*ast.Ident); ok && id.Name == ident {
						seen[fd.Name.Name] = struct{}{}
					}
				}
				return true
			})
		}
	}
	return lazySortedKeys(seen)
}

// funcsMatchingIdentPair returns the names of top-level functions containing a
// call to pkg.sel whose argument list mentions ident.
func funcsMatchingIdentPair(t *testing.T, dir, pkg, sel, ident string) []string {
	t.Helper()
	_, files := parseNonTestFiles(t, dir)
	seen := map[string]struct{}{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				se, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || se.Sel.Name != sel {
					return true
				}
				if x, ok := se.X.(*ast.Ident); !ok || x.Name != pkg {
					return true
				}
				for _, arg := range call.Args {
					if id, ok := arg.(*ast.Ident); ok && id.Name == ident {
						seen[fd.Name.Name] = struct{}{}
					}
				}
				return true
			})
		}
	}
	return lazySortedKeys(seen)
}

// guardsOfReturn renders, for every `return ident`, the source text of the
// nearest enclosing if-condition (or "" when there is none). It is used to
// assert that the lazy stop is dominated by the lazyStop predicate.
func guardsOfReturn(t *testing.T, dir, ident string) []string {
	t.Helper()
	fset, files := parseNonTestFiles(t, dir)

	var guards []string
	for _, file := range files {
		// Walk with a stack so the enclosing if-statements are known.
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)

			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			names := false
			for _, res := range ret.Results {
				if id, ok := res.(*ast.Ident); ok && id.Name == ident {
					names = true
				}
			}
			if !names {
				return true
			}

			guard := ""
			for i := len(stack) - 1; i >= 0; i-- {
				ifs, ok := stack[i].(*ast.IfStmt)
				if !ok {
					continue
				}
				guard = nodeText(t, fset, dir, ifs.Cond)
				break
			}
			guards = append(guards, guard)
			return true
		})
	}
	sort.Strings(guards)
	return guards
}

// nodeText reads the raw source span of a node.
func nodeText(t *testing.T, fset *token.FileSet, dir string, n ast.Node) string {
	t.Helper()
	pos := fset.Position(n.Pos())
	end := fset.Position(n.End())
	data, err := os.ReadFile(filepath.Clean(pos.Filename))
	require.NoError(t, err)
	if pos.Offset < 0 || end.Offset > len(data) || pos.Offset > end.Offset {
		return ""
	}
	return string(data[pos.Offset:end.Offset])
}

// callersOfMethodInPackage returns the names of top-level functions containing
// a call of the form `<expr>.method(...)`.
func callersOfMethodInPackage(t *testing.T, dir, method string) []string {
	t.Helper()
	_, files := parseNonTestFiles(t, dir)
	seen := map[string]struct{}{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fd.Recv != nil && fd.Name.Name == method {
				continue // the method's own declaration is not a caller
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if se, ok := call.Fun.(*ast.SelectorExpr); ok && se.Sel.Name == method {
					seen[fd.Name.Name] = struct{}{}
				}
				return true
			})
		}
	}
	return lazySortedKeys(seen)
}
