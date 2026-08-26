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

package alpsevidence

// Structural guards for the class every review round on this attestor has
// found: THE PREDICATE CLAIMING STRONGER EVIDENCE THAN IT HOLDS.
//
// Codex raised it four consecutive times, each in a place the previous fix had
// not reached: round 1 bound the digest to one handle, round 3 bound the
// version to the snapshot, round 4 found matching and resolution still looking
// the path up separately, and round 5 found BOTH remaining shapes — a version
// read out of a file beside the image through a path the snapshot never bound,
// and a fingerprint naming a basis that had not matched. Every one of those
// fixes was correct and none of them held, because the defect stayed
// EXPRESSIBLE — a comment saying "consume the snapshot, do not re-resolve" is
// advice a later edit can simply not read.
//
// The guards below replace the advice. The compile-time ones stop the package
// building if the shape is reverted; the source-level one fails if a symlink
// resolution appears anywhere except the one file allowed to perform it.
// Neither can be satisfied by a promise.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Compile-time shape guards. These assert nothing about behavior; reverting a
// structural decision stops this file compiling.
// ---------------------------------------------------------------------------

// A provider receives the SNAPSHOT, never a raw path. Changing
// InspectRequest.Executable back to a resolved-path string — the round-3
// shape, which round 4 found insufficient — fails here.
var _ = func(r InspectRequest) executableSnapshot { return r.Executable }

// Both measured providers inspect from that request and nothing else. Adding
// a path parameter alongside it fails here.
var (
	_ func(ClaudeCodeProvider, context.Context, InspectRequest) Inspection = ClaudeCodeProvider.Inspect
	_ func(CodexProvider, context.Context, InspectRequest) Inspection      = CodexProvider.Inspect
)

// The predicate's executable evidence is assembled from the snapshot, not
// from loose fields a caller paired up itself.
var _ func(ProcessInfo, executableSnapshot, map[string]string) ProcessRef = processRef

// Reading a file that sits BESIDE the image is a method ON the snapshot and
// takes no path. Round 5's defect was the free-function form: it accepted any
// path, and the caller handed it the kernel-recorded one, so a package manifest
// replaced after exec could put its version next to the earlier image's digest.
// Restoring a path parameter — the only way to reintroduce that — fails here.
var _ func(executableSnapshot, string) string = executableSnapshot.npmPackageVersion

// A recorded configuration file takes NO role argument. The vocabulary no
// longer contains a value meaning "the agent loaded this one", and describe
// cannot accept one — reintroducing the parameter, which is how that claim
// would come back, fails here. See ResolutionRole for why it was withdrawn.
var _ func(*configSnapshot, string, ...string) *ConfigSource = (*configSnapshot).describe

// The verdict is COMPUTED from the walk's coverage and takes no other input.
// Giving it a parameter — a status to prefer, an "assume complete" flag — is
// how a caller would talk it into a claim its observations do not support, and
// fails here.
var (
	_ func(walkCoverage) ObservationStatus = walkCoverage.verdict
	_ func(walkCoverage) []string          = walkCoverage.explain
)

// Every identity setter takes the READ'S OWN (value, error) pair, so a
// platform source forwards a two-result read directly and the error has
// nowhere to be dropped. Reducing any of these to a value-only setter — which
// is what `exe, _ := os.Readlink(...)` looked like — fails here.
var (
	_ func(*processInfoBuilder, string, error) *processInfoBuilder   = (*processInfoBuilder).executable
	_ func(*processInfoBuilder, string, error) *processInfoBuilder   = (*processInfoBuilder).comm
	_ func(*processInfoBuilder, []string, error) *processInfoBuilder = (*processInfoBuilder).argv
	_ func(*processInfoBuilder) ProcessInfo                          = (*processInfoBuilder).build
)

// The one opener for agent-influenced paths hands back the os.FileInfo it
// checked, from the HANDLE. Reducing it to just a *os.File — which is what
// dropping the regular-file check would look like — fails here, and so does
// reverting to a path-based stat.
var _ func(string) (*os.File, os.FileInfo) = openAgentPath

// A fingerprint's basis half is DERIVED from the branch that matched, never
// chosen by the caller. matchByName is handed a product prefix and names; the
// basis is the one thing it does not accept. Adding a basis parameter, which is
// what would let a provider claim executable evidence for an argv[0] match
// again, fails here.
var _ func(ProcessInfo, string, ...string) MatchResult = matchByName

// Match-time resolution yields a fingerprintPath, and fingerprintPath stays a
// STRUCT. Reverting it to a defined string type breaks the composite literal
// below — and would make string(...) start compiling, which is precisely the
// escape hatch that must not exist: it would let a match-time resolution be
// handed to a version parser again.
var (
	_ func(string) fingerprintPath = matchTimeResolve
	_                              = fingerprintPath{}
)

// TestSymlinkResolutionLivesInExactlyOnePlace is the source-level half of the
// same guard. The compile-time assertions above pin the shapes that exist; this
// pins that no NEW resolution appears somewhere a snapshot cannot reach.
//
// filepath.EvalSymlinks is the only way this package resolves a path, and it
// is confined to fsutil.go, where every caller is accounted for:
// matchTimeResolve (identity only, returns a fingerprintPath),
// verifyResolutionAgainstHandle (evidence, checked against the digested
// handle), and projectRootFromWorkingDir (directory selection only — no
// evidence is derived from the resolution itself; every settings file it
// leads to still goes through loadConfigSnapshot's guarded open). A
// resolution anywhere else is the round-1/3/4 defect returning.
func TestSymlinkResolutionLivesInExactlyOnePlace(t *testing.T) {
	files := packageFilesCalling(t, "filepath", "EvalSymlinks")
	assert.Equal(t, []string{"fsutil.go"}, files,
		"symlink resolution must stay in fsutil.go; a resolution elsewhere cannot be bound to the executable snapshot")
}

// TestFilesystemEntryPointsStayWhereABoundCanBeEnforced is the widened form of
// the guard that let round 5's follow-up through.
//
// It used to be two tests, one pinning os.Open and one pinning os.ReadFile,
// and that split WAS the hole: the manifest read used os.ReadFile, so the
// os.Open guard never saw it, and when the read moved into fsutil.go it landed
// on an agent-controlled path with no bound at all. Enumerating one function
// per test means the next entry point nobody thought of is unguarded again, so
// every way this package can reach the filesystem is listed here together.
//
// The allowlists are deliberately narrow, and each one SHRANK when the safe
// opener arrived:
//
//   - os.OpenFile: fsutil.go only. That is openAgentPath, the single
//     non-blocking, fstat-checked opener for paths the agent influences.
//   - os.Open: process_linux.go only, for /proc/<pid>/exe — a kernel-provided
//     image handle, not a path the agent can point at a pipe. configsource.go
//     and fsutil.go both dropped off this list by routing through
//     openAgentPath.
//   - os.ReadFile: process_linux.go only, for /proc/<int>/<fixed name>. An
//     unbounded whole-file read is exactly what must not exist anywhere a path
//     is agent-influenced, and /proc entries are neither agent-named nor
//     unbounded in practice. fsutil.go dropped off this list when the manifest
//     read became a bounded read of a guarded handle.
//
// Adding a file here should be a decision someone makes on purpose, which is
// why it is a list and not a pattern.
func TestFilesystemEntryPointsStayWhereABoundCanBeEnforced(t *testing.T) {
	for _, tc := range []struct {
		fn   string
		want []string
		why  string
	}{
		{"OpenFile", []string{"fsutil.go"},
			"the guarded opener is the only place a path may be opened; a second one would not be non-blocking or fstat-checked"},
		{"Open", []string{"process_linux.go"},
			"a plain open blocks forever on a FIFO, so it is allowed only for kernel-provided /proc handles"},
		{"ReadFile", []string{"process_linux.go"},
			"an unbounded whole-file read of an agent-influenced path lets a matched process spend this attestor's memory"},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			assert.Equal(t, tc.want, packageFilesCalling(t, "os", tc.fn), tc.why)
		})
	}
}

// TestVerdictsAreOnlyProducedByWalkCoverage is the binding this round
// establishes, in the form the previous two rounds proved is the only one that
// holds.
//
// Round 6 bound not-detected to walk completeness and left the other verdicts
// alone, so detected was still assigned directly at the match site — and a
// match found past an ancestor that could not be examined was signed as "the
// invoker" anyway. Patching that one site would have left the same shape for
// the next verdict anyone adds.
//
// So no verdict is assigned anywhere. The status constants may be MENTIONED
// where a caller compares against them, but a verdict VALUE is produced in
// exactly one function, from the walk's own observations. detector.go holds
// that function, in its OWN FILE — verdict.go. That separation is load-bearing
// and was verified by disabling it: while walkCoverage still lived in
// detector.go, reintroducing `out.Status = StatusDetected` inside the walk
// passed this guard, because the guard's allowlist named the file that held
// both the chokepoint and the walk. StatusUnavailable is deliberately not
// guarded: it describes a walk that never happened, not a claim about an
// ancestry.
func TestVerdictsAreOnlyProducedByWalkCoverage(t *testing.T) {
	for _, verdict := range []string{"StatusDetected", "StatusNotDetected", "StatusIncomplete"} {
		files := packageFiles(t, func(file *ast.File, mark func()) {
			ast.Inspect(file, func(n ast.Node) bool {
				// A verdict is "produced" when it is returned or assigned.
				// Comparing against one (== / switch) is reading, not claiming.
				switch stmt := n.(type) {
				case *ast.ReturnStmt:
					for _, r := range stmt.Results {
						if isIdent(r, verdict) {
							mark()
						}
					}
				case *ast.AssignStmt:
					for _, r := range stmt.Rhs {
						if isIdent(r, verdict) {
							mark()
						}
					}
				}
				return true
			})
		})
		assert.Equalf(t, []string{"verdict.go"}, files,
			"%s may only be produced by walkCoverage.verdict; a verdict emitted anywhere else is not bound to what the walk observed", verdict)
	}
}

func isIdent(e ast.Expr, name string) bool {
	ident, ok := e.(*ast.Ident)
	return ok && ident.Name == name
}

// TestProcessInfoIsOnlyPopulatedByItsBuilder is the source-level half of the
// identity-coverage guard.
//
// The compile-time assertions above pin the builder's SHAPE. They cannot stop a
// platform source from going around it and writing a ProcessInfo literal, which
// is exactly what both sources did — and a literal cannot record that a read
// failed, so the result claimed to have been examined when it had not been.
//
// A populated ProcessInfo literal may therefore appear only in process.go,
// where the builder itself assembles one. Empty literals are unrestricted:
// `return ProcessInfo{}, err` is the honest failure form and carries no claim.
// Test files are excluded — a fixture legitimately models a completed read, and
// fixtures_test.go routes them through the real builder anyway.
func TestProcessInfoIsOnlyPopulatedByItsBuilder(t *testing.T) {
	files := packageFiles(t, func(file *ast.File, mark func()) {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || len(lit.Elts) == 0 {
				return true
			}
			if ident, isIdent := lit.Type.(*ast.Ident); isIdent && ident.Name == "ProcessInfo" {
				mark()
			}
			return true
		})
	})
	assert.Equal(t, []string{"process.go"}, files,
		"a ProcessInfo built outside its builder cannot record which identity reads failed, so it silently claims to have been examined")
}

// TestIdentityFieldsAreNeverAssignedAfterTheBuild closes the other half of that
// hole. Construction is not the only way to put a value in: assigning
// p.Executable after the fact would leave the coverage record describing reads
// that no longer match the fields.
func TestIdentityFieldsAreNeverAssignedAfterTheBuild(t *testing.T) {
	identityFields := map[string]bool{"Executable": true, "Comm": true, "Argv": true}

	files := packageFiles(t, func(file *ast.File, mark func()) {
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range assign.Lhs {
				if sel, isSel := lhs.(*ast.SelectorExpr); isSel && identityFields[sel.Sel.Name] {
					mark()
				}
			}
			return true
		})
	})
	assert.Equal(t, []string{"process.go"}, files,
		"an identity field assigned outside the builder desynchronizes the value from the coverage record")
}

// TestBasisNamesAreNeverSpelledOutByHand is the source-level half of the
// fingerprint-basis guard.
//
// The compile-time assertion above pins that matchByName decides the basis. It
// cannot stop a provider from going around it and writing the literal
// "executable-basename" into a fingerprint of its own — which is precisely what
// Cursor, Gemini and Copilot each did, and how three providers came to publish
// executable evidence for a kernel-comm or argv[0] match.
//
// The basis vocabulary therefore exists as constants in exactly one file, and
// every fingerprint that names a basis is built from them. A literal anywhere
// else is a provider spelling out a claim instead of deriving it.
func TestBasisNamesAreNeverSpelledOutByHand(t *testing.T) {
	for _, basis := range []string{basisExecutableBase, basisKernelComm, basisArgv0Title, basisNodeScriptArg} {
		files := packageFilesWithStringContaining(t, basis)
		assert.Equalf(t, []string{"provider.go"}, files,
			"%q must come from the shared basis constants; spelling it out lets a fingerprint name a basis that did not match", basis)
	}
}

// TestFingerprintPathHasNoWayOut is the third guard, and the one that keeps
// the second compile-time assertion from being defeated by addition rather
// than by reversion.
//
// fingerprintPath being a struct stops `string(f)` compiling, but nothing
// stops someone ADDING a method that hands the path back — at which point a
// match-time resolution could be fed to a version parser again and the whole
// separation would be decorative. No method on fingerprintPath may return a
// string. Answering a question about the path is allowed; producing the path
// is not.
func TestFingerprintPathHasNoWayOut(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fsutil.go", nil, 0)
	require.NoError(t, err)

	methods := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		ident, ok := fn.Recv.List[0].Type.(*ast.Ident)
		if !ok || ident.Name != "fingerprintPath" {
			continue
		}
		methods++
		if fn.Type.Results == nil {
			continue
		}
		for _, result := range fn.Type.Results.List {
			resultType, isIdent := result.Type.(*ast.Ident)
			require.Truef(t, isIdent, "unexpected result type on fingerprintPath.%s", fn.Name.Name)
			assert.NotEqualf(t, "string", resultType.Name,
				"fingerprintPath.%s returns a string: a match-time resolution must never be handed back as a path",
				fn.Name.Name)
		}
	}
	require.NotZero(t, methods, "fingerprintPath's methods must live in fsutil.go, where this guard can see them")
}

// packageFilesWithStringContaining returns the sorted non-test file names in
// this package containing a string literal with needle in it. Constant
// declarations count: the point is to find every place the vocabulary is
// written out, not only the places it is used.
func packageFilesWithStringContaining(t *testing.T, needle string) []string {
	t.Helper()

	return packageFiles(t, func(file *ast.File, mark func()) {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING && strings.Contains(lit.Value, needle) {
				mark()
			}
			return true
		})
	})
}

// packageFilesCalling returns the sorted non-test file names in this package
// that contain a call to pkg.fn.
func packageFilesCalling(t *testing.T, pkg, fn string) []string {
	t.Helper()

	return packageFiles(t, func(file *ast.File, mark func()) {
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != fn {
				return true
			}
			if ident, isIdent := sel.X.(*ast.Ident); isIdent && ident.Name == pkg {
				mark()
			}
			return true
		})
	})
}

// packageFiles parses every non-test file in this package and returns, sorted,
// the names of those the inspector marked. Every file is parsed regardless of
// build tags, so a defect hidden behind a GOOS constraint is still caught.
func packageFiles(t *testing.T, inspect func(file *ast.File, mark func())) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoErrorf(t, perr, "parse %s", name)

		inspect(file, func() { seen[name] = true })
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
