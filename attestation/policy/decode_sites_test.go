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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The AST scan of design 3.6 (revision 4.3, F43-5): no non-test code outside
// the decoder decodes into policy.Policy. The engine refuses Step.About unless
// the Policy carries the decoder's v0.2 stamp, so a second decode site cannot
// get v0.2 semantics; what it CAN do is decode an unknown policy type, or a
// v0.2 policy with a member this verifier does not know, and silently drop
// what it did not recognise. This scan keeps the decoder the only way in.
//
// Scope, stated: the rookery tree (attestation, plugins, cilock, compat,
// presets, examples). judge-api's decode sites are outside this module and
// are not scanned here.
//
// What it recognises, syntactically, per file: a call named Unmarshal or
// UnmarshalStrict (target: the second argument) or Decode (target: the last
// argument) whose target is &T{}, new(T), &x or x, where T is policy.Policy
// (under any import name of the rookery package or the go-witness alias
// package, or bare Policy inside this package) and x is declared in the same
// file by var, :=, or as a parameter. It does NOT follow a target through a
// struct field, a function result or another file; TestPolicyDecodeScan
// pins the shapes it does see, so a blind scan cannot pass as a clean one.

// allowedPolicyDecodeSites maps a file, relative to the rookery root, to why
// it may decode into Policy.
var allowedPolicyDecodeSites = map[string]string{
	"attestation/policy/decode.go": "DecodePolicyEnvelope, the decoder itself",
}

var policyImportPaths = map[string]bool{
	"github.com/aflock-ai/rookery/attestation/policy": true,
	"github.com/in-toto/go-witness/policy":            true,
}

type policyDecodeSite struct {
	File string
	Line int
	Call string
}

func (s policyDecodeSite) String() string { return fmt.Sprintf("%s:%d %s", s.File, s.Line, s.Call) }

// scanPolicyDecodes reports every decode into Policy in one parsed file.
// inPolicyPackage makes a bare Policy identifier the type.
func scanPolicyDecodes(fset *token.FileSet, file *ast.File, rel string, inPolicyPackage bool) []policyDecodeSite {
	names := map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !policyImportPaths[path] {
			continue
		}
		name := "policy"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = true
	}
	if len(names) == 0 && !inPolicyPackage {
		return nil
	}

	var isPolicy func(e ast.Expr) bool
	isPolicy = func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.ParenExpr:
			return isPolicy(v.X)
		case *ast.SelectorExpr:
			x, ok := v.X.(*ast.Ident)
			return ok && names[x.Name] && v.Sel.Name == "Policy"
		case *ast.Ident:
			// Inside the package, Policy is unresolved (declared in another
			// file) or resolves to the package's own type declaration.
			return inPolicyPackage && v.Name == "Policy" && (v.Obj == nil || v.Obj.Kind == ast.Typ)
		}
		return false
	}
	// valueType is the static type an initializer expression produces, when
	// it can be read off the syntax: T{} is T, &T{} and new(T) are *T.
	valueType := func(e ast.Expr) ast.Expr {
		switch v := e.(type) {
		case *ast.CompositeLit:
			return v.Type
		case *ast.UnaryExpr:
			if lit, ok := v.X.(*ast.CompositeLit); ok && v.Op == token.AND {
				return &ast.StarExpr{X: lit.Type}
			}
		case *ast.CallExpr:
			if fn, ok := v.Fun.(*ast.Ident); ok && fn.Name == "new" && len(v.Args) == 1 {
				return &ast.StarExpr{X: v.Args[0]}
			}
		}
		return nil
	}
	declType := func(id *ast.Ident) ast.Expr {
		if id.Obj == nil {
			return nil
		}
		switch d := id.Obj.Decl.(type) {
		case *ast.ValueSpec:
			if d.Type != nil {
				return d.Type
			}
			for i, n := range d.Names {
				if n.Name == id.Name && i < len(d.Values) {
					return valueType(d.Values[i])
				}
			}
		case *ast.AssignStmt:
			for i, l := range d.Lhs {
				if li, ok := l.(*ast.Ident); ok && li.Name == id.Name && len(d.Rhs) == len(d.Lhs) {
					return valueType(d.Rhs[i])
				}
			}
		case *ast.Field:
			return d.Type
		}
		return nil
	}
	isPtrToPolicy := func(t ast.Expr) bool {
		star, ok := t.(*ast.StarExpr)
		return ok && isPolicy(star.X)
	}
	// targetIsPolicy: the decode target is a *Policy.
	targetIsPolicy := func(arg ast.Expr) bool {
		if t := valueType(arg); t != nil {
			return isPtrToPolicy(t)
		}
		switch v := arg.(type) {
		case *ast.UnaryExpr:
			if id, ok := v.X.(*ast.Ident); ok && v.Op == token.AND {
				t := declType(id)
				return t != nil && isPolicy(t)
			}
		case *ast.Ident:
			t := declType(v)
			return t != nil && isPtrToPolicy(t)
		}
		return false
	}

	var out []policyDecodeSite
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		var target ast.Expr
		switch sel.Sel.Name {
		case "Unmarshal", "UnmarshalStrict":
			if len(call.Args) >= 2 {
				target = call.Args[1]
			}
		case "Decode":
			if len(call.Args) >= 1 {
				target = call.Args[len(call.Args)-1]
			}
		}
		if target != nil && targetIsPolicy(target) {
			out = append(out, policyDecodeSite{File: rel, Line: fset.Position(call.Pos()).Line, Call: sel.Sel.Name})
		}
		return true
	})
	return out
}

// rookeryRoot walks up to the directory holding go.work.
func rookeryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.work above the test directory")
	return ""
}

func TestPolicyIsDecodedOnlyByTheDecoder(t *testing.T) {
	root := rookeryRoot(t)
	var sites []policyDecodeSite
	files := 0
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata", "security-patches":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		files++
		seen[rel] = true
		inPolicy := filepath.ToSlash(filepath.Dir(rel)) == "attestation/policy"
		sites = append(sites, scanPolicyDecodes(fset, f, rel, inPolicy)...)
		return nil
	})
	require.NoError(t, err, "an unreadable or unparseable file is a failure, never a quiet pass")
	require.Greater(t, files, 300, "the walk must cover the tree, not one directory (467 non-test files when written)")
	for _, must := range []string{
		"plugins/attestors/policyverify/policyverify.go",
		"cilock/cli/verify.go",
		"compat/go-witness/witness.go",
		"attestation/workflow/verify.go",
	} {
		require.True(t, seen[must], "the walk must reach %s, a verify-path file", must)
	}

	var outside []string
	allowedSeen := map[string]bool{}
	for _, s := range sites {
		if _, ok := allowedPolicyDecodeSites[s.File]; ok {
			allowedSeen[s.File] = true
			continue
		}
		outside = append(outside, s.String())
	}
	sort.Strings(outside)
	require.Empty(t, outside, "decode a policy with policy.DecodePolicyEnvelope(payloadType, payload): "+
		"it applies the type allowlist, the strict v0.2 decode and the version stamp the engine checks")
	for file := range allowedPolicyDecodeSites {
		require.True(t, allowedSeen[file], "the scan must see the decoder's own decode in %s; not seeing it means the scan is blind", file)
	}
}

// The scan's known positives and known negatives, so a scan that sees nothing
// cannot pass TestPolicyIsDecodedOnlyByTheDecoder as a clean tree.
func TestPolicyDecodeScan(t *testing.T) {
	const header = `package p
import (
	"encoding/json"
	"bytes"
	wp "github.com/in-toto/go-witness/policy"
	"github.com/aflock-ai/rookery/attestation/policy"
	yaml "sigs.k8s.io/yaml"
)
var _ = bytes.NewReader
var _ = wp.Policy{}
var _ = yaml.Unmarshal
`
	flagged := map[string]string{
		"var decl":           `func f(b []byte) { var p policy.Policy; _ = json.Unmarshal(b, &p) }`,
		"short var literal":  `func f(b []byte) { p := policy.Policy{}; _ = json.Unmarshal(b, &p) }`,
		"pointer literal":    `func f(b []byte) { p := &policy.Policy{}; _ = json.Unmarshal(b, p) }`,
		"new":                `func f(b []byte) { p := new(policy.Policy); _ = json.Unmarshal(b, p) }`,
		"inline literal":     `func f(b []byte) { _ = json.Unmarshal(b, &policy.Policy{}) }`,
		"inline new":         `func f(b []byte) { _ = json.Unmarshal(b, new(policy.Policy)) }`,
		"parameter":          `func f(b []byte, p *policy.Policy) { _ = json.Unmarshal(b, p) }`,
		"decoder":            `func f(b []byte) { var p policy.Policy; _ = json.NewDecoder(bytes.NewReader(b)).Decode(&p) }`,
		"go-witness alias":   `func f(b []byte) { var p wp.Policy; _ = json.Unmarshal(b, &p) }`,
		"yaml":               `func f(b []byte) { var p policy.Policy; _ = yaml.Unmarshal(b, &p) }`,
		"package-level var":  `var pv policy.Policy; func f(b []byte) { _ = json.Unmarshal(b, &pv) }`,
		"multi-assign":       `func f(b []byte) { n, p := 1, policy.Policy{}; _ = n; _ = json.Unmarshal(b, &p) }`,
		"parenthesised type": `func f(b []byte) { var p (policy.Policy); _ = json.Unmarshal(b, &p) }`,
	}
	notFlagged := map[string]string{
		"another type":       `type other struct{}; func f(b []byte) { var o other; _ = json.Unmarshal(b, &o) }`,
		"a step, not policy": `func f(b []byte) { var s policy.Step; _ = json.Unmarshal(b, &s) }`,
		"encode, not decode": `func f() { p := policy.Policy{}; _, _ = json.Marshal(p) }`,
	}
	parse := func(t *testing.T, src string) []policyDecodeSite {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "snippet.go", header+src, 0)
		require.NoError(t, err)
		return scanPolicyDecodes(fset, f, "snippet.go", false)
	}
	for name, src := range flagged {
		t.Run("flags/"+name, func(t *testing.T) {
			require.Len(t, parse(t, src), 1)
		})
	}
	for name, src := range notFlagged {
		t.Run("ignores/"+name, func(t *testing.T) {
			require.Empty(t, parse(t, src))
		})
	}

	t.Run("in-package bare Policy", func(t *testing.T) {
		for name, src := range map[string]string{
			"declared in another file": `package policy
import "encoding/json"
func d(b []byte) { var p Policy; _ = json.Unmarshal(b, &p) }
`,
			"declared in the same file": `package policy
import "encoding/json"
type Policy struct{}
func d(b []byte) { p := &Policy{}; _ = json.Unmarshal(b, p) }
`,
		} {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "decode.go", src, 0)
			require.NoError(t, err)
			require.Len(t, scanPolicyDecodes(fset, f, "decode.go", true), 1, name)
			require.Empty(t, scanPolicyDecodes(fset, f, "decode.go", false), "%s: outside the package a bare Policy is someone else's type", name)
		}
	})
}
