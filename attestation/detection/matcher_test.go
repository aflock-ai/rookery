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

package detection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArgvPrefix(t *testing.T) {
	cases := []struct {
		name   string
		argv   []string
		prefix []string
		want   PredicateState
	}{
		{"exact match", []string{"docker", "build", "."}, []string{"docker", "build"}, StateMatch},
		{"basename match", []string{"/usr/bin/docker", "build"}, []string{"docker", "build"}, StateMatch},
		{"no match - flag in way", []string{"docker", "--debug", "build"}, []string{"docker", "build"}, StateNoMatch},
		{"short argv", []string{"docker"}, []string{"docker", "build"}, StateNoMatch},
		{"empty prefix", []string{"docker", "build"}, []string{}, StateNoMatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := NewEvalContext(GatePre)
			ctx.Argv = tc.argv
			got := evalArgvPrefix(tc.prefix, ctx)
			if got.State != tc.want {
				t.Errorf("got %v, want %v (rule=%s)", got.State, tc.want, got.Rule)
			}
		})
	}
}

func TestArgvContains(t *testing.T) {
	ctx := NewEvalContext(GatePre)
	ctx.Argv = []string{"docker", "buildx", "build", "--provenance=true", "."}
	if r := evalArgvContains("--provenance=true", ctx); r.State != StateMatch {
		t.Errorf("contains should match: %v", r)
	}
	if r := evalArgvContains("--missing", ctx); r.State != StateNoMatch {
		t.Errorf("contains should miss: %v", r)
	}
	if r := evalArgvContains("", ctx); r.State != StateNoMatch {
		t.Errorf("empty needle should not match: %v", r)
	}
}

func TestEnvSetEquals(t *testing.T) {
	ctx := NewEvalContext(GatePre)
	ctx.Env = map[string]string{"GITHUB_ACTIONS": "true", "EMPTY": ""}

	if r := evalEnvSet("GITHUB_ACTIONS", ctx); r.State != StateMatch {
		t.Errorf("env_set GITHUB_ACTIONS should match: %v", r)
	}
	if r := evalEnvSet("EMPTY", ctx); r.State != StateMatch {
		t.Errorf("env_set EMPTY (empty value) should still match (presence-only): %v", r)
	}
	if r := evalEnvSet("MISSING", ctx); r.State != StateNoMatch {
		t.Errorf("env_set MISSING should miss: %v", r)
	}
	if !ctx.observedEnv["GITHUB_ACTIONS"] {
		t.Errorf("env_set should record observed key")
	}

	if r := evalEnvEquals(&EnvEqualsLeaf{Var: "GITHUB_ACTIONS", Value: "true"}, ctx); r.State != StateMatch {
		t.Errorf("env_equals match: %v", r)
	}
	if r := evalEnvEquals(&EnvEqualsLeaf{Var: "GITHUB_ACTIONS", Value: "false"}, ctx); r.State != StateNoMatch {
		t.Errorf("env_equals differ: %v", r)
	}
	if r := evalEnvEquals(&EnvEqualsLeaf{Var: "MISSING", Value: "x"}, ctx); r.State != StateNoMatch {
		t.Errorf("env_equals unset: %v", r)
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := NewEvalContext(GatePre)
	ctx.Cwd = dir

	if r := evalFileExists("hello.txt", ctx); r.State != StateMatch {
		t.Errorf("file_exists hello.txt should match: %v", r)
	}
	if r := evalFileExists("nope.txt", ctx); r.State != StateNoMatch {
		t.Errorf("file_exists nope.txt should miss: %v", r)
	}
	// Forward-slash normalization: caller writes "sub/file.txt"; we
	// normalize to OS sep. Both forms must work.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := evalFileExists("sub/file.txt", ctx); r.State != StateMatch {
		t.Errorf("file_exists with forward slash should match on all OSes: %v", r)
	}
}

func TestFileGlob(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := NewEvalContext(GatePre)
	ctx.Cwd = dir

	if r := evalFileGlob([]string{"package-lock.json"}, ctx); r.State != StateMatch {
		t.Errorf("file_glob package-lock.json should match: %v", r)
	}
	if r := evalFileGlob([]string{"**/*.go"}, ctx); r.State != StateMatch {
		t.Errorf("file_glob **/*.go should recursively match: %v", r)
	}
	if r := evalFileGlob([]string{"*.notfound"}, ctx); r.State != StateNoMatch {
		t.Errorf("file_glob *.notfound should miss: %v", r)
	}
}

func TestArgvRegex(t *testing.T) {
	ctx := NewEvalContext(GatePre)
	ctx.Argv = []string{"docker", "build", "-t", "test:v1", "."}
	if r := evalArgvRegex(`-t\s+\S+:v\d+`, ctx); r.State != StateMatch {
		t.Errorf("argv_regex tagged build should match: %v", r)
	}
	if r := evalArgvRegex(`nope`, ctx); r.State != StateNoMatch {
		t.Errorf("argv_regex no match: %v", r)
	}
	if r := evalArgvRegex(`(((`, ctx); r.State != StateNoMatch {
		t.Errorf("argv_regex invalid pattern returns no-match: %v", r)
	}
}

func TestAnyOf(t *testing.T) {
	ctx := NewEvalContext(GatePre)
	ctx.Argv = []string{"docker", "buildx", "build"}

	p := &Predicate{
		AnyOf: []Predicate{
			{ArgvPrefix: []string{"docker", "build"}},           // no match (buildx in way)
			{ArgvPrefix: []string{"docker", "buildx", "build"}}, // match
		},
	}
	r := Evaluate(p, ctx)
	if r.State != StateMatch {
		t.Errorf("any_of should match when second child matches: %v", r)
	}
}

func TestAnyOfNoMatch(t *testing.T) {
	ctx := NewEvalContext(GatePre)
	ctx.Argv = []string{"echo", "hi"}
	p := &Predicate{
		AnyOf: []Predicate{
			{ArgvPrefix: []string{"docker", "build"}},
			{ArgvPrefix: []string{"buildah", "build"}},
		},
	}
	if r := Evaluate(p, ctx); r.State != StateNoMatch {
		t.Errorf("any_of with no children matching: %v", r)
	}
}

func TestAllOf(t *testing.T) {
	ctx := NewEvalContext(GatePre)
	ctx.Argv = []string{"docker", "build", "--provenance=true", "."}
	p := &Predicate{
		AllOf: []Predicate{
			{ArgvPrefix: []string{"docker", "build"}},
			{ArgvContains: "--provenance=true"},
		},
	}
	if r := Evaluate(p, ctx); r.State != StateMatch {
		t.Errorf("all_of two matches: %v", r)
	}

	// One miss → no-match.
	p2 := &Predicate{
		AllOf: []Predicate{
			{ArgvPrefix: []string{"docker", "build"}},
			{ArgvContains: "--missing"},
		},
	}
	if r := Evaluate(p2, ctx); r.State != StateNoMatch {
		t.Errorf("all_of one-miss: %v", r)
	}
}

func TestNot(t *testing.T) {
	ctx := NewEvalContext(GatePre)
	ctx.Argv = []string{"docker", "build"}
	p := &Predicate{Not: &Predicate{ArgvContains: "--provenance=true"}}
	if r := Evaluate(p, ctx); r.State != StateMatch {
		t.Errorf("not(absent) should match: %v", r)
	}

	ctx.Argv = []string{"docker", "build", "--provenance=true"}
	if r := Evaluate(p, ctx); r.State != StateNoMatch {
		t.Errorf("not(present) should miss: %v", r)
	}
}

func TestExecObservedTraceUnavailable(t *testing.T) {
	ctx := NewEvalContext(GatePost)
	ctx.TraceMode = TraceOff
	ctx.ExecTrace = nil
	p := &Predicate{
		ExecObserved: &Predicate{ArgvPrefix: []string{"docker", "build"}},
	}
	r := Evaluate(p, ctx)
	if r.State != StateTraceUnavailable {
		t.Errorf("exec_observed without trace should be trace-unavailable: %v", r)
	}
}

func TestExecObservedMatch(t *testing.T) {
	ctx := NewEvalContext(GatePost)
	ctx.TraceMode = TraceLight
	ctx.ExecTrace = []ExecEvent{
		{Argv: []string{"make", "build"}},
		{Argv: []string{"/usr/bin/docker", "build", "-t", "x", "."}},
	}
	p := &Predicate{
		ExecObserved: &Predicate{ArgvPrefix: []string{"docker", "build"}},
	}
	r := Evaluate(p, ctx)
	if r.State != StateMatch {
		t.Errorf("exec_observed should match the docker exec in the trace: %v", r)
	}
}

func TestAnyOfTraceUnavailable(t *testing.T) {
	// any_of with one trace-unavailable child and no matching children
	// should propagate trace-unavailable, so cilock can audit that the
	// rule was undecidable rather than decisively false.
	ctx := NewEvalContext(GatePost)
	ctx.TraceMode = TraceOff
	p := &Predicate{
		AnyOf: []Predicate{
			{ProductGlob: []string{"*.notfound"}},                               // no-match (no products)
			{ExecObserved: &Predicate{ArgvPrefix: []string{"docker", "build"}}}, // trace-unavailable
		},
	}
	r := Evaluate(p, ctx)
	if r.State != StateTraceUnavailable {
		t.Errorf("any_of with one unavailable + others no-match should be unavailable: %v", r)
	}
}

func TestNotTraceUnavailable(t *testing.T) {
	ctx := NewEvalContext(GatePost)
	ctx.TraceMode = TraceOff
	p := &Predicate{
		Not: &Predicate{ExecObserved: &Predicate{ArgvPrefix: []string{"docker", "build"}}},
	}
	r := Evaluate(p, ctx)
	if r.State != StateTraceUnavailable {
		t.Errorf("not(trace-unavailable) should propagate as trace-unavailable: %v", r)
	}
}

func TestExitCode(t *testing.T) {
	ctx := NewEvalContext(GatePost)
	ctx.ExitCode = 0
	zero := 0
	one := 1
	if r := evalExitCode(&ExitCodeLeaf{Eq: &zero}, ctx); r.State != StateMatch {
		t.Errorf("exit_code eq=0 should match: %v", r)
	}
	if r := evalExitCode(&ExitCodeLeaf{Eq: &one}, ctx); r.State != StateNoMatch {
		t.Errorf("exit_code eq=1 should miss: %v", r)
	}
	if r := evalExitCode(&ExitCodeLeaf{Ne: &zero}, ctx); r.State != StateNoMatch {
		t.Errorf("exit_code ne=0 should miss when actual is 0: %v", r)
	}
	if r := evalExitCode(&ExitCodeLeaf{In: []int{0, 1, 2}}, ctx); r.State != StateMatch {
		t.Errorf("exit_code in [0,1,2] should match: %v", r)
	}
	if r := evalExitCode(&ExitCodeLeaf{In: []int{3, 4}}, ctx); r.State != StateNoMatch {
		t.Errorf("exit_code in [3,4] should miss: %v", r)
	}
}

func TestProductGlob(t *testing.T) {
	ctx := NewEvalContext(GatePost)
	ctx.Products = map[string]ProductRef{
		"image.tar":      {Path: "image.tar"},
		"out/nested.tar": {Path: "out/nested.tar"},
		"out/report.txt": {Path: "out/report.txt"},
	}
	// *.tar matches root-level only (gobwas/glob with sep='/').
	if r := evalProductGlob([]string{"*.tar"}, ctx); r.State != StateMatch {
		t.Errorf("product_glob *.tar should match image.tar: %v", r)
	}
	// **/*.tar matches anywhere.
	if r := evalProductGlob([]string{"**/*.tar"}, ctx); r.State != StateMatch {
		t.Errorf("product_glob **/*.tar should match nested: %v", r)
	}
	if r := evalProductGlob([]string{"*.deb"}, ctx); r.State != StateNoMatch {
		t.Errorf("product_glob *.deb should miss: %v", r)
	}
}

func TestMaterialChanged(t *testing.T) {
	ctx := NewEvalContext(GatePost)
	ctx.MaterialsDiff = []string{"src/main.go", "go.mod"}
	if r := evalMaterialChanged("go.mod", ctx); r.State != StateMatch {
		t.Errorf("material_changed exact should match: %v", r)
	}
	if r := evalMaterialChanged("nope.txt", ctx); r.State != StateNoMatch {
		t.Errorf("material_changed miss: %v", r)
	}
	if r := evalMaterialChanged("**/*.go", ctx); r.State != StateMatch {
		t.Errorf("material_changed glob should match: %v", r)
	}
}

// FuzzMatcherNoPanic feeds arbitrary input shapes to Evaluate and
// asserts it never panics. The matcher operates on user-authored YAML;
// even though we validate at parse time, defense in depth on the
// runtime path is cheap and worth having.
func FuzzMatcherNoPanic(f *testing.F) {
	f.Add("docker", "build", "GITHUB_ACTIONS=true", "/tmp")
	f.Fuzz(func(t *testing.T, argv0, argv1, envKV, cwd string) {
		ctx := NewEvalContext(GatePre)
		ctx.Argv = []string{argv0, argv1}
		ctx.Env = map[string]string{"X": envKV}
		ctx.Cwd = cwd
		p := &Predicate{
			AnyOf: []Predicate{
				{ArgvPrefix: []string{argv0}},
				{ArgvContains: argv1},
				{EnvSet: "X"},
				{Not: &Predicate{ArgvRegex: argv1}},
			},
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("matcher panicked: %v", r)
			}
		}()
		_ = Evaluate(p, ctx)
	})
}
