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

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aflock-ai/rookery/cilock/cli"
)

// formal:differential cilock-ci TestAutomodeCIContextMatchesLeanModel

// TestAutomodeCIContextMatchesLeanModel runs the shipped binary's REAL catalog
// detectors over generated CI environments and requires the CI context
// attestors they attach (github, gitlab) to be the model's `ciContext`
// (formal/cilock-ci, CilockCi/Automode.lean), which automode_ci_parity is about.
func TestAutomodeCIContextMatchesLeanModel(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "formal", "cilock-ci"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, ".lake", "build", "bin", "cilock-ci-eval")
	if lake, lerr := exec.LookPath("lake"); lerr == nil {
		build := exec.Command(lake, "build", "cilock-ci-eval")
		build.Dir = dir
		if out, berr := build.CombinedOutput(); berr != nil {
			t.Fatalf("lake build cilock-ci-eval: %v\n%s", berr, out)
		}
	} else {
		t.Skip("Lean evaluator not built and `lake` not on PATH; install elan to run the differential test")
	}

	rng := rand.New(rand.NewSource(20260929)) //nolint:gosec // deterministic test cases
	values := []string{"true", "true", "false", "1", ""}
	var envs []map[string]string
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for i := 0; i < 400; i++ {
		env := map[string]string{"PATH": "/usr/bin:/bin"}
		lean := [][2]any{}
		for _, k := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "CI"} {
			if rng.Intn(2) == 0 {
				v := values[rng.Intn(len(values))]
				env[k] = v
				lean = append(lean, [2]any{k, map[string]any{"t": "str", "s": v}})
			}
		}
		if err := enc.Encode(map[string]any{"fn": "ci", "env": lean}); err != nil {
			t.Fatal(err)
		}
		envs = append(envs, env)
	}
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(in.Bytes())
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("cilock-ci-eval: %v", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	wd := t.TempDir()
	seen := map[string]int{}
	n := 0
	for ; sc.Scan(); n++ {
		var want struct {
			CI []string `json:"ci"`
		}
		if err := json.Unmarshal(sc.Bytes(), &want); err != nil {
			t.Fatalf("case %d: %s: %v", n, sc.Bytes(), err)
		}
		got := []string{}
		for _, a := range cli.DetectCatalogAttestorsIn([]string{"true"}, wd, envs[n]) {
			if a == "github" || a == "gitlab" {
				got = append(got, a)
			}
		}
		if want.CI == nil {
			want.CI = []string{}
		}
		seen[fmt.Sprint(got)]++
		if !slices.Equal(got, want.CI) {
			t.Fatalf("case %d env %v: detectors attached %v, Lean %v", n, envs[n], got, want.CI)
		}
	}
	if n != len(envs) {
		t.Fatalf("lean evaluator returned %d results for %d cases", n, len(envs))
	}
	for _, k := range []string{"[]", "[github]", "[gitlab]"} {
		if seen[k] == 0 {
			t.Errorf("no case produced %s (%v)", k, seen)
		}
	}
	t.Logf("automode CI context agrees: %v", seen)
}

// TestAutomodeSameAttestorsOnGitHubAndGitLab: the same wrapped command in the
// same tree attaches the same attestors in a GitHub job and a GitLab job,
// except the CI context attestor itself (automode_ci_parity), for real
// detectors and several real build commands.
func TestAutomodeSameAttestorsOnGitHubAndGitLab(t *testing.T) {
	wd := t.TempDir()
	for _, f := range []string{"go.mod", "package.json", "Dockerfile", "Makefile"} {
		if err := os.WriteFile(filepath.Join(wd, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/home/runner", "CI": "true"}
	gh := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "GITHUB_RUN_ID": "1"}
	gl := map[string]string{"GITLAB_CI": "true", "CI_SERVER_URL": "https://gitlab.example", "CI_PROJECT_PATH": "acme/app",
		"CI_PIPELINE_ID": "1", "CI_JOB_ID": "10"}
	merge := func(a, b map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range a {
			m[k] = v
		}
		for k, v := range b {
			m[k] = v
		}
		return m
	}
	swap := func(xs []string) []string {
		out := slices.Clone(xs)
		for i, x := range out {
			if x == "github" {
				out[i] = "gitlab"
			}
		}
		return out
	}
	for _, argv := range [][]string{{"go", "build", "./..."}, {"go", "test", "./..."}, {"npm", "ci"}, {"make"},
		{"docker", "build", "."}, {"bash", "-c", "go test ./... && go build"}, {"sh", "-c", "set -e\nmake\nmake test\n"}} {
		ghSet := cli.DetectCatalogAttestorsIn(argv, wd, merge(base, gh))
		glSet := cli.DetectCatalogAttestorsIn(argv, wd, merge(base, gl))
		if !slices.Contains(glSet, "gitlab") || slices.Contains(glSet, "github") {
			t.Errorf("%q in GitLab: want the gitlab context attestor and not github, got %v", argv, glSet)
		}
		if !slices.Equal(swap(ghSet), glSet) {
			t.Errorf("%q: GitHub attaches %v, GitLab attaches %v; only the CI context attestor may differ", argv, ghSet, glSet)
		}
	}
}
