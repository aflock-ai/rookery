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

package l3

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math/rand"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// formal:differential ci-provenance TestL3AcceptMatchesLeanModel

// TestL3AcceptMatchesLeanModel runs random policies and evidence through
// Accept (the shipped `cilock verify --slsa-level 3` decision) and through
// `l3Accept` in the Lean model (formal/ci-provenance,
// CiProvenance/SlsaL3Workflow.lean), and fails on the first disagreement.
// Theorem `l3_sound` is about Accept only while the two agree.
//
// Half the cases are fully random; the other half are the honest scene with
// exactly one field mutated, so every conjunct of l3Accept is the sole reason
// for some rejection and deleting any one check from Accept makes the two
// disagree.
//
// It skips when `lake` is not on PATH (the evaluator is rebuilt before every use).
func TestL3AcceptMatchesLeanModel(t *testing.T) {
	eval := leanEvaluator(t)
	cases := l3DifferentialCases(20260925, 4000)
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, c := range cases {
		if err := enc.Encode(map[string]any{"fn": "l3Accept", "policy": c.pol, "evidence": leanEvidence(t, c.e)}); err != nil {
			t.Fatal(err)
		}
	}
	out := runLeanEvaluator(t, eval, in.Bytes())
	if len(out) != len(cases) {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), len(cases))
	}
	accepted := 0
	for i, c := range cases {
		var r struct {
			Accept *bool  `json:"accept"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(out[i], &r); err != nil || r.Error != "" || r.Accept == nil {
			t.Fatalf("case %d: lean result %q: %v %s", i, out[i], err, r.Error)
		}
		got := Accept(c.pol, c.e)
		if got.Accepted() != *r.Accept {
			t.Fatalf("case %d (%s): Go accepted=%v %v, Lean accepted=%v", i, c.label, got.Accepted(), got.Failures, *r.Accept)
		}
		if *r.Accept {
			accepted++
		}
	}
	if accepted < len(cases)/50 || accepted == len(cases) {
		t.Fatalf("%d of %d accepted: the comparison did not exercise both outcomes enough", accepted, len(cases))
	}
	t.Logf("%d cases agree (%d accepted)", len(cases), accepted)
}

type l3Case struct {
	label string
	pol   Policy
	e     Evidence
}

// l3Mutations each break exactly one conjunct of l3Accept in the honest scene.
var l3Mutations = []struct {
	name  string
	apply func(*Policy, *Evidence)
}{
	{"signer root untrusted", func(_ *Policy, e *Evidence) { e.Signer.Root = RootPublicSigstore }},
	{"signer path", func(_ *Policy, e *Evidence) {
		e.Signer.Ext.SignerPath, e.Statement.BuilderPath = "acme/app/.github/workflows/release.yml", "acme/app/.github/workflows/release.yml"
	}},
	{"signer digest", func(_ *Policy, e *Evidence) { e.Signer.Ext.SignerDigest = "evil" }},
	{"signer ref", func(_ *Policy, e *Evidence) {
		e.Signer.Ext.SignerRef, e.Statement.BuilderRef = "v1", "v1"
	}},
	{"self-hosted", func(_ *Policy, e *Evidence) { e.Signer.Ext.Hosted = false }},
	{"expected repo", func(p *Policy, _ *Evidence) { p.Repo = "mallory/tool" }},
	{"pull_request", func(_ *Policy, e *Evidence) { e.Signer.Ext.Trigger = "pull_request" }},
	{"pull_request_target", func(_ *Policy, e *Evidence) { e.Signer.Ext.Trigger = "pull_request_target" }},
	{"workflow_run", func(_ *Policy, e *Evidence) { e.Signer.Ext.Trigger = "workflow_run" }},
	{"builder path", func(_ *Policy, e *Evidence) { e.Statement.BuilderPath = "x" }},
	{"builder ref", func(_ *Policy, e *Evidence) { e.Statement.BuilderRef = "v1" }},
	{"stmt repo", func(_ *Policy, e *Evidence) { e.Statement.Repo = "mallory/tool" }},
	{"stmt commit", func(_ *Policy, e *Evidence) { e.Statement.Commit = "c2" }},
	{"stmt run", func(_ *Policy, e *Evidence) { e.Statement.RunID = "2" }},
	{"no subjects", func(_ *Policy, e *Evidence) { e.Statement.Subjects = []string{} }},
	{"no builds", func(_ *Policy, e *Evidence) { e.Builds = []Collection{} }},
	{"build root untrusted", func(_ *Policy, e *Evidence) { e.Builds[0].Cert.Root = RootPublicSigstore }},
	{"build run", func(_ *Policy, e *Evidence) { e.Builds[0].Cert.Ext.RunID = "2" }},
	{"build repo", func(_ *Policy, e *Evidence) { e.Builds[0].Cert.Ext.SourceRepo = "mallory/tool" }},
	{"build commit", func(_ *Policy, e *Evidence) { e.Builds[0].Cert.Ext.SourceDigest = "c2" }},
	{"build lacks subject", func(_ *Policy, e *Evidence) { e.Builds[0].Subjects = []string{"sha256:b"} }},
	{"unlinked second subject", func(_ *Policy, e *Evidence) {
		e.Statement.Subjects = append(e.Statement.Subjects, "sha256:b")
	}},
	{"none", func(*Policy, *Evidence) {}},
}

func l3DifferentialCases(seed int64, n int) []l3Case {
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test cases, not crypto
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	ext := func() Ext {
		return Ext{
			SignerPath: pick(WorkflowPath, WorkflowPath, "acme/app/.github/workflows/release.yml"), SignerRef: pick("good", "good", "v1"),
			SignerDigest: pick("good", "good", "evil"), SourceRepo: pick("acme/app", "acme/app", "mallory/tool"),
			SourceDigest: pick("c1", "c1", "c2"), RunID: strconv.Itoa(1 + rng.Intn(2)),
			Trigger: pick("push", "push", "release", "workflow_dispatch", "pull_request", "pull_request_target", "workflow_run"),
			Hosted:  rng.Intn(5) != 0,
		}
	}
	root := func() Root { return Root(pick(string(RootPlatform), string(RootPlatform), string(RootPublicSigstore))) }
	subjects := func() []string {
		out := []string{}
		for k := rng.Intn(3); k > 0; k-- {
			out = append(out, pick("sha256:a", "sha256:b"))
		}
		return out
	}
	policy := func() Policy {
		roots := [][]Root{{RootPlatform}, {RootPublicSigstore}, {RootPlatform, RootPublicSigstore}}[rng.Intn(3)]
		return Policy{Roots: roots, Path: WorkflowPath, SHA: "good", Repo: pick("acme/app", "acme/app", "mallory/tool")}
	}
	honest := func() (Policy, Evidence) {
		sig := Ext{SignerPath: WorkflowPath, SignerRef: "good", SignerDigest: "good", SourceRepo: "acme/app", SourceDigest: "c1", RunID: "1", Trigger: pick("push", "release", "workflow_dispatch"), Hosted: true}
		b := Ext{SignerPath: "acme/app/.github/workflows/release.yml", SignerRef: "refs/heads/main", SignerDigest: "c1", SourceRepo: "acme/app", SourceDigest: "c1", RunID: "1", Trigger: "push", Hosted: true}
		return Policy{Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: "good", Repo: "acme/app"}, Evidence{
			Signer:    Cert{Root: RootPlatform, Ext: sig},
			Statement: Statement{BuilderPath: WorkflowPath, BuilderRef: "good", Repo: "acme/app", Commit: "c1", RunID: "1", Subjects: []string{"sha256:a"}},
			Builds:    []Collection{{Cert: Cert{Root: RootPlatform, Ext: b}, Subjects: []string{"sha256:a"}}},
		}
	}

	cases := make([]l3Case, 0, n)
	for i := 0; i < n; i++ {
		if i%2 == 1 {
			pol, e := honest()
			m := l3Mutations[(i/2)%len(l3Mutations)]
			m.apply(&pol, &e)
			cases = append(cases, l3Case{label: "honest+" + m.name, pol: pol, e: e})
			continue
		}
		pol := policy()
		signer := Cert{Root: root(), Ext: ext()}
		stmt := Statement{
			BuilderPath: signer.Ext.SignerPath, BuilderRef: signer.Ext.SignerRef, Repo: signer.Ext.SourceRepo,
			Commit: signer.Ext.SourceDigest, RunID: signer.Ext.RunID, Subjects: subjects(),
		}
		if rng.Intn(2) == 0 {
			stmt.Commit = pick("c1", "c2")
			stmt.RunID = strconv.Itoa(1 + rng.Intn(2))
		}
		builds := []Collection{}
		for k := rng.Intn(3); k > 0; k-- {
			b := Collection{Cert: Cert{Root: root(), Ext: ext()}, Subjects: subjects()}
			if rng.Intn(2) == 0 {
				b.Cert.Ext.RunID, b.Cert.Ext.SourceRepo, b.Cert.Ext.SourceDigest = signer.Ext.RunID, signer.Ext.SourceRepo, signer.Ext.SourceDigest
			}
			builds = append(builds, b)
		}
		cases = append(cases, l3Case{label: "random", pol: pol, e: Evidence{Signer: signer, Statement: stmt, Builds: builds}})
	}
	return cases
}

// leanEvidence renders e in ciprov-eval's l3Accept shape: run ids are
// naturals, builder.id is a pair.
func leanEvidence(t *testing.T, e Evidence) map[string]any {
	t.Helper()
	nat := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("run id %q is not a natural", s)
		}
		return n
	}
	cert := func(c Cert) map[string]any {
		x := c.Ext
		return map[string]any{"root": c.Root, "ext": map[string]any{
			"buildSignerPath": x.SignerPath, "buildSignerRef": x.SignerRef, "buildSignerDigest": x.SignerDigest,
			"sourceRepository": x.SourceRepo, "sourceDigest": x.SourceDigest, "runId": nat(x.RunID),
			"trigger": x.Trigger, "hosted": x.Hosted,
		}}
	}
	builds := make([]any, 0, len(e.Builds))
	for _, b := range e.Builds {
		builds = append(builds, map[string]any{"cert": cert(b.Cert), "subjects": b.Subjects})
	}
	subjects := e.Statement.Subjects
	if subjects == nil {
		subjects = []string{}
	}
	return map[string]any{
		"signer": cert(e.Signer),
		"stmt": map[string]any{
			"builderId": []string{e.Statement.BuilderPath, e.Statement.BuilderRef}, "repo": e.Statement.Repo,
			"commit": e.Statement.Commit, "runId": nat(e.Statement.RunID), "subjects": subjects,
		},
		"builds": builds,
	}
}

func leanEvaluator(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "formal", "ci-provenance"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, ".lake", "build", "bin", "ciprov-eval")
	// Always run the incremental build: lake rebuilds only what changed, and
	// reusing an existing binary would compare the code against whatever
	// model was built last rather than the model in the tree.
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("`lake` not on PATH, so the Lean evaluator cannot be rebuilt from the current model; install elan to run the differential test")
	}
	build := exec.Command(lake, "build", "ciprov-eval")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build ciprov-eval: %v\n%s", err, out)
	}
	return bin
}

func runLeanEvaluator(t *testing.T, bin string, input []byte) [][]byte {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(input)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("ciprov-eval: %v", err)
	}
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}
