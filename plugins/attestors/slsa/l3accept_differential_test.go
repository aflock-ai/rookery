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

package slsa

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"slices"
	"testing"
)

// PENDING DIFFERENTIAL. `cilock verify --slsa-level 3` does not exist yet, so
// this test diffs the Lean model's `l3Accept` (CiProvenance/SlsaL3Workflow.lean)
// against l3AcceptStub, a Go transliteration written from the design, NOT
// against shipped code. It proves the oracle and the harness work; it binds
// nothing until the stub is replaced by the real verifier's decision function.

// formal:differential ci-provenance TestL3AcceptStubMatchesLeanModel

type l3Ext struct {
	BuildSignerPath   string `json:"buildSignerPath"`
	BuildSignerRef    string `json:"buildSignerRef"`
	BuildSignerDigest string `json:"buildSignerDigest"`
	SourceRepository  string `json:"sourceRepository"`
	SourceDigest      string `json:"sourceDigest"`
	RunID             int    `json:"runId"`
	Trigger           string `json:"trigger"`
	Hosted            bool   `json:"hosted"`
}

type l3Cert struct {
	Root string `json:"root"`
	Ext  l3Ext  `json:"ext"`
}

type l3Stmt struct {
	BuilderID [2]string `json:"builderId"`
	Repo      string    `json:"repo"`
	Commit    string    `json:"commit"`
	RunID     int       `json:"runId"`
	Subjects  []string  `json:"subjects"`
}

type l3Build struct {
	Cert     l3Cert   `json:"cert"`
	Subjects []string `json:"subjects"`
}

type l3Evidence struct {
	Signer l3Cert    `json:"signer"`
	Stmt   l3Stmt    `json:"stmt"`
	Builds []l3Build `json:"builds"`
}

type l3Policy struct {
	Roots []string `json:"roots"`
	Path  string   `json:"path"`
	Sha   string   `json:"sha"`
}

// l3AcceptStub is the design's verifier, transliterated. Replace with the real one.
func l3AcceptStub(pol l3Policy, e l3Evidence) bool {
	x := e.Signer.Ext
	writerOnly := x.Trigger == "push" || x.Trigger == "release" || x.Trigger == "workflow_dispatch"
	if !slices.Contains(pol.Roots, e.Signer.Root) || x.BuildSignerPath != pol.Path || x.BuildSignerDigest != pol.Sha ||
		x.BuildSignerRef != pol.Sha || !x.Hosted || !writerOnly {
		return false
	}
	if e.Stmt.BuilderID != [2]string{x.BuildSignerPath, x.BuildSignerRef} || e.Stmt.Repo != x.SourceRepository ||
		e.Stmt.Commit != x.SourceDigest || e.Stmt.RunID != x.RunID || len(e.Stmt.Subjects) == 0 {
		return false
	}
	for _, s := range e.Stmt.Subjects {
		linked := false
		for _, b := range e.Builds {
			if slices.Contains(pol.Roots, b.Cert.Root) && b.Cert.Ext.RunID == x.RunID &&
				b.Cert.Ext.SourceRepository == x.SourceRepository && b.Cert.Ext.SourceDigest == x.SourceDigest &&
				slices.Contains(b.Subjects, s) {
				linked = true
				break
			}
		}
		if !linked {
			return false
		}
	}
	return true
}

func TestL3AcceptStubMatchesLeanModel(t *testing.T) {
	eval := leanEvaluator(t)
	t.Log("PENDING: compares the Lean model with a Go stub; no shipped verifier exists yet")
	rng := rand.New(rand.NewSource(20260925)) //nolint:gosec // deterministic test cases, not crypto
	const path = "aflock-ai/cilock-action/.github/workflows/provenance.yml"
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	ext := func() l3Ext {
		return l3Ext{
			BuildSignerPath: pick(path, path, "acme/app/.github/workflows/release.yml"), BuildSignerRef: pick("good", "good", "v1"),
			BuildSignerDigest: pick("good", "good", "evil"), SourceRepository: pick("acme/app", "acme/app", "mallory/tool"),
			SourceDigest: pick("c1", "c1", "c2"), RunID: 1 + rng.Intn(2),
			Trigger: pick("push", "push", "release", "workflow_dispatch", "pull_request", "pull_request_target", "workflow_run"),
			Hosted:  rng.Intn(5) != 0,
		}
	}
	cert := func() l3Cert { return l3Cert{Root: pick("platform", "platform", "public-sigstore"), Ext: ext()} }
	subjects := func() []string {
		out := []string{}
		for n := rng.Intn(3); n > 0; n-- {
			out = append(out, pick("sha256:a", "sha256:b"))
		}
		return out
	}

	const cases = 3000
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	want := make([]bool, 0, cases)
	for i := 0; i < cases; i++ {
		pol := l3Policy{Roots: [][]string{{"platform"}, {"public-sigstore"}, {"platform", "public-sigstore"}}[rng.Intn(3)], Path: path, Sha: "good"}
		signer := cert()
		// Half the cases start from a self-consistent statement, so acceptance is reachable.
		stmt := l3Stmt{
			BuilderID: [2]string{signer.Ext.BuildSignerPath, signer.Ext.BuildSignerRef}, Repo: signer.Ext.SourceRepository,
			Commit: signer.Ext.SourceDigest, RunID: signer.Ext.RunID, Subjects: subjects(),
		}
		if rng.Intn(2) == 0 {
			stmt.Commit = pick("c1", "c2")
			stmt.RunID = 1 + rng.Intn(2)
		}
		var builds []l3Build
		for n := rng.Intn(3); n > 0; n-- {
			b := l3Build{Cert: cert(), Subjects: subjects()}
			if rng.Intn(2) == 0 {
				b.Cert.Ext.RunID, b.Cert.Ext.SourceRepository, b.Cert.Ext.SourceDigest = signer.Ext.RunID, signer.Ext.SourceRepository, signer.Ext.SourceDigest
			}
			builds = append(builds, b)
		}
		if builds == nil {
			builds = []l3Build{}
		}
		e := l3Evidence{Signer: signer, Stmt: stmt, Builds: builds}
		want = append(want, l3AcceptStub(pol, e))
		if err := enc.Encode(map[string]any{"fn": "l3Accept", "policy": pol, "evidence": e}); err != nil {
			t.Fatal(err)
		}
	}
	out := runLeanEvaluator(t, eval, in.Bytes())
	if len(out) != cases {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), cases)
	}
	accepted := 0
	for i := range out {
		var r struct {
			Accept *bool  `json:"accept"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(out[i], &r); err != nil || r.Error != "" || r.Accept == nil {
			t.Fatalf("case %d: lean result %q: %v %s", i, out[i], err, r.Error)
		}
		if *r.Accept != want[i] {
			t.Fatalf("case %d: Go stub %v, Lean %v", i, want[i], *r.Accept)
		}
		if want[i] {
			accepted++
		}
	}
	if accepted == 0 || accepted == cases {
		t.Fatalf("%d of %d accepted: the comparison did not exercise both outcomes", accepted, cases)
	}
	t.Logf("%d cases agree (%d accepted)", cases, accepted)
}
