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

package alpsevidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// formal:differential ci-provenance TestVerdictMatchesLeanModel

// TestVerdictMatchesLeanModel runs the same walk coverages through
// walkCoverage.verdict and through `verdict` in the Lean model
// (formal/ci-provenance, CiProvenance/Verdict.lean) and requires the two to
// agree. The theorems there (a positive verdict needs a complete walk; the
// walk never reports unavailable) are only about this code while the two
// functions compute the same thing.
//
// It skips when the Lean evaluator is neither built nor buildable (no `lake`).
func TestVerdictMatchesLeanModel(t *testing.T) {
	eval := leanEvaluator(t)

	type leanCase struct {
		Fn         string   `json:"fn"`
		Unexamined []string `json:"unexamined"`
		Stopped    string   `json:"stopped"`
		Matched    bool     `json:"matched"`
		Unbound    string   `json:"unbound"`
	}
	var covs []walkCoverage
	// Every combination of the four inputs' shapes, then random ones.
	for mask := 0; mask < 16; mask++ {
		c := walkCoverage{matched: mask&1 != 0}
		if mask&2 != 0 {
			c.stopped = "walk cancelled"
		}
		if mask&4 != 0 {
			c.unexamined = []string{"pid 7: exe unreadable"}
		}
		if mask&8 != 0 {
			c.unbound = "symlink retargeted"
		}
		covs = append(covs, c)
	}
	rng := rand.New(rand.NewSource(20260924)) //nolint:gosec // deterministic test cases, not crypto
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	for i := 0; i < 2000; i++ {
		c := walkCoverage{
			stopped: pick("", "", "", "ppid loop", " "),
			unbound: pick("", "", "", "retargeted", "\t"),
			matched: rng.Intn(2) == 0,
		}
		for n := rng.Intn(3); n > 0; n-- {
			c.unexamined = append(c.unexamined, pick("pid 1", "", "pid 9: gone"))
		}
		covs = append(covs, c)
	}

	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, c := range covs {
		u := c.unexamined
		if u == nil {
			u = []string{}
		}
		if err := enc.Encode(leanCase{Fn: "verdict", Unexamined: u, Stopped: c.stopped, Matched: c.matched, Unbound: c.unbound}); err != nil {
			t.Fatal(err)
		}
	}
	out := runLeanEvaluator(t, eval, in.Bytes())
	if len(out) != len(covs) {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), len(covs))
	}
	seen := map[ObservationStatus]int{}
	for i, c := range covs {
		var r struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(out[i], &r); err != nil || r.Error != "" {
			t.Fatalf("case %d: lean result %q: %v %s", i, out[i], err, r.Error)
		}
		got := c.verdict()
		seen[got]++
		if string(got) != r.Status {
			t.Fatalf("case %d %+v: Go verdict %q, Lean verdict %q", i, c, got, r.Status)
		}
	}
	// Guard against a vacuous pass: every reachable status must have occurred.
	for _, s := range []ObservationStatus{StatusDetected, StatusNotDetected, StatusIncomplete} {
		if seen[s] == 0 {
			t.Fatalf("no case produced %q; the comparison did not exercise it", s)
		}
	}
	t.Logf("%d cases agree: %v", len(covs), seen)
}

// leanEvaluator returns the path of the built `ciprov-eval`, building it with
// lake when needed, or skips.
func leanEvaluator(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "formal", "ci-provenance"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, ".lake", "build", "bin", "ciprov-eval")
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("Lean evaluator not built and `lake` not on PATH; install elan to run the differential test")
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
