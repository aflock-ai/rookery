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

package standards

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

// formal:differential ci-provenance TestCeilingMatchesLeanModel

// TestCeilingMatchesLeanModel runs generated observation sets through the Go
// ceiling (Observations -> evidence -> DeriveSLSA / DeriveALPS) and through
// `deriveSlsa` / `deriveAlps` in the Lean model (formal/ci-provenance,
// `ciprov-eval` fns "slsa" and "alps"), and requires the levels to agree.
//
// What this binds and what it does not:
//   - The DECISION (evidence Booleans -> level) is compared exhaustively: every
//     one of the 2^5 SLSA and 2^6 ALPS evidence vectors, not only the ones the
//     observation mapping can produce.
//   - The OBSERVATION MAPPING (Observations -> evidence) has no counterpart in
//     the model: the model's `emit` maps a Deployment and an adversary, which
//     cilock cannot observe. Generated observations are pushed through the Go
//     mapping and the resulting evidence is evaluated by BOTH sides, so the
//     mapping is exercised, but its correctness is argued in guidance.go, not
//     proved.
//
// Set CIPROV_EVAL to a built `ciprov-eval`; otherwise it is built from
// ../../formal/ci-provenance with lake, and the test skips when neither
// exists (the model lives on feat/formal-ci-provenance until it merges).
func TestCeilingMatchesLeanModel(t *testing.T) {
	eval := leanEvaluator(t)

	var slsaCases []SLSAEvidence
	for m := 0; m < 1<<5; m++ {
		slsaCases = append(slsaCases, SLSAEvidence{
			Present: m&1 != 0, HostedWorkflowSigner: m&2 != 0, TrustedBuilderSigner: m&4 != 0,
			Timestamped: m&8 != 0, EphemeralRunner: m&16 != 0,
		})
	}
	var alpsCases []ALPSEvidence
	for m := 0; m < 1<<6; m++ {
		alpsCases = append(alpsCases, ALPSEvidence{
			Signed: m&1 != 0, Issued: m&2 != 0, Timestamped: m&4 != 0,
			BoundaryClaimed: m&8 != 0, BoundaryByObserver: m&16 != 0, Isolated: m&32 != 0,
		})
	}
	principals := []string{PrincipalUnknown, PrincipalKey, PrincipalHuman, PrincipalAgent, PrincipalWorkflow}
	rng := rand.New(rand.NewSource(20260924)) //nolint:gosec // deterministic test cases, not crypto
	for i := 0; i < 2000; i++ {
		o := Observations{
			Signed: rng.Intn(4) != 0, Provenance: rng.Intn(3) != 0, Timestamped: rng.Intn(3) != 0,
			HostedRunner: rng.Intn(2) == 0, TrustedBuilder: rng.Intn(3) == 0,
			BoundaryByObserver: rng.Intn(4) == 0, Isolated: rng.Intn(4) == 0,
			Principal: principals[rng.Intn(len(principals))],
		}
		slsaCases = append(slsaCases, o.SLSAEvidence())
		alpsCases = append(alpsCases, o.ALPSEvidence())
	}

	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, c := range slsaCases {
		if err := enc.Encode(struct {
			Fn string `json:"fn"`
			SLSAEvidence
		}{"slsa", c}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range alpsCases {
		if err := enc.Encode(struct {
			Fn string `json:"fn"`
			ALPSEvidence
		}{"alps", c}); err != nil {
			t.Fatal(err)
		}
	}
	out := runLeanEvaluator(t, eval, in.Bytes())
	if want := len(slsaCases) + len(alpsCases); len(out) != want {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), want)
	}
	seenSLSA, seenALPS := map[SLSALevel]int{}, map[ALPSLevel]int{}
	for i, c := range slsaCases {
		lean := leanLevel(t, i, out[i])
		got := DeriveSLSA(c)
		seenSLSA[got]++
		if got.String() != lean {
			t.Fatalf("slsa case %d %+v: Go %s, Lean %s", i, c, got, lean)
		}
	}
	for j, c := range alpsCases {
		i := len(slsaCases) + j
		lean := leanLevel(t, i, out[i])
		got := DeriveALPS(c)
		seenALPS[got]++
		if got.String() != lean {
			t.Fatalf("alps case %d %+v: Go %s, Lean %s", j, c, got, lean)
		}
	}
	// Guard against a vacuous pass: every level must have occurred.
	for _, l := range []SLSALevel{SLSANone, SLSAL1, SLSAL2, SLSAL3} {
		if seenSLSA[l] == 0 {
			t.Fatalf("no case produced SLSA %s", l)
		}
	}
	for _, l := range []ALPSLevel{ALPSUnknown, ALPS0, ALPS1, ALPS2, ALPS3} {
		if seenALPS[l] == 0 {
			t.Fatalf("no case produced %s", l)
		}
	}
	t.Logf("%d SLSA and %d ALPS cases agree: %v %v", len(slsaCases), len(alpsCases), seenSLSA, seenALPS)
}

func leanLevel(t *testing.T, i int, raw []byte) string {
	t.Helper()
	var r struct {
		Level string `json:"level"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.Error != "" {
		t.Fatalf("case %d: lean result %q: %v %s", i, raw, err, r.Error)
	}
	return r.Level
}

func leanEvaluator(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("CIPROV_EVAL"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("CIPROV_EVAL=%s: %v", bin, err)
		}
		return bin
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "formal", "ci-provenance"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, ".lake", "build", "bin", "ciprov-eval")
	// Always run the incremental build: reusing an existing binary would
	// compare the code against whatever model was built last.
	if _, err := os.Stat(dir); err != nil {
		t.Skip("Lean model formal/ci-provenance not in this tree; set CIPROV_EVAL to run the differential test")
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
