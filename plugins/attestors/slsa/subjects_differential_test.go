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
	"bufio"
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// formal:differential ci-provenance TestSubjectsMatchLeanModel

// TestSubjectsMatchLeanModel runs random product and subject maps through
// Provenance.Subjects and through `slsaSubjects` in the Lean model
// (formal/ci-provenance, CiProvenance/Subjects.lean), and requires the same
// subject map, digest algorithm by digest algorithm. The subject-binding
// theorems there are about this function only while the two agree.
//
// It skips when the Lean evaluator is neither built nor buildable (no `lake`).
func TestSubjectsMatchLeanModel(t *testing.T) {
	eval := leanEvaluator(t)
	rng := rand.New(rand.NewSource(20260924)) //nolint:gosec // deterministic test cases, not crypto
	algs := []string{"sha256", "sha1", "gitoid:sha256", "gitoid:sha1", "dirHash"}
	names := []string{"app", "lib/a.so", "file:app", "tree:products", "manifestdigest:x", ""}
	values := []string{"aa", "bb", "cc"}

	randomSet := func() map[string]string {
		m := map[string]string{}
		for _, a := range algs {
			if rng.Intn(2) == 0 {
				m[a] = values[rng.Intn(len(values))]
			}
		}
		return m
	}
	type pair = [2]any
	encode := func(m map[string]map[string]string) []pair {
		var out []pair
		for n, ds := range m {
			var d [][2]string
			for a, v := range ds {
				d = append(d, [2]string{a, v})
			}
			if d == nil {
				d = [][2]string{}
			}
			out = append(out, pair{n, d})
		}
		if out == nil {
			out = []pair{}
		}
		return out
	}

	const cases = 1000
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	want := make([]map[string]map[string]string, 0, cases)
	collisions := 0
	for i := 0; i < cases; i++ {
		products := map[string]map[string]string{}
		extra := map[string]map[string]string{}
		for n := rng.Intn(4); n > 0; n-- {
			products[names[rng.Intn(len(names))]] = randomSet()
		}
		for n := rng.Intn(3); n > 0; n-- {
			k := names[rng.Intn(len(names))]
			if rng.Intn(3) == 0 {
				k = "file:" + names[rng.Intn(len(names))]
			}
			extra[k] = randomSet()
		}
		p := &Provenance{products: map[string]attestation.Product{}, subjects: map[string]cryptoutil.DigestSet{}}
		for n, ds := range products {
			d, err := cryptoutil.NewDigestSet(ds)
			if err != nil {
				t.Fatal(err)
			}
			p.products[n] = attestation.Product{Digest: d}
		}
		for k, ds := range extra {
			d, err := cryptoutil.NewDigestSet(ds)
			if err != nil {
				t.Fatal(err)
			}
			p.subjects[k] = d
			if _, ok := products[strings.TrimPrefix(k, "file:")]; ok && strings.HasPrefix(k, "file:") {
				collisions++
			}
		}
		got := map[string]map[string]string{}
		for k, d := range p.Subjects() {
			nm, err := d.ToNameMap()
			if err != nil {
				t.Fatal(err)
			}
			got[k] = nm
		}
		want = append(want, got)
		if err := enc.Encode(map[string]any{"fn": "slsaSubjects", "products": encode(products), "extra": encode(extra)}); err != nil {
			t.Fatal(err)
		}
	}

	out := runLeanEvaluator(t, eval, in.Bytes())
	if len(out) != cases {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), cases)
	}
	for i := range out {
		var r struct {
			Subjects [][2]json.RawMessage `json:"subjects"`
			Error    string               `json:"error"`
		}
		if err := json.Unmarshal(out[i], &r); err != nil || r.Error != "" {
			t.Fatalf("case %d: lean result %q: %v %s", i, out[i], err, r.Error)
		}
		lean := map[string]map[string]string{}
		for _, s := range r.Subjects {
			var name string
			var ds [][2]string
			if err := json.Unmarshal(s[0], &name); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(s[1], &ds); err != nil {
				t.Fatal(err)
			}
			if _, dup := lean[name]; dup {
				t.Fatalf("case %d: Lean emitted subject %q twice", i, name)
			}
			m := map[string]string{}
			for _, d := range ds {
				m[d[0]] = d[1]
			}
			lean[name] = m
		}
		if !reflect.DeepEqual(lean, want[i]) {
			t.Fatalf("case %d:\n Go   %v\n Lean %v", i, want[i], lean)
		}
	}
	// Guard against a vacuous pass: the overwrite path must have been exercised.
	if collisions == 0 {
		t.Fatal("no case put a file:<product> key in the other subjects; the overwrite path went untested")
	}
	t.Logf("%d cases agree (%d with a file: key colliding with a product)", cases, collisions)
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
