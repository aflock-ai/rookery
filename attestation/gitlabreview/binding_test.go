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

package gitlabreview

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math/rand"
	"os/exec"
	"path/filepath"
	"testing"
)

// formal:differential cilock-ci TestBindingMatchesLeanModel

// TestApprovalOnTheParentShaDoesNotCount is Cole's ruling as a test: the
// parent was pushed at 10, the head at 20, and an approval given at 15 was
// given on the parent. It does not count for the head; it would count for
// the parent. An approval after the head's version counts.
func TestApprovalOnTheParentShaDoesNotCount(t *testing.T) {
	vs := []Version{{Head: "parent", CreatedAt: 10}, {Head: "head", CreatedAt: 20}}
	onParent := []Approval{{User: 7, ApprovedAt: 15}}
	if n := CountFor(0, vs, onParent, 100, "head", nil); n != 0 {
		t.Fatalf("an approval given on the parent sha counted %d for the head", n)
	}
	if n := CountFor(0, vs, onParent, 100, "parent", nil); n != 1 {
		t.Fatalf("the approval must still bind to the parent, counted %d", n)
	}
	if n := CountFor(0, vs, []Approval{{User: 7, ApprovedAt: 25}}, 100, "head", nil); n != 1 {
		t.Fatalf("an approval after the head's version must count, got %d", n)
	}
}

func TestBindingEdges(t *testing.T) {
	vs := []Version{{Head: "a", CreatedAt: 10}, {Head: "b", CreatedAt: 20}, {Head: "a", CreatedAt: 30}}
	for name, c := range map[string]struct {
		skew, at int64
		want     string
	}{
		"tie is unbound":                 {0, 20, ""},
		"before every version":           {0, 5, ""},
		"inside the clock guard":         {60, 70, ""},
		"force-push back rebinds to a":   {0, 35, "a"},
		"between a and b binds to a":     {0, 15, "a"},
		"past the guard binds to newest": {60, 100, "a"},
		"a negative guard binds nothing": {-5, 20, ""},
	} {
		got, _ := BoundHead(c.skew, vs, c.at)
		if got != c.want {
			t.Errorf("%s: bound %q, want %q", name, got, c.want)
		}
	}
	if Counts(0, vs, 30, "a", Approval{User: 1, ApprovedAt: 35}) {
		t.Error("an approval after the merge must not count")
	}
	author := int64(1)
	if n := CountFor(0, vs, []Approval{{1, 35}, {2, 36}, {2, 37}}, 100, "a", &author); n != 1 {
		t.Errorf("author excluded and duplicates collapsed: got %d, want 1", n)
	}
	if _, ok := BoundHead(0, []Version{{"x", 10}, {"y", 10}}, 20); ok {
		t.Error("two heads at the newest instant must bind to nothing")
	}
}

// TestBindingMatchesLeanModel runs generated timelines through BoundHead and
// CountFor and through `boundHead`/`countFor` in formal/cilock-ci
// (CilockCi/Review.lean), whose theorems include other_sha_not_counted.
func TestBindingMatchesLeanModel(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "formal", "cilock-ci"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, ".lake", "build", "bin", "cilock-ci-eval")
	if lake, lerr := exec.LookPath("lake"); lerr == nil {
		b := exec.Command(lake, "build", "cilock-ci-eval")
		b.Dir = dir
		if out, berr := b.CombinedOutput(); berr != nil {
			t.Fatalf("lake build: %v\n%s", berr, out)
		}
	} else {
		t.Skip("Lean evaluator not built and `lake` not on PATH")
	}
	rng := rand.New(rand.NewSource(20260929)) //nolint:gosec // deterministic cases
	type tc struct {
		vs       []Version
		as       []Approval
		skew, at int64
		merged   int64
		head     string
		author   *int64
	}
	heads := []string{"a", "b", "c"}
	var cases []tc
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for i := 0; i < 3000; i++ {
		c := tc{skew: []int64{0, 0, 0, 2}[rng.Intn(4)], merged: int64(rng.Intn(40)), head: heads[rng.Intn(3)]}
		for n := rng.Intn(4); n > 0; n-- {
			c.vs = append(c.vs, Version{Head: heads[rng.Intn(3)], CreatedAt: int64(rng.Intn(30))})
		}
		for n := rng.Intn(4); n > 0; n-- {
			c.as = append(c.as, Approval{User: int64(rng.Intn(3)), ApprovedAt: int64(rng.Intn(40))})
		}
		c.at = int64(rng.Intn(40))
		if rng.Intn(3) == 0 {
			u := int64(rng.Intn(3))
			c.author = &u
		}
		vs := make([]map[string]any, 0, len(c.vs))
		for _, v := range c.vs {
			vs = append(vs, map[string]any{"head": v.Head, "createdAt": v.CreatedAt})
		}
		as := make([]map[string]any, 0, len(c.as))
		for _, a := range c.as {
			as = append(as, map[string]any{"user": a.User, "at": a.ApprovedAt})
		}
		row := map[string]any{"fn": "review", "env": []any{}, "versions": vs, "approvals": as, "skew": c.skew,
			"t": c.at, "mergedAt": c.merged, "head": c.head}
		if c.author != nil {
			row["author"] = *c.author
		}
		if err := enc.Encode(row); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, c)
	}
	cmd := exec.Command(bin)
	cmd.Stdin = &in
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	bound, counted := 0, 0
	for i := 0; sc.Scan(); i++ {
		var want struct {
			Bound *string `json:"bound"`
			Count int     `json:"count"`
		}
		if err := json.Unmarshal(sc.Bytes(), &want); err != nil {
			t.Fatalf("case %d: %s", i, sc.Bytes())
		}
		c := cases[i]
		gotHead, ok := BoundHead(c.skew, c.vs, c.at)
		if ok != (want.Bound != nil) || (ok && gotHead != *want.Bound) {
			t.Fatalf("case %d %+v: Go bound (%q,%v), Lean %v", i, c, gotHead, ok, want.Bound)
		}
		if got := CountFor(c.skew, c.vs, c.as, c.merged, c.head, c.author); got != want.Count {
			t.Fatalf("case %d %+v: Go count %d, Lean %d", i, c, got, want.Count)
		}
		if ok {
			bound++
		}
		counted += want.Count
	}
	if bound < 300 || counted < 150 {
		t.Fatalf("generator starved: %d bound, %d counted", bound, counted)
	}
	t.Logf("%d cases agree (%d bound, %d approvals counted)", len(cases), bound, counted)
}
