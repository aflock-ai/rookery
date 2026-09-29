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

package semgrep

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// formal:differential semgrep-attestor TestSelectMatchesLeanModel TestSummaryMatchesLeanModel

// The theorems in formal/semgrep-attestor (design doc §3.11) are about this
// code only while the Go and the model compute the same thing. These tests run
// the same cases through Attest and through `semgrep-eval`, the model's JSON
// evaluator, and fail on the first disagreement. They skip when the evaluator
// is neither built nor buildable (no `lake`).

type leanClass string

const (
	classForeign leanClass = "foreign"
	classBroken  leanClass = "broken"
	classGood    leanClass = "good"
)

// TestSelectMatchesLeanModel checks which product Attest signs, if any,
// against `select` (SemgrepAttestor/Select.lean). Each product is built to be
// of one class; broken ones rotate through the three ways a claiming report
// fails (cut off, a required member absent, bytes that differ from the
// recorded digest), so the model's single `broken` class is exercised by each.
func TestSelectMatchesLeanModel(t *testing.T) {
	eval := semgrepLeanEvaluator(t)

	var cases [][]leanClass
	all := []leanClass{classForeign, classBroken, classGood}
	var enumerate func(prefix []leanClass, n int)
	enumerate = func(prefix []leanClass, n int) {
		cases = append(cases, append([]leanClass(nil), prefix...))
		if n == 0 {
			return
		}
		for _, c := range all {
			enumerate(append(prefix, c), n-1)
		}
	}
	enumerate(nil, 3)                         // every list of up to three products, the empty step included
	rng := rand.New(rand.NewSource(20260928)) //nolint:gosec // deterministic test cases, not crypto
	for i := 0; i < 60; i++ {
		c := make([]leanClass, 4+rng.Intn(3))
		for j := range c {
			c[j] = all[rng.Intn(len(all))]
		}
		cases = append(cases, c)
	}

	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, c := range cases {
		classes := make([]string, len(c))
		for i, k := range c {
			classes[i] = string(k)
		}
		require.NoError(t, enc.Encode(map[string]any{"fn": "select", "classes": classes}))
	}
	out := runSemgrepLeanEvaluator(t, eval, in.Bytes())
	require.Len(t, out, len(cases), "one lean result per case")

	seen := map[string]int{}
	for i, c := range cases {
		var r struct {
			Outcome string `json:"outcome"`
			Error   string `json:"error"`
		}
		require.NoError(t, json.Unmarshal(out[i], &r), "case %d: %s", i, out[i])
		require.Empty(t, r.Error, "case %d", i)
		got := goSelect(t, c, i)
		seen[got]++
		require.Equal(t, r.Outcome, got, "case %d %v: Go outcome vs Lean outcome", i, c)
	}
	for _, o := range []string{"soft", "refuse", "attest"} {
		require.NotZero(t, seen[o], "no case produced %q; the comparison did not exercise it", o)
	}
	t.Logf("%d cases agree: %v", len(cases), seen)
}

// goSelect builds one product per class, runs Attest and names its outcome the
// way the model does.
func goSelect(t *testing.T, classes []leanClass, caseNo int) string {
	t.Helper()
	dir := t.TempDir()
	products := map[string][]byte{}
	var swapped []string
	for i, c := range classes {
		name := fmt.Sprintf("p%d.json", i)
		good := semgrepDoc(t, []map[string]any{result(fmt.Sprintf("rule.%d", i), "a.py", i+1, 1, "ERROR", "m", nil)}, nil)
		switch c {
		case classForeign:
			products[name] = []byte(fmt.Sprintf(`{"tool":"other","n":%d}`, i))
		case classGood:
			products[name] = good
		case classBroken:
			switch (caseNo + i) % 3 {
			case 0: // cut off mid-write
				products[name] = good[:len(good)-2]
			case 1: // a required member absent
				products[name] = []byte(fmt.Sprintf(`{"version":"1.119.0","results":[],"paths":{"scanned":["p%d"]}}`, i))
			default: // replaced after cilock recorded its digest
				products[name] = good
				swapped = append(swapped, name)
			}
		}
	}
	ctx := contextWithIn(t, dir, products, nil)
	for _, name := range swapped {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o600))
	}
	err := New().Attest(ctx)
	switch {
	case err == nil:
		return "attest"
	case attestation.IsSoftError(err):
		return "soft"
	default:
		return "refuse"
	}
}

type leanFinding struct {
	ID      int    `json:"id"`
	Sev     string `json:"sev"`
	Ignored bool   `json:"ignored"`
	File    *int   `json:"file"`
}

type leanSummary struct {
	ScanComplete bool     `json:"scanComplete"`
	Critical     int      `json:"critical"`
	High         int      `json:"high"`
	Medium       int      `json:"medium"`
	Low          int      `json:"low"`
	Info         int      `json:"info"`
	Unknown      int      `json:"unknown"`
	Ignored      int      `json:"ignored"`
	Live         int      `json:"live"`
	Subjects     []string `json:"subjects"`
	Error        string   `json:"error"`
}

// rawSeverities maps each spelling Semgrep writes onto the model's bucket.
var rawSeverities = []struct{ raw, sev string }{
	{"CRITICAL", "critical"}, {"HIGH", "high"}, {"ERROR", "high"}, {"MEDIUM", "medium"},
	{"WARNING", "medium"}, {"LOW", "low"}, {"INFO", "info"}, {"info", "info"},
	{"", "unknown"}, {"EXPERIMENT", "unknown"},
}

// TestSummaryMatchesLeanModel checks the signed roll-up and subjects against
// SemgrepAttestor/Summary.lean: scanComplete, the six live severity buckets,
// the ignored and live counts, and the finding and file subjects.
func TestSummaryMatchesLeanModel(t *testing.T) {
	eval := semgrepLeanEvaluator(t)
	rng := rand.New(rand.NewSource(20260929)) //nolint:gosec // deterministic test cases, not crypto

	type sumCase struct {
		errors   int
		raw      []string
		findings []leanFinding
	}
	var cases []sumCase
	for n := 0; n < 80; n++ {
		c := sumCase{errors: []int{0, 0, 1, 3}[rng.Intn(4)]}
		for i := rng.Intn(7); i > 0; i-- {
			id := len(c.findings)
			s := rawSeverities[rng.Intn(len(rawSeverities))]
			f := leanFinding{ID: id, Sev: s.sev, Ignored: rng.Intn(3) == 0}
			if rng.Intn(4) != 0 {
				d := id
				f.File = &d
			}
			c.findings = append(c.findings, f)
			c.raw = append(c.raw, s.raw)
		}
		cases = append(cases, c)
	}

	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, c := range cases {
		fs := c.findings
		if fs == nil {
			fs = []leanFinding{}
		}
		require.NoError(t, enc.Encode(map[string]any{"fn": "summary", "errors": c.errors, "findings": fs}))
	}
	out := runSemgrepLeanEvaluator(t, eval, in.Bytes())
	require.Len(t, out, len(cases), "one lean result per case")

	var incomplete, ignored, fileSubjects int
	for i, c := range cases {
		var want leanSummary
		require.NoError(t, json.Unmarshal(out[i], &want), "case %d: %s", i, out[i])
		require.Empty(t, want.Error, "case %d", i)
		sort.Strings(want.Subjects)
		if want.Subjects == nil {
			want.Subjects = []string{}
		}
		want.Error = ""

		got := goSummary(t, c.errors, c.raw, c.findings)
		require.Equal(t, want, got, "case %d %+v: Go summary vs Lean summary", i, c)
		if !got.ScanComplete {
			incomplete++
		}
		ignored += got.Ignored
		for _, s := range got.Subjects {
			if strings.HasPrefix(s, "file:") {
				fileSubjects++
			}
		}
	}
	require.NotZero(t, incomplete, "no incomplete scan was compared")
	require.NotZero(t, ignored, "no ignored finding was compared")
	require.NotZero(t, fileSubjects, "no file subject was compared")
	t.Logf("%d cases agree", len(cases))
}

// goSummary builds the report and the recorded materials a case describes,
// runs Attest, and projects the predicate onto the model's vocabulary. Rule
// subjects are dropped: the model omits them, as they carry no evidence of
// their own.
func goSummary(t *testing.T, nErrors int, raw []string, findings []leanFinding) leanSummary {
	t.Helper()
	results := make([]map[string]any, 0, len(findings))
	materials := map[string][]byte{}
	fileOf := map[string]string{} // recorded digest -> "file:<id>"
	for i, f := range findings {
		path := fmt.Sprintf("f%d.py", f.ID)
		results = append(results, result(fmt.Sprintf("rule.%d", f.ID), path, 1, 1, raw[i], "m",
			map[string]any{"is_ignored": f.Ignored}))
		if f.File != nil {
			src := []byte(fmt.Sprintf("print(%d)\n", *f.File))
			materials[path] = src
			fileOf[sha256Hex(t, src)] = fmt.Sprintf("file:%d", *f.File)
		}
	}
	errs := make([]map[string]any, 0, nErrors)
	for i := 0; i < nErrors; i++ {
		errs = append(errs, map[string]any{"code": 3, "level": "warn", "type": "Timeout", "message": fmt.Sprintf("e%d", i), "path": "x.py"})
	}
	a := attest(t, contextWith(t, map[string][]byte{"semgrep.json": semgrepDoc(t, results, errs)}, materials))

	s := a.Summary
	got := leanSummary{
		ScanComplete: s.ScanComplete,
		Critical:     s.BySeverity.Critical,
		High:         s.BySeverity.High,
		Medium:       s.BySeverity.Medium,
		Low:          s.BySeverity.Low,
		Info:         s.BySeverity.Info,
		Unknown:      s.BySeverity.Unknown,
		Ignored:      s.IgnoredCount,
		Live:         s.TotalFindings - s.IgnoredCount,
		Subjects:     []string{},
	}
	findingOf := map[string]string{} // finding id -> "finding:<id>"
	for _, f := range s.Findings {
		findingOf[f.ID] = "finding:" + strings.TrimPrefix(f.RuleID, "rule.")
	}
	for key, ds := range a.Subjects() {
		switch {
		case strings.HasPrefix(key, "semgrep:finding:"):
			name, ok := findingOf[strings.TrimPrefix(key, "semgrep:finding:")]
			require.True(t, ok, "finding subject %s names no finding", key)
			got.Subjects = append(got.Subjects, name)
		case strings.HasPrefix(key, "semgrep:file:"):
			var name string
			for _, v := range ds {
				name = fileOf[v]
			}
			require.NotEmpty(t, name, "file subject %s carries no recorded digest", key)
			got.Subjects = append(got.Subjects, name)
		case strings.HasPrefix(key, "semgrep:rule:"):
		default:
			t.Fatalf("unexpected subject %s", key)
		}
	}
	sort.Strings(got.Subjects)
	return got
}

// semgrepLeanEvaluator returns the path of the built `semgrep-eval`, building
// it with lake when needed, or skips.
func semgrepLeanEvaluator(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "formal", "semgrep-attestor"))
	require.NoError(t, err)
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("`lake` not on PATH; install elan to run the differential test")
	}
	// Always build: lake is incremental, and a stale binary would compare the
	// Go against an older model.
	build := exec.Command(lake, "build", "semgrep-eval")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build semgrep-eval: %v\n%s", err, out)
	}
	return filepath.Join(dir, ".lake", "build", "bin", "semgrep-eval")
}

func runSemgrepLeanEvaluator(t *testing.T, bin string, input []byte) [][]byte {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(input)
	raw, err := cmd.Output()
	require.NoError(t, err, "semgrep-eval")
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	require.NoError(t, sc.Err())
	return lines
}
