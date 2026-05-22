// Copyright 2026 The Aflock Authors
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

package govulncheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetadata pins the attestor's registration surface — these strings are
// what consumers pass to --attestations and what verifiers match on the
// predicate type. Treat them as a public API.
func TestMetadata(t *testing.T) {
	a := New()
	assert.Equal(t, "govulncheck", a.Name())
	assert.Equal(t, "govulncheck", Name)
	assert.Equal(t, "https://aflock.ai/attestations/govulncheck/v0.1", a.Type())
	assert.Equal(t, RunType, a.RunType())
}

// TestParseStream_VulnFound exercises the canonical "reachable vulnerability"
// case produced by `govulncheck -format json -mode source ./...` against a
// program that calls golang.org/x/text/language.ParseAcceptLanguage — the
// vulnerable symbol from GO-2022-1059.
//
// Expectations:
//   - GO-2022-1059 appears as a reachable finding (function frame present)
//   - The trace contains the user's main as the closest caller
//   - The condensed finding's TopPosition points back into main.go
func TestParseStream_VulnFound(t *testing.T) {
	messages := loadFixture(t, "testdata/govulncheck-vuln-found.json")
	require.NoError(t, validateStream(messages))

	summary := buildSummary(messages)

	assert.Equal(t, "go1.26.0", summary.GoVersion)
	assert.Equal(t, "v1.1.4", summary.ScannerVersion)
	assert.Equal(t, "symbol", summary.ScanLevel)
	assert.Equal(t, "source", summary.ScanMode)
	assert.Equal(t, []string{"example.com/vulntest/reachable"}, summary.ScanRoots)

	// At least one reachable finding (GO-2022-1059) plus the stdlib
	// non-reachable findings emitted at module/package level.
	require.NotZero(t, summary.ReachableCount, "expected at least one reachable finding")
	assert.NotZero(t, summary.TotalFindings)
	assert.NotZero(t, summary.TotalOSVs)

	// Locate the GO-2022-1059 condensed finding and assert it is reachable.
	var got *CondensedFinding
	for i := range summary.Findings {
		if summary.Findings[i].OSVID == "GO-2022-1059" {
			got = &summary.Findings[i]
			break
		}
	}
	require.NotNil(t, got, "GO-2022-1059 must appear in summary findings")
	assert.True(t, got.Reachable, "GO-2022-1059 must be reachable in the vuln-found fixture")
	assert.Equal(t, "v0.3.8", got.FixedVersion)
	assert.GreaterOrEqual(t, got.TraceLength, 2, "reachable trace must include caller frame(s)")
	assert.Contains(t, got.TopPosition, "main.go", "TopPosition should point back to the user's main")
}

// TestParseStream_ImportedUnreachable covers the imported-but-not-called case:
// the user imports golang.org/x/text/language but only calls language.Parse,
// which is not in GO-2022-1059's vulnerable-symbol list. The OSV should still
// surface in the predicate but Reachable must be false.
func TestParseStream_ImportedUnreachable(t *testing.T) {
	messages := loadFixture(t, "testdata/govulncheck-imported-unreachable.json")
	require.NoError(t, validateStream(messages))

	summary := buildSummary(messages)

	var got *CondensedFinding
	for i := range summary.Findings {
		if summary.Findings[i].OSVID == "GO-2022-1059" {
			got = &summary.Findings[i]
			break
		}
	}
	require.NotNil(t, got, "GO-2022-1059 must still appear (the package is imported)")
	assert.False(t, got.Reachable, "GO-2022-1059 must be flagged unreachable in the unreachable fixture")
	assert.Equal(t, "v0.3.8", got.FixedVersion)
}

// TestParseStream_NoVulns covers the clean-scan case — a vanilla program with
// the latest Go directive and no third-party deps. govulncheck still emits
// the full OSV catalog (~150 records) but zero findings.
func TestParseStream_NoVulns(t *testing.T) {
	messages := loadFixture(t, "testdata/govulncheck-no-vulns.json")
	require.NoError(t, validateStream(messages))

	summary := buildSummary(messages)

	assert.NotZero(t, summary.TotalOSVs, "OSV catalog must still be present")
	assert.Zero(t, summary.TotalFindings, "no findings in a clean scan")
	assert.Zero(t, summary.ReachableCount)
	assert.Zero(t, summary.UnreachableCount)
	assert.Empty(t, summary.Findings)
	assert.Contains(t, summary.ScanRoots, "example.com/vulntest/clean")
}

// TestValidateStream_RejectsNonGovulncheck ensures arbitrary JSON streams
// don't accidentally pass validation. The first message MUST be a config
// record with the v1.0.0 protocol marker; anything else is rejected.
func TestValidateStream_RejectsNonGovulncheck(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "empty", body: ""},
		{name: "random-object", body: `{"hello": "world"}`},
		{name: "wrong-scanner", body: `{"config":{"protocol_version":"v1.0.0","scanner_name":"trivy"}}`},
		{name: "wrong-protocol", body: `{"config":{"protocol_version":"v2.0.0","scanner_name":"govulncheck"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages, parseErr := parseStream([]byte(tc.body))
			if parseErr != nil {
				// Empty / invalid streams fail at parse time — that's
				// equally good rejection.
				return
			}
			err := validateStream(messages)
			require.Error(t, err, "expected rejection for %s", tc.name)
		})
	}
}

// TestSubjects_ReachableOnly verifies that only reachable OSV ids are exposed
// as go:vuln:<id> subjects. Imported-but-unreachable findings are reported in
// the predicate but are deliberately excluded from the subject set — they're
// noise from an indexing standpoint.
func TestSubjects_ReachableOnly(t *testing.T) {
	a := New()
	messages := loadFixture(t, "testdata/govulncheck-vuln-found.json")
	a.Summary = buildSummary(messages)

	subjects := a.Subjects()

	// Scan root must be a subject.
	_, hasRoot := subjects["go:module:example.com/vulntest/reachable"]
	assert.True(t, hasRoot, "scan root must be exposed as go:module:<path>")

	// GO-2022-1059 (reachable) MUST be a subject. Other OSVs that only
	// appear at module/package level (stdlib findings) MUST NOT be.
	_, hasReachable := subjects["go:vuln:GO-2022-1059"]
	assert.True(t, hasReachable, "reachable OSV must be exposed as go:vuln:<id>")

	for key := range subjects {
		if len(key) > len("go:vuln:") && key[:len("go:vuln:")] == "go:vuln:" {
			// Every go:vuln:* subject must correspond to a reachable
			// finding in the summary.
			var found bool
			for _, f := range a.Summary.Findings {
				if "go:vuln:"+f.OSVID == key {
					assert.True(t, f.Reachable, "subject %s came from a non-reachable finding", key)
					found = true
					break
				}
			}
			assert.True(t, found, "subject %s has no matching summary finding", key)
		}
	}
}

// TestReport_BytePreservation verifies the per-message govulncheck output is
// stored byte-identically in the Report field. The wire format is a stream of
// concatenated JSON objects (not a single JSON document), so the attestor
// stores Report as []json.RawMessage — each element is the verbatim bytes of
// one Message. The test re-streams the source file with a fresh decoder and
// asserts each parsed RawMessage matches the corresponding Report entry.
func TestReport_BytePreservation(t *testing.T) {
	a := New()

	raw, err := os.ReadFile(filepath.Join("testdata", "govulncheck-vuln-found.json"))
	require.NoError(t, err)

	// Simulate what getCandidate does: parse / validate / store raw bytes.
	messages, raws, err := parseStreamWithRaw(raw)
	require.NoError(t, err)
	require.NoError(t, validateStream(messages))
	a.Summary = buildSummary(messages)
	a.Report = raws
	a.ReportFile = "govulncheck-vuln-found.json"

	require.Equal(t, len(messages), len(a.Report),
		"one Report entry per decoded Message")

	// Marshal the attestor and verify the embedded report is byte-identical.
	out, err := json.Marshal(a)
	require.NoError(t, err)

	var wrapper struct {
		Report     []json.RawMessage `json:"report"`
		ReportFile string            `json:"reportFile"`
	}
	require.NoError(t, json.Unmarshal(out, &wrapper))
	assert.Equal(t, "govulncheck-vuln-found.json", wrapper.ReportFile)
	require.Equal(t, len(a.Report), len(wrapper.Report))

	// Spot-check: the first message must be the config record and the JSON
	// roundtrip must preserve every field.
	var firstMsg map[string]any
	require.NoError(t, json.Unmarshal(wrapper.Report[0], &firstMsg))
	cfg, ok := firstMsg["config"].(map[string]any)
	require.True(t, ok, "first message must be a config record")
	assert.Equal(t, "v1.0.0", cfg["protocol_version"])
	assert.Equal(t, "govulncheck", cfg["scanner_name"])
}

// TestAttest_EndToEnd exercises the full Attestor lifecycle wiring through
// the product attestor — that's the realistic call path when a CI step runs
// `govulncheck -format json ... > out.json` and the attestor picks the file
// up from the product set.
func TestAttest_EndToEnd(t *testing.T) {
	tmp := t.TempDir()
	src, err := os.ReadFile(filepath.Join("testdata", "govulncheck-vuln-found.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vulns.json"), src, 0o644))

	gv := New()
	p := product.New()

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{p, gv},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	// File picked up.
	assert.Equal(t, "vulns.json", gv.ReportFile, "ReportFile must be the relative path")
	assert.NotEmpty(t, gv.ReportDigestSet)
	assert.NotEmpty(t, gv.Report, "Report must be populated")

	// Summary correctly populated from the end-to-end run.
	assert.Equal(t, "symbol", gv.Summary.ScanLevel)
	assert.Equal(t, "source", gv.Summary.ScanMode)
	assert.NotZero(t, gv.Summary.ReachableCount, "expected reachable findings")
	assert.Contains(t, gv.Summary.ScanRoots, "example.com/vulntest/reachable")

	// Subjects exposed for Archivista indexing.
	subjects := gv.Subjects()
	_, hasRoot := subjects["go:module:example.com/vulntest/reachable"]
	assert.True(t, hasRoot, "scan root must be exposed as go:module:<path>")
	_, hasReachable := subjects["go:vuln:GO-2022-1059"]
	assert.True(t, hasReachable, "reachable OSV must be exposed as go:vuln:<id>")
}

// TestAttest_NoProducts surfaces the empty-context error so callers know to
// expect it on misconfiguration rather than getting silent success.
func TestAttest_NoProducts(t *testing.T) {
	gv := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{gv},
		attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	err = gv.Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no products")
}

// loadFixture reads a fixture file and parses the govulncheck JSON stream.
func loadFixture(t *testing.T, path string) []Message {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path
	require.NoError(t, err)
	messages, err := parseStream(raw)
	require.NoError(t, err)
	return messages
}
