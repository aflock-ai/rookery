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

// Package testresults emits a structured attestation predicate covering
// test-run results in two canonical formats: JUnit XML (legacy, ubiquitous)
// and CTRF JSON (https://ctrf.io/). SLSA Level 3 essentially requires
// evidence that tests ran and passed; this attestor closes that loop by
// recording a tamper-evident summary (totals, failed tests, tool identity)
// plus a digest of the source report file.
package testresults

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	// Name is the attestor identifier consumers pass to --attestations.
	Name = "test-results"
	// Type is the in-toto predicate type URL.
	Type = "https://aflock.ai/attestations/test-results/v0.1"
	// RunType marks this attestor as running after products are produced.
	RunType = attestation.PostProductRunType

	// Wire format identifiers stored verbatim in Predicate.Format.
	FormatJUnitXML = "junit-xml"
	FormatCTRFJSON = "ctrf-json"

	// maxFailedTests caps the embedded failed-test list. Failed counts
	// in Summary are always exact — the trim only affects the per-test
	// detail snippets that downstream tooling renders.
	maxFailedTests = 50
)

// Compile-time interface checks. The attestor exposes a typed predicate
// (Attest) plus subject extraction for graph linkage (Subjects).
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// Predicate is the JSON shape signed inside the attestation envelope.
// It is deliberately format-agnostic: the Format field carries the source
// dialect so consumers know which inputs to expect, but every other field
// is normalized so a rego policy can be written once and gate both JUnit
// and CTRF reports uniformly.
type Predicate struct {
	Format       string               `json:"format"`
	ToolName     string               `json:"toolName,omitempty"`
	ToolVersion  string               `json:"toolVersion,omitempty"`
	Summary      Summary              `json:"summary"`
	FailedTests  []FailedTest         `json:"failedTests,omitempty"`
	ReportFile   string               `json:"reportFile"`
	ReportDigest cryptoutil.DigestSet `json:"reportDigest"`
}

// Summary holds the aggregate counts. DurationSeconds is the wall-clock
// time of the run as reported by the source format; both JUnit and CTRF
// expose this so it is always populated for a well-formed input.
type Summary struct {
	Total           int     `json:"total"`
	Passed          int     `json:"passed"`
	Failed          int     `json:"failed"`
	Skipped         int     `json:"skipped"`
	Errors          int     `json:"errors,omitempty"`
	DurationSeconds float64 `json:"durationSeconds"`
}

// FailedTest captures the per-failure information policies need to render
// diagnostic output. Both Suite and Classname are kept because JUnit
// frameworks vary in which they populate (pytest fills Classname; many
// Java frameworks fill Suite via the parent testsuite name).
type FailedTest struct {
	Name      string  `json:"name"`
	Suite     string  `json:"suite,omitempty"`
	Classname string  `json:"classname,omitempty"`
	Message   string  `json:"message,omitempty"`
	Duration  float64 `json:"duration,omitempty"`
}

// Attestor is the registered attestation.Attestor implementation. The
// embedded Predicate is what gets marshaled into the DSSE envelope.
type Attestor struct {
	Predicate Predicate `json:"predicate"`

	// suites records the top-level suite names observed during parsing
	// so Subjects() can emit `test-suite:` graph edges without re-walking
	// the source report.
	suites []string
}

// New constructs an empty Attestor ready for Attest().
func New() *Attestor {
	return &Attestor{}
}

// Name returns the registered attestor name.
func (a *Attestor) Name() string { return Name }

// Type returns the in-toto predicate type URL.
func (a *Attestor) Type() string { return Type }

// RunType returns the lifecycle phase this attestor wants to run in.
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema returns the JSON schema describing the Predicate shape.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

// Attest scans the product set for a JUnit-XML or CTRF-JSON report and
// records a normalized summary plus the source digest.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/test-results) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects exposes graph-edge identifiers derived from the test report:
//   - "test-suite:<name>" for each top-level suite observed.
//   - "test-failure:<fqName>" for each failed test (cross-attestation
//     linkage to PR/commit attestations).
//
// Subject values are SHA-256 digests of the identifier string, matching
// the convention established by the prowler and aws-codebuild attestors.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	add := func(key, value string) {
		if value == "" {
			return
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/test-results) failed to hash subject %s: %v", key, err)
			return
		}
		subjects[key] = ds
	}

	seenSuite := make(map[string]bool)
	for _, s := range a.suites {
		if s == "" || seenSuite[s] {
			continue
		}
		seenSuite[s] = true
		add(fmt.Sprintf("test-suite:%s", s), s)
	}

	seenFail := make(map[string]bool)
	for _, f := range a.Predicate.FailedTests {
		fq := failedFQName(f)
		if fq == "" || seenFail[fq] {
			continue
		}
		seenFail[fq] = true
		add(fmt.Sprintf("test-failure:%s", fq), fq)
	}

	return subjects
}

// failedFQName composes a stable fully-qualified identifier for a failed
// test. JUnit frameworks tend to fill Classname (pytest, Maven Surefire);
// CTRF emitters tend to fill Suite (Jest, Mocha). Either is accepted; if
// both are empty we fall back to the bare test name.
func failedFQName(f FailedTest) string {
	switch {
	case f.Classname != "" && f.Name != "":
		return f.Classname + "." + f.Name
	case f.Suite != "" && f.Name != "":
		return f.Suite + "::" + f.Name
	default:
		return f.Name
	}
}

// getCandidate walks the AttestationContext products, picks the first
// file whose bytes look like JUnit XML or CTRF JSON, and populates the
// Predicate. Detection is intentionally byte-based (peek at the first
// non-whitespace byte) rather than MIME-based so a misconfigured product
// classifier doesn't silently skip a valid test report.
func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		fullPath := filepath.Join(ctx.WorkingDir(), path)

		// Verify the file on disk still matches the digest the product
		// attestor recorded — the rest of the pipeline assumes this
		// invariant, so a mismatch means a TOCTOU and we refuse to
		// attest the file. This mirrors the prowler/sarif pattern.
		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(fullPath, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/test-results) digest calc failed for %s: %v", path, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/test-results) integrity error for %s", path)
			continue
		}

		f, err := os.Open(fullPath) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/test-results) open %s: %v", fullPath, err)
			continue
		}
		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/test-results) read %s: %v", fullPath, err)
			continue
		}

		format := detectFormat(reportBytes)
		if format == "" {
			continue
		}

		pred, suites, err := parseReport(format, reportBytes)
		if err != nil {
			log.Debugf("(attestation/test-results) parse %s as %s: %v", path, format, err)
			continue
		}

		pred.ReportFile = path
		pred.ReportDigest = product.Digest
		a.Predicate = pred
		a.suites = suites
		return nil
	}

	return fmt.Errorf("no JUnit XML or CTRF JSON test report found in products")
}

// detectFormat peeks at the first non-whitespace byte to discriminate
// JUnit XML (`<`) from CTRF JSON (`{`). The two formats can never
// collide because the first byte uniquely identifies the document type
// per their respective specs (XML 1.0 §2.1 prolog, RFC 8259 §2 object).
// A leading BOM is tolerated.
func detectFormat(b []byte) string {
	// Strip UTF-8 BOM if present.
	b = trimBOM(b)
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '<':
			return FormatJUnitXML
		case '{':
			return FormatCTRFJSON
		default:
			return ""
		}
	}
	return ""
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func parseReport(format string, b []byte) (Predicate, []string, error) {
	switch format {
	case FormatJUnitXML:
		return parseJUnit(b)
	case FormatCTRFJSON:
		return parseCTRF(b)
	default:
		return Predicate{}, nil, fmt.Errorf("unknown format %q", format)
	}
}

// --- JUnit XML ----------------------------------------------------------

// junitTestsuites mirrors the root element of a JUnit report. JUnit has
// no canonical schema; this struct captures the union of fields the
// `go-junit-report`, `pytest`, Maven Surefire, and Gradle dialects emit.
// Unknown attributes are ignored by encoding/xml, so future extensions
// won't break parsing.
type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Skipped  int              `xml:"skipped,attr"`
	Time     float64          `xml:"time,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

// junitTestsuite handles both the nested case (under <testsuites>) and
// the standalone case (a single <testsuite> root, which some emitters
// produce). The decoder logic in parseJUnit handles both via a second
// unmarshal attempt.
type junitTestsuite struct {
	XMLName  xml.Name        `xml:"testsuite"`
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Skipped  int             `xml:"skipped,attr"`
	Time     float64         `xml:"time,attr"`
	Cases    []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitMessage `xml:"failure"`
	Error     *junitMessage `xml:"error"`
	Skipped   *junitMessage `xml:"skipped"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

func parseJUnit(b []byte) (Predicate, []string, error) {
	// Try the <testsuites> root first; fall back to a bare <testsuite>.
	var root junitTestsuites
	if err := xml.Unmarshal(b, &root); err != nil || len(root.Suites) == 0 {
		var single junitTestsuite
		if err2 := xml.Unmarshal(b, &single); err2 == nil && single.Name != "" {
			root.Suites = []junitTestsuite{single}
			root.Tests = single.Tests
			root.Failures = single.Failures
			root.Errors = single.Errors
			root.Skipped = single.Skipped
			root.Time = single.Time
		} else if err != nil {
			return Predicate{}, nil, fmt.Errorf("invalid JUnit XML: %w", err)
		}
	}

	if len(root.Suites) == 0 {
		return Predicate{}, nil, fmt.Errorf("JUnit document contains no testsuite elements")
	}

	pred := Predicate{Format: FormatJUnitXML}
	var suites []string
	var failed []FailedTest

	// JUnit attribute totals are advisory — many emitters get them wrong
	// (pytest counts errors as failures, go-junit-report drops zero
	// values entirely). Recompute from the actual cases.
	var total, passed, failures, errors, skipped int
	var totalTime float64
	for _, ts := range root.Suites {
		suites = append(suites, ts.Name)
		totalTime += ts.Time

		for _, tc := range ts.Cases {
			total++
			switch {
			case tc.Failure != nil:
				failures++
				failed = appendBounded(failed, FailedTest{
					Name:      tc.Name,
					Suite:     ts.Name,
					Classname: tc.Classname,
					Message:   firstNonEmpty(tc.Failure.Message, tc.Failure.Body),
					Duration:  tc.Time,
				})
			case tc.Error != nil:
				errors++
				failed = appendBounded(failed, FailedTest{
					Name:      tc.Name,
					Suite:     ts.Name,
					Classname: tc.Classname,
					Message:   firstNonEmpty(tc.Error.Message, tc.Error.Body),
					Duration:  tc.Time,
				})
			case tc.Skipped != nil:
				skipped++
			default:
				passed++
			}
		}
	}

	// If the document only published totals at the root and emitted no
	// individual <testcase> elements, fall back to the root attributes.
	// This shouldn't happen for any conformant emitter but defends
	// against minimal/summary-only reports.
	if total == 0 && root.Tests > 0 {
		total = root.Tests
		failures = root.Failures
		errors = root.Errors
		skipped = root.Skipped
		passed = total - failures - errors - skipped
		if passed < 0 {
			passed = 0
		}
		totalTime = root.Time
	}

	pred.Summary = Summary{
		Total:           total,
		Passed:          passed,
		Failed:          failures,
		Skipped:         skipped,
		Errors:          errors,
		DurationSeconds: totalTime,
	}
	pred.FailedTests = failed
	return pred, suites, nil
}

// --- CTRF JSON ----------------------------------------------------------

// ctrfReport mirrors the parts of the CTRF schema this attestor reads.
// Full schema: https://ctrf.io/docs/schema/overview
type ctrfReport struct {
	Results ctrfResults `json:"results"`
}

type ctrfResults struct {
	Tool    ctrfTool    `json:"tool"`
	Summary ctrfSummary `json:"summary"`
	Tests   []ctrfTest  `json:"tests"`
}

type ctrfTool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ctrfSummary fields are integers per the CTRF schema. Start/Stop are
// epoch values whose unit is not pinned by the spec — some emitters use
// seconds, others (Jest's reporter) use milliseconds. We disambiguate
// in parseCTRF by clamping the magnitude.
type ctrfSummary struct {
	Tests   int   `json:"tests"`
	Passed  int   `json:"passed"`
	Failed  int   `json:"failed"`
	Skipped int   `json:"skipped"`
	Pending int   `json:"pending"`
	Other   int   `json:"other"`
	Start   int64 `json:"start"`
	Stop    int64 `json:"stop"`
}

// ctrfTest fields per CTRF schema. Duration is in milliseconds in the
// canonical spec; we convert to seconds for the predicate so JUnit and
// CTRF report-data is unit-compatible downstream.
type ctrfTest struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration int64  `json:"duration"`
	Suite    string `json:"suite,omitempty"`
	Message  string `json:"message,omitempty"`
	Type     string `json:"type,omitempty"`
}

func parseCTRF(b []byte) (Predicate, []string, error) {
	var rep ctrfReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return Predicate{}, nil, fmt.Errorf("invalid CTRF JSON: %w", err)
	}
	if rep.Results.Tool.Name == "" && len(rep.Results.Tests) == 0 && rep.Results.Summary.Tests == 0 {
		// A document with none of the three CTRF anchor fields is not
		// CTRF — better to reject explicitly than emit an empty
		// predicate.
		return Predicate{}, nil, fmt.Errorf("not a CTRF report: missing results.tool.name, results.tests, and results.summary.tests")
	}

	pred := Predicate{
		Format:      FormatCTRFJSON,
		ToolName:    rep.Results.Tool.Name,
		ToolVersion: rep.Results.Tool.Version,
	}

	// Build summary. Trust the summary block's totals; if it under-
	// reports compared to the tests array, take the test array as truth
	// (some emitters forget to update summary on dynamic test discovery).
	s := rep.Results.Summary
	if s.Tests == 0 && len(rep.Results.Tests) > 0 {
		s = recomputeCTRFSummary(rep.Results.Tests)
		s.Start = rep.Results.Summary.Start
		s.Stop = rep.Results.Summary.Stop
	}

	pred.Summary = Summary{
		Total:           s.Tests,
		Passed:          s.Passed,
		Failed:          s.Failed,
		Skipped:         s.Skipped + s.Pending,
		DurationSeconds: ctrfDurationSeconds(s.Start, s.Stop),
	}

	// Collect failed tests and unique suite names. CTRF emitters use a
	// flat tests array; the suite field is a single string per test
	// (Jest's reporter formats it as "<file> > <describe>", which we
	// preserve verbatim).
	suiteSet := make(map[string]bool)
	var suites []string
	var failed []FailedTest
	for _, t := range rep.Results.Tests {
		if t.Suite != "" && !suiteSet[t.Suite] {
			suiteSet[t.Suite] = true
			suites = append(suites, t.Suite)
		}
		if strings.EqualFold(t.Status, "failed") {
			failed = appendBounded(failed, FailedTest{
				Name:     t.Name,
				Suite:    t.Suite,
				Message:  t.Message,
				Duration: float64(t.Duration) / 1000.0,
			})
		}
	}
	pred.FailedTests = failed
	return pred, suites, nil
}

// recomputeCTRFSummary aggregates a fresh ctrfSummary from a tests array.
// Used when the source document omits per-bucket counts but does include
// per-test status — splitting this out keeps parseCTRF's complexity under
// the project's gocyclo budget.
func recomputeCTRFSummary(tests []ctrfTest) ctrfSummary {
	s := ctrfSummary{Tests: len(tests)}
	for _, t := range tests {
		switch strings.ToLower(t.Status) {
		case "passed":
			s.Passed++
		case "failed":
			s.Failed++
		case "skipped":
			s.Skipped++
		case "pending":
			s.Pending++
		default:
			s.Other++
		}
	}
	return s
}

// ctrfDurationSeconds converts a CTRF (start, stop) pair to seconds.
// Heuristic: if either value is greater than 1e12, it is a millisecond
// epoch (Jest, Mocha) — divide by 1000 to recover seconds. Otherwise
// the values are seconds (the spec's nominal unit).
func ctrfDurationSeconds(start, stop int64) float64 {
	if stop <= start {
		return 0
	}
	d := stop - start
	if start > 1_000_000_000_000 || stop > 1_000_000_000_000 {
		return float64(d) / 1000.0
	}
	return float64(d)
}

// --- helpers ------------------------------------------------------------

func appendBounded(dst []FailedTest, item FailedTest) []FailedTest {
	if len(dst) >= maxFailedTests {
		return dst
	}
	return append(dst, item)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return strings.TrimSpace(b)
}
