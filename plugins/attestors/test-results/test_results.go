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
	"bytes"
	"crypto"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
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

	// maxClaimedCount bounds every count a report declares. The tally sums
	// declared counts across suites, so an unbounded one wraps the int and
	// erases a failure; a negative one cancels a sibling's. Below 2^31 per
	// attribute, a sum overflows int64 only past 2^32 suites, which no
	// report that fits in memory holds. int is 64-bit on every target cilock
	// ships (.github/workflows/release.yml: amd64 and arm64); 32-bit builds
	// are unsupported.
	maxClaimedCount = 1<<31 - 1
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
	// Cases directly under the root: Node's junit reporter writes every
	// top-level test() here, outside any <testsuite>.
	Cases []junitTestcase `xml:"testcase"`
}

// junitTestsuite handles both the nested case (under <testsuites>) and
// the standalone case (a single <testsuite> root, which some emitters
// produce). The decoder logic in parseJUnit handles both via a second
// unmarshal attempt. Suites nest: Node's junit reporter writes a
// describe() inside its parent's <testsuite>.
type junitTestsuite struct {
	XMLName  xml.Name         `xml:"testsuite"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Skipped  int              `xml:"skipped,attr"`
	Time     float64          `xml:"time,attr"`
	Cases    []junitTestcase  `xml:"testcase"`
	Suites   []junitTestsuite `xml:"testsuite"`
	// SystemErr is where Terraform 1.16+ writes a test file's own
	// diagnostics when the file fails before its runs start.
	SystemErr string `xml:"system-err"`
}

type junitTestcase struct {
	Name      string  `xml:"name,attr"`
	Classname string  `xml:"classname,attr"`
	Time      float64 `xml:"time,attr"`
	Timestamp string  `xml:"timestamp,attr"`
	// Status is CTest's (and googletest's) run status: "run", "fail",
	// "notrun" or "disabled". Most emitters leave it empty.
	Status string `xml:"status,attr"`
	// Result is googletest's: "completed", "skipped" or "suppressed".
	Result  string        `xml:"result,attr"`
	Failure *junitMessage `xml:"failure"`
	Error   *junitMessage `xml:"error"`
	Skipped *junitMessage `xml:"skipped"`
	// Surefire's rerun records. A case whose every rerun failed also carries
	// a <failure>; a lone rerun record is still a run that did not pass.
	// <flakyFailure> (failed, then passed on rerun) is a pass.
	RerunFailure []junitMessage `xml:"rerunFailure"`
	RerunError   []junitMessage `xml:"rerunError"`
}

// CTest and googletest status attribute values.
const (
	statusRun      = "run"
	statusFail     = "fail"
	statusNotRun   = "notrun"
	statusDisabled = "disabled"

	resultSkipped    = "skipped"
	resultSuppressed = "suppressed"
)

// knownStatuses and knownResults are every status/result value a supported
// emitter writes. Any other value is an outcome this parser cannot read,
// so it counts as an error rather than defaulting to a pass.
var (
	knownStatuses = map[string]bool{"": true, statusRun: true, statusFail: true, statusNotRun: true, statusDisabled: true}
	knownResults  = map[string]bool{"": true, "completed": true, resultSkipped: true, resultSuppressed: true}
)

type caseOutcome int

const (
	outcomePassed caseOutcome = iota
	outcomeFailed
	outcomeError
	outcomeSkipped
)

// classifyCase decides one <testcase>'s outcome and, for a failure or
// error, its message. A case its runner did not run is never a pass.
func classifyCase(suite, systemErr string, tc junitTestcase) (caseOutcome, string) {
	notRun, couldNotRun := notRunError(tc)
	switch {
	case terraformRunNotStarted(suite, tc):
		return outcomeError, terraformNotStartedMessage(systemErr)
	case tc.Failure != nil:
		return outcomeFailed, firstNonEmpty(tc.Failure.Message, tc.Failure.Body)
	case tc.Error != nil:
		return outcomeError, firstNonEmpty(tc.Error.Message, tc.Error.Body)
	case len(tc.RerunFailure) > 0:
		return outcomeFailed, firstNonEmpty(tc.RerunFailure[0].Message, tc.RerunFailure[0].Body)
	case len(tc.RerunError) > 0:
		return outcomeError, firstNonEmpty(tc.RerunError[0].Message, tc.RerunError[0].Body)
	case couldNotRun:
		return outcomeError, notRun
	case tc.Status == statusFail:
		// The status says it failed although no <failure> child says why,
		// and a <skipped> child does not outrank it.
		return outcomeFailed, "status=fail"
	case !knownStatuses[tc.Status]:
		return outcomeError, fmt.Sprintf("unrecognized status=%q", tc.Status)
	case !knownResults[tc.Result]:
		return outcomeError, fmt.Sprintf("unrecognized result=%q", tc.Result)
	// A declared skip, as a child element, a status or a googletest result,
	// is a skip even when no <skipped> child says why.
	case tc.Skipped != nil, tc.Status == statusNotRun, tc.Status == statusDisabled,
		tc.Result == resultSkipped, tc.Result == resultSuppressed:
		return outcomeSkipped, ""
	default:
		return outcomePassed, ""
	}
}

// notRunError reports whether a case marked status="notrun" is a test that
// was required and could not run, and why. CTest writes every Not Run test
// as <skipped message="<reason>"/> although it counts it FAILED and exits
// non-zero: a missing executable (the build never produced it), missing
// REQUIRED_FILES, a failed fixture setup. Only its two deliberate-skip
// reasons are skips. Any other reason is an error, so a reason a future
// CTest adds refuses rather than admits. A notrun case with no <skipped>
// child (googletest's DISABLED_ tests) is a skip.
func notRunError(tc junitTestcase) (string, bool) {
	if tc.Status != statusNotRun || tc.Skipped == nil {
		return "", false
	}
	reason := firstNonEmpty(tc.Skipped.Message, tc.Skipped.Body)
	if strings.HasPrefix(reason, "SKIP_RETURN_CODE=") || reason == "SKIP_REGULAR_EXPRESSION_MATCHED" {
		return "", false
	}
	if reason == "" {
		reason = "not run"
	}
	return reason, true
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// decodeJUnitRoot reads a <testsuites> root, falling back to a bare
// <testsuite> root, which some emitters (CTest among them) produce.
func decodeJUnitRoot(b []byte) (junitTestsuites, error) {
	var root junitTestsuites
	if err := requireSingleRoot(b); err != nil {
		return root, err
	}
	if err := xml.Unmarshal(b, &root); err != nil || (len(root.Suites) == 0 && len(root.Cases) == 0) {
		var single junitTestsuite
		if err2 := xml.Unmarshal(b, &single); err2 == nil && single.Name != "" {
			root.Suites = []junitTestsuite{single}
			root.Tests = single.Tests
			root.Failures = single.Failures
			root.Errors = single.Errors
			root.Skipped = single.Skipped
			root.Time = single.Time
		} else if err != nil {
			return root, fmt.Errorf("invalid JUnit XML: %w", err)
		}
	}
	if len(root.Suites) == 0 && len(root.Cases) == 0 {
		return root, fmt.Errorf("JUnit document contains no testsuite elements")
	}
	if err := checkCounts("testsuites", root.Tests, root.Failures, root.Errors, root.Skipped); err != nil {
		return root, err
	}
	for _, ts := range root.Suites {
		if err := checkSuiteCounts(ts); err != nil {
			return root, err
		}
	}
	return root, nil
}

// checkSuiteCounts refuses a suite, at any depth, whose declared counts
// fall outside [0, maxClaimedCount].
func checkSuiteCounts(ts junitTestsuite) error {
	if err := checkCounts("testsuite "+strconv.Quote(ts.Name), ts.Tests, ts.Failures, ts.Errors, ts.Skipped); err != nil {
		return err
	}
	for _, n := range ts.Suites {
		if err := checkSuiteCounts(n); err != nil {
			return err
		}
	}
	return nil
}

// checkCounts refuses any count outside [0, maxClaimedCount].
func checkCounts(where string, counts ...int) error {
	for _, c := range counts {
		if c < 0 || c > maxClaimedCount {
			return fmt.Errorf("invalid test report: %s declares a count of %d, outside 0..%d", where, c, maxClaimedCount)
		}
	}
	return nil
}

// requireSingleRoot refuses a document with more than one root element.
// xml.Unmarshal reads the first root and ignores the rest, so a second
// <testsuites> (two reports concatenated) would vanish from the counts.
func requireSingleRoot(b []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(b))
	depth, roots := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid JUnit XML: %w", err)
		}
		switch tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 {
					return fmt.Errorf("invalid JUnit XML: more than one root element")
				}
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
}

// junitTally accumulates case outcomes across every nesting level.
type junitTally struct {
	summary Summary
	failed  []FailedTest
	// cases counts real <testcase> elements. summary.Total can also grow
	// from reconcile's synthesized errors, so it cannot say whether the
	// report had any cases.
	cases int
}

// reconcile holds a suite (or the root) to its own failures/errors
// attributes, each category against what its subtree shows since before. A
// report claiming more failures (or errors) than its cases show recorded a run
// that did not pass, so the shortfall is booked in that category, taken from
// the passes first. Each category is kept apart: collapsing them would let a
// claimed failure read as a pass or hide it from a policy on summary.failed.
// A report that counts one outcome in both attributes is over-counted, never
// under-counted; it already records a non-passing case.
func (t *junitTally) reconcile(suite string, claimedFailures, claimedErrors int, before Summary) {
	shownFailed := t.summary.Failed - before.Failed
	shownErrors := t.summary.Errors - before.Errors
	failedShort := max(claimedFailures-shownFailed, 0)
	errorsShort := max(claimedErrors-shownErrors, 0)
	excess := failedShort + errorsShort
	if excess == 0 {
		return
	}
	fromPassed := min(excess, t.summary.Passed-before.Passed)
	t.summary.Passed -= fromPassed
	t.summary.Total += excess - fromPassed
	t.summary.Failed += failedShort
	t.summary.Errors += errorsShort
	t.failed = appendBounded(t.failed, FailedTest{
		Suite: suite,
		Message: fmt.Sprintf("report claims %d failures and %d errors, its cases show %d and %d",
			claimedFailures, claimedErrors, shownFailed, shownErrors),
	})
}

func (t *junitTally) count(suite, systemErr string, cases []junitTestcase) {
	for _, tc := range cases {
		t.cases++
		t.summary.Total++
		outcome, message := classifyCase(suite, systemErr, tc)
		switch outcome {
		case outcomeFailed:
			t.summary.Failed++
		case outcomeError:
			t.summary.Errors++
		case outcomeSkipped:
			t.summary.Skipped++
			continue
		default:
			t.summary.Passed++
			continue
		}
		t.failed = appendBounded(t.failed, FailedTest{
			Name:      tc.Name,
			Suite:     suite,
			Classname: tc.Classname,
			Message:   message,
			Duration:  tc.Time,
		})
	}
}

func (t *junitTally) walk(ts junitTestsuite) {
	before := t.summary
	t.count(ts.Name, ts.SystemErr, ts.Cases)
	for _, nested := range ts.Suites {
		t.walk(nested)
	}
	t.reconcile(ts.Name, ts.Failures, ts.Errors, before)
}

func parseJUnit(b []byte) (Predicate, []string, error) {
	root, err := decodeJUnitRoot(b)
	if err != nil {
		return Predicate{}, nil, err
	}

	// JUnit attribute totals are advisory; many emitters get them wrong
	// (pytest counts errors as failures, go-junit-report drops zero
	// values entirely). Recompute from the actual cases, at every nesting
	// level: a case the walk skips is a failure the predicate never shows.
	var tally junitTally
	var suites []string
	// A parent suite's time already includes its nested suites, so only
	// top-level suites and root-level cases add to the run's duration.
	tally.count("", "", root.Cases)
	for _, tc := range root.Cases {
		tally.summary.DurationSeconds += tc.Time
	}
	for _, ts := range root.Suites {
		suites = append(suites, ts.Name)
		tally.summary.DurationSeconds += suiteTime(ts)
		tally.walk(ts)
	}

	// A summary-only report (no <testcase> anywhere) is read from its
	// attributes: the root's, or when the root carries none, the sum of the
	// top-level suites'. It is decided on real cases, not on Total, which
	// reconcile may have raised with synthesized errors. This shouldn't
	// happen for a conformant emitter but defends minimal reports.
	if tally.cases == 0 {
		tally.summary = summaryFromAttributes(root, tally.summary.DurationSeconds)
	} else {
		tally.reconcile("", root.Failures, root.Errors, Summary{})
	}

	return Predicate{Format: FormatJUnitXML, Summary: tally.summary, FailedTests: tally.failed}, suites, nil
}

// attrCounts is one level's failures/errors/tests/skipped attributes.
type attrCounts struct{ tests, failures, errors, skipped int }

func maxCounts(a, b attrCounts) attrCounts {
	return attrCounts{max(a.tests, b.tests), max(a.failures, b.failures), max(a.errors, b.errors), max(a.skipped, b.skipped)}
}

// subtreeCounts is a suite's claim, field by field the larger of its own
// attribute and the sum of its nested suites' claims, so a failure declared
// at any depth survives.
func subtreeCounts(ts junitTestsuite) attrCounts {
	var kids attrCounts
	for _, n := range ts.Suites {
		c := subtreeCounts(n)
		kids = attrCounts{kids.tests + c.tests, kids.failures + c.failures, kids.errors + c.errors, kids.skipped + c.skipped}
	}
	return maxCounts(attrCounts{ts.Tests, ts.Failures, ts.Errors, ts.Skipped}, kids)
}

// summaryFromAttributes reads a summary-only report: field by field, the
// larger of the root's attributes and the sum of its suites' claims. Agreeing
// attributes give the same counts; a failure claimed at any level is kept.
func summaryFromAttributes(root junitTestsuites, suiteDuration float64) Summary {
	var suites attrCounts
	for _, ts := range root.Suites {
		c := subtreeCounts(ts)
		suites = attrCounts{suites.tests + c.tests, suites.failures + c.failures, suites.errors + c.errors, suites.skipped + c.skipped}
	}
	a := maxCounts(attrCounts{root.Tests, root.Failures, root.Errors, root.Skipped}, suites)
	passed := max(a.tests-a.failures-a.errors-a.skipped, 0)
	duration := suiteDuration
	if root.Time > 0 {
		duration = root.Time
	}
	return Summary{Total: a.tests, Passed: passed, Failed: a.failures,
		Skipped: a.skipped, Errors: a.errors, DurationSeconds: duration}
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
	sum := rep.Results.Summary
	if err := checkCounts("results.summary", sum.Tests, sum.Passed, sum.Failed, sum.Skipped, sum.Pending, sum.Other); err != nil {
		return Predicate{}, nil, err
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

// suiteTime is a suite's own time attribute, or, when the emitter times only
// its cases (Terraform's writer omits the suite's), the sum of its cases and
// nested suites.
func suiteTime(ts junitTestsuite) float64 {
	if ts.Time > 0 {
		return ts.Time
	}
	var sum float64
	for _, tc := range ts.Cases {
		sum += tc.Time
	}
	for _, nested := range ts.Suites {
		sum += suiteTime(nested)
	}
	return sum
}

// terraformRunNotStarted recognizes `terraform test -junit-xml`'s record of a
// run block that never started because its test file failed first (an
// unconfigurable provider, a file-level error). Terraform writes it as a bare
// <testcase> with no outcome element and no time or timestamp, inside the
// suite named for the .tftest.hcl/.tftest.json file, while its own summary
// counts the run as neither passed nor failed and the command exits 1. Every
// run Terraform executed carries a timestamp, and a skipped one a <skipped>
// element. A bare case from any other emitter still counts as passed, per
// JUnit convention.
func terraformRunNotStarted(suite string, tc junitTestcase) bool {
	if !strings.HasSuffix(suite, ".tftest.hcl") && !strings.HasSuffix(suite, ".tftest.json") {
		return false
	}
	return tc.Classname == suite && tc.Failure == nil && tc.Error == nil && tc.Skipped == nil &&
		tc.Timestamp == "" && tc.Time == 0
}

func terraformNotStartedMessage(systemErr string) string {
	const reason = "terraform did not run this case: its test file failed before the run started"
	if detail := strings.TrimSpace(systemErr); detail != "" {
		return reason + ": " + detail
	}
	return reason
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return strings.TrimSpace(b)
}
