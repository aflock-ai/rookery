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

package testresults

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestName/TestType/TestRunType pin the registration surface — these
// strings are referenced from --attestations flags and from rego
// policies, so they must not change without a major version bump.
func TestName(t *testing.T) {
	assert.Equal(t, Name, New().Name())
}

func TestType(t *testing.T) {
	assert.Equal(t, Type, New().Type())
}

func TestRunType(t *testing.T) {
	assert.Equal(t, RunType, New().RunType())
}

// TestDetectFormat exercises the byte-peek discriminator that decides
// whether to dispatch to the JUnit XML parser or the CTRF JSON parser.
// Leading whitespace and a UTF-8 BOM are both tolerated.
func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"junit-with-decl", `<?xml version="1.0"?><testsuites/>`, FormatJUnitXML},
		{"junit-bare-tag", `<testsuites/>`, FormatJUnitXML},
		{"junit-leading-ws", "  \n\t<testsuites/>", FormatJUnitXML},
		{"ctrf-bare", `{"results":{}}`, FormatCTRFJSON},
		{"ctrf-leading-ws", "\n  {\"results\":{}}", FormatCTRFJSON},
		{"ctrf-utf8-bom", "\xef\xbb\xbf{\"results\":{}}", FormatCTRFJSON},
		{"unknown-array", `[1,2,3]`, ""},
		{"empty", ``, ""},
		{"only-whitespace", "   \n\t  ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, detectFormat([]byte(tc.input)))
		})
	}
}

// TestParseJUnit_Passing verifies the parser handles a real `pytest
// --junitxml=` output with all-passing tests. The fixture was generated
// by running pytest against a 6-case Python module — see
// testdata/junit-passing.xml.
func TestParseJUnit_Passing(t *testing.T) {
	pred, suites, err := parseJUnit(readFixture(t, "testdata/junit-passing.xml"))
	require.NoError(t, err)

	assert.Equal(t, FormatJUnitXML, pred.Format)
	assert.Equal(t, 6, pred.Summary.Total)
	assert.Equal(t, 6, pred.Summary.Passed)
	assert.Equal(t, 0, pred.Summary.Failed)
	assert.Equal(t, 0, pred.Summary.Errors)
	assert.Equal(t, 0, pred.Summary.Skipped)
	assert.Empty(t, pred.FailedTests, "no failures in passing fixture")
	assert.Contains(t, suites, "pytest", "top-level suite name should be captured")
}

// TestParseJUnit_Failing verifies failure + skip handling against a
// real go-junit-report fixture (testdata/junit-failing.xml). The
// fixture has 6 cases: 3 pass, 1 skip, 2 fail.
func TestParseJUnit_Failing(t *testing.T) {
	pred, suites, err := parseJUnit(readFixture(t, "testdata/junit-failing.xml"))
	require.NoError(t, err)

	assert.Equal(t, FormatJUnitXML, pred.Format)
	assert.Equal(t, 6, pred.Summary.Total)
	assert.Equal(t, 3, pred.Summary.Passed)
	assert.Equal(t, 2, pred.Summary.Failed)
	assert.Equal(t, 1, pred.Summary.Skipped)
	require.Len(t, pred.FailedTests, 2)

	// Each failed test should preserve its name and classname plus the
	// failure message verbatim.
	names := []string{pred.FailedTests[0].Name, pred.FailedTests[1].Name}
	assert.Contains(t, names, "TestFails")
	assert.Contains(t, names, "TestErrorish")
	for _, f := range pred.FailedTests {
		assert.NotEmpty(t, f.Message, "failure %q should carry a message", f.Name)
		assert.NotEmpty(t, f.Suite, "failure %q should carry its suite name", f.Name)
		assert.NotEmpty(t, f.Classname, "failure %q should carry its classname", f.Name)
	}
	assert.NotEmpty(t, suites)
}

// TestParseJUnit_NodeTestNestedSuites pins Node's built-in junit reporter
// (`node --test --test-reporter=junit`, Node 24). It nests a describe()
// block's <testsuite> inside its parent and puts top-level test() cases
// directly under <testsuites>. Reading one level only counted 1 of 4 cases
// and missed the failure entirely, so `summary.failed == 0` admitted a
// failing run. Every nesting level and root-level case is counted.
func TestParseJUnit_NodeTestNestedSuites(t *testing.T) {
	pred, suites, err := parseJUnit(readFixture(t, "testdata/junit-node-test.xml"))
	require.NoError(t, err)

	assert.Equal(t, 4, pred.Summary.Total)
	assert.Equal(t, 2, pred.Summary.Passed)
	assert.Equal(t, 1, pred.Summary.Failed)
	assert.Equal(t, 1, pred.Summary.Skipped)
	require.Len(t, pred.FailedTests, 1)
	assert.Equal(t, "rejects unknown option", pred.FailedTests[0].Name)
	assert.Equal(t, "nested options", pred.FailedTests[0].Suite, "a failure names its innermost suite")
	assert.Equal(t, "parser.nested options", pred.FailedTests[0].Classname)
	assert.Equal(t, "1 == 2", pred.FailedTests[0].Message)
	assert.Equal(t, []string{"parser"}, suites, "test-suite subjects stay top-level")
}

// TestParseJUnit_CTestNotRunIsNotASkip pins CTest's --output-junit (CTest
// 3.31.6, the C fixture's; 4.2.3 writes the same elements). The capture is
// one test for each way a CTest test can end. CTest itself reports 7 FAILED
// (4 Failed/Timeout plus 3 "Not Run": a missing executable, a missing
// REQUIRED_FILES entry, a failed fixture setup) and exits 8, but writes the
// three Not Run tests as <skipped>, and a DISABLED test as a bare
// status="disabled" case with no child. Read naively that is failed 4,
// skipped 5, and the disabled test PASSED: a build that never produced a
// test executable looks like a skip, and `failed == 0` admits it.
//
// status="notrun" with a <skipped> message that is not one of CTest's two
// deliberate-skip markers (SKIP_RETURN_CODE=<n>, SKIP_REGULAR_EXPRESSION_MATCHED)
// is an error: the test was required and could not run. Any other message,
// including one a future CTest invents, fails closed as an error.
func TestParseJUnit_CTestNotRunIsNotASkip(t *testing.T) {
	pred, suites, err := parseJUnit(readFixture(t, "testdata/junit-ctest.xml"))
	require.NoError(t, err)

	assert.Equal(t, 11, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed, "only `ok` ran and passed; a disabled test did not pass")
	assert.Equal(t, 4, pred.Summary.Failed, "Failed, a failed fixture setup, Timeout, WILL_FAIL")
	assert.Equal(t, 3, pred.Summary.Errors, "missing executable, missing required file, failed fixture dependency")
	assert.Equal(t, 3, pred.Summary.Skipped, "SKIP_RETURN_CODE, SKIP_REGULAR_EXPRESSION, DISABLED")
	assert.Equal(t, pred.Summary.Total,
		pred.Summary.Passed+pred.Summary.Failed+pred.Summary.Errors+pred.Summary.Skipped)

	byName := map[string]FailedTest{}
	for _, f := range pred.FailedTests {
		byName[f.Name] = f
	}
	assert.Len(t, byName, 7, "every test CTest called FAILED is named")
	assert.Equal(t, "Unable to find executable", byName["missingexe"].Message)
	assert.Equal(t, "Required Files Missing", byName["needsfile"].Message)
	assert.Equal(t, "Fixture dependency failed", byName["needsfixture"].Message)
	assert.Equal(t, "Timeout", byName["timeout"].Message)
	assert.Equal(t, []string{"(empty)"}, suites)
}

// A skip message outside CTest's deliberate-skip markers is only special
// under status="notrun"; every other emitter's <skipped> stays a skip, and a
// status="notrun" case with no child (googletest's DISABLED_ tests) is a
// skip, never a pass.
func TestParseJUnit_NotRunStatusScope(t *testing.T) {
	pred, _, err := parseJUnit([]byte(`<testsuites><testsuite name="s">
	<testcase name="pytest-skip" classname="c"><skipped message="Unable to find executable"/></testcase>
	<testcase name="gtest-disabled" classname="c" status="notrun" result="suppressed"/>
	<testcase name="ctest-future" classname="c" status="notrun"><skipped message="Some New Reason"/></testcase>
	<testcase name="ctest-skip-code" classname="c" status="notrun"><skipped message="SKIP_RETURN_CODE=4"/></testcase>
	<testcase name="ran" classname="c" status="run"/>
</testsuite></testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, 5, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed)
	assert.Equal(t, 3, pred.Summary.Skipped)
	assert.Equal(t, 1, pred.Summary.Errors, "an unrecognized not-run reason fails closed")
	require.Len(t, pred.FailedTests, 1)
	assert.Equal(t, "ctest-future", pred.FailedTests[0].Name)
}

// TestParseJUnit_TerraformTest pins `terraform test -junit-xml` (Terraform
// 1.14.5, sources in testdata/terraform-junit). One <testsuite> per test file,
// one <testcase> per run block: a pass, an assertion failure, a run error, a
// run skipped after that error, a file with an undeclared reference, and a file
// whose provider cannot be configured. Terraform never starts the last file's
// run and writes it as a bare <testcase> with no outcome and no timestamp, and
// its own summary reads "1 passed, 3 failed, 1 skipped" with exit 1. Counting
// that bare case as passed reported a run Terraform refused as green.
func TestParseJUnit_TerraformTest(t *testing.T) {
	pred, suites, err := parseJUnit(readFixture(t, "testdata/junit-terraform-test.xml"))
	require.NoError(t, err)

	assert.Equal(t, 6, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed, "only the run Terraform reported as pass")
	assert.Equal(t, 1, pred.Summary.Failed)
	assert.Equal(t, 3, pred.Summary.Errors, "two run errors and the run that never started")
	assert.Equal(t, 1, pred.Summary.Skipped)
	require.Len(t, pred.FailedTests, 4)
	notRun := pred.FailedTests[3]
	assert.Equal(t, "uses_unknown_provider", notRun.Name)
	assert.Equal(t, "tests/d.tftest.hcl", notRun.Suite)
	assert.Contains(t, notRun.Message, "did not run")
	assert.Equal(t, []string{"tests/a.tftest.hcl", "tests/b.tftest.hcl", "tests/c.tftest.hcl", "tests/d.tftest.hcl"}, suites)
	// Terraform times each <testcase> but not its <testsuite>; the run's
	// duration is the cases' sum, not zero.
	assert.InDelta(t, 0.051632, pred.Summary.DurationSeconds, 1e-9)
}

// Terraform 1.16 still writes the never-started run as a bare <testcase> but
// adds the file's diagnostics as the suite's <system-err>; that is the reason
// the case carries.
func TestParseJUnit_TerraformFileLevelError(t *testing.T) {
	pred, _, err := parseJUnit(readFixture(t, "testdata/junit-terraform-file-error.xml"))
	require.NoError(t, err)
	assert.Equal(t, 1, pred.Summary.Total)
	assert.Equal(t, 0, pred.Summary.Passed)
	assert.Equal(t, 1, pred.Summary.Errors)
	require.Len(t, pred.FailedTests, 1)
	assert.Contains(t, pred.FailedTests[0].Message, "unknown provider registry.terraform.io/hashicorp/unknownthing")
}

// Only Terraform's own shape is read as "never started": a bare case from any
// other emitter, or a Terraform case that carries its timestamp, still passes.
func TestParseJUnit_BareCaseOutsideTerraformStillPasses(t *testing.T) {
	pred, _, err := parseJUnit([]byte(`<testsuites>
	<testsuite name="pkg" tests="1"><testcase name="a" classname="pkg"/></testsuite>
	<testsuite name="x.tftest.hcl" tests="1"><testcase name="r" classname="x.tftest.hcl" time="0.1" timestamp="2026-09-25T06:25:36Z"/></testsuite>
	<testsuite name="y.tftest.hcl" tests="1"><testcase name="r" classname="other"/></testsuite>
</testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, 3, pred.Summary.Total)
	assert.Equal(t, 3, pred.Summary.Passed)
	assert.Empty(t, pred.FailedTests)
}

// TestParseJUnit_CTestProbeStatuses pins a second real CTest 3.31.6 report
// (the C++ fixture's probe: one test per state, fewer than junit-ctest.xml).
// The disabled test, a bare status="disabled" case, is skipped, not passed;
// the two tests CTest could not run are errors; the SKIP_RETURN_CODE skip
// stays a skip.
func TestParseJUnit_CTestProbeStatuses(t *testing.T) {
	pred, suites, err := parseJUnit(readFixture(t, "testdata/junit-ctest-probe.xml"))
	require.NoError(t, err)

	assert.Equal(t, 6, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed, "only `passes` ran and passed; `disabled` never ran")
	assert.Equal(t, 1, pred.Summary.Failed)
	assert.Equal(t, 2, pred.Summary.Errors, "notrun (missing executable), required_missing")
	assert.Equal(t, 2, pred.Summary.Skipped, "disabled, skipcode")
	require.Len(t, pred.FailedTests, 3)
	assert.Equal(t, []string{"(empty)"}, suites, "CTest's single root <testsuite>")
}

// A status attribute that contradicts a missing child element never reads
// as a pass: status="fail" with no <failure> child is a failure, and
// disabled or notrun with no child is a skip.
func TestParseJUnit_StatusWithoutChild(t *testing.T) {
	pred, _, err := parseJUnit([]byte(`<testsuite name="s">
	<testcase name="ok" status="run"/>
	<testcase name="off" status="disabled"/>
	<testcase name="gone" status="notrun"/>
	<testcase name="bad" status="fail"/>
</testsuite>`))
	require.NoError(t, err)
	assert.Equal(t, 4, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed)
	assert.Equal(t, 2, pred.Summary.Skipped)
	assert.Equal(t, 1, pred.Summary.Failed)
	require.Len(t, pred.FailedTests, 1)
	assert.Equal(t, "bad", pred.FailedTests[0].Name)
	assert.Equal(t, "status=fail", pred.FailedTests[0].Message)
}

// A report whose tests are all top-level test() calls has no <testsuite>
// at all; its cases are still the run, not an empty document.
func TestParseJUnit_RootLevelCasesOnly(t *testing.T) {
	pred, suites, err := parseJUnit([]byte(`<testsuites>
	<testcase name="a" classname="test"/>
	<testcase name="b" classname="test"><failure message="boom"/></testcase>
</testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, 2, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Failed)
	require.Len(t, pred.FailedTests, 1)
	assert.Equal(t, "b", pred.FailedTests[0].Name)
	assert.Empty(t, suites)
}

// TestParseJUnit_FailedRunIsNeverClean: a policy on summary.failed == 0
// (or failed + errors == 0) trusts these counts. Every report below records
// a run that did not pass, through a signal other than a <failure>/<error>
// child on the case. The parser must either refuse the document or count a
// failure or error; a bare case is a pass only when nothing else in the
// report says otherwise.
func TestParseJUnit_FailedRunIsNeverClean(t *testing.T) {
	docs := map[string]string{
		"unrecognized status failed":      `<testsuites><testsuite name="s"><testcase name="a" status="failed"/></testsuite></testsuites>`,
		"unrecognized status error":       `<testsuites><testsuite name="s"><testcase name="a" status="error"/></testsuite></testsuites>`,
		"unrecognized status timeout":     `<testsuites><testsuite name="s"><testcase name="a" status="timeout"/></testsuite></testsuites>`,
		"unrecognized result failed":      `<testsuites><testsuite name="s"><testcase name="a" status="run" result="failed"/></testsuite></testsuites>`,
		"status fail with skipped":        `<testsuite name="s"><testcase name="a" status="fail"><skipped message="x"/></testcase></testsuite>`,
		"rerunFailure without failure":    `<testsuites><testsuite name="s"><testcase name="a"><rerunFailure message="x"/></testcase></testsuite></testsuites>`,
		"rerunError without error":        `<testsuites><testsuite name="s"><testcase name="a"><rerunError message="x"/></testcase></testsuite></testsuites>`,
		"suite failures attr, bare cases": `<testsuites><testsuite name="s" tests="2" failures="1"><testcase name="a"/><testcase name="b"/></testsuite></testsuites>`,
		"suite errors attr, no cases":     `<testsuites><testsuite name="s" tests="0" errors="1"><system-err>setup failed</system-err></testsuite><testsuite name="t"><testcase name="a"/></testsuite></testsuites>`,
		"nested suite failures attr":      `<testsuites><testsuite name="outer"><testsuite name="inner" failures="1"><testcase name="a"/></testsuite></testsuite></testsuites>`,
		"root failures attr, bare cases":  `<testsuites tests="1" failures="1"><testsuite name="s"><testcase name="a"/></testsuite></testsuites>`,
		"root errors attr, bare cases":    `<testsuites tests="1" errors="1"><testsuite name="s"><testcase name="a"/></testsuite></testsuites>`,
		"second root with a failure": `<testsuites><testsuite name="s"><testcase name="a"/></testsuite></testsuites>` +
			`<testsuites><testsuite name="t"><testcase name="b"><failure/></testcase></testsuite></testsuites>`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			pred, _, err := parseJUnit([]byte(doc))
			if err != nil {
				return // refused: nothing for a policy to admit
			}
			s := pred.Summary
			assert.Positive(t, s.Failed+s.Errors, "failed run summarized as clean: %+v", s)
			assert.NotEmpty(t, pred.FailedTests, "a counted failure must say what failed")
		})
	}
}

// A summary-only report (attributes, no <testcase>) keeps the counts its
// attributes give. Reconciling a suite's attributes against its (absent)
// cases must not replace them with one synthesized error.
func TestParseJUnit_SummaryOnlyReportKeepsItsAttributes(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  string
		want Summary
	}{
		"bare testsuite root": {`<testsuite name="s" tests="10" failures="1"/>`,
			Summary{Total: 10, Passed: 9, Failed: 1}},
		"suites without root attributes": {`<testsuites><testsuite name="s" tests="10" failures="1" errors="2"/></testsuites>`,
			Summary{Total: 10, Passed: 7, Failed: 1, Errors: 2}},
		"root attributes win": {`<testsuites tests="4" failures="1"><testsuite name="s" tests="4" failures="1"/></testsuites>`,
			Summary{Total: 4, Passed: 3, Failed: 1}},
		"passing summary": {`<testsuite name="s" tests="3"/>`,
			Summary{Total: 3, Passed: 3}},
		// The failure is declared only on the nested suite.
		"nested failure, outer claims none": {`<testsuites><testsuite name="outer" tests="1"><testsuite name="inner" tests="1" failures="1"/></testsuite></testsuites>`,
			Summary{Total: 1, Failed: 1}},
		"root claims none, nested suite fails": {`<testsuites tests="2"><testsuite name="a" tests="1"/><testsuite name="b" tests="1" errors="1"/></testsuites>`,
			Summary{Total: 2, Passed: 1, Errors: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			pred, _, err := parseJUnit([]byte(tc.doc))
			require.NoError(t, err)
			assert.Equal(t, tc.want, pred.Summary)
		})
	}
}

// Claimed failures over bare cases are booked as failures, so a policy that
// reads only summary.failed still refuses the run; claimed errors stay errors.
func TestParseJUnit_ClaimedFailuresCountAsFailed(t *testing.T) {
	pred, _, err := parseJUnit([]byte(`<testsuites><testsuite name="s" tests="2" failures="1"><testcase name="a"/><testcase name="b"/></testsuite></testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, Summary{Total: 2, Passed: 1, Failed: 1}, pred.Summary)

	pred, _, err = parseJUnit([]byte(`<testsuites><testsuite name="s" tests="1" errors="1"><testcase name="a"/></testsuite></testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, Summary{Total: 1, Errors: 1}, pred.Summary)

	// Both categories claimed at once: each is kept, and no pass survives.
	pred, _, err = parseJUnit([]byte(`<testsuites><testsuite name="s" tests="3" failures="1" errors="2"><testcase name="a"/><testcase name="b"/><testcase name="c"/></testsuite></testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, Summary{Total: 3, Failed: 1, Errors: 2}, pred.Summary)
}

// A count attribute outside [0, maxClaimedCount] is refused, never summed:
// a claim near MaxInt wraps the tally negative and erases a failure, and a
// negative claim cancels a sibling's failure in the summary-only sum.
func TestParseJUnit_RefusesOutOfRangeCounts(t *testing.T) {
	cases := map[string]string{
		"wrapping failures": `<testsuites><testcase name="p1"/><testcase name="p2"/><testcase name="f"><failure/></testcase>` +
			`<testsuite name="a" failures="9223372036854775807"/><testsuite name="b" failures="9223372036854775807"/></testsuites>`,
		"negative cancels a sibling": `<testsuites><testsuite name="a" tests="5" failures="5"/><testsuite name="b" tests="0" failures="-5"/></testsuites>`,
		"negative root":              `<testsuites errors="-1"><testsuite name="a"><testcase name="x"/></testsuite></testsuites>`,
		"nested tests over cap":      `<testsuites><testsuite name="a"><testsuite name="b" tests="2147483648"/></testsuite></testsuites>`,
		"bare suite skipped":         `<testsuite name="a" skipped="-3"><testcase name="x"/></testsuite>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseJUnit([]byte(doc))
			require.Error(t, err)
		})
	}
	// The cap itself is admitted.
	_, _, err := parseJUnit([]byte(`<testsuites><testsuite name="a" tests="2147483647"/></testsuites>`))
	require.NoError(t, err)
}

func TestParseCTRF_RefusesOutOfRangeCounts(t *testing.T) {
	for _, field := range []string{"tests", "passed", "failed", "skipped", "pending", "other"} {
		for _, v := range []string{"-1", "2147483648", "9223372036854775807"} {
			doc := `{"results":{"tool":{"name":"x"},"summary":{"tests":1,"passed":1,"` + field + `":` + v + `}}}`
			t.Run(field+"="+v, func(t *testing.T) {
				_, _, err := parseCTRF([]byte(doc))
				require.Error(t, err)
			})
		}
	}
}

// A declared skip is a skip, never a pass: googletest writes result="skipped"
// or "suppressed", and a <skipped> child is not guaranteed.
func TestParseJUnit_DeclaredSkipWithoutChildIsSkipped(t *testing.T) {
	pred, _, err := parseJUnit([]byte(`<testsuites><testsuite name="s">
	<testcase name="a" status="run" result="skipped"/>
	<testcase name="b" status="notrun" result="suppressed"/>
	<testcase name="c" status="run" result="completed"/>
</testsuite></testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, Summary{Total: 3, Passed: 1, Skipped: 2}, pred.Summary)
}

// The checks above must not turn honest reports into failures: attribute
// totals that agree with the cases, or that an emitter under-reports or
// omits, change nothing, and every status and result value a known emitter
// writes keeps its meaning.
func TestParseJUnit_ConsistentAttributesAndKnownValuesUnchanged(t *testing.T) {
	pred, _, err := parseJUnit([]byte(`<testsuites tests="6" failures="1" errors="1">
	<testsuite name="pytest" tests="3" failures="1" errors="1" skipped="0">
		<testcase name="a"/>
		<testcase name="b"><failure message="x"/></testcase>
		<testcase name="c"><error message="y"/></testcase>
	</testsuite>
	<testsuite name="go-junit-report" tests="1"><testcase name="d"/></testsuite>
	<testsuite name="gtest"><testcase name="e" status="run" result="completed"/><testcase name="f" status="run" result="skipped"><skipped/></testcase></testsuite>
	<testsuite name="surefire"><testcase name="g"><flakyFailure message="passed on rerun"/></testcase></testsuite>
</testsuites>`))
	require.NoError(t, err)
	assert.Equal(t, Summary{Total: 7, Passed: 4, Failed: 1, Errors: 1, Skipped: 1}, pred.Summary)
	require.Len(t, pred.FailedTests, 2)
}

// TestParseCTRF_Passing verifies parsing of a real Jest CTRF report
// (testdata/ctrf-passing.json) generated by jest-ctrf-json-reporter.
func TestParseCTRF_Passing(t *testing.T) {
	pred, suites, err := parseCTRF(readFixture(t, "testdata/ctrf-passing.json"))
	require.NoError(t, err)

	assert.Equal(t, FormatCTRFJSON, pred.Format)
	assert.Equal(t, "jest", pred.ToolName)
	assert.Equal(t, 5, pred.Summary.Total)
	assert.Equal(t, 5, pred.Summary.Passed)
	assert.Equal(t, 0, pred.Summary.Failed)
	assert.Empty(t, pred.FailedTests)

	// Suite names come from Jest's "<file> > <describe>" formatting.
	require.NotEmpty(t, suites)
	for _, s := range suites {
		assert.True(t, strings.Contains(s, ">"), "Jest suite name should contain '>' separator: %q", s)
	}

	// Duration in seconds must derive correctly from ms-epoch start/stop.
	assert.Greater(t, pred.Summary.DurationSeconds, 0.0)
	assert.Less(t, pred.Summary.DurationSeconds, 60.0, "test run completed in under a minute")
}

// TestParseCTRF_Failing verifies the parser captures failed test
// messages and aggregates pending tests into the skipped count.
func TestParseCTRF_Failing(t *testing.T) {
	pred, _, err := parseCTRF(readFixture(t, "testdata/ctrf-failing.json"))
	require.NoError(t, err)

	assert.Equal(t, FormatCTRFJSON, pred.Format)
	assert.Equal(t, "jest", pred.ToolName)
	assert.Equal(t, 6, pred.Summary.Total)
	assert.Equal(t, 2, pred.Summary.Passed)
	assert.Equal(t, 3, pred.Summary.Failed)
	// Skipped + pending are folded into the skipped column so policies
	// don't need a separate gate for the Jest pending state.
	assert.Equal(t, 1, pred.Summary.Skipped)

	require.Len(t, pred.FailedTests, 3)
	for _, f := range pred.FailedTests {
		assert.NotEmpty(t, f.Name)
		assert.NotEmpty(t, f.Suite, "Jest CTRF tests always carry a suite identifier")
		assert.NotEmpty(t, f.Message, "Jest failed tests carry an error message")
	}
}

// TestParseCTRF_Rejects_NonCTRF makes sure a JSON document that lacks
// every CTRF anchor field is rejected rather than producing an empty
// (but signed) predicate.
func TestParseCTRF_Rejects_NonCTRF(t *testing.T) {
	cases := []string{
		`{"foo": "bar"}`,
		`{"results": {}}`,
		`{"results": {"tool": {}}}`,
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, _, err := parseCTRF([]byte(tc))
			require.Error(t, err)
		})
	}
}

// TestParseJUnit_Rejects_Garbage confirms malformed XML and XML that
// does not contain any <testsuite> elements are both rejected.
func TestParseJUnit_Rejects_Garbage(t *testing.T) {
	cases := []string{
		`<not-xml`,
		`<rootelement/>`,
		`<testsuites></testsuites>`,
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, _, err := parseJUnit([]byte(tc))
			require.Error(t, err)
		})
	}
}

// TestAttest_JUnit_HappyPath exercises the full Attestor lifecycle
// against a JUnit fixture: write the file into a temp working dir,
// classify it through the product attestor (using New())... but we
// don't need the product attestor in this test — Attestor.getCandidate
// reads products from ctx.Products(), which we populate directly via
// a stub Producer. Instead, follow the same pattern as the SARIF tests:
// rely on the product attestor running first inside RunAttestors().
//
// We can't import the product attestor here without creating a cyclic
// or coupled dependency; instead we test getCandidate against a
// hand-rolled context that surfaces a single Product. The product
// attestor's behavior is exercised in its own package's tests.
func TestAttest_JUnit_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	src := mustReadFile(t, "testdata/junit-failing.xml")
	dst := filepath.Join(tmp, "junit.xml")
	require.NoError(t, os.WriteFile(dst, src, 0o644)) //nolint:gosec // test fixture

	att := New()
	ctx := newCtxWithProduct(t, tmp, "junit.xml", src, att)
	require.NoError(t, ctx.RunAttestors())

	assert.Equal(t, FormatJUnitXML, att.Predicate.Format)
	assert.Equal(t, "junit.xml", att.Predicate.ReportFile)
	assert.NotEmpty(t, att.Predicate.ReportDigest)
	assert.Equal(t, 6, att.Predicate.Summary.Total)
	assert.Equal(t, 2, att.Predicate.Summary.Failed)
	assert.Len(t, att.Predicate.FailedTests, 2)

	// Subjects must surface both the suite and the failures.
	subs := att.Subjects()
	hasSuite, hasFailure := false, false
	for k := range subs {
		switch {
		case strings.HasPrefix(k, "test-suite:"):
			hasSuite = true
		case strings.HasPrefix(k, "test-failure:"):
			hasFailure = true
		}
	}
	assert.True(t, hasSuite, "Subjects() must emit at least one test-suite: entry")
	assert.True(t, hasFailure, "Subjects() must emit at least one test-failure: entry")
}

// TestAttest_CTRF_HappyPath checks the CTRF path of the same lifecycle.
func TestAttest_CTRF_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	src := mustReadFile(t, "testdata/ctrf-failing.json")
	dst := filepath.Join(tmp, "ctrf-report.json")
	require.NoError(t, os.WriteFile(dst, src, 0o644)) //nolint:gosec // test fixture

	att := New()
	ctx := newCtxWithProduct(t, tmp, "ctrf-report.json", src, att)
	require.NoError(t, ctx.RunAttestors())

	assert.Equal(t, FormatCTRFJSON, att.Predicate.Format)
	assert.Equal(t, "jest", att.Predicate.ToolName)
	assert.Equal(t, 3, att.Predicate.Summary.Failed)
	assert.Len(t, att.Predicate.FailedTests, 3)
}

// TestAttest_NoProducts asserts the empty-context error surfaces
// instead of a silent no-op.
func TestAttest_NoProducts(t *testing.T) {
	att := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{att},
		attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	err = att.Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no products")
}

// TestFailedFQName covers the suite/classname/name composition rules.
func TestFailedFQName(t *testing.T) {
	cases := []struct {
		name string
		in   FailedTest
		want string
	}{
		{"classname+name", FailedTest{Name: "test_x", Classname: "pkg.Suite"}, "pkg.Suite.test_x"},
		{"suite+name", FailedTest{Name: "test_x", Suite: "math"}, "math::test_x"},
		{"only name", FailedTest{Name: "test_x"}, "test_x"},
		{"empty", FailedTest{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, failedFQName(tc.in))
		})
	}
}

// --- test helpers ------------------------------------------------------

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	return mustReadFile(t, path)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test fixture path
	require.NoError(t, err)
	return data
}

// digestOf computes a single-hash DigestSet over content. The test
// only needs enough digest agreement for the getCandidate integrity
// check; SHA-256 is the universal floor.
func digestOf(t *testing.T, content []byte) cryptoutil.DigestSet {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromBytes(content, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	return ds
}

// stubProducer surfaces a single product into an AttestationContext so
// the test-results attestor's getCandidate can find it without
// depending on the product attestor's MIME-sniffing implementation.
type stubProducer struct {
	products map[string]attestation.Product
}

func (s stubProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (s stubProducer) Name() string                                   { return "stub-producer" }
func (s stubProducer) Type() string                                   { return "stub-producer" }
func (s stubProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (s stubProducer) Schema() *jsonschema.Schema                     { return &jsonschema.Schema{} }
func (s stubProducer) Products() map[string]attestation.Product       { return s.products }

// newCtxWithProduct builds a real AttestationContext rooted at tmpDir
// with a single product (relPath) pre-populated. It returns the context
// ready for ctx.RunAttestors(), which will call the test-results
// attestor's Attest method.
func newCtxWithProduct(t *testing.T, tmpDir, relPath string, content []byte, att attestation.Attestor) *attestation.AttestationContext {
	t.Helper()
	ds := digestOf(t, content)
	prod := stubProducer{products: map[string]attestation.Product{
		relPath: {MimeType: "application/octet-stream", Digest: ds},
	}}
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{prod, att},
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	return ctx
}
