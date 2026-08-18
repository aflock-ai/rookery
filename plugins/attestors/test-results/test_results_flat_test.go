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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Node's built-in test runner emits testcases DIRECTLY under <testsuites>, with
// no intervening <testsuite>. This is the exact output of
//
//	node --test --test-reporter=junit --test-reporter-destination=junit.xml
//
// on Node 22, and it is the shape a JS project gets by reaching for the runner
// that ships with the language — no plugin, no config.
//
// The parser accepted <testsuites><testsuite> and a bare <testsuite> root, so
// this document was detected as JUnit and then rejected with "JUnit document
// contains no testsuite elements". The attestor failed, no test-results
// attestation was produced, and any policy requiring one could not be satisfied
// by that project at all — while the tests themselves passed and the report on
// disk was valid.
const nodeFlatJUnit = `<?xml version="1.0" encoding="utf-8"?>
<testsuites>
	<testcase name="parses the ordinary shape" time="0.000769" classname="test"/>
	<testcase name="orders numbers numerically" time="0.000212" classname="test"/>
	<testcase name="a prerelease sorts below its release" time="0.000181" classname="test"/>
</testsuites>`

const nodeFlatJUnitWithFailure = `<?xml version="1.0" encoding="utf-8"?>
<testsuites>
	<testcase name="passes" time="0.001" classname="test"/>
	<testcase name="breaks" time="0.002" classname="test">
		<failure type="testCodeFailure" message="expected 1 to equal 2">stack here</failure>
	</testcase>
	<testcase name="ignored" time="0.000" classname="test">
		<skipped message="not today"/>
	</testcase>
</testsuites>`

func TestParseJUnit_TestcasesDirectlyUnderTestsuites(t *testing.T) {
	pred, suites, err := parseJUnit([]byte(nodeFlatJUnit))
	require.NoError(t, err, "the JUnit report produced by `node --test` was rejected")

	assert.Equal(t, FormatJUnitXML, pred.Format)
	assert.Equal(t, 3, pred.Summary.Total)
	assert.Equal(t, 3, pred.Summary.Passed)
	assert.Equal(t, 0, pred.Summary.Failed)
	assert.Empty(t, pred.FailedTests)
	// One synthetic suite stands in for the absent <testsuite> wrapper.
	assert.Len(t, suites, 1)
}

// Counts must come from the cases, not from attributes the flat form does not
// carry — otherwise a passing run reports zero tests and "no test passed" is
// indistinguishable from a real empty suite.
func TestParseJUnit_FlatFormCountsFailuresAndSkips(t *testing.T) {
	pred, _, err := parseJUnit([]byte(nodeFlatJUnitWithFailure))
	require.NoError(t, err)

	assert.Equal(t, 3, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed)
	assert.Equal(t, 1, pred.Summary.Failed)
	assert.Equal(t, 1, pred.Summary.Skipped)
	require.Len(t, pred.FailedTests, 1)
	assert.Equal(t, "breaks", pred.FailedTests[0].Name)
	assert.Equal(t, "expected 1 to equal 2", pred.FailedTests[0].Message)
}

// A bare <testsuite> root with no name attribute is the second shape the
// fallback missed: it required single.Name != "", so an unnamed suite full of
// real cases parsed to nothing and hit the same dead end.
func TestParseJUnit_BareUnnamedTestsuite(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<testsuite tests="2">
	<testcase name="a" time="0.1"/>
	<testcase name="b" time="0.2"><failure message="nope"/></testcase>
</testsuite>`

	pred, _, err := parseJUnit([]byte(doc))
	require.NoError(t, err, "an unnamed <testsuite> root was rejected")
	assert.Equal(t, 2, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed)
	assert.Equal(t, 1, pred.Summary.Failed)
}

// The guard still has to reject a document with genuinely nothing in it —
// widening the parser must not turn "no tests ran" into a pass.
func TestParseJUnit_StillRejectsEmptyDocument(t *testing.T) {
	_, _, err := parseJUnit([]byte(`<?xml version="1.0"?><testsuites></testsuites>`))
	require.Error(t, err, "an empty <testsuites> must not parse as a successful run")
}


// A failing `node --test` run writes the assertion text into <failure> with the
// ANSI escapes still in it, so the document is not well-formed XML. Before this
// was handled, such a run produced NO attestation: the reason tests failed was
// indistinguishable from no tests having run.
func TestParseJUnit_FailureBodyWithANSIEscapes(t *testing.T) {
	doc := "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<testsuites>\n" +
		"\t<testcase name=\"passes\" time=\"0.001\" classname=\"test\"/>\n" +
		"\t<testcase name=\"orders numbers numerically\" time=\"0.0008\" classname=\"test\">\n" +
		"\t\t<failure type=\"testCodeFailure\" message=\"Expected values to be strictly equal\">\n" +
		"\x1b[32m-1\x1b[0m !== \x1b[31m1\x1b[0m\n" +
		"\t\t</failure>\n" +
		"\t</testcase>\n" +
		"</testsuites>"

	pred, _, err := parseJUnit([]byte(doc))
	require.NoError(t, err, "a failing run's report was rejected as malformed XML")
	assert.Equal(t, 2, pred.Summary.Total)
	assert.Equal(t, 1, pred.Summary.Passed)
	assert.Equal(t, 1, pred.Summary.Failed)
	require.Len(t, pred.FailedTests, 1)
	assert.Equal(t, "orders numbers numerically", pred.FailedTests[0].Name)
}

// Stripping illegal bytes must not become a general repair pass: a document
// broken in any other way still has to fail rather than parse to something
// plausible.
func TestParseJUnit_StillRejectsMalformedStructure(t *testing.T) {
	_, _, err := parseJUnit([]byte(`<testsuites><testcase name="a"></testsuites>`))
	require.Error(t, err, "an unclosed element parsed successfully")
}
