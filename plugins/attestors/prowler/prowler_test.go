// Copyright 2022 The Witness Contributors
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

package prowler

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// TestResolveProductPath guards the regression where product paths (recorded
// relative to the attestation working directory) were opened relative to the
// process CWD instead. That broke discovery whenever cilock was invoked with
// --workingdir/-d pointing somewhere other than the CWD.
func TestResolveProductPath(t *testing.T) {
	wd := t.TempDir()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(wd))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}

	// A relative product path must resolve against the working dir.
	if got, want := resolveProductPath(ctx, "prowler-output-eks.json"), filepath.Join(wd, "prowler-output-eks.json"); got != want {
		t.Errorf("relative path: got %q, want %q", got, want)
	}

	// Absolute paths pass through unchanged.
	abs := filepath.Join(wd, "abs.json")
	if got := resolveProductPath(ctx, abs); got != abs {
		t.Errorf("absolute path: got %q, want %q", got, abs)
	}
}

// expectedSummary describes the canonical Summary the three fixtures should
// all aggregate into. Each fixture encodes the same six logical findings
// (1 PASS Critical, 1 FAIL Critical, 1 FAIL High, 1 FAIL Medium, 1 PASS Low,
// 1 FAIL Low) so all three rows in this table-driven test compare against the
// same expected values.
type expectedSummary struct {
	totalChecks  int
	passCount    int
	failCount    int
	bySeverity   map[string]SeverityCounts
	failedChecks []string // CheckIDs, sorted
	accountId    string
}

// TestProwlerAttestor_ParsesAllFormats verifies the prowler attestor accepts
// all three modern Prowler output shapes (v3 native, v4 OCSF, v4 ASFF) and
// aggregates them into an equivalent Summary. This guards the contract that
// downstream rego policies depend on:
//   - summary.bySeverity.<severity>.{pass,fail}
//   - summary.failedChecks[].checkId
//   - summary.{totalChecks,passCount,failCount,accountId}
func TestProwlerAttestor_ParsesAllFormats(t *testing.T) {
	expected := expectedSummary{
		totalChecks: 6,
		passCount:   2,
		failCount:   4,
		bySeverity: map[string]SeverityCounts{
			"critical": {Pass: 1, Fail: 1},
			"high":     {Pass: 0, Fail: 1},
			"medium":   {Pass: 0, Fail: 1},
			"low":      {Pass: 1, Fail: 1},
		},
		failedChecks: []string{
			"ec2_securitygroup_allow_ingress_from_internet_to_port_22",
			"iam_check_saml_providers_sts",
			"kms_cmk_rotation_enabled",
			"s3_bucket_public_access",
		},
		accountId: "123456789012",
	}

	cases := []struct {
		name    string
		fixture string
	}{
		{name: "prowler-v3-native", fixture: "prowler-v3-native.json"},
		{name: "prowler-v4-ocsf", fixture: "prowler-v4-ocsf.json"},
		{name: "prowler-v4-asff", fixture: "prowler-v4-asff.json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("testdata", tc.fixture)
			bytes, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path
			if err != nil {
				t.Fatalf("read fixture %s: %v", path, err)
			}

			findings, err := parseProwlerReport(bytes)
			if err != nil {
				t.Fatalf("parseProwlerReport(%s): %v", tc.fixture, err)
			}
			if err := validateProwlerFindings(findings); err != nil {
				t.Fatalf("validateProwlerFindings(%s): %v", tc.fixture, err)
			}

			summary := buildSummary(findings)
			assertSummary(t, tc.name, summary, expected)
		})
	}
}

func assertSummary(t *testing.T, format string, got Summary, want expectedSummary) {
	t.Helper()

	if got.TotalChecks != want.totalChecks {
		t.Errorf("[%s] TotalChecks: got %d, want %d", format, got.TotalChecks, want.totalChecks)
	}
	if got.PassCount != want.passCount {
		t.Errorf("[%s] PassCount: got %d, want %d", format, got.PassCount, want.passCount)
	}
	if got.FailCount != want.failCount {
		t.Errorf("[%s] FailCount: got %d, want %d", format, got.FailCount, want.failCount)
	}
	if got.AccountId != want.accountId {
		t.Errorf("[%s] AccountId: got %q, want %q", format, got.AccountId, want.accountId)
	}

	// Compare BySeverity values. Allow missing severities only if they're zero.
	for sev, wantCounts := range want.bySeverity {
		gotCounts := got.BySeverity[sev]
		if gotCounts.Pass != wantCounts.Pass || gotCounts.Fail != wantCounts.Fail {
			t.Errorf("[%s] BySeverity[%q]: got %+v, want %+v", format, sev, gotCounts, wantCounts)
		}
	}
	for sev, gotCounts := range got.BySeverity {
		if _, wanted := want.bySeverity[sev]; !wanted {
			if gotCounts.Pass != 0 || gotCounts.Fail != 0 {
				t.Errorf("[%s] BySeverity[%q]: unexpected non-zero %+v", format, sev, gotCounts)
			}
		}
	}

	// failedChecks: compare the sorted CheckID set so order doesn't matter.
	gotIDs := make([]string, 0, len(got.FailedChecks))
	for _, fc := range got.FailedChecks {
		gotIDs = append(gotIDs, fc.CheckID)
	}
	sort.Strings(gotIDs)
	if !equalStringSlices(gotIDs, want.failedChecks) {
		t.Errorf("[%s] failedChecks CheckIDs: got %v, want %v", format, gotIDs, want.failedChecks)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestProwlerAttestor_RejectsUnknownShape verifies a non-Prowler JSON array
// (or random object) doesn't accidentally match one of the detectors.
func TestProwlerAttestor_RejectsUnknownShape(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "not-array", body: `{"hello": "world"}`},
		{name: "empty-array", body: `[]`},
		{name: "unrelated-object", body: `[{"foo": "bar", "baz": 1}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseProwlerReport([]byte(tc.body))
			if err == nil {
				t.Fatalf("expected parse error for %q, got nil", tc.body)
			}
		})
	}
}

// TestProwlerAttestor_Metadata sanity-checks the static identity of the
// attestor stays put — these constants are referenced by external policies
// and the builder preset registration.
func TestProwlerAttestor_Metadata(t *testing.T) {
	a := New()
	if a.Name() != Name {
		t.Errorf("Name(): got %q, want %q", a.Name(), Name)
	}
	if a.Type() != Type {
		t.Errorf("Type(): got %q, want %q", a.Type(), Type)
	}
	if a.RunType() != RunType {
		t.Errorf("RunType(): got %q, want %q", a.RunType(), RunType)
	}
}
