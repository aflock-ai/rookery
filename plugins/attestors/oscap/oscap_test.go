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

package oscap

import (
	"testing"
)

// sampleXCCDF is a minimal but structurally complete XCCDF 1.2 document that
// mirrors the output of `oscap xccdf eval --results results.xml` on a RHEL/STIG
// benchmark.  It is intentionally self-contained (no external DTD references).
const sampleXCCDF = `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"
           id="xccdf_mil.disa.stig_benchmark_RHEL-8-V1R12">
  <TestResult id="xccdf_mil.disa.stig_testresult_RHEL-8-V1R12">
    <profile idref="xccdf_mil.disa.stig_profile_MAC-1_Classified"/>
    <target>rhel8-host.example.com</target>
    <rule-result idref="xccdf_mil.disa.stig_rule_SV-230224r877787_rule" severity="high">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_mil.disa.stig_rule_SV-230225r858734_rule" severity="medium">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_mil.disa.stig_rule_SV-230226r877789_rule" severity="high">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_mil.disa.stig_rule_SV-230227r858736_rule" severity="low">
      <result>notapplicable</result>
    </rule-result>
    <rule-result idref="xccdf_mil.disa.stig_rule_SV-230228r999999_rule" severity="medium">
      <result>error</result>
    </rule-result>
  </TestResult>
</Benchmark>`

// sampleXCCDFInARF wraps the Benchmark inside an ARF envelope, which is the
// default output format when using `oscap xccdf eval --results-arf`.
const sampleXCCDFInARF = `<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"
                             xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <arf:reports>
    <arf:report>
      <xccdf:Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"
                       id="xccdf_mil.disa.stig_benchmark_RHEL-8-V1R12">
        <TestResult id="xccdf_mil.disa.stig_testresult_RHEL-8-V1R12">
          <profile idref="xccdf_mil.disa.stig_profile_MAC-1_Public"/>
          <target>arf-host.example.com</target>
          <rule-result idref="xccdf_mil.disa.stig_rule_SV-230224r877787_rule" severity="high">
            <result>pass</result>
          </rule-result>
          <rule-result idref="xccdf_mil.disa.stig_rule_SV-230226r877789_rule" severity="high">
            <result>fail</result>
          </rule-result>
        </TestResult>
      </xccdf:Benchmark>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>`

func TestIsXCCDF(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid xccdf", sampleXCCDF, true},
		{"valid arf wrapping xccdf", sampleXCCDFInARF, true},
		{"json document", `{"key":"value"}`, false},
		{"plain xml no xccdf ns", `<root><child/></root>`, false},
		{"nessus xml", `<NessusClientData_v2><Report/></NessusClientData_v2>`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isXCCDF([]byte(tc.input))
			if got != tc.expected {
				t.Errorf("isXCCDF() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestParseXCCDF(t *testing.T) {
	bm, err := parseXCCDF([]byte(sampleXCCDF))
	if err != nil {
		t.Fatalf("parseXCCDF failed: %v", err)
	}
	if bm.ID != "xccdf_mil.disa.stig_benchmark_RHEL-8-V1R12" {
		t.Errorf("unexpected benchmark ID: %q", bm.ID)
	}
	if len(bm.Results) != 1 {
		t.Fatalf("expected 1 TestResult, got %d", len(bm.Results))
	}
	if len(bm.Results[0].RuleResults) != 5 {
		t.Errorf("expected 5 rule-results, got %d", len(bm.Results[0].RuleResults))
	}
}

//nolint:gocyclo // table-driven test with per-case branch assertions
func TestBuildSummaryAndSubjects(t *testing.T) {
	a := New()

	bm, err := parseXCCDF([]byte(sampleXCCDF))
	if err != nil {
		t.Fatalf("parseXCCDF failed: %v", err)
	}

	a.buildSummaryAndSubjects(bm)

	// --- counts ---
	if a.ScanSummary.PassCount != 2 {
		t.Errorf("PassCount: got %d, want 2", a.ScanSummary.PassCount)
	}
	if a.ScanSummary.FailCount != 1 {
		t.Errorf("FailCount: got %d, want 1", a.ScanSummary.FailCount)
	}
	if a.ScanSummary.NotApplicable != 1 {
		t.Errorf("NotApplicable: got %d, want 1", a.ScanSummary.NotApplicable)
	}
	if a.ScanSummary.ErrorCount != 1 {
		t.Errorf("ErrorCount: got %d, want 1", a.ScanSummary.ErrorCount)
	}

	// --- failed rules list ---
	if len(a.ScanSummary.FailedRules) != 1 {
		t.Fatalf("FailedRules: got %d, want 1", len(a.ScanSummary.FailedRules))
	}
	if a.ScanSummary.FailedRules[0].IDRef != "xccdf_mil.disa.stig_rule_SV-230226r877789_rule" {
		t.Errorf("unexpected failed rule IDRef: %q", a.ScanSummary.FailedRules[0].IDRef)
	}
	if a.ScanSummary.FailedRules[0].Severity != "high" {
		t.Errorf("expected severity high, got %q", a.ScanSummary.FailedRules[0].Severity)
	}

	// --- metadata fields ---
	if a.ScanSummary.Profile != "xccdf_mil.disa.stig_profile_MAC-1_Classified" {
		t.Errorf("unexpected profile: %q", a.ScanSummary.Profile)
	}
	if a.ScanSummary.TargetSystem != "rhel8-host.example.com" {
		t.Errorf("unexpected target system: %q", a.ScanSummary.TargetSystem)
	}
	if a.ScanSummary.BenchmarkID != "xccdf_mil.disa.stig_benchmark_RHEL-8-V1R12" {
		t.Errorf("unexpected benchmark ID: %q", a.ScanSummary.BenchmarkID)
	}

	// --- subjects ---
	subjects := a.Subjects()
	if _, ok := subjects["profile:xccdf_mil.disa.stig_profile_MAC-1_Classified"]; !ok {
		t.Error("missing subject: profile:xccdf_mil.disa.stig_profile_MAC-1_Classified")
	}
	if _, ok := subjects["host:rhel8-host.example.com"]; !ok {
		t.Error("missing subject: host:rhel8-host.example.com")
	}
	if _, ok := subjects["benchmark:xccdf_mil.disa.stig_benchmark_RHEL-8-V1R12"]; !ok {
		t.Error("missing subject: benchmark:xccdf_mil.disa.stig_benchmark_RHEL-8-V1R12")
	}
	if len(subjects) != 3 {
		t.Errorf("expected exactly 3 subjects, got %d: %v", len(subjects), subjects)
	}
}

func TestBuildSummaryARFWrapped(t *testing.T) {
	a := New()

	bm, err := parseXCCDF([]byte(sampleXCCDFInARF))
	if err != nil {
		t.Fatalf("parseXCCDF on ARF-wrapped document failed: %v", err)
	}

	a.buildSummaryAndSubjects(bm)

	if a.ScanSummary.PassCount != 1 {
		t.Errorf("PassCount: got %d, want 1", a.ScanSummary.PassCount)
	}
	if a.ScanSummary.FailCount != 1 {
		t.Errorf("FailCount: got %d, want 1", a.ScanSummary.FailCount)
	}
	if a.ScanSummary.TargetSystem != "arf-host.example.com" {
		t.Errorf("TargetSystem: got %q, want arf-host.example.com", a.ScanSummary.TargetSystem)
	}

	subjects := a.Subjects()
	if _, ok := subjects["host:arf-host.example.com"]; !ok {
		t.Error("missing subject: host:arf-host.example.com")
	}
}

func TestBuildSummaryEmptyResults(t *testing.T) {
	a := New()
	a.buildSummaryAndSubjects(benchmarkXML{ID: "empty-benchmark"})

	if a.ScanSummary.BenchmarkID != "empty-benchmark" {
		t.Errorf("unexpected benchmark ID: %q", a.ScanSummary.BenchmarkID)
	}
	if a.ScanSummary.PassCount != 0 || a.ScanSummary.FailCount != 0 {
		t.Error("expected zero counts for empty benchmark")
	}
	if len(a.Subjects()) != 0 {
		t.Errorf("expected no subjects for empty benchmark, got %v", a.Subjects())
	}
}

func TestMetadata(t *testing.T) {
	a := New()
	if a.Name() != Name {
		t.Errorf("Name() = %q, want %q", a.Name(), Name)
	}
	if a.Type() != Type {
		t.Errorf("Type() = %q, want %q", a.Type(), Type)
	}
	if a.RunType() != RunType {
		t.Errorf("RunType() = %v, want %v", a.RunType(), RunType)
	}
}

func TestParseXCCDFNoBenchmark(t *testing.T) {
	const noBenchmark = `<?xml version="1.0"?>
<root xmlns="http://checklists.nist.gov/xccdf/1.2">
  <SomeOtherElement/>
</root>`

	_, err := parseXCCDF([]byte(noBenchmark))
	if err == nil {
		t.Error("expected error when no Benchmark element found, got nil")
	}
}
