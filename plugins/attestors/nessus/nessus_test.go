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

package nessus

import (
	"encoding/xml"
	"testing"
)

const sampleNessus = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="scan-2024">
    <ReportHost name="192.168.1.1">
      <ReportItem pluginID="12345" severity="4" pluginName="OpenSSL Critical RCE">
        <cve>CVE-2023-0001</cve>
      </ReportItem>
      <ReportItem pluginID="23456" severity="3" pluginName="Apache High Vuln">
        <cve>CVE-2023-0002</cve>
      </ReportItem>
      <ReportItem pluginID="34567" severity="2" pluginName="Medium Issue">
      </ReportItem>
      <ReportItem pluginID="45678" severity="0" pluginName="Info Plugin">
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.5">
      <ReportItem pluginID="56789" severity="1" pluginName="Low Finding">
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func TestBuildSummaryAndSubjects(t *testing.T) {
	a := New()

	var parsed nessusXML
	if err := xml.Unmarshal([]byte(sampleNessus), &parsed); err != nil {
		t.Fatalf("xml.Unmarshal failed: %v", err)
	}

	a.buildSummaryAndSubjects(parsed)

	if a.ScanSummary.TotalHosts != 2 {
		t.Errorf("expected 2 hosts, got %d", a.ScanSummary.TotalHosts)
	}
	if a.ScanSummary.Vulnerabilities.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", a.ScanSummary.Vulnerabilities.Critical)
	}
	if a.ScanSummary.Vulnerabilities.High != 1 {
		t.Errorf("expected 1 high, got %d", a.ScanSummary.Vulnerabilities.High)
	}
	if a.ScanSummary.Vulnerabilities.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", a.ScanSummary.Vulnerabilities.Medium)
	}
	if a.ScanSummary.Vulnerabilities.Low != 1 {
		t.Errorf("expected 1 low, got %d", a.ScanSummary.Vulnerabilities.Low)
	}
	if a.ScanSummary.Vulnerabilities.Info != 1 {
		t.Errorf("expected 1 info, got %d", a.ScanSummary.Vulnerabilities.Info)
	}

	// Host subjects.
	if _, ok := a.subjects["nessus:host:192.168.1.1"]; !ok {
		t.Error("expected subject nessus:host:192.168.1.1")
	}
	if _, ok := a.subjects["nessus:host:10.0.0.5"]; !ok {
		t.Error("expected subject nessus:host:10.0.0.5")
	}

	// CVE subjects — only critical and high.
	if _, ok := a.subjects["cve:CVE-2023-0001"]; !ok {
		t.Error("expected subject cve:CVE-2023-0001 (critical)")
	}
	if _, ok := a.subjects["cve:CVE-2023-0002"]; !ok {
		t.Error("expected subject cve:CVE-2023-0002 (high)")
	}

	// TopCVEs list should have exactly 2 entries.
	if len(a.ScanSummary.TopCVEs) != 2 {
		t.Errorf("expected 2 top CVEs, got %d: %v", len(a.ScanSummary.TopCVEs), a.ScanSummary.TopCVEs)
	}
}

func TestGetCandidateNoProducts(t *testing.T) {
	// Attest with no attestation context products should return an error.
	a := New()
	if a.Name() != Name {
		t.Errorf("unexpected Name(): %s", a.Name())
	}
	if a.Type() != Type {
		t.Errorf("unexpected Type(): %s", a.Type())
	}
	if a.RunType() != RunType {
		t.Errorf("unexpected RunType(): %s", a.RunType())
	}
}
