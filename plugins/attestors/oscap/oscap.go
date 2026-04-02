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

// Package oscap attests OpenSCAP XCCDF/ARF scan results produced by
// `oscap xccdf eval --results results.xml`.
package oscap

import (
	"crypto"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "oscap"
	Type    = "https://aflock.ai/attestations/oscap/v0.1"
	RunType = attestation.PostProductRunType

	// xccdfNamespace is the XML namespace for XCCDF 1.2 documents.
	// We check for this to validate that the file is actually an XCCDF report.
	xccdfNamespace = "http://checklists.nist.gov/xccdf/1.2"
)

// compile-time interface checks
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// ------------------- XML structures -------------------

// benchmarkXML is a lightweight representation of an XCCDF Benchmark document.
// We only decode the fields we need; the XML decoder ignores the rest.
type benchmarkXML struct {
	XMLName xml.Name    `xml:"Benchmark"`
	ID      string      `xml:"id,attr"`
	Results []resultXML `xml:"TestResult"`
}

// profileRef maps to the <profile> element inside <TestResult>.
type profileRef struct {
	IDRef string `xml:"idref,attr"`
}

// resultXML maps to <TestResult> inside an XCCDF Benchmark.
type resultXML struct {
	ID          string          `xml:"id,attr"`
	Profile     profileRef      `xml:"profile"`
	Target      string          `xml:"target"`
	RuleResults []ruleResultXML `xml:"rule-result"`
}

// ruleResultXML maps to a single <rule-result> entry.
type ruleResultXML struct {
	IDRef    string `xml:"idref,attr"`
	Severity string `xml:"severity,attr"`
	// <result> is a child element, not an attribute.
	Result string `xml:"result"`
}

// FailedRule records a rule that produced a non-pass outcome.
type FailedRule struct {
	IDRef    string `json:"idref"`
	Severity string `json:"severity,omitempty"`
	Result   string `json:"result"`
}

// Summary is the human-readable summary embedded in the attestation.
type Summary struct {
	Profile       string       `json:"profile"`
	BenchmarkID   string       `json:"benchmarkId"`
	TargetSystem  string       `json:"targetSystem"`
	PassCount     int          `json:"passCount"`
	FailCount     int          `json:"failCount"`
	NotApplicable int          `json:"notApplicableCount"`
	ErrorCount    int          `json:"errorCount"`
	FailedRules   []FailedRule `json:"failedRules,omitempty"`
}

// Attestor reads an XCCDF/ARF XML file produced by OpenSCAP and attests to
// the scan result.  It implements attestation.Subjecter to expose the profile,
// target host, and benchmark as verifiable subjects.
type Attestor struct {
	ReportFile      string               `json:"reportFile"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet"`
	ScanSummary     Summary              `json:"scanSummary"`

	subjects map[string]cryptoutil.DigestSet
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/oscap) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects implements attestation.Subjecter.
// It exposes three subjects per scan:
//   - profile:<profile-id>     — the XCCDF profile that was evaluated
//   - host:<target-hostname>   — the system that was scanned
//   - benchmark:<benchmark-id> — the XCCDF benchmark document
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

// ------------------- candidate selection -------------------

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		// Only consider XML files — skip others quickly.
		if !strings.HasSuffix(path, ".xml") {
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/oscap) error calculating digest set from file %s: %v", path, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/oscap) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/oscap) error opening file %s: %v", path, err)
			continue
		}

		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/oscap) error reading file %s: %v", path, err)
			continue
		}

		// Validate that this is an XCCDF document before attempting full parse.
		if !isXCCDF(reportBytes) {
			log.Debugf("(attestation/oscap) %s does not appear to be an XCCDF document", path)
			continue
		}

		benchmark, err := parseXCCDF(reportBytes)
		if err != nil {
			log.Debugf("(attestation/oscap) error parsing XCCDF from %s: %v", path, err)
			continue
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest
		a.buildSummaryAndSubjects(benchmark)
		return nil
	}

	return fmt.Errorf("no XCCDF/ARF XML file found in products")
}

// isXCCDF returns true if the raw XML bytes declare the XCCDF 1.2 namespace.
// This is a fast pre-filter before doing a full structural parse.
func isXCCDF(data []byte) bool {
	return strings.Contains(string(data), xccdfNamespace)
}

// parseXCCDF decodes raw XCCDF XML bytes into our lightweight struct.
// XCCDF documents may be wrapped inside an ARF <arf:asset-report-collection>
// envelope; we search for the first <Benchmark> element regardless of depth.
func parseXCCDF(data []byte) (benchmarkXML, error) {
	var benchmark benchmarkXML
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return benchmark, fmt.Errorf("xml token error: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "Benchmark" {
			if err := dec.DecodeElement(&benchmark, &se); err != nil {
				return benchmark, fmt.Errorf("decoding Benchmark element: %w", err)
			}
			return benchmark, nil
		}
	}
	return benchmark, fmt.Errorf("no XCCDF Benchmark element found")
}

// ------------------- summary & subjects -------------------

func (a *Attestor) buildSummaryAndSubjects(bm benchmarkXML) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	summary := Summary{BenchmarkID: bm.ID}

	// Use the first TestResult — oscap xccdf eval produces exactly one.
	if len(bm.Results) == 0 {
		a.ScanSummary = summary
		a.subjects = subjects
		return
	}

	result := bm.Results[0]
	summary.Profile = result.Profile.IDRef
	summary.TargetSystem = strings.TrimSpace(result.Target)

	var failed []FailedRule
	for _, rr := range result.RuleResults {
		res := strings.TrimSpace(rr.Result)
		switch res {
		case "pass":
			summary.PassCount++
		case "fail":
			summary.FailCount++
			failed = append(failed, FailedRule{
				IDRef:    rr.IDRef,
				Severity: rr.Severity,
				Result:   res,
			})
		case "notapplicable", "not applicable":
			summary.NotApplicable++
		case "error":
			summary.ErrorCount++
		}
	}
	summary.FailedRules = failed
	a.ScanSummary = summary

	// Emit subjects so policy can reference profile, host, and benchmark.
	subjectValues := map[string]string{
		fmt.Sprintf("profile:%s", summary.Profile):       summary.Profile,
		fmt.Sprintf("host:%s", summary.TargetSystem):     summary.TargetSystem,
		fmt.Sprintf("benchmark:%s", summary.BenchmarkID): summary.BenchmarkID,
	}

	for key, value := range subjectValues {
		if value == "" {
			continue
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/oscap) failed to hash subject %s: %v", key, err)
			continue
		}
		subjects[key] = ds
	}

	a.subjects = subjects
}
