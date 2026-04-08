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
	Name    = "nessus"
	Type    = "https://aflock.ai/attestations/nessus/v0.1"
	RunType = attestation.PostProductRunType
)

// compile-time interface check
var _ attestation.Attestor = &Attestor{}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// nessusXML mirrors the .nessus file structure for XML decoding.
type nessusXML struct {
	XMLName xml.Name    `xml:"NessusClientData_v2"`
	Reports []reportXML `xml:"Report"`
}

type reportXML struct {
	Name  string         `xml:"name,attr"`
	Hosts []reportHostXML `xml:"ReportHost"`
}

type reportHostXML struct {
	Name  string           `xml:"name,attr"`
	Items []reportItemXML  `xml:"ReportItem"`
}

type reportItemXML struct {
	PluginID   string `xml:"pluginID,attr"`
	Severity   int    `xml:"severity,attr"`
	PluginName string `xml:"pluginName,attr"`
	CVEs       []string `xml:"cve"`
}

// Severity levels as used by Nessus (numeric severity -> label).
const (
	severityInfo     = 0
	severityLow      = 1
	severityMedium   = 2
	severityHigh     = 3
	severityCritical = 4
)

// SeverityCounts holds vulnerability counts per severity level.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Summary is the human-readable summary stored in the attestation.
type Summary struct {
	TotalHosts     int            `json:"totalHosts"`
	Vulnerabilities SeverityCounts `json:"vulnerabilities"`
	TopCVEs        []string       `json:"topCVEs"`
}

// Attestor reads a .nessus XML file produced by Tenable Nessus and attests
// to the scan results, exposing hosts and critical/high CVEs as subjects.
type Attestor struct {
	ReportFile      string               `json:"reportFile"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet"`
	ScanSummary     Summary              `json:"scanSummary"`

	// subjects built during Attest — not serialised separately
	subjects map[string]cryptoutil.DigestSet
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/nessus) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects implements attestation.Subjecter.
// It exposes nessus:host:<name> subjects for every scanned host and
// cve:<id> subjects for every CVE referenced in critical or high findings.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		// Only attempt files that look like .nessus reports.
		if !strings.HasSuffix(path, ".nessus") {
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/nessus) error calculating digest set from file %s: %v", path, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/nessus) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/nessus) error opening file %s: %v", path, err)
			continue
		}

		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/nessus) error reading file %s: %v", path, err)
			continue
		}

		var parsed nessusXML
		if err := xml.Unmarshal(reportBytes, &parsed); err != nil {
			log.Debugf("(attestation/nessus) error parsing XML from %s: %v", path, err)
			continue
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest
		a.buildSummaryAndSubjects(parsed)
		return nil
	}

	return fmt.Errorf("no .nessus file found in products")
}

func (a *Attestor) buildSummaryAndSubjects(parsed nessusXML) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	cveSet := make(map[string]struct{})
	var counts SeverityCounts
	hostCount := 0

	for _, report := range parsed.Reports {
		for _, host := range report.Hosts {
			hostCount++

			// subject: nessus:host:<name-or-ip>
			key := fmt.Sprintf("nessus:host:%s", host.Name)
			if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(host.Name), hashes); err == nil {
				subjects[key] = ds
			} else {
				log.Debugf("(attestation/nessus) failed to hash host subject %s: %v", host.Name, err)
			}

			for _, item := range host.Items {
				switch item.Severity {
				case severityCritical:
					counts.Critical++
				case severityHigh:
					counts.High++
				case severityMedium:
					counts.Medium++
				case severityLow:
					counts.Low++
				default:
					counts.Info++
				}

				// Emit CVE subjects only for critical and high findings.
				if item.Severity >= severityHigh {
					for _, cve := range item.CVEs {
						cve = strings.TrimSpace(cve)
						if cve == "" {
							continue
						}
						cveSet[cve] = struct{}{}

						key := fmt.Sprintf("cve:%s", cve)
						if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(cve), hashes); err == nil {
							subjects[key] = ds
						} else {
							log.Debugf("(attestation/nessus) failed to hash CVE subject %s: %v", cve, err)
						}
					}
				}
			}
		}
	}

	// Collect unique CVEs for summary.
	topCVEs := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		topCVEs = append(topCVEs, cve)
	}

	a.ScanSummary = Summary{
		TotalHosts:      hostCount,
		Vulnerabilities: counts,
		TopCVEs:         topCVEs,
	}
	a.subjects = subjects
}
