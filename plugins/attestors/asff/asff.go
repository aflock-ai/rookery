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

package asff

import (
	"crypto"
	"encoding/json"
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
	Name    = "asff"
	Type    = "https://aflock.ai/attestations/asff/v0.1"
	RunType = attestation.PostProductRunType
)

// Compile-time interface check.
var _ attestation.Attestor = &Attestor{}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// ---- ASFF JSON types (subset used by aws securityhub get-findings) ----

// asffResponse is the top-level envelope produced by `aws securityhub get-findings --output json`.
type asffResponse struct {
	Findings []Finding `json:"Findings"`
}

// Finding represents a single AWS Security Finding Format record.
type Finding struct {
	// Id is the ARN of the finding, e.g. "arn:aws:securityhub:us-east-1:123456789012:subscription/..."
	Id         string      `json:"Id"`
	Title      string      `json:"Title"`
	ProductArn string      `json:"ProductArn"`
	AwsAccountId string    `json:"AwsAccountId"`
	Severity   Severity    `json:"Severity"`
	Compliance Compliance  `json:"Compliance"`
	Resources  []Resource  `json:"Resources"`
}

// Severity holds the finding severity information from ASFF.
type Severity struct {
	// Label is one of: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	Label string `json:"Label"`
}

// Compliance holds the compliance status from ASFF.
type Compliance struct {
	// Status is one of: PASSED, FAILED, WARNING, NOT_AVAILABLE
	Status string `json:"Status"`
}

// Resource represents an AWS resource referenced in a finding.
type Resource struct {
	Type string `json:"Type"`
	Id   string `json:"Id"`
}

// ---- Summary types stored in the attestation predicate ----

// FailedFinding is a condensed record for findings with FAILED compliance status.
type FailedFinding struct {
	FindingArn    string     `json:"findingArn"`
	Title         string     `json:"title"`
	Severity      string     `json:"severity"`
	ProductArn    string     `json:"productArn"`
	AwsAccountId  string     `json:"awsAccountId"`
	Resources     []Resource `json:"resources"`
}

// ComplianceStatusCounts holds per-severity breakdowns across compliance statuses.
type ComplianceStatusCounts struct {
	Passed       int `json:"passed"`
	Failed       int `json:"failed"`
	Warning      int `json:"warning"`
	NotAvailable int `json:"notAvailable"`
}

// SeverityCounts holds pass/fail finding counts per ASFF severity label.
type SeverityCounts struct {
	Count int `json:"count"`
}

// Summary is the attestation predicate stored in the signed envelope.
type Summary struct {
	// AwsAccountId extracted from the first finding that has one.
	AwsAccountId string `json:"awsAccountId"`

	TotalFindings int `json:"totalFindings"`

	// BySeverity maps severity label (e.g. "CRITICAL") to a count of findings at that level.
	BySeverity map[string]SeverityCounts `json:"bySeverity"`

	// ByComplianceStatus maps compliance status (e.g. "FAILED") to a count.
	ByComplianceStatus map[string]int `json:"byComplianceStatus"`

	// FailedFindings contains condensed records for every finding with Compliance.Status == "FAILED".
	FailedFindings []FailedFinding `json:"failedFindings"`

	ReportFile   string               `json:"reportFile"`
	ReportDigest cryptoutil.DigestSet `json:"reportDigest"`
}

// ---- Attestor ----

// Attestor reads AWS Security Hub ASFF JSON output and produces a signed summary attestation.
type Attestor struct {
	Summary Summary `json:"summary"`
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
	return jsonschema.Reflect(&a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/asff) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects returns graph-edge subjects derived from the ASFF findings:
//   - The AWS account being scanned: "aws:account:<id>"
//   - Each unique resource ARN from all findings: "aws:arn:<arn>"
//   - The ARN of each CRITICAL or HIGH severity finding: "aws:finding:<arn>"
//
// SHA-256 digests of the identifier strings follow the same pattern as
// other AWS attestors (aws-codebuild, prowler), allowing Archivista to
// index and cross-link attestations that reference the same cloud resources.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	addSubject := func(key, value string) {
		if value == "" {
			return
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/asff) failed to hash subject %s: %v", key, err)
			return
		}
		subjects[key] = ds
	}

	if a.Summary.AwsAccountId != "" {
		addSubject(fmt.Sprintf("aws:account:%s", a.Summary.AwsAccountId), a.Summary.AwsAccountId)
	}

	seenARNs := make(map[string]bool)
	for _, ff := range a.Summary.FailedFindings {
		// Emit a subject for the finding ARN itself if it's CRITICAL or HIGH.
		sev := strings.ToUpper(ff.Severity)
		if (sev == "CRITICAL" || sev == "HIGH") && ff.FindingArn != "" {
			addSubject(fmt.Sprintf("aws:finding:%s", ff.FindingArn), ff.FindingArn)
		}

		// Emit a subject for each resource ARN referenced in the finding.
		for _, r := range ff.Resources {
			if r.Id != "" && !seenARNs[r.Id] {
				seenARNs[r.Id] = true
				addSubject(fmt.Sprintf("aws:arn:%s", r.Id), r.Id)
			}
		}
	}

	return subjects
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	mimeTypes := []string{"text/plain", "application/json"}

	for path, product := range products {
		if product.MimeType == "" {
			continue
		}
		mimeMatch := false
		for _, mt := range mimeTypes {
			if product.MimeType == mt {
				mimeMatch = true
				break
			}
		}
		if !mimeMatch {
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/asff) error calculating digest set from file %s: %v", path, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/asff) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/asff) error opening file %s: %v", path, err)
			continue
		}
		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/asff) error reading file %s: %v", path, err)
			continue
		}

		var response asffResponse
		if err := json.Unmarshal(reportBytes, &response); err != nil {
			log.Debugf("(attestation/asff) not ASFF JSON in %s: %v", path, err)
			continue
		}

		if err := validateASFF(response.Findings); err != nil {
			log.Debugf("(attestation/asff) validation failed for %s: %v", path, err)
			continue
		}

		a.Summary = buildSummary(response.Findings)
		a.Summary.ReportFile = path
		a.Summary.ReportDigest = product.Digest
		return nil
	}

	return fmt.Errorf("no ASFF JSON output file found in products")
}

// validateASFF confirms the parsed slice actually looks like ASFF output from Security Hub.
// It verifies the Findings array is non-empty and that every record has the mandatory
// fields that Security Hub always populates: Id, Severity.Label, and Compliance.Status.
func validateASFF(findings []Finding) error {
	if len(findings) == 0 {
		return fmt.Errorf("ASFF Findings array is empty")
	}

	validSeverities := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFORMATIONAL": true,
	}
	validComplianceStatuses := map[string]bool{
		"PASSED": true, "FAILED": true, "WARNING": true, "NOT_AVAILABLE": true,
	}

	for i, f := range findings {
		if f.Id == "" {
			return fmt.Errorf("finding at index %d is missing Id — not ASFF output", i)
		}
		sev := strings.ToUpper(f.Severity.Label)
		if !validSeverities[sev] {
			return fmt.Errorf("finding at index %d has unexpected Severity.Label %q", i, f.Severity.Label)
		}
		status := strings.ToUpper(f.Compliance.Status)
		if !validComplianceStatuses[status] {
			return fmt.Errorf("finding at index %d has unexpected Compliance.Status %q", i, f.Compliance.Status)
		}
	}

	return nil
}

func buildSummary(findings []Finding) Summary {
	s := Summary{
		BySeverity:         make(map[string]SeverityCounts),
		ByComplianceStatus: make(map[string]int),
		FailedFindings:     []FailedFinding{},
	}

	for _, f := range findings {
		if s.AwsAccountId == "" {
			s.AwsAccountId = f.AwsAccountId
		}

		s.TotalFindings++

		sev := strings.ToUpper(f.Severity.Label)
		sevCounts := s.BySeverity[sev]
		sevCounts.Count++
		s.BySeverity[sev] = sevCounts

		status := strings.ToUpper(f.Compliance.Status)
		s.ByComplianceStatus[status]++

		if status == "FAILED" {
			s.FailedFindings = append(s.FailedFindings, FailedFinding{
				FindingArn:   f.Id,
				Title:        f.Title,
				Severity:     sev,
				ProductArn:   f.ProductArn,
				AwsAccountId: f.AwsAccountId,
				Resources:    f.Resources,
			})
		}
	}

	return s
}
