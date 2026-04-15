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
	Name    = "prowler"
	Type    = "https://aflock.ai/attestations/prowler/v0.1"
	RunType = attestation.PostProductRunType
)

// Compile-time interface check.
var _ attestation.Attestor = &Attestor{}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// Finding represents a single prowler check result as produced by `prowler -M json`.
type Finding struct {
	AssessmentStartTime string            `json:"AssessmentStartTime"`
	FindingUniqueId     string            `json:"FindingUniqueId"`
	Provider            string            `json:"Provider"`
	CheckID             string            `json:"CheckID"`
	CheckTitle          string            `json:"CheckTitle"`
	CheckType           []string          `json:"CheckType"`
	ServiceName         string            `json:"ServiceName"`
	SubServiceName      string            `json:"SubServiceName"`
	Status              string            `json:"Status"`
	StatusExtended      string            `json:"StatusExtended"`
	Severity            string            `json:"Severity"`
	ResourceType        string            `json:"ResourceType"`
	ResourceDetails     string            `json:"ResourceDetails"`
	Description         string            `json:"Description"`
	Risk                string            `json:"Risk"`
	AccountId           string            `json:"AccountId"`
	Region              string            `json:"Region"`
	ResourceId          string            `json:"ResourceId"`
	ResourceArn         string            `json:"ResourceArn"`
	ResourceTags        map[string]string `json:"ResourceTags"`
	Notes               string            `json:"Notes"`
}

// FailedCheck is a condensed representation stored in the attestation predicate
// to avoid embedding the full (potentially enormous) finding.
type FailedCheck struct {
	CheckID        string `json:"checkId"`
	CheckTitle     string `json:"checkTitle"`
	Severity       string `json:"severity"`
	ServiceName    string `json:"serviceName"`
	Region         string `json:"region"`
	ResourceId     string `json:"resourceId"`
	ResourceArn    string `json:"resourceArn"`
	StatusExtended string `json:"statusExtended"`
}

// SeverityCounts holds pass/fail counts per severity level.
type SeverityCounts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
}

// Summary is the attestation predicate stored in the signed envelope.
type Summary struct {
	AccountId    string                    `json:"accountId"`
	Provider     string                    `json:"provider"`
	TotalChecks  int                       `json:"totalChecks"`
	PassCount    int                       `json:"passCount"`
	FailCount    int                       `json:"failCount"`
	BySeverity   map[string]SeverityCounts `json:"bySeverity"`
	FailedChecks []FailedCheck             `json:"failedChecks"`
	ReportFile   string                    `json:"reportFile"`
	ReportDigest cryptoutil.DigestSet      `json:"reportDigest"`
}

// Attestor reads prowler JSON output and produces a signed summary attestation.
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
		log.Debugf("(attestation/prowler) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects returns graph-edge subjects derived from the prowler findings:
//   - The AWS account being scanned: "aws:account:<id>"
//   - Each unique resource ARN: "aws:arn:<arn>"
//   - Each unique AWS service scanned: "aws:service:<name>"
//
// Using SHA-256 digests of the identifier strings follows the same pattern
// as the aws-codebuild attestor, allowing Archivista to index and cross-link
// attestations that reference the same cloud resources.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	addSubject := func(key, value string) {
		if value == "" {
			return
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/prowler) failed to hash subject %s: %v", key, err)
			return
		}
		subjects[key] = ds
	}

	if a.Summary.AccountId != "" {
		addSubject(fmt.Sprintf("aws:account:%s", a.Summary.AccountId), a.Summary.AccountId)
	}

	// Deduplicate resource ARNs and service names across all failed checks.
	seenARNs := make(map[string]bool)
	seenServices := make(map[string]bool)
	for _, fc := range a.Summary.FailedChecks {
		if fc.ResourceArn != "" && !seenARNs[fc.ResourceArn] {
			seenARNs[fc.ResourceArn] = true
			addSubject(fmt.Sprintf("aws:arn:%s", fc.ResourceArn), fc.ResourceArn)
		}
		if fc.ServiceName != "" && !seenServices[fc.ServiceName] {
			seenServices[fc.ServiceName] = true
			addSubject(fmt.Sprintf("aws:service:%s", fc.ServiceName), fc.ServiceName)
		}
	}

	return subjects
}

//nolint:gocognit // sequential candidate scan: iterate products → open → decode → validate
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
			log.Debugf("(attestation/prowler) error calculating digest set from file %s: %v", path, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/prowler) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/prowler) error opening file %s: %v", path, err)
			continue
		}
		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/prowler) error reading file %s: %v", path, err)
			continue
		}

		var findings []Finding
		if err := json.Unmarshal(reportBytes, &findings); err != nil {
			log.Debugf("(attestation/prowler) not a prowler JSON array in %s: %v", path, err)
			continue
		}

		if err := validateProwlerFindings(findings); err != nil {
			log.Debugf("(attestation/prowler) validation failed for %s: %v", path, err)
			continue
		}

		a.Summary = buildSummary(findings)
		a.Summary.ReportFile = path
		a.Summary.ReportDigest = product.Digest
		return nil
	}

	return fmt.Errorf("no prowler JSON output file found in products")
}

// validateProwlerFindings confirms the parsed slice actually looks like prowler output.
// It checks that at least one finding has the mandatory fields prowler always populates.
func validateProwlerFindings(findings []Finding) error {
	if len(findings) == 0 {
		return fmt.Errorf("prowler output contains no findings")
	}

	// All prowler findings must have CheckID, Status, and AccountId.
	for i, f := range findings {
		if f.CheckID == "" {
			return fmt.Errorf("finding at index %d is missing CheckID — not prowler output", i)
		}
		status := strings.ToUpper(f.Status)
		if status != "PASS" && status != "FAIL" && status != "MANUAL" && status != "NOT_AVAILABLE" && status != "MUTED" {
			return fmt.Errorf("finding at index %d has unexpected Status %q", i, f.Status)
		}
		// Provider is always present in real prowler output.
		if f.Provider == "" {
			return fmt.Errorf("finding at index %d is missing Provider — not prowler output", i)
		}
	}

	return nil
}

func buildSummary(findings []Finding) Summary {
	s := Summary{
		BySeverity:   make(map[string]SeverityCounts),
		FailedChecks: []FailedCheck{},
	}

	for _, f := range findings {
		// Capture top-level account and provider from first finding.
		if s.AccountId == "" {
			s.AccountId = f.AccountId
		}
		if s.Provider == "" {
			s.Provider = f.Provider
		}

		s.TotalChecks++

		sev := strings.ToLower(f.Severity)
		counts := s.BySeverity[sev]
		status := strings.ToUpper(f.Status)
		if status == "PASS" {
			s.PassCount++
			counts.Pass++
		} else {
			// FAIL, MANUAL, NOT_AVAILABLE, MUTED all treated as non-pass.
			s.FailCount++
			counts.Fail++
			s.FailedChecks = append(s.FailedChecks, FailedCheck{
				CheckID:        f.CheckID,
				CheckTitle:     f.CheckTitle,
				Severity:       f.Severity,
				ServiceName:    f.ServiceName,
				Region:         f.Region,
				ResourceId:     f.ResourceId,
				ResourceArn:    f.ResourceArn,
				StatusExtended: f.StatusExtended,
			})
		}
		s.BySeverity[sev] = counts
	}

	return s
}
