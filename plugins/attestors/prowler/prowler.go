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
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	Name    = "prowler"
	Type    = "https://aflock.ai/attestations/prowler/v0.1"
	RunType = attestation.PostProductRunType

	// statusPass / statusFail are the canonical internal status values
	// downstream consumers (buildSummary, rego policies) expect, regardless
	// of which Prowler output format produced the finding.
	statusPass = "PASS"
	statusFail = "FAIL"
)

// Compile-time interface check.
var _ attestation.Attestor = &Attestor{}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
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
// resolveProductPath turns a product path (recorded relative to the attestation
// working directory) into a path that can be opened from the current process,
// which may have a different CWD than the working directory. Absolute paths are
// returned unchanged.
func resolveProductPath(ctx *attestation.AttestationContext, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if wd := ctx.WorkingDir(); wd != "" {
		return filepath.Join(wd, path)
	}
	return path
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

		// Product paths are recorded relative to the attestation working
		// directory, which is not necessarily the process CWD (e.g. when the
		// caller passed --workingdir/-d). Resolve against ctx.WorkingDir() so
		// discovery works regardless of where cilock was invoked from.
		resolved := resolveProductPath(ctx, path)

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(resolved, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/prowler) error calculating digest set from file %s: %v", resolved, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/prowler) integrity error for %s: product digest does not match", resolved)
			continue
		}

		f, err := os.Open(resolved) //nolint:gosec // G304: path from attestation context products, resolved against working dir
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

		findings, err := parseProwlerReport(reportBytes)
		if err != nil {
			log.Debugf("(attestation/prowler) parse failed for %s: %v", path, err)
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

// parseProwlerReport detects which Prowler JSON shape `reportBytes` is in and
// converts every supported shape into the canonical []Finding used by
// buildSummary. Detection order: OCSF (Prowler 4 default) → ASFF (Prowler 4
// Security Hub) → legacy Prowler 3 native. The first detector that produces a
// non-empty, validated set wins.
func parseProwlerReport(reportBytes []byte) ([]Finding, error) {
	// All three supported shapes are top-level JSON arrays. Decode generically
	// first to peek at the first record without committing to a struct shape.
	var raw []json.RawMessage
	if err := json.Unmarshal(reportBytes, &raw); err != nil {
		return nil, fmt.Errorf("not a JSON array: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("prowler output contains no findings")
	}

	// Probe the first record to identify the shape. Use a permissive map so
	// callers don't have to declare every field up front.
	var first map[string]json.RawMessage
	if err := json.Unmarshal(raw[0], &first); err != nil {
		return nil, fmt.Errorf("first record is not a JSON object: %w", err)
	}

	switch {
	case isOCSF(first):
		return parseOCSF(raw)
	case isASFF(first):
		return parseASFF(raw)
	case isLegacyV3(first):
		var findings []Finding
		if err := json.Unmarshal(reportBytes, &findings); err != nil {
			return nil, fmt.Errorf("legacy v3 unmarshal failed: %w", err)
		}
		return findings, nil
	default:
		return nil, fmt.Errorf("unrecognized prowler JSON shape (not OCSF, ASFF, or v3 native)")
	}
}

// isOCSF detects Prowler 4 OCSF Compliance Finding shape. Either class_uid=2003
// (canonical OCSF Compliance Finding) or the presence of both `finding` and
// `status_id` (still unambiguous vs. ASFF and v3, neither of which use those
// keys).
func isOCSF(rec map[string]json.RawMessage) bool {
	if cu, ok := rec["class_uid"]; ok {
		var n int
		if err := json.Unmarshal(cu, &n); err == nil && n == 2003 {
			return true
		}
	}
	_, hasFinding := rec["finding"]
	_, hasStatusID := rec["status_id"]
	return hasFinding && hasStatusID
}

// isASFF detects AWS Security Hub Finding Format. Cheapest reliable signal is
// `ProductArn` starting with `arn:aws:securityhub:`; fall back to (`ProductArn`
// + `Compliance`) which together still beat v3 (no ProductArn) and OCSF
// (no PascalCase keys).
func isASFF(rec map[string]json.RawMessage) bool {
	pa, hasPA := rec["ProductArn"]
	if !hasPA {
		return false
	}
	var s string
	if err := json.Unmarshal(pa, &s); err == nil && strings.HasPrefix(s, "arn:aws:securityhub:") {
		return true
	}
	_, hasCompliance := rec["Compliance"]
	return hasCompliance
}

// isLegacyV3 detects the Prowler 3 native shape this attestor originally
// targeted: PascalCase keys CheckID + Provider + Status on every record.
func isLegacyV3(rec map[string]json.RawMessage) bool {
	_, hasCheckID := rec["CheckID"]
	_, hasProvider := rec["Provider"]
	_, hasStatus := rec["Status"]
	return hasCheckID && hasProvider && hasStatus
}

// ocsfFinding mirrors the subset of OCSF Compliance Finding (class_uid=2003)
// that Prowler 4 actually populates. Anything we don't read is ignored.
type ocsfFinding struct {
	ClassUID     int    `json:"class_uid"`
	StatusID     int    `json:"status_id"`
	StatusCode   string `json:"status_code"`
	StatusDetail string `json:"status_detail"`
	Message      string `json:"message"`
	Severity     string `json:"severity"`
	Finding      struct {
		UID   string `json:"uid"`
		Title string `json:"title"`
		Desc  string `json:"desc"`
	} `json:"finding"`
	Cloud struct {
		Region  string `json:"region"`
		Account struct {
			UID  string `json:"uid"`
			Name string `json:"name"`
		} `json:"account"`
		Provider string `json:"provider"`
	} `json:"cloud"`
	Resources []struct {
		UID    string `json:"uid"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Region string `json:"region"`
		Group  struct {
			Name string `json:"name"`
		} `json:"group"`
	} `json:"resources"`
}

// parseOCSF converts a Prowler 4 OCSF Compliance Finding array into the
// canonical Finding slice. Field mapping follows the table in issue #85; where
// real Prowler differs from the issue (`status_detail`/`message` for
// StatusExtended; `cloud.provider` is title-case `AWS`/`Azure`/etc.), real
// Prowler wins.
func parseOCSF(raw []json.RawMessage) ([]Finding, error) {
	findings := make([]Finding, 0, len(raw))
	for i, rm := range raw {
		var rec ocsfFinding
		if err := json.Unmarshal(rm, &rec); err != nil {
			return nil, fmt.Errorf("ocsf record %d: %w", i, err)
		}

		status := statusFail
		if rec.StatusID == 1 || strings.EqualFold(rec.StatusCode, "PASS") || strings.EqualFold(rec.StatusCode, "Success") {
			status = statusPass
		}

		statusExtended := rec.StatusDetail
		if statusExtended == "" {
			statusExtended = rec.Message
		}

		// Pull the first resource if any — Prowler always emits exactly one
		// for compliance findings, but defend against an empty slice.
		var (
			resArn  string
			resID   string
			resType string
			region  string
		)
		if len(rec.Resources) > 0 {
			r := rec.Resources[0]
			resArn = r.UID
			resID = r.Name
			resType = r.Group.Name
			region = r.Region
		}
		if region == "" {
			region = rec.Cloud.Region
		}

		findings = append(findings, Finding{
			CheckID:        rec.Finding.UID,
			CheckTitle:     rec.Finding.Title,
			Provider:       strings.ToLower(rec.Cloud.Provider),
			Status:         status,
			StatusExtended: statusExtended,
			Severity:       titleCaseSeverity(rec.Severity),
			ServiceName:    resType,
			Region:         region,
			ResourceId:     resID,
			ResourceArn:    resArn,
			AccountId:      rec.Cloud.Account.UID,
			Description:    rec.Finding.Desc,
		})
	}
	return findings, nil
}

// asffFinding mirrors the subset of AWS Security Hub Finding Format Prowler 4
// populates when invoked with `--output-modes json-asff`.
type asffFinding struct {
	AwsAccountId string `json:"AwsAccountId"`
	GeneratorId  string `json:"GeneratorId"`
	Title        string `json:"Title"`
	Description  string `json:"Description"`
	ProductArn   string `json:"ProductArn"`
	Severity     struct {
		Label string `json:"Label"`
	} `json:"Severity"`
	Compliance struct {
		Status string `json:"Status"`
	} `json:"Compliance"`
	Resources []struct {
		Id      string `json:"Id"`
		Type    string `json:"Type"`
		Region  string `json:"Region"`
		Details struct {
			AwsAccount struct {
				Region string `json:"Region"`
			} `json:"AwsAccount"`
		} `json:"Details"`
	} `json:"Resources"`
}

// parseASFF converts a Prowler 4 ASFF array into the canonical Finding slice.
// Following the mapping table in issue #85, with three real-Prowler
// adjustments noted in the test file.
func parseASFF(raw []json.RawMessage) ([]Finding, error) {
	findings := make([]Finding, 0, len(raw))
	for i, rm := range raw {
		var rec asffFinding
		if err := json.Unmarshal(rm, &rec); err != nil {
			return nil, fmt.Errorf("asff record %d: %w", i, err)
		}

		// CheckID = last `/`-delimited segment of GeneratorId.
		checkID := rec.GeneratorId
		if idx := strings.LastIndex(checkID, "/"); idx >= 0 && idx < len(checkID)-1 {
			checkID = checkID[idx+1:]
		}

		// Status: ASFF uses PASSED/FAILED/WARNING/NOT_AVAILABLE. Only PASSED
		// counts as PASS; everything else is treated as non-pass (matches the
		// existing buildSummary policy).
		status := statusFail
		if strings.EqualFold(rec.Compliance.Status, "PASSED") {
			status = statusPass
		}

		// Resource fields. Strip the `AwsXxx::` prefix from Type and
		// lower-case the remainder per the mapping table.
		var (
			resArn  string
			resID   string
			service string
			region  string
		)
		if len(rec.Resources) > 0 {
			r := rec.Resources[0]
			resArn = r.Id
			// ResourceId = last `/` or `:` segment of the ARN.
			resID = r.Id
			if idx := strings.LastIndexAny(resID, "/:"); idx >= 0 && idx < len(resID)-1 {
				resID = resID[idx+1:]
			}
			service = strings.ToLower(stripAwsTypePrefix(r.Type))
			region = r.Region
			if region == "" {
				region = r.Details.AwsAccount.Region
			}
		}

		findings = append(findings, Finding{
			CheckID:        checkID,
			CheckTitle:     rec.Title,
			Provider:       "aws",
			Status:         status,
			StatusExtended: rec.Description,
			Severity:       titleCaseSeverity(rec.Severity.Label),
			ServiceName:    service,
			Region:         region,
			ResourceId:     resID,
			ResourceArn:    resArn,
			AccountId:      rec.AwsAccountId,
			Description:    rec.Description,
		})
	}
	return findings, nil
}

// stripAwsTypePrefix removes the leading `AwsXxx::` from an ASFF resource Type
// (e.g. `AwsIamUser` → `IamUser`, `AwsIam::User` → `User`).
func stripAwsTypePrefix(t string) string {
	if idx := strings.Index(t, "::"); idx >= 0 {
		return t[idx+2:]
	}
	if strings.HasPrefix(t, "Aws") && len(t) > 3 {
		// Drop the `Aws` literal prefix; what's left is the resource type
		// suffix (e.g. `IamUser`).
		return t[3:]
	}
	return t
}

// titleCaseSeverity normalizes a severity string to Prowler v3's casing
// (`Critical`/`High`/`Medium`/`Low`/`Informational`). OCSF emits Title-case
// already; ASFF emits SHOUTING; v3 emits Title-case. Lowercasing the rest
// keeps SeverityCounts keys (which downstream rego policies key on with
// `summary.bySeverity.critical.fail`) stable across all three formats.
func titleCaseSeverity(s string) string {
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	return strings.ToUpper(lower[:1]) + lower[1:]
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
