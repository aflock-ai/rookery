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

// Package trivy implements an attestor that ingests Trivy's native JSON
// scan output (SchemaVersion: 2) and emits a structured summary predicate.
//
// Wire format: Trivy's native JSON output is the canonical product of any
// `trivy <command> --format json` invocation. The shape is documented at
// https://trivy.dev/docs/latest/configuration/reporting/ and discussed in
// https://github.com/aquasecurity/trivy/discussions/7552. We target
// SchemaVersion: 2 — older v1 reports (Trivy <0.20) are not supported.
//
// Top-level layout we depend on:
//
//	{
//	  "SchemaVersion": 2,
//	  "ArtifactName": "<image:tag or fs path>",
//	  "ArtifactType": "container_image" | "filesystem" | "repository" | "config" | ...,
//	  "Metadata":     { "OS": {...}, "ImageID": "...", "RepoTags": [...], "RepoDigests": [...] },
//	  "Results": [
//	    {
//	      "Target": "...",
//	      "Class":  "config" | "lang-pkgs" | "os-pkgs" | "secret" | "license",
//	      "Type":   "alpine" | "npm" | "dockerfile" | ...,
//	      "Vulnerabilities":   [...],
//	      "Misconfigurations": [...],
//	      "Secrets":           [...],
//	      "Licenses":          [...]
//	    }
//	  ]
//	}
//
// We deliberately summarize rather than mirror — the predicate captures
// per-class counts, severity rollups, and only the *failed* findings in a
// condensed shape (id/title/severity/class/target/resourceId). The full
// raw report is preserved byte-for-byte as a json.RawMessage so verifiers
// can still re-validate the underlying scan data.
package trivy

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
	Name    = "trivy"
	Type    = "https://aflock.ai/attestations/trivy/v0.1"
	RunType = attestation.PostProductRunType
)

// Compile-time interface checks.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}

	// Trivy emits JSON; the product attestor classifies it as either
	// text/plain (heuristic match on small/short reports) or
	// application/json. Both are accepted here.
	mimeTypes = []string{"text/plain", "application/json"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// Report is the minimal typed view of a Trivy native JSON report we need
// in order to build the summary. Unknown fields are tolerated — Trivy adds
// new top-level keys over time (e.g. ReportID, CreatedAt, Trivy) which we
// don't read but also don't reject.
type Report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Metadata      Metadata `json:"Metadata"`
	Results       []Result `json:"Results"`
}

// Metadata holds the image/host metadata Trivy emits for container_image
// and certain filesystem scans. All fields are optional; a `trivy fs` of a
// pure source tree typically emits an empty Metadata object.
type Metadata struct {
	OS          OSInfo   `json:"OS"`
	ImageID     string   `json:"ImageID"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

// OSInfo is the container/host OS Trivy detected. Populated for image and
// rootfs scans; empty for plain filesystem/repository scans.
type OSInfo struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// Result is one row of `Results[]` — Trivy emits one entry per
// (target, class) tuple. Class drives which of the four finding-list
// fields below is populated:
//
//	"os-pkgs"   → Vulnerabilities
//	"lang-pkgs" → Vulnerabilities
//	"config"    → Misconfigurations
//	"secret"    → Secrets
//	"license"   → Licenses
type Result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	Vulnerabilities   []Vulnerability    `json:"Vulnerabilities"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations"`
	Secrets           []Secret           `json:"Secrets"`
	Licenses          []License          `json:"Licenses"`
}

// Vulnerability is the package-CVE pairing Trivy reports for os-pkgs and
// lang-pkgs results. PkgIdentifier.PURL is the most useful linking key
// because it includes ecosystem + name + version + (for distro packages)
// the OS family/version.
type Vulnerability struct {
	VulnerabilityID  string        `json:"VulnerabilityID"`
	PkgID            string        `json:"PkgID"`
	PkgName          string        `json:"PkgName"`
	PkgIdentifier    PkgIdentifier `json:"PkgIdentifier"`
	InstalledVersion string        `json:"InstalledVersion"`
	FixedVersion     string        `json:"FixedVersion"`
	Status           string        `json:"Status"`
	Severity         string        `json:"Severity"`
	Title            string        `json:"Title"`
	PrimaryURL       string        `json:"PrimaryURL"`
}

// PkgIdentifier carries the PURL Trivy computed for a package — this is the
// stable identifier downstream tooling (VEX, Archivista) uses for linking.
type PkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

// Misconfiguration is a single policy violation Trivy detected via its
// embedded misconfig scanner (Dockerfile, Kubernetes, Terraform, etc.).
// CauseMetadata.Resource is populated for Kubernetes/IaC scans; for
// Dockerfile checks Resource is empty and Service stays at "general".
type Misconfiguration struct {
	Type        string        `json:"Type"`
	ID          string        `json:"ID"`
	Title       string        `json:"Title"`
	Description string        `json:"Description"`
	Message     string        `json:"Message"`
	Severity    string        `json:"Severity"`
	PrimaryURL  string        `json:"PrimaryURL"`
	Status      string        `json:"Status"`
	CauseMeta   CauseMetadata `json:"CauseMetadata"`
}

// CauseMetadata identifies the resource a misconfiguration was found on.
// Trivy populates Resource for IaC scans (`Deployment/foo`, `aws_s3_bucket.bar`)
// but leaves it blank for Dockerfile findings.
type CauseMetadata struct {
	Resource string `json:"Resource"`
	Provider string `json:"Provider"`
	Service  string `json:"Service"`
}

// Secret is a credential leak Trivy's secret scanner found.
type Secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

// License is a license finding from the license scanner. Modeled minimally
// because we don't currently summarize licenses beyond the count.
type License struct {
	Severity   string `json:"Severity"`
	Category   string `json:"Category"`
	PkgName    string `json:"PkgName"`
	FilePath   string `json:"FilePath"`
	Name       string `json:"Name"`
	Confidence string `json:"Confidence"`
}

// FailedFinding is the condensed shape stored in the attestation predicate
// for every non-pass finding. Keeping this lean keeps the predicate small
// even when a scan reports hundreds of CVEs.
type FailedFinding struct {
	ID         string `json:"id"`         // CVE-XXXX-NNNN, DS-NNNN, secret RuleID, etc.
	Title      string `json:"title"`      // Human-readable finding title.
	Severity   string `json:"severity"`   // CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN.
	Class      string `json:"class"`      // Result.Class — vuln, misconfig, secret, license.
	Target     string `json:"target"`     // Result.Target — the scanned file/package list.
	ResourceID string `json:"resourceId"` // PURL for vulns, Resource for misconfig, RuleID for secrets.
}

// SeverityCounts holds pass/fail counts per severity level. For Trivy vulns
// every finding is by definition a "fail" (Trivy doesn't report passing
// CVEs); we still preserve the pass slot so the shape is identical to the
// prowler attestor — downstream rego policies that key on
// `summary.bySeverity.critical.fail` work uniformly across attestors.
type SeverityCounts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
}

// OSMeta is the OS subset of trivy Metadata we record in the predicate.
// Kept separate from the OSInfo wire type so callers iterating the
// predicate don't have to deal with the case-sensitive Trivy JSON shape.
type OSMeta struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// MetadataSummary is the predicate's view of Trivy's top-level Metadata.
type MetadataSummary struct {
	OS          OSMeta   `json:"os"`
	ImageID     string   `json:"imageId,omitempty"`
	RepoTags    []string `json:"repoTags,omitempty"`
	RepoDigests []string `json:"repoDigests,omitempty"`
}

// Summary is the attestation predicate stored in the signed envelope.
// It is intentionally bag-of-counts plus failed-findings — for the full
// scan data, consumers look at the embedded Report.
type Summary struct {
	ArtifactName    string                    `json:"artifactName"`
	ArtifactType    string                    `json:"artifactType"`
	SchemaVersion   int                       `json:"schemaVersion"`
	Metadata        MetadataSummary           `json:"metadata"`
	VulnCount       int                       `json:"vulnCount"`
	MisconfigCount  int                       `json:"misconfigCount"`
	SecretCount     int                       `json:"secretCount"`
	LicenseCount    int                       `json:"licenseCount"`
	BySeverity      map[string]SeverityCounts `json:"bySeverity"`
	FailedFindings  []FailedFinding           `json:"failedFindings"`
	ReportFile      string                    `json:"reportFile"`
	ReportDigestSet cryptoutil.DigestSet      `json:"reportDigestSet"`
}

// Attestor consumes a Trivy native JSON report from the attestation
// context products and emits both a structured Summary (for policy
// evaluation) and the full report bytes (for re-verification).
//
// Report is preserved as json.RawMessage so the attestation predicate is
// byte-identical to the scan output — verifiers can re-hash the embedded
// document and compare against ReportDigestSet to prove integrity.
type Attestor struct {
	Summary Summary         `json:"summary"`
	Report  json.RawMessage `json:"report"`
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
		log.Debugf("(attestation/trivy) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects returns graph-edge subjects for cross-linking attestations that
// reference the same scan artifact, CVE, or misconfigured resource. The
// scheme follows the prowler attestor's `aws:arn:*` convention:
//
//   - trivy:artifact:<artifactName> for the scan target
//   - trivy:cve:<vulnID>            for each unique CVE / vuln id
//   - trivy:resource:<resourceArn>  for each unique misconfig resource id
//
// All subject digests are SHA-256 of the identifier string, matching the
// aws-codebuild / prowler pattern Archivista already indexes on.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	addSubject := func(key, value string) {
		if value == "" {
			return
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/trivy) failed to hash subject %s: %v", key, err)
			return
		}
		subjects[key] = ds
	}

	if a.Summary.ArtifactName != "" {
		addSubject(fmt.Sprintf("trivy:artifact:%s", a.Summary.ArtifactName), a.Summary.ArtifactName)
	}

	// Deduplicate CVE IDs and misconfig resource IDs across failed
	// findings. RuleID-only secret findings have no useful identifier
	// for cross-linking, so we skip them here.
	seenCVEs := make(map[string]bool)
	seenResources := make(map[string]bool)
	for _, ff := range a.Summary.FailedFindings {
		switch ff.Class {
		case "vuln", "os-pkgs", "lang-pkgs":
			if ff.ID != "" && !seenCVEs[ff.ID] {
				seenCVEs[ff.ID] = true
				addSubject(fmt.Sprintf("trivy:cve:%s", ff.ID), ff.ID)
			}
		case "config", "misconfig":
			if ff.ResourceID != "" && !seenResources[ff.ResourceID] {
				seenResources[ff.ResourceID] = true
				addSubject(fmt.Sprintf("trivy:resource:%s", ff.ResourceID), ff.ResourceID)
			}
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

		// Join the attestation context's working directory so the file
		// lookup matches what sarif/sbom do. Tests pass relative paths.
		fullPath := filepath.Join(ctx.WorkingDir(), path)

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(fullPath, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/trivy) error calculating digest set from file %s: %v", fullPath, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/trivy) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(fullPath) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/trivy) error opening file %s: %v", fullPath, err)
			continue
		}
		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/trivy) error reading file %s: %v", fullPath, err)
			continue
		}

		report, err := parseTrivyReport(reportBytes)
		if err != nil {
			log.Debugf("(attestation/trivy) parse failed for %s: %v", path, err)
			continue
		}
		if err := validateTrivyReport(report); err != nil {
			log.Debugf("(attestation/trivy) validation failed for %s: %v", path, err)
			continue
		}

		a.Summary = buildSummary(report)
		a.Summary.ReportFile = path
		a.Summary.ReportDigestSet = product.Digest
		a.Report = json.RawMessage(reportBytes)
		return nil
	}

	return fmt.Errorf("no trivy JSON output file found in products")
}

// parseTrivyReport unmarshals the bytes into the typed Report struct.
// Returns a non-nil error for malformed JSON or for documents that lack
// the SchemaVersion field — Trivy always emits SchemaVersion at the top
// level, so its absence is a reliable rejection criterion for non-Trivy
// JSON that happens to be a JSON object.
func parseTrivyReport(reportBytes []byte) (*Report, error) {
	if !json.Valid(reportBytes) {
		return nil, fmt.Errorf("not valid JSON")
	}
	// Detect the shape via a permissive map first so we can give a
	// useful error message rather than "json: cannot unmarshal".
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(reportBytes, &probe); err != nil {
		return nil, fmt.Errorf("expected top-level JSON object: %w", err)
	}
	if _, ok := probe["SchemaVersion"]; !ok {
		return nil, fmt.Errorf("missing SchemaVersion field — not a trivy native JSON report")
	}

	var r Report
	if err := json.Unmarshal(reportBytes, &r); err != nil {
		return nil, fmt.Errorf("unmarshal trivy report: %w", err)
	}
	return &r, nil
}

// validateTrivyReport enforces the minimum invariants we rely on: the
// report must be SchemaVersion: 2 (the only schema this attestor supports)
// and must carry an ArtifactType (Trivy always emits one — its absence
// means we're looking at a fragment, not a full report).
func validateTrivyReport(r *Report) error {
	if r == nil {
		return fmt.Errorf("nil report")
	}
	if r.SchemaVersion != 2 {
		return fmt.Errorf("unsupported SchemaVersion %d (only 2 is supported)", r.SchemaVersion)
	}
	if r.ArtifactType == "" {
		return fmt.Errorf("missing ArtifactType — not a complete trivy report")
	}
	return nil
}

// buildSummary collapses the typed Report into the Summary predicate.
// Severity normalization: Trivy emits all-uppercase severities
// (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN); we lowercase the BySeverity map key
// so rego policies can use `summary.bySeverity.critical.fail` without
// caring about casing, matching the prowler attestor's convention.
func buildSummary(r *Report) Summary {
	s := Summary{
		ArtifactName:   r.ArtifactName,
		ArtifactType:   r.ArtifactType,
		SchemaVersion:  r.SchemaVersion,
		Metadata:       buildMetadataSummary(r.Metadata),
		BySeverity:     make(map[string]SeverityCounts),
		FailedFindings: []FailedFinding{},
	}

	for _, res := range r.Results {
		// Vulnerabilities (os-pkgs and lang-pkgs results).
		for _, v := range res.Vulnerabilities {
			s.VulnCount++
			sev := strings.ToLower(v.Severity)
			counts := s.BySeverity[sev]
			counts.Fail++
			s.BySeverity[sev] = counts

			s.FailedFindings = append(s.FailedFindings, FailedFinding{
				ID:         v.VulnerabilityID,
				Title:      v.Title,
				Severity:   strings.ToUpper(v.Severity),
				Class:      res.Class,
				Target:     res.Target,
				ResourceID: v.PkgIdentifier.PURL,
			})
		}

		// Misconfigurations: Trivy emits both passing and failing
		// checks here (Status: "PASS" or "FAIL"). Only failing ones
		// land in failedFindings, but both contribute to the BySeverity
		// rollups so policies can reason about coverage.
		for _, m := range res.Misconfigurations {
			s.MisconfigCount++
			sev := strings.ToLower(m.Severity)
			counts := s.BySeverity[sev]
			if strings.EqualFold(m.Status, "PASS") {
				counts.Pass++
			} else {
				counts.Fail++
				s.FailedFindings = append(s.FailedFindings, FailedFinding{
					ID:         m.ID,
					Title:      m.Title,
					Severity:   strings.ToUpper(m.Severity),
					Class:      res.Class,
					Target:     res.Target,
					ResourceID: m.CauseMeta.Resource,
				})
			}
			s.BySeverity[sev] = counts
		}

		// Secrets are always failures — Trivy doesn't emit "passing"
		// secret checks. Use RuleID as the stable identifier.
		for _, sec := range res.Secrets {
			s.SecretCount++
			sev := strings.ToLower(sec.Severity)
			counts := s.BySeverity[sev]
			counts.Fail++
			s.BySeverity[sev] = counts

			s.FailedFindings = append(s.FailedFindings, FailedFinding{
				ID:         sec.RuleID,
				Title:      sec.Title,
				Severity:   strings.ToUpper(sec.Severity),
				Class:      res.Class,
				Target:     res.Target,
				ResourceID: sec.RuleID,
			})
		}

		// Licenses — only the count is summarized for now. The license
		// scanner uses severity to classify forbidden/restricted
		// licenses; a future predicate version may break those out.
		s.LicenseCount += len(res.Licenses)
	}

	return s
}

func buildMetadataSummary(m Metadata) MetadataSummary {
	return MetadataSummary{
		OS: OSMeta{
			Family: m.OS.Family,
			Name:   m.OS.Name,
		},
		ImageID:     m.ImageID,
		RepoTags:    m.RepoTags,
		RepoDigests: m.RepoDigests,
	}
}
