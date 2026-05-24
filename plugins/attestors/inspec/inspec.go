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

package inspec

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "inspec"
	Type    = "https://aflock.ai/attestations/inspec/v0.1"
	RunType = attestation.PostProductRunType
)

// compile-time interface check
var _ attestation.Attestor = &Attestor{}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// inspecReport mirrors the JSON output produced by `inspec exec --reporter json`.
type inspecReport struct {
	Platform   inspecPlatform   `json:"platform"`
	Profiles   []inspecProfile  `json:"profiles"`
	Statistics inspecStatistics `json:"statistics"`
}

type inspecPlatform struct {
	Name    string `json:"name"`
	Release string `json:"release"`
}

type inspecProfile struct {
	Name     string          `json:"name"`
	Controls []inspecControl `json:"controls"`
}

type inspecControl struct {
	ID      string         `json:"id"`
	Title   string         `json:"title"`
	Results []inspecResult `json:"results"`
}

type inspecResult struct {
	Status   string `json:"status"`
	CodeDesc string `json:"code_desc"`
}

type inspecStatistics struct {
	Duration float64 `json:"duration"`
}

// FailedControl captures a control that had at least one failing result.
type FailedControl struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Profile string `json:"profile"`
}

// Summary is the structured summary stored in the attestation.
type Summary struct {
	ProfileName     string          `json:"profileName"`
	Platform        string          `json:"platform"`
	TotalControls   int             `json:"totalControls"`
	PassedControls  int             `json:"passedControls"`
	FailedControls  int             `json:"failedControls"`
	SkippedControls int             `json:"skippedControls"`
	FailedDetails   []FailedControl `json:"failedDetails"`
}

// Attestor reads an InSpec JSON report and attests to the scan results.
// It exposes profile, platform, and failed control IDs as subjects.
type Attestor struct {
	ReportFile      string               `json:"reportFile"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet"`
	ScanSummary     Summary              `json:"scanSummary"`

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
		log.Debugf("(attestation/inspec) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects implements attestation.Subjecter.
// It exposes:
//   - profile:<profile-name> for each InSpec profile
//   - platform:<os-name>-<release> for the scanned platform
//   - inspec:control:<id> for each control that has a failing result
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		if !isAcceptedMimeType(product.MimeType) {
			continue
		}

		parsed, err := a.tryParseReport(ctx, path, product)
		if err != nil {
			continue
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest
		a.buildSummaryAndSubjects(parsed)
		return nil
	}

	return fmt.Errorf("no InSpec JSON report found in products")
}

func isAcceptedMimeType(mime string) bool {
	return mime == "text/plain" || mime == "application/json"
}

func (a *Attestor) tryParseReport(ctx *attestation.AttestationContext, path string, product attestation.Product) (inspecReport, error) {
	newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
	if err != nil {
		log.Debugf("(attestation/inspec) error calculating digest set from file %s: %v", path, err)
		return inspecReport{}, err
	}
	if newDigestSet == nil {
		log.Debugf("(attestation/inspec) nil digest set for file %s", path)
		return inspecReport{}, fmt.Errorf("nil digest set for file %s", path)
	}

	if !newDigestSet.Equal(product.Digest) {
		log.Debugf("(attestation/inspec) integrity error for %s: product digest does not match", path)
		return inspecReport{}, fmt.Errorf("digest mismatch")
	}

	f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
	if err != nil {
		log.Debugf("(attestation/inspec) error opening file %s: %v", path, err)
		return inspecReport{}, err
	}
	defer func() { _ = f.Close() }()

	reportBytes, err := io.ReadAll(f)
	if err != nil {
		log.Debugf("(attestation/inspec) error reading file %s: %v", path, err)
		return inspecReport{}, err
	}

	var parsed inspecReport
	if err := json.Unmarshal(reportBytes, &parsed); err != nil {
		log.Debugf("(attestation/inspec) error parsing JSON from %s: %v", path, err)
		return inspecReport{}, err
	}

	if !isInSpecReport(parsed) {
		log.Debugf("(attestation/inspec) %s does not appear to be an InSpec JSON report", path)
		return inspecReport{}, fmt.Errorf("not an InSpec report")
	}

	return parsed, nil
}

// isInSpecReport returns true when the parsed document looks like InSpec JSON output.
// InSpec reports always have a non-empty profiles array; each profile has a controls field.
func isInSpecReport(r inspecReport) bool {
	if len(r.Profiles) == 0 {
		return false
	}
	// Every real InSpec profile has a controls key in the JSON, even when there
	// are zero controls.  We cannot distinguish a missing key from an empty
	// slice after unmarshalling, so just require at least one profile.
	return true
}

const (
	statusPassed  = "passed"
	statusFailed  = "failed"
	statusSkipped = "skipped"
)

func (a *Attestor) buildSummaryAndSubjects(parsed inspecReport) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	platformStr := buildPlatformString(parsed.Platform)
	addSubject(subjects, "platform", platformStr, hashes)

	var totalControls, passed, failed, skipped int
	failedDetails := make([]FailedControl, 0, len(parsed.Profiles))

	summaryProfileName := ""
	for i, profile := range parsed.Profiles {
		if i == 0 {
			summaryProfileName = profile.Name
		}
		addSubject(subjects, "profile", profile.Name, hashes)

		p, f, s, details := processControls(profile, subjects, hashes)
		passed += p
		failed += f
		skipped += s
		totalControls += p + f + s
		failedDetails = append(failedDetails, details...)
	}

	a.ScanSummary = Summary{
		ProfileName:     summaryProfileName,
		Platform:        platformStr,
		TotalControls:   totalControls,
		PassedControls:  passed,
		FailedControls:  failed,
		SkippedControls: skipped,
		FailedDetails:   failedDetails,
	}
	a.subjects = subjects
}

func buildPlatformString(p inspecPlatform) string {
	if p.Release != "" {
		return p.Name + "-" + p.Release
	}
	return p.Name
}

func addSubject(subjects map[string]cryptoutil.DigestSet, prefix, value string, hashes []cryptoutil.DigestValue) {
	if value == "" {
		return
	}
	key := fmt.Sprintf("%s:%s", prefix, value)
	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes); err == nil {
		subjects[key] = ds
	}
}

func processControls(profile inspecProfile, subjects map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue) (passed, failed, skipped int, details []FailedControl) {
	for _, ctrl := range profile.Controls {
		switch controlOutcome(ctrl) {
		case statusPassed:
			passed++
		case statusFailed:
			failed++
			details = append(details, FailedControl{ID: ctrl.ID, Title: ctrl.Title, Profile: profile.Name})
			addSubject(subjects, "inspec:control", ctrl.ID, hashes)
		default:
			skipped++
		}
	}
	return passed, failed, skipped, details
}

// controlOutcome determines the aggregate outcome of a control based on its results.
func controlOutcome(ctrl inspecControl) string {
	if len(ctrl.Results) == 0 {
		return statusSkipped
	}
	allSkipped := true
	for _, r := range ctrl.Results {
		if r.Status == statusFailed {
			return statusFailed
		}
		if r.Status != statusSkipped {
			allSkipped = false
		}
	}
	if allSkipped {
		return statusSkipped
	}
	return statusPassed
}
