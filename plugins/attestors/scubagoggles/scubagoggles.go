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

// Package scubagoggles is a post-product attestor that captures the RAW Google
// Workspace configuration collected by CISA's ScubaGoggles provider phase, and
// signs it as evidence.
//
// This attestor deliberately captures FACTS, not a verdict. ScubaGoggles' OPA
// step produces per-control Pass/Fail (its `Results`); we ignore that. We sign
// the `Raw` provider settings — the actual tenant configuration (policies, DNS
// records, super-admins, OU layout, group settings) — which is the same object
// ScubaGoggles feeds to OPA as `input`. The compliance VERDICT is rendered
// separately by policy: recipes that cite CISA's SCuBA rego baselines, run in
// policyverify over this predicate's Config as `input`. Keeping the decision in
// policy (not baked into the evidence) is the point — the raw config is reusable
// ground truth that any policy can evaluate.
//
// Source artifact: either a ScubaResults*.json (whose `Raw` section is the
// config) or a bare ProviderSettingsExport.json (the config at top level).
// ScubaGoggles ships as a Python package (pip), not a binary — a recipe execs
// the `scubagoggles` CLI to produce the artifact this attestor consumes.
package scubagoggles

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	Name    = "scubagoggles"
	Type    = "https://aflock.ai/attestations/scubagoggles/v0.1"
	RunType = attestation.PostProductRunType
)

// Compile-time interface checks.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// tenantInfo mirrors the tenant_info block ScubaGoggles' provider phase emits.
type tenantInfo struct {
	ID         string `json:"ID"`
	Domain     string `json:"domain"`
	TopLevelOU string `json:"topLevelOU"`
}

// providerConfig is the subset of the raw provider settings we read for
// identity/subjects. The full object is preserved verbatim in the predicate's
// Config field; this struct only pulls out the addressable identifiers.
type providerConfig struct {
	TenantInfo              tenantInfo `json:"tenant_info"`
	Domains                 []string   `json:"domains"`
	OrganizationalUnitNames []string   `json:"organizational_unit_names"`
}

// scubaMeta mirrors the MetaData block present when the source artifact is a
// ScubaResults file (absent for a bare ProviderSettingsExport).
type scubaMeta struct {
	Tool          string `json:"Tool"`
	ToolVersion   string `json:"ToolVersion"`
	TimestampZulu string `json:"TimestampZulu"`
}

// Predicate is the signed evidence: a snapshot of the RAW Google Workspace
// configuration. It is NOT a compliance verdict — Config is the exact object
// ScubaGoggles feeds to OPA, so a policy citing CISA's rego baselines evaluates
// it unchanged in policyverify.
type Predicate struct {
	Tool         string               `json:"tool"`
	ToolVersion  string               `json:"toolVersion,omitempty"`
	CollectedAt  string               `json:"collectedAt,omitempty"`
	TenantID     string               `json:"tenantId"`
	DomainName   string               `json:"domainName"`
	DisplayName  string               `json:"displayName,omitempty"`
	Domains      []string             `json:"domains,omitempty"`
	OrgUnits     []string             `json:"orgUnits,omitempty"`
	Config       json.RawMessage      `json:"config"`
	SourceFile   string               `json:"sourceFile"`
	SourceDigest cryptoutil.DigestSet `json:"sourceDigest"`
}

// Attestor captures the raw Google Workspace provider config as a signed
// predicate.
type Attestor struct {
	Predicate Predicate `json:"predicate"`
}

func New() *Attestor { return &Attestor{} }

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }

func (a *Attestor) Schema() *jsonschema.Schema { return jsonschema.Reflect(&a) }

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/scubagoggles) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects returns graph-edge subjects derived from the config:
//   - the tenant (GWS customer id): "googleworkspace:tenant:<id>"
//   - every domain:                 "googleworkspace:domain:<domain>"
//   - every org unit:               "googleworkspace:orgunit:<path>"
//
// Hashing the SHA-256 of the identity string (prowler/steampipe convention)
// lets policyverify join by digest value. The tenant id is the GWS customer id,
// so this converges with a steampipe googledirectory attestation's customer_id
// subject.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)
	add := func(key, value string) {
		if value == "" {
			return
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/scubagoggles) failed to hash subject %s: %v", key, err)
			return
		}
		subjects[key] = ds
	}

	add(fmt.Sprintf("googleworkspace:tenant:%s", a.Predicate.TenantID), a.Predicate.TenantID)

	seen := make(map[string]bool)
	addDomain := func(d string) {
		if d == "" || seen["d:"+d] {
			return
		}
		seen["d:"+d] = true
		add(fmt.Sprintf("googleworkspace:domain:%s", d), d)
	}
	addDomain(a.Predicate.DomainName)
	for _, d := range a.Predicate.Domains {
		addDomain(d)
	}
	for _, ou := range a.Predicate.OrgUnits {
		if ou == "" || seen["ou:"+ou] {
			continue
		}
		seen["ou:"+ou] = true
		add(fmt.Sprintf("googleworkspace:orgunit:%s", ou), ou)
	}

	return subjects
}

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

// getCandidate scans products for a ScubaGoggles provider-config JSON (a
// ScubaResults file whose `Raw` section is the config, or a bare
// ProviderSettingsExport) and builds the predicate from the first match.
//
// Product keys are iterated in sorted order so that, when multiple parseable
// JSON products are present, the attested source is deterministic — signed
// evidence must not vary run-to-run with Go's randomized map iteration.
//
//nolint:gocognit // sequential candidate scan: iterate products → read → hash → decode → validate
func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	mimeTypes := map[string]bool{"text/plain": true, "application/json": true}

	paths := make([]string, 0, len(products))
	for path := range products {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		product := products[path]
		if !mimeTypes[product.MimeType] {
			continue
		}

		// Product paths are recorded relative to the attestation working
		// directory, which is not necessarily the process CWD (e.g. when the
		// caller passed --workingdir/-d). Resolve against ctx.WorkingDir() so
		// discovery works regardless of where cilock was invoked from.
		resolved := resolveProductPath(ctx, path)

		// Read once, then hash the exact bytes we parse. This closes the
		// TOCTOU gap between the integrity check and the read: a swap between
		// hashing and opening can't substitute the attested content.
		reportBytes, err := os.ReadFile(resolved) //nolint:gosec // G304: path from attestation context products, resolved against working dir
		if err != nil {
			log.Debugf("(attestation/scubagoggles) error reading file %s: %v", resolved, err)
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromBytes(reportBytes, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/scubagoggles) error calculating digest set from file %s: %v", resolved, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/scubagoggles) integrity error for %s: product digest does not match", resolved)
			continue
		}

		pred, perr := buildPredicate(reportBytes)
		if perr != nil {
			log.Debugf("(attestation/scubagoggles) parse failed for %s: %v", path, perr)
			continue
		}

		pred.SourceFile = path
		pred.SourceDigest = product.Digest
		a.Predicate = *pred
		return nil
	}

	return fmt.Errorf("no ScubaGoggles provider-config JSON found in products")
}

// buildPredicate decodes the artifact, locates the raw provider config (the
// `Raw` section of a ScubaResults file, or the top-level object of a
// ProviderSettingsExport), validates it is Google Workspace data, and captures
// it verbatim.
func buildPredicate(b []byte) (*Predicate, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}

	// Config root: prefer the `Raw` section (ScubaResults), else the whole
	// object (a bare ProviderSettingsExport).
	configRaw, fromResults := top["Raw"]
	if !fromResults || len(configRaw) == 0 {
		configRaw = json.RawMessage(b)
	}

	var cfg providerConfig
	if err := json.Unmarshal(configRaw, &cfg); err != nil {
		return nil, fmt.Errorf("config root is not a provider object: %w", err)
	}
	if cfg.TenantInfo.ID == "" && cfg.TenantInfo.Domain == "" {
		return nil, fmt.Errorf("missing tenant_info — not a ScubaGoggles provider config")
	}

	pred := &Predicate{
		Tool:        "ScubaGoggles",
		TenantID:    cfg.TenantInfo.ID,
		DomainName:  cfg.TenantInfo.Domain,
		DisplayName: cfg.TenantInfo.TopLevelOU,
		Domains:     dedupeNonEmpty(cfg.Domains),
		OrgUnits:    dedupeNonEmpty(cfg.OrganizationalUnitNames),
		Config:      configRaw,
	}

	// Provenance metadata, present when the source was a ScubaResults file.
	if metaRaw, ok := top["MetaData"]; ok {
		var m scubaMeta
		if json.Unmarshal(metaRaw, &m) == nil {
			if m.Tool != "" {
				pred.Tool = m.Tool
			}
			pred.ToolVersion = m.ToolVersion
			pred.CollectedAt = m.TimestampZulu
		}
	}

	return pred, nil
}

// dedupeNonEmpty trims, drops empties, dedupes, and sorts — for stable subjects.
func dedupeNonEmpty(in []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
