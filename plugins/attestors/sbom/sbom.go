// Copyright 2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

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
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

// sbomSubjectExtractor parses the minimal field surface (per the SPDX 2.3 and
// CycloneDX 1.6 public specs) needed to derive subject names. These structs
// are NOT a copy of any upstream library — they are hand-written from the
// JSON Schemas the two formats publish. The full document is stored as
// json.RawMessage to preserve byte-equality with the input.
type sbomSubjectExtractor struct {
	// SPDX 2.3 §6.4 documentName property — JSON key is "name".
	// Spec: https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#64-document-name
	SPDXDocumentName string `json:"name"`

	// CycloneDX 1.6 metadata.component.{name,version} per the
	// bom-1.6.schema.json definition.
	// Spec: https://cyclonedx.org/docs/1.6/json/#metadata_component
	Metadata struct {
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
}

const (
	Name                   = "sbom"
	Type                   = "https://aflock.ai/attestations/sbom/v0.1"
	RunType                = attestation.PostProductRunType
	defaultExport          = false
	SPDXPredicateType      = "https://spdx.dev/Document"
	SPDXMimeType           = "application/spdx+json"
	CycloneDxPredicateType = "https://cyclonedx.org/bom"
	CycloneDxMimeType      = "application/vnd.cyclonedx+json"
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &SBOMAttestor{}
	_ attestation.Subjecter = &SBOMAttestor{}
	_ attestation.Exporter  = &SBOMAttestor{}
)

func init() {
	attestation.RegisterAttestationWithTypes(Name, []string{Type, SPDXPredicateType, CycloneDxPredicateType}, RunType,
		func() attestation.Attestor { return NewSBOMAttestor() },
		registry.BoolConfigOption(
			"export",
			"Export the SBOM predicate in its own attestation",
			defaultExport,
			func(a attestation.Attestor, export bool) (attestation.Attestor, error) {
				sbomAttestor, ok := a.(*SBOMAttestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not an SBOM attestor", a)
				}
				WithExport(export)(sbomAttestor)
				return sbomAttestor, nil
			},
		),
		registry.StringConfigOption(
			"file",
			"Path to an existing SBOM file to attest directly (SPDX-JSON or CycloneDX-JSON). Bypasses product-set scanning; format auto-detected from JSON content. Relative paths are resolved against the working directory.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				sbomAttestor, ok := a.(*SBOMAttestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not an SBOM attestor", a)
				}
				WithSBOMFile(val)(sbomAttestor)
				return sbomAttestor, nil
			},
		),
	)
	detection.Register(Name, detectorYAML)
}

type Option func(*SBOMAttestor)

func WithExport(export bool) Option {
	return func(a *SBOMAttestor) {
		a.export = export
	}
}

// WithSBOMFile pins the attestor to a specific SBOM file on disk. When
// set, getCandidate reads the file directly instead of scanning the
// product attestor's output set — useful when the SBOM existed before
// the wrapped command ran (i.e., it's a material, not a product).
//
// The value supports relative or absolute paths; relatives are
// resolved against ctx.WorkingDir() at attest time.
func WithSBOMFile(path string) Option {
	return func(a *SBOMAttestor) {
		a.sbomFile = path
	}
}

type SBOMAttestor struct {
	SBOMDocument  interface{}
	predicateType string
	export        bool
	sbomFile      string
	subjects      map[string]cryptoutil.DigestSet
}

func NewSBOMAttestor() *SBOMAttestor {
	return &SBOMAttestor{
		predicateType: Type,
	}
}

func (a *SBOMAttestor) Name() string {
	return Name
}

func (a *SBOMAttestor) Type() string {
	return a.predicateType
}

func (a *SBOMAttestor) RunType() attestation.RunType {
	return RunType
}

func (a *SBOMAttestor) Export() bool {
	return a.export
}

func (a *SBOMAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *SBOMAttestor) Attest(ctx *attestation.AttestationContext) error {
	// Explicit-file mode: when --attestor-sbom-file points at a path,
	// skip the product-set scan entirely and attest that file directly.
	// This covers the common "I generated the SBOM in a previous step,
	// now attest it" workflow where the SBOM is a material, not a product.
	if a.sbomFile != "" {
		if err := a.loadFromExplicitFile(ctx); err != nil {
			log.Debugf("(attestation/sbom) explicit file load failed: %v", err)
			return err
		}
		return nil
	}

	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/sbom) error getting candidate: %v", err)
		return err
	}

	return nil
}

// loadFromExplicitFile reads the file at a.sbomFile, auto-detects
// SPDX-JSON vs CycloneDX-JSON from the JSON content, and populates the
// attestor's predicate + subjects exactly as getCandidate would for a
// product-set match. Format detection uses three unambiguous signals
// published by the respective specs:
//
//   - SPDX 2.x:        top-level "spdxVersion": "SPDX-2.x"
//   - CycloneDX 1.x:   top-level "bomFormat": "CycloneDX"
//   - SPDX 3.0:        top-level "specVersion": "3.x.y" + "@context"
//     pointing at the SPDX 3 JSON-LD context. SPDX 3 dropped the
//     `spdxVersion` field entirely and replaced it with a JSON-LD
//     shape, so it can't be detected by the 2.x signal.
//
// Detection order is 2.x first, CycloneDX second, 3.0 third (least
// common today). Anything else (or a file that doesn't parse as JSON)
// is rejected with an actionable error so the user knows immediately
// rather than silently producing an empty attestation.
func (a *SBOMAttestor) loadFromExplicitFile(ctx *attestation.AttestationContext) error {
	resolved := a.sbomFile
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(ctx.WorkingDir(), resolved)
	}

	sbomBytes, err := os.ReadFile(resolved) //nolint:gosec // G304: user-specified flag
	if err != nil {
		return fmt.Errorf("sbom: read --attestor-sbom-file %s: %w", resolved, err)
	}
	if !json.Valid(sbomBytes) {
		return fmt.Errorf("sbom: --attestor-sbom-file %s is not valid JSON", resolved)
	}

	predicateType, ok := sniffPredicateType(sbomBytes)
	if !ok {
		return fmt.Errorf("sbom: --attestor-sbom-file %s is not a recognized SBOM (need top-level spdxVersion, bomFormat:\"CycloneDX\", or specVersion:\"3.x\"+@context for SPDX 3.0)", resolved)
	}
	a.predicateType = predicateType

	// Reuse the existing subject-extraction code path for parity with
	// product-scanned SBOMs. SPDX 3.0 documents have a different shape
	// (subjects live in @graph[].name / rootElements), so we leave
	// subjects-by-name empty for now — capturing the file digest is
	// enough; a follow-up will extract 3.0 subjects properly.
	subjectsByName := make(map[string]string)
	var extracted sbomSubjectExtractor
	_ = json.Unmarshal(sbomBytes, &extracted)
	switch a.predicateType {
	case SPDXPredicateType:
		if extracted.SPDXDocumentName != "" {
			subjectsByName["name"] = extracted.SPDXDocumentName
		}
	case CycloneDxPredicateType:
		if extracted.Metadata.Component.Name != "" {
			subjectsByName["name"] = extracted.Metadata.Component.Name
		}
		if extracted.Metadata.Component.Version != "" {
			subjectsByName["version"] = extracted.Metadata.Component.Version
		}
	}

	a.SBOMDocument = json.RawMessage(sbomBytes)
	a.subjects = make(map[string]cryptoutil.DigestSet)

	// Subject for the file itself — same shape ("file:<path>") as the
	// product-set path uses, so policy can match without dispatch.
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	fileDigest, err := cryptoutil.CalculateDigestSetFromBytes(sbomBytes, hashes)
	if err == nil {
		a.subjects[fmt.Sprintf("file:%v", a.sbomFile)] = fileDigest
	}
	for k, v := range subjectsByName {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(v), hashes); err == nil {
			a.subjects[fmt.Sprintf("%s:%s", k, v)] = ds
		}
	}
	return nil
}

// sniffPredicateType inspects the top-level JSON of an SBOM and
// returns the matching predicate type URI. Detection signals (all at
// the top level, all non-overlapping):
//
//   - SPDX 2.x:   "spdxVersion" set.
//   - CycloneDX:  "bomFormat" == "CycloneDX".
//   - SPDX 3.0:   "specVersion" starts with "3." AND "@context" present.
//     SPDX 3 dropped `spdxVersion` and switched to JSON-LD, so 2.x's
//     signal can't be reused.
//
// SPDX 3 reuses the SPDX predicate URI because the URI names the
// SPDX *predicate*, not a spec version — verifiers dispatch on the
// document shape, not the URI. `@context` is RawMessage because SPDX
// 3 allows it to be either a string or an array; we only check for
// presence.
//
// Returns (predicateType, true) on a hit, ("", false) otherwise.
func sniffPredicateType(sbomBytes []byte) (string, bool) {
	var sniff struct {
		SPDXVersion string          `json:"spdxVersion"`
		BOMFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		Context     json.RawMessage `json:"@context"`
	}
	_ = json.Unmarshal(sbomBytes, &sniff)
	switch {
	case sniff.SPDXVersion != "":
		return SPDXPredicateType, true
	case sniff.BOMFormat == "CycloneDX":
		return CycloneDxPredicateType, true
	case strings.HasPrefix(sniff.SpecVersion, "3.") && len(sniff.Context) > 0:
		return SPDXPredicateType, true
	}
	return "", false
}

func (a *SBOMAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

// MarshalJSON emits the SBOM document with a cilock-added `_sbomFormat`
// discriminator field appended ("cyclonedx" or "spdx"). The underscore
// prefix signals the field is added by the attestor, not part of the
// underlying SBOM spec, so policy authors can dispatch on
// `input._sbomFormat == "cyclonedx"` without dual-shape walking. The
// rest of the document is byte-preserved from the source file.
//
// Issue #49 — the predicate is no longer format-ambiguous to rego.
func (a *SBOMAttestor) MarshalJSON() ([]byte, error) {
	doc, err := json.Marshal(&a.SBOMDocument)
	if err != nil {
		return nil, err
	}
	format := a.formatName()
	if format == "" {
		// No discriminator known — emit the bare document as before so
		// MarshalJSON stays lossless for unknown/legacy cases.
		return doc, nil
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		// Document doesn't parse as a JSON object (rare — could be an
		// array or scalar). Pass through unchanged rather than panic.
		// The original doc bytes are still valid JSON (json.Marshal
		// just emitted them), so callers get a lossless predicate
		// without a discriminator. Suppress the linter's "nilerr"
		// warning: returning the error would break Marshal callers
		// that expect doc to be valid bytes here.
		_ = err
		return doc, nil //nolint:nilerr // intentional: lossless pass-through for non-object SBOMs
	}
	m["_sbomFormat"] = format
	return json.Marshal(m)
}

// formatName returns the canonical short name for the active predicate
// type ("cyclonedx" or "spdx"), or "" if the predicate type is unset.
func (a *SBOMAttestor) formatName() string {
	switch a.predicateType {
	case SPDXPredicateType:
		return "spdx"
	case CycloneDxPredicateType:
		return "cyclonedx"
	}
	return ""
}

func (a *SBOMAttestor) UnmarshalJSON(data []byte) error {
	if product.IsSPDXJson(data) {
		a.predicateType = SPDXPredicateType
	} else if product.IsCycloneDXJson(data) {
		a.predicateType = CycloneDxPredicateType
	} else {
		log.Warn("Unknown sbom predicate type")
	}

	if err := json.Unmarshal(data, &a.SBOMDocument); err != nil {
		return err
	}

	return nil
}

func (a *SBOMAttestor) getCandidate(ctx *attestation.AttestationContext) error { //nolint:gocognit,gocyclo,funlen // SBOM candidate selection requires complex matching
	products := ctx.Products()

	if len(products) == 0 {
		// Soft opt-out: sbom ran but the upstream product set was empty.
		// The attestor's contract was satisfied (it ran); there just was
		// no SBOM-candidate input to wrap. CI shouldn't fail on this.
		// See finding #221.
		return attestation.NewSoftError("no products to attest")
	}

	a.subjects = make(map[string]cryptoutil.DigestSet)
	for path, product := range products {
		var predicateType string
		switch product.MimeType {
		case SPDXMimeType:
			predicateType = SPDXPredicateType
		case CycloneDxMimeType:
			predicateType = CycloneDxPredicateType
		default:
			// Issue #48: silently skipping unexpected MIME types means
			// users debugging "why isn't my SBOM attached?" have no
			// signal. Surface the skip at Debug.
			log.Debugf("(attestation/sbom) skipping %s: MIME %q not in accepted list [%s %s]", path, product.MimeType, SPDXMimeType, CycloneDxMimeType)
			continue
		}

		f, err := os.Open(filepath.Join(ctx.WorkingDir(), path)) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/sbom) error opening file %s: %v", path, err)
			continue
		}

		sbomBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/sbom) error reading file %s: %v", path, err)
			continue
		}

		// Validate the bytes parse as JSON before doing anything else.
		// Both SPDX-JSON and CycloneDX-JSON are JSON documents — invalid
		// JSON is the only common rejection criterion.
		if !json.Valid(sbomBytes) {
			log.Debugf("(attestation/sbom) %s is not valid JSON", path)
			continue
		}

		subjectsByName := make(map[string]string)
		var extracted sbomSubjectExtractor
		// Field-extraction parse is best-effort; missing fields are normal.
		_ = json.Unmarshal(sbomBytes, &extracted)

		switch predicateType {
		case SPDXPredicateType:
			if extracted.SPDXDocumentName != "" {
				subjectsByName["name"] = extracted.SPDXDocumentName
			}
		case CycloneDxPredicateType:
			if extracted.Metadata.Component.Name != "" {
				subjectsByName["name"] = extracted.Metadata.Component.Name
			}
			if extracted.Metadata.Component.Version != "" {
				subjectsByName["version"] = extracted.Metadata.Component.Version
			}
		default:
			continue
		}

		// Store the document as raw JSON — byte-preserving, avoids
		// re-encoding normalization. Downstream verifiers see the input.
		a.SBOMDocument = json.RawMessage(sbomBytes)

		// Record subject only after successful parse — recording before
		// validation would claim the SBOM was observed even on parse failure.
		a.predicateType = predicateType
		a.subjects[fmt.Sprintf("file:%v", path)] = product.Digest

		hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
		for k, v := range subjectsByName {
			if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(v), hashes); err == nil {
				a.subjects[fmt.Sprintf("%s:%s", k, v)] = ds
			} else {
				log.Debugf("(attestation/sbom) failed to record %v subject: %v", k, err)
			}
		}

		return nil
	}

	// Soft opt-out: the upstream product set contained no SBOM-shaped
	// file. The attestor's contract was satisfied; there was nothing to
	// attest.
	//
	// Note: this attestor ATTESTS to an SBOM you produced (CycloneDX
	// JSON/XML, SPDX JSON, in-toto SBOM-bundle); it does NOT generate
	// one. To populate a workspace with an SBOM, run a generator
	// alongside your command — e.g. `npm install && cyclonedx-npm
	// --output-file bom.cdx.json`, or `syft . -o cyclonedx-json`.
	// CI shouldn't fail on a project that doesn't ship an SBOM, so this
	// is a soft error (skipped, not a fatal). See finding #221.
	return attestation.NewSoftError(
		"no SBOM file found in product set — the sbom attestor records " +
			"the output of an SBOM generator (cyclonedx-npm / syft / etc.); " +
			"it does not generate one itself. Configure your build command " +
			"to emit a *.cdx.json / *.spdx.json file alongside your products.",
	)
}
