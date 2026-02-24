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
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
	"github.com/spdx/tools-golang/spdx"
)

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
	)
}

type Option func(*SBOMAttestor)

func WithExport(export bool) Option {
	return func(a *SBOMAttestor) {
		a.export = export
	}
}

type SBOMAttestor struct {
	SBOMDocument  interface{}
	predicateType string
	export        bool
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
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/sbom) error getting candidate: %v", err)
		return err
	}

	return nil
}

func (a *SBOMAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

func (a *SBOMAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(&a.SBOMDocument)
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
		return fmt.Errorf("no products to attest")
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

		subjectsByName := make(map[string]string)
		switch predicateType {
		case SPDXPredicateType:
			var document *spdx.Document
			err := json.Unmarshal(sbomBytes, &document)
			if err != nil {
				log.Debugf("(attestation/sbom) error unmarshaling SPDX document from %s: %v", path, err)
				continue
			}

			if document.DocumentName != "" {
				subjectsByName["name"] = document.DocumentName
			}

			a.SBOMDocument = document
		case CycloneDxPredicateType:
			bom := cyclonedx.NewBOM()
			decoder := cyclonedx.NewBOMDecoder(bytes.NewReader(sbomBytes), cyclonedx.BOMFileFormatJSON)
			err := decoder.Decode(bom)
			if err != nil {
				log.Debugf("(attestation/sbom) error decoding CycloneDX BOM from %s: %v", path, err)
				continue
			}

			if bom.Metadata != nil && bom.Metadata.Component != nil {
				if bom.Metadata.Component.Name != "" {
					subjectsByName["name"] = bom.Metadata.Component.Name
				}

				if bom.Metadata.Component.Version != "" {
					subjectsByName["version"] = bom.Metadata.Component.Version
				}
			}

			a.SBOMDocument = bom
		default:
			continue
		}

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

	return fmt.Errorf("no SBOM file found")
}
