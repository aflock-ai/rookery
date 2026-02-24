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

package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
	"github.com/owenrumney/go-sarif/sarif"
)

const (
	Name    = "sarif"
	Type    = "https://aflock.ai/attestations/sarif/v0.1"
	RunType = attestation.PostProductRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &Attestor{}

	mimeTypes = []string{"text/plain", "application/json"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	sarif.Report    `json:"report"`
	ReportFile      string               `json:"reportFileName"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet"`
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
		log.Debugf("(attestation/sarif) error getting candidate: %v", err)
		return err
	}

	return nil
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error { //nolint:gocognit // SARIF candidate selection requires complex matching
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		if product.MimeType == "" {
			continue
		}
		mimeMatch := false
		for _, mimeType := range mimeTypes {
			if product.MimeType == mimeType {
				mimeMatch = true
				break
			}
		}
		if !mimeMatch {
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/sarif) error calculating digest set from file %s: %v", path, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/sarif) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/sarif) error opening file %s: %v", path, err)
			continue
		}

		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/sarif) error reading file %s: %v", path, err)
			continue
		}

		//check to see if we can unmarshal into sarif type
		if err := json.Unmarshal(reportBytes, &a.Report); err != nil {
			log.Debugf("(attestation/sarif) error unmarshaling report: %v", err)
			continue
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest

		return nil
	}
	return fmt.Errorf("no sarif file found")
}
