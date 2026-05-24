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
	"path/filepath"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
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

// Attestor stores a SARIF report alongside its source path and digest. The
// report is preserved as json.RawMessage so the attestation predicate is
// byte-identical to the input file — the previous implementation deserialized
// into a typed struct from owenrumney/go-sarif and re-encoded, which dragged
// the whole library plus its jsonschema validation tree.
//
// The SARIF 2.1.0 wire format is defined by the OASIS SARIF TC spec
// (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html); the
// attestor doesn't need a typed view to record the report's bytes.
type Attestor struct {
	Report          json.RawMessage      `json:"report"`
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
			log.Debugf("(attestation/sarif) skipping %s: empty MIME type (run product attestor first or write a recognized format)", path)
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
			// Issue #48: if no candidate emits, the caller gets the
			// terminal "no sarif file found" error with no clue why.
			// Log every skipped product at Debug with detected MIME so
			// `--log-level=debug` makes the mismatch visible.
			log.Debugf("(attestation/sarif) skipping %s: MIME %q not in accepted list %v", path, product.MimeType, mimeTypes)
			continue
		}

		// Join the attestation context's working directory so the file
		// lookup matches what sbom does. The previous implementation
		// opened `path` directly, which silently failed any time the
		// context's WorkingDir was not the test/process cwd.
		fullPath := filepath.Join(ctx.WorkingDir(), path)

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(fullPath, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/sarif) error calculating digest set from file %s: %v", fullPath, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/sarif) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(fullPath) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/sarif) error opening file %s: %v", fullPath, err)
			continue
		}

		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/sarif) error reading file %s: %v", fullPath, err)
			continue
		}

		// Validate that the bytes are JSON — a SARIF report is a JSON
		// document by definition. Anything else is the wrong product even
		// if the mime sniffer guessed application/json.
		if !json.Valid(reportBytes) {
			log.Debugf("(attestation/sarif) %s is not valid JSON", path)
			continue
		}

		a.Report = json.RawMessage(reportBytes)
		a.ReportFile = path
		a.ReportDigestSet = product.Digest

		return nil
	}
	return fmt.Errorf("no sarif file found")
}
