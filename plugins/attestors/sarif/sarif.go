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
	Name    = "sarif"
	Type    = "https://aflock.ai/attestations/sarif/v0.1"
	RunType = attestation.PostProductRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}

	mimeTypes = []string{"text/plain", "application/json"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
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

// imageProperties is the minimal view of a SARIF run's properties bag used to
// derive image subjects. Container image scanners (trivy's `trivy image
// --format sarif`) stamp the scanned image's identity there: imageName,
// repoDigests ("repo@sha256:<hex>"), repoTags, and imageID. Only imageName and
// repoDigests are read — imageID is the image CONFIG digest (a platform-local
// identity), not the manifest digest, so it would not connect to the manifest
// edges the oci/docker attestors emit.
type imageProperties struct {
	ImageName   string   `json:"imageName"`
	RepoDigests []string `json:"repoDigests"`
}

// reportImageProperties extracts runs[0].properties from the recorded report.
// Returns the zero value when the report is absent, not the expected shape, or
// carries no properties bag (gosec, golangci-lint, and other non-image SARIF).
func (a *Attestor) reportImageProperties() imageProperties {
	var doc struct {
		Runs []struct {
			Properties imageProperties `json:"properties"`
		} `json:"runs"`
	}
	if len(a.Report) == 0 || json.Unmarshal(a.Report, &doc) != nil || len(doc.Runs) == 0 {
		return imageProperties{}
	}
	return doc.Runs[0].Properties
}

// isSHA256Hex reports whether s is exactly 64 lowercase hex characters — the
// strict digest form an OCI repo digest reference carries after "@sha256:".
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Subjects exposes the scanned container image's identity when the recorded
// SARIF is an image scan (trivy stamps runs[0].properties on `trivy image`),
// so the report self-links to the image's build attestations at upload time.
// Non-image SARIF (gosec, golangci-lint, ...) carries no properties bag and
// yields no subjects. Key/value conventions follow the oci attestor:
//
//   - imagedigest:<hex>       the REAL manifest digest from repoDigests as the
//     DigestSet value (bare hex, oci's manifestdigest style — NOT a hash of
//     the string), so shared edges connect across collections
//   - imageref:<imageName>    label subject; DigestSet is the sha256 of the
//     literal string, mirroring how oci hashes imagetag strings
//
// Malformed repoDigests entries (missing "@sha256:", non-hex or wrong-length
// digest, empty repo) are skipped silently — a scanner bug must not fail the
// attestation, it just contributes no edge.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	props := a.reportImageProperties()

	for _, repoDigest := range props.RepoDigests {
		repo, digest, found := strings.Cut(repoDigest, "@sha256:")
		if !found || repo == "" || !isSHA256Hex(digest) {
			log.Debugf("(attestation/sarif) skipping malformed repo digest %q", repoDigest)
			continue
		}
		subjects[fmt.Sprintf("imagedigest:%s", digest)] = cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA256}: digest,
		}
	}

	if props.ImageName != "" {
		hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(props.ImageName), hashes); err == nil {
			subjects[fmt.Sprintf("imageref:%s", props.ImageName)] = ds
		} else {
			log.Debugf("(attestation/sarif) error hashing imageref subject %q: %v", props.ImageName, err)
		}
	}

	return subjects
}

// BackRefs anchors the scan verdict to the scanned image's manifest digest —
// the cross-collection identity — so the platform graph can walk from this
// report to the image's build attestations. Only the imagedigest subjects are
// backreffed (BackRefs ⊆ Subjects, per the contract rules): the imageref label
// stays a subject only, since names are mutable and re-tagging would fan the
// edge out across unrelated builds.
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	refs := make(map[string]cryptoutil.DigestSet)
	for key, ds := range a.Subjects() {
		if strings.HasPrefix(key, "imagedigest:") {
			refs[key] = ds
		}
	}
	return refs
}
