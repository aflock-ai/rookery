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

// sarifVersion is the only value the SARIF 2.1.0 spec permits in the log's
// `version` member (§3.13.2), and the only one this attestor's predicate type
// (…/attestations/sarif/v0.1) claims to carry. It is pinned rather than merely
// required-non-empty: "garbage" is not a SARIF version, and a genuinely new
// SARIF major needs a new predicate version — not a silently widened check
// here that would let an unreadable document be signed as if we understood it.
// All 240 well-formed SARIF bodies in the recorded production corpus carry
// exactly this value.
const sarifVersion = "2.1.0"

// jsonObject decodes b as a JSON object, naming what it got instead. Decoding
// into a map is what rejects null, scalars and arrays: `null` unmarshals into
// a map as a nil map without error, so the raw bytes are checked first.
func jsonObject(b []byte, what string) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, fmt.Errorf("%s must be an object: %w", what, err)
	}
	if obj == nil {
		return nil, fmt.Errorf("%s must be an object, got null", what)
	}
	return obj, nil
}

// isSARIFLog reports whether b is a SARIF log document, returning a reason
// when it is not.
//
// This is the invariant that makes a sarif-typed attestation structurally
// incapable of carrying a foreign format. It keys purely on SHAPE — the
// members the SARIF 2.1.0 spec marks REQUIRED — and deliberately never on
// file names, step names or tool names: producers ship formats we have never
// seen under names we do not control, and a name-based check would wave those
// straight through.
//
// Enforced, all fail-closed:
//
//   - a top-level JSON OBJECT (§3.13), so a bare findings array cannot pass;
//   - `version` exactly sarifVersion (§3.13.2);
//   - `runs` present and an ARRAY (§3.13.4) — `[]` is accepted, that is a
//     genuine clean scan, but missing or null is not: it is a structurally
//     incomplete log, and a consumer reading it as "zero findings" turns it
//     into a silent false negative on vulnerability evidence;
//   - every run an OBJECT carrying `tool` (§3.14.6), itself carrying `driver`
//     (§3.18.1) with a non-empty `name` (§3.19.8) — all spec-REQUIRED. This is
//     what rejects `runs:[null]`, `runs:[{}]` and `driver:{}`, documents that
//     parse as JSON and satisfy a shallower check while carrying no
//     attributable scanner identity at all.
//
// `results` is deliberately NOT required: the spec marks it OPTIONAL, and a
// run that legitimately omits it must not be turned into a failed step. The
// platform-side parser already fails closed on an absent results array rather
// than projecting it as "no findings".
//
// This is typed structural validation rather than JSON-schema validation
// against the published SARIF schema. That is a deliberate trade: this
// attestor's whole reason for holding the report as json.RawMessage was to
// shed the go-sarif library "plus its jsonschema validation tree" (see the
// Attestor doc comment), and rookery gates linked-dependency growth through
// .dep-budget.yaml. The checks above cover every member the spec marks
// required on the path this attestor actually depends on.
func isSARIFLog(b []byte) error {
	// Unmarshaling into a map both rejects non-object top levels (a bare
	// array, a scalar) and validates the document's syntax end to end.
	fields, err := jsonObject(b, "a SARIF log")
	if err != nil {
		return fmt.Errorf("not a SARIF log: %w", err)
	}

	rawVersion, ok := fields["version"]
	if !ok {
		return fmt.Errorf("not a SARIF log: missing required %q member", "version")
	}
	var version string
	if err := json.Unmarshal(rawVersion, &version); err != nil {
		return fmt.Errorf("not a SARIF log: %q must be a string: %w", "version", err)
	}
	if version != sarifVersion {
		return fmt.Errorf("not a SARIF log: %q is %q, want %q", "version", version, sarifVersion)
	}

	rawRuns, ok := fields["runs"]
	if !ok {
		return fmt.Errorf("not a SARIF log: missing required %q member", "runs")
	}
	// A POINTER to the slice distinguishes `"runs": null` (nil pointer — an
	// incomplete log) from `"runs": []` (non-nil, empty — a clean scan).
	var runs *[]json.RawMessage
	if err := json.Unmarshal(rawRuns, &runs); err != nil {
		return fmt.Errorf("not a SARIF log: %q must be an array: %w", "runs", err)
	}
	if runs == nil {
		return fmt.Errorf("not a SARIF log: %q must be an array, got null", "runs")
	}

	for i, rawRun := range *runs {
		if err := validateSARIFRun(rawRun, i); err != nil {
			return fmt.Errorf("not a SARIF log: %w", err)
		}
	}
	return nil
}

// validateSARIFRun checks one element of a log's `runs` array against the
// members the spec marks REQUIRED on a run: the run itself an object
// (§3.14.6) carrying `tool`, the tool carrying `driver` (§3.18.1), and the
// driver carrying a non-empty `name` (§3.19.8).
//
// `name` earns its check: it is the field the platform's evidence classifier
// keys on to identify the producing scanner. A blank name does not degrade to
// "unrecognized tool" — it reads as NO SIGNAL, a different state the platform
// keeps deliberately distinct. Rejecting a nameless driver at the producer is
// what keeps that distinction meaningful for every downstream consumer.
func validateSARIFRun(raw json.RawMessage, i int) error {
	run, err := jsonObject(raw, fmt.Sprintf("runs[%d]", i))
	if err != nil {
		return err
	}
	rawTool, ok := run["tool"]
	if !ok {
		return fmt.Errorf("runs[%d] is missing required %q member", i, "tool")
	}
	tool, err := jsonObject(rawTool, fmt.Sprintf("runs[%d].tool", i))
	if err != nil {
		return err
	}
	rawDriver, ok := tool["driver"]
	if !ok {
		return fmt.Errorf("runs[%d].tool is missing required %q member", i, "driver")
	}
	driver, err := jsonObject(rawDriver, fmt.Sprintf("runs[%d].tool.driver", i))
	if err != nil {
		return err
	}
	rawName, ok := driver["name"]
	if !ok {
		return fmt.Errorf("runs[%d].tool.driver is missing required %q member", i, "name")
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil {
		return fmt.Errorf("runs[%d].tool.driver.name must be a string: %w", i, err)
	}
	if name == "" {
		return fmt.Errorf("runs[%d].tool.driver.name must be non-empty", i)
	}
	return nil
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error { //nolint:gocognit // SARIF candidate selection requires complex matching
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	// Products is a MAP, and ranging a Go map is randomized. Selecting the
	// first match off an unordered walk made the recorded report a coin flip
	// whenever a step left more than one JSON product in its workdir — which
	// is exactly how the prod TLS lane, emitting both testssl.json and the
	// converted testssl-results.sarif, attested the raw testssl report in 4
	// of 5 observed runs. Walk paths in sorted order so selection is
	// reproducible from the product set alone.
	paths := make([]string, 0, len(products))
	for path := range products {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	// Candidates rejected for shape are reported in the terminal error: the
	// bare "no sarif file found" left an operator with a failing step and no
	// clue which product was wrong or why.
	var rejected []string

	for _, path := range paths {
		product := products[path]
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

		// Validate that the bytes are a SARIF LOG, not merely valid JSON. The
		// MIME sniffer only tells us the product is text/JSON; it cannot tell
		// a SARIF log from a scanner's native report. Recording the latter
		// under this attestor's predicate type publishes a signed statement
		// that claims to be SARIF and is not — evidence no consumer can read
		// and no verifier can reject on shape. Skip it and say why.
		if err := isSARIFLog(reportBytes); err != nil {
			log.Debugf("(attestation/sarif) rejecting %s: %v", path, err)
			rejected = append(rejected, fmt.Sprintf("%s: %v", path, err))
			continue
		}

		a.Report = json.RawMessage(reportBytes)
		a.ReportFile = path
		a.ReportDigestSet = product.Digest

		return nil
	}
	if len(rejected) > 0 {
		return fmt.Errorf("no sarif file found (rejected %d candidate(s): %s)",
			len(rejected), strings.Join(rejected, "; "))
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
