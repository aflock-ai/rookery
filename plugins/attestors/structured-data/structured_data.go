// Package structureddata is a generic JSON-ingestion attestor. It reads a
// recipe-pointed JSON file from the attestation product list, selects subject
// paths with an RFC 9535 JSONPath subset, canonicalizes the data per RFC 8785
// for a stable digest, and emits a signed envelope keyed on those subjects.
//
// Shape mirrors the prowler attestor (subtrees/rookery/plugins/attestors/prowler):
// its own Go module under plugins/attestors/, registers in init(), and exposes
// the standard Attestor + Subjecter + Materialer + Exporter capability set.
//
// Why generic: FedRAMP 20x KSI evidence collection runs into the long tail of
// customer-specific data sources (a Kratos admin-API response, a Splunk-saved
// search result, a Snyk project export) where shipping a bespoke attestor per
// shape would balloon the rookery repo. structured-data + a YAML recipe lets
// new sources land as data, not code.
package structureddata

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"

	"github.com/aflock-ai/rookery/plugins/attestors/structured-data/internal/canonical"
	"github.com/aflock-ai/rookery/plugins/attestors/structured-data/internal/jsonpath"
)

const (
	Name    = "structured-data"
	Type    = "https://aflock.ai/attestations/structured-data/v0.1"
	RunType = attestation.PostProductRunType
)

// Compile-time interface check.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.Materialer = &Attestor{}
	_ attestation.Exporter   = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// Predicate is the structured-data attestor's signed payload.
type Predicate struct {
	DataType      string    `json:"dataType"`
	CollectedAt   time.Time `json:"collectedAt"`
	SubjectQuery  string    `json:"subjectQuery"`
	SubjectPrefix string    `json:"subjectPrefix,omitempty"`
	SubjectCount  int       `json:"subjectCount"`
	// Data carries the canonicalized JSON when EmbedData is true. Recipe
	// authors typically leave EmbedData false for large data sets — only the
	// digest is needed for verification.
	Data       json.RawMessage `json:"data,omitempty"`
	DataDigest string          `json:"dataDigest"`
	// Per-subject path → value digest map. The Subjects() method exposes
	// these as in-toto subjects so cross-attestation linkage works.
	SubjectDigests map[string]string `json:"subjectDigests,omitempty"`

	SourceFile   string               `json:"sourceFile,omitempty"`
	SourceDigest cryptoutil.DigestSet `json:"sourceDigest,omitempty"`
}

// Attestor implements the standard rookery attestor capability set.
type Attestor struct {
	// Predicate ends up in the signed DSSE statement.
	Predicate Predicate `json:"predicate"`

	// Configuration set by recipes via the registry ConfigOption system.
	dataFile      string
	subjectQuery  string
	subjectPrefix string
	dataType      string
	embedData     bool

	// Cached subject map for the Subjects() interface — populated by Attest.
	subjects map[string]cryptoutil.DigestSet
}

func New() *Attestor {
	return &Attestor{
		subjects: map[string]cryptoutil.DigestSet{},
	}
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(&a) }

// Exporter — each recipe's data is an independently-addressable envelope, not
// merged into the parent Collection. That matters for FedRAMP 20x because
// per-KSI evidence is consumed by separate policyverify VSAs.
func (a *Attestor) Export() bool { return true }

// Materials reports the source file the recipe handed us, so verifiers can
// confirm the bytes we attested over are the bytes the recipe produced.
func (a *Attestor) Materials() map[string]cryptoutil.DigestSet {
	if a.Predicate.SourceFile == "" {
		return nil
	}
	return map[string]cryptoutil.DigestSet{a.Predicate.SourceFile: a.Predicate.SourceDigest}
}

// Subjects returns the in-toto subjects derived from the configured JSONPath
// against the attested data. Each subject's key is the subject-prefix + the
// normalized JSONPath path; each digest is the SHA-256 of the JCS-canonical
// encoding of the selected value.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet { return a.subjects }

// Attest reads the data file, validates JSON, selects subjects, and fills the
// Predicate. The signed envelope's stable digest comes from JCS canonical
// encoding — same input bytes produce the same envelope across runs.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if a.subjectQuery == "" {
		return fmt.Errorf("structured-data: subject-query is required (RFC 9535 JSONPath)")
	}

	path, err := a.resolveDataFile(ctx)
	if err != nil {
		return err
	}

	bytesIn, sourceDigest, err := readAndDigest(path, ctx)
	if err != nil {
		return err
	}

	var root any
	if err := json.Unmarshal(bytesIn, &root); err != nil {
		return fmt.Errorf("structured-data: data file %s is not valid JSON: %w", path, err)
	}

	canonBytes, err := canonical.Marshal(root)
	if err != nil {
		return fmt.Errorf("structured-data: JCS canonicalization failed: %w", err)
	}
	digest := sha256.Sum256(canonBytes)

	matches, err := jsonpath.Select(root, a.subjectQuery)
	if err != nil {
		return fmt.Errorf("structured-data: subject-query %q failed: %w", a.subjectQuery, err)
	}

	// Subject construction follows the prowler / aws-config / asff
	// convention shared with the steampipe attestor:
	//   key    = <subjectPrefix><identity-value-as-string>
	//   digest = sha256(<identity-value-as-string>)
	//
	// This is what makes cross-attestation graph traversal work:
	// policyverify joins by digest value (see attestation/policy/policy.go),
	// so two attestors that hash the same identity string converge in BFS
	// regardless of subject-key style.
	//
	// Bug we're fixing: the previous implementation digested
	// canonical.Marshal(m.Value), which for a string identity wraps it in
	// quotes ("abc-123" → "\"abc-123\"") and produces a DIFFERENT digest
	// than every other attestor's `sha256("abc-123")`. Cross-attestation
	// joins were silently broken. The key was also `prefix + m.Path`,
	// meaning a subject was keyed by the JSONPath
	// (`kratos:identity:$['identities'][0]['id']`) rather than by the
	// value the path resolves to.
	//
	// Non-scalar matches (maps, slices) are skipped — they can't be
	// stringified to a stable identity. Recipe authors selecting non-
	// scalar values get a debug log and the row is dropped from subjects.
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := map[string]cryptoutil.DigestSet{}
	subjectDigests := map[string]string{}
	for _, m := range matches {
		identity := stringifyIdentity(m.Value)
		if identity == "" {
			log.Debugf("(attestation/structured-data) skipping non-scalar match at %s", m.Path)
			continue
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(identity), hashes)
		if err != nil {
			log.Debugf("(attestation/structured-data) hash subject %s: %v", m.Path, err)
			continue
		}
		key := a.subjectPrefix + identity
		subjects[key] = ds
		sum := sha256.Sum256([]byte(identity))
		subjectDigests[key] = hex.EncodeToString(sum[:])
	}

	a.subjects = subjects
	a.Predicate = Predicate{
		DataType:       a.dataType,
		CollectedAt:    time.Now().UTC(),
		SubjectQuery:   a.subjectQuery,
		SubjectPrefix:  a.subjectPrefix,
		SubjectCount:   len(subjects),
		DataDigest:     hex.EncodeToString(digest[:]),
		SubjectDigests: subjectDigests,
		SourceFile:     path,
		SourceDigest:   sourceDigest,
	}
	if a.embedData {
		a.Predicate.Data = canonBytes
	}

	return nil
}

// resolveDataFile picks the JSON product to attest over. If the recipe set an
// explicit `data-file` it wins; otherwise we look for the first product whose
// MIME type is JSON.
func (a *Attestor) resolveDataFile(ctx *attestation.AttestationContext) (string, error) {
	products := ctx.Products()
	if a.dataFile != "" {
		if _, ok := products[a.dataFile]; ok {
			return a.dataFile, nil
		}
		return "", fmt.Errorf("structured-data: configured data-file %q not in product list", a.dataFile)
	}
	for path, p := range products {
		if strings.Contains(p.MimeType, "json") {
			return path, nil
		}
	}
	return "", fmt.Errorf("structured-data: no JSON product found and no data-file configured")
}

// readAndDigest re-digests the file against the attestation context's hash
// list and reads its bytes. We re-digest rather than trust the product
// metadata so a recipe that swaps the file mid-run gets caught here.
func readAndDigest(path string, ctx *attestation.AttestationContext) ([]byte, cryptoutil.DigestSet, error) {
	products := ctx.Products()
	product, ok := products[path]
	if !ok {
		return nil, nil, fmt.Errorf("structured-data: product %s not in context", path)
	}
	digestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
	if err != nil {
		return nil, nil, fmt.Errorf("structured-data: re-digest %s: %w", path, err)
	}
	if !digestSet.Equal(product.Digest) {
		return nil, nil, fmt.Errorf("structured-data: file %s digest mismatch — concurrent write?", path)
	}
	f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
	if err != nil {
		return nil, nil, fmt.Errorf("structured-data: open %s: %w", path, err)
	}
	defer f.Close()
	bytesIn, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("structured-data: read %s: %w", path, err)
	}
	return bytesIn, digestSet, nil
}

// ConfigOption setters. Kept package-level so the registry can wire them as
// CLI flags via the standard rookery convention.
func WithDataFile(p string) func(*Attestor)      { return func(a *Attestor) { a.dataFile = p } }
func WithSubjectQuery(q string) func(*Attestor)  { return func(a *Attestor) { a.subjectQuery = q } }
func WithSubjectPrefix(p string) func(*Attestor) { return func(a *Attestor) { a.subjectPrefix = p } }
func WithDataType(t string) func(*Attestor)      { return func(a *Attestor) { a.dataType = t } }
func WithEmbedData(b bool) func(*Attestor)       { return func(a *Attestor) { a.embedData = b } }

// stringifyIdentity coerces a JSONPath-selected value into a stable string
// suitable for use as an in-toto subject identity. Returns "" for non-scalar
// shapes (arrays, objects, nil) so the caller skips them.
//
// JSON numbers always decode to float64 from encoding/json; we render
// whole numbers as integers ("123" not "123.0", "339150376714" not
// "3.39150376714e+11") so identity strings from numeric ids in JSON
// round-trip through cross-attestation digest joins. Booleans render as
// "true" / "false".
//
// Inlined here rather than imported from the steampipe attestor: each
// rookery attestor is its own Go module and we don't want a shared
// utility package adding a new dep edge.
func stringifyIdentity(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return ""
}
