// Package steampipe is an attestor that runs Steampipe queries against cloud /
// SaaS APIs (AWS, Okta, Azure AD, GitHub, GCP), captures the result rows, and
// emits a signed envelope summarizing the query, plugin, and per-row digests.
// Steampipe is the open-source SQL-over-API engine — the attestor wraps it
// so a recipe can ship a `.sql` query pack with KSI / NIST frontmatter and
// produce signed evidence for FedRAMP 20x indicators (KSI-IAM-MFA,
// KSI-CNA-NTW, etc.) without bespoke per-cloud code.
//
// Shape mirrors prowler (subtrees/rookery/plugins/attestors/prowler): own Go
// module, registers in init(), shells out to the `steampipe` binary.
//
// What this attestor is NOT: an alternative to the policyverify VSA layer.
// steampipe produces the **evidence** (signed query result); policyverify
// produces the **verdict** by evaluating a rego policy over that evidence.
package steampipe

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "steampipe"
	Type    = "https://aflock.ai/attestations/steampipe/v0.1"
	RunType = attestation.PostProductRunType
)

// steampipe is a state-reporting attestor (same class as prowler,
// aws-config, asff, sarif, sbom, docker-bench, kube-bench, oscap,
// nessus, inspec — every one of which implements Subjecter but NOT
// BackReffer). The BackReffer interface is reserved for CI/build-context
// attestors (git, github, gitlab, jenkins, githubwebhook, aws-codebuild)
// that have a workflow-run identity to anchor downstream verdicts on.
// State-reporting attestors expose their evidence via Subjects only;
// verifiers discover via subject-digest match, and the chain ends at
// the DSSE envelope's gitoid in Archivista.
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

// QueryFrontmatter captures the YAML metadata recipes embed at the top of
// each `.sql` file. Fields here map back to FedRAMP / NIST so the workflow
// can route the resulting envelope at the right KSI.
type QueryFrontmatter struct {
	ID       string   `json:"id" yaml:"id"`
	Task     string   `json:"task,omitempty" yaml:"task,omitempty"`
	KSIs     []string `json:"ksis,omitempty" yaml:"ksis,omitempty"`
	NIST     []string `json:"nist,omitempty" yaml:"nist,omitempty"`
	Plugin   string   `json:"plugin,omitempty" yaml:"plugin,omitempty"`
	Severity string   `json:"severity,omitempty" yaml:"severity,omitempty"`
}

// QueryResult is one steampipe query execution captured by the attestor.
// Rows is omitted from the predicate when truncated for envelope size —
// only the digest survives, but that's enough to verify the bytes.
type QueryResult struct {
	Frontmatter QueryFrontmatter `json:"frontmatter"`
	SQL         string           `json:"sql"`
	RanAt       time.Time        `json:"ranAt"`
	Duration    string           `json:"duration"`
	RowCount    int              `json:"rowCount"`
	ResultHash  string           `json:"resultHash"`
	Rows        json.RawMessage  `json:"rows,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// Predicate is the signed envelope's payload — version-pinned steampipe info
// plus the captured query results.
type Predicate struct {
	SteampipeVersion string            `json:"steampipeVersion,omitempty"`
	Plugins          []string          `json:"plugins,omitempty"`
	CollectedAt      time.Time         `json:"collectedAt"`
	Results          []QueryResult     `json:"results"`
	Identities       map[string]string `json:"identities,omitempty"`
}

type Attestor struct {
	Predicate Predicate `json:"predicate"`

	// Configuration set by recipes. queryPackPath points at a directory of
	// .sql files with YAML frontmatter; the attestor reads each, runs it
	// against steampipe, and accumulates results.
	queryPackPath   string
	maxRowsPerQuery int

	// frontmatter + sql are injected by the recipe driver (cilock) after it
	// parses the .sql comment block. The attestor cannot do that itself —
	// the .sql file lives outside the attestation context's product list —
	// and we don't want the attestor to read arbitrary files off disk. So
	// the recipe driver hands us the parsed frontmatter explicitly, and
	// the attestor stamps it onto every Result entry that comes out of
	// the matching JSON product. Phase 4's scanKSIProjection workflow
	// uses Frontmatter.KSIs to route the resulting envelope to the right
	// KSIValidation row.
	frontmatter QueryFrontmatter
	sql         string

	subjects  map[string]cryptoutil.DigestSet
	materials map[string]cryptoutil.DigestSet
}

func New() *Attestor {
	return &Attestor{
		subjects:        map[string]cryptoutil.DigestSet{},
		materials:       map[string]cryptoutil.DigestSet{},
		maxRowsPerQuery: 500,
	}
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(&a) }
func (a *Attestor) Export() bool                 { return true }

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet  { return a.subjects }
func (a *Attestor) Materials() map[string]cryptoutil.DigestSet { return a.materials }

// Attest reads the previously-produced steampipe JSON product(s) from the
// attestation context and packs them into the predicate. Recipes typically
// run `steampipe query --output json my-pack/check.sql > out.json` as a
// commandrun step; this attestor then runs in the PostProduct phase to seal
// the result.
//
// (Running `steampipe` ourselves from inside the attestor would require
// shipping the binary in every CI image; we instead consume the artifact
// the recipe's commandrun step produced — same pattern as the asff and
// sarif attestors.)
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("steampipe: no products to attest — recipe must produce a JSON output file")
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	var results []QueryResult
	for path, p := range products {
		result, ok := a.processProduct(ctx, path, p, hashes)
		if !ok {
			continue
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return fmt.Errorf("steampipe: no JSON products parsed as valid steampipe output")
	}

	a.Predicate = Predicate{
		CollectedAt: time.Now().UTC(),
		Results:     results,
	}
	return nil
}

// processProduct handles a single product entry from the attestation context.
// It returns the parsed QueryResult and ok=true if the product was a valid
// steampipe JSON output; ok=false indicates the product was skipped (wrong
// mime type, digest mismatch, read error, or unparseable body) and the caller
// should move on.
func (a *Attestor) processProduct(
	ctx *attestation.AttestationContext,
	path string,
	p attestation.Product,
	hashes []cryptoutil.DigestValue,
) (QueryResult, bool) {
	if !strings.Contains(p.MimeType, "json") && !strings.HasSuffix(path, ".json") {
		return QueryResult{}, false
	}

	newDigest, body, ok := readVerifiedProduct(ctx, path, p)
	if !ok {
		return QueryResult{}, false
	}

	qr, ok := parseSteampipeOutput(body)
	if !ok {
		return QueryResult{}, false
	}

	// Capture the source file as a material so verifiers can re-derive
	// the captured bytes from the original JSON output.
	a.materials[path] = newDigest

	// Subjects: fan-out per row per identity axis, keyed by convention
	// from the plugin name in the recipe frontmatter. Each subject
	// digest is sha256(identity_string) — matching prowler / aws-config
	// / asff so cross-attestation graph traversal joins on the same
	// digests. Per-attestation framework wraps these with
	// `steampipe/<key>` at the collection level (see
	// rookery/attestation/collection.go), so no within-graph collision
	// with other attestors using the same prefix shapes.
	//
	// Map semantics dedupe automatically: 4 IAM users sharing an
	// account_id collapse to one `aws:account:<id>` subject.
	a.accumulateSubjects(qr.parsedRows, hashes)

	// Keep the envelope-level result digest for the predicate
	// (auditors compare against the source-file Material's digest to
	// confirm the bytes that fed the attestor). It's NOT emitted as a
	// subject — no existing attestor does an envelope-level subject;
	// the DSSE envelope's own gitoid in Archivista is the envelope
	// identity, and recipe-id-level pivots happen via
	// Frontmatter.ID inside the predicate (indexable by Archivista).
	envDigest := sha256.Sum256(body)

	return QueryResult{
		Frontmatter: a.resolveFrontmatter(qr.id),
		SQL:         a.sql,
		RanAt:       time.Now().UTC(),
		RowCount:    len(qr.parsedRows),
		ResultHash:  hex.EncodeToString(envDigest[:]),
		Rows:        body,
	}, true
}

// readVerifiedProduct re-hashes the product file and reads its body if the
// recomputed digest still matches what the attestation context recorded.
// Returns ok=false on any verification or I/O failure (logged at debug).
func readVerifiedProduct(
	ctx *attestation.AttestationContext,
	path string,
	p attestation.Product,
) (cryptoutil.DigestSet, []byte, bool) {
	newDigest, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
	if err != nil {
		log.Debugf("(attestation/steampipe) digest %s: %v", path, err)
		return nil, nil, false
	}
	if !newDigest.Equal(p.Digest) {
		log.Debugf("(attestation/steampipe) digest mismatch for %s — concurrent write?", path)
		return nil, nil, false
	}
	f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
	if err != nil {
		log.Debugf("(attestation/steampipe) open %s: %v", path, err)
		return nil, nil, false
	}
	body, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		log.Debugf("(attestation/steampipe) read %s: %v", path, err)
		return nil, nil, false
	}
	return newDigest, body, true
}

// accumulateSubjects extracts identity axes from each row via the
// plugin-specific convention and writes their sha256 digests into a.subjects.
// Map semantics dedupe duplicates automatically.
func (a *Attestor) accumulateSubjects(rows []map[string]any, hashes []cryptoutil.DigestValue) {
	for _, row := range rows {
		for _, ext := range extract(a.frontmatter.Plugin, row) {
			ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(ext.Value), hashes)
			if err != nil {
				log.Debugf("(attestation/steampipe) hash subject %s: %v", ext.Key, err)
				continue
			}
			a.subjects[ext.Key] = ds
		}
	}
}

// resolveFrontmatter returns the per-result frontmatter, preferring the
// recipe-driver-injected one and falling back to the steampipe output's
// intrinsic id (already defaulted to "anonymous" by parseSteampipeOutput).
func (a *Attestor) resolveFrontmatter(fallbackID string) QueryFrontmatter {
	fm := a.frontmatter
	if fm.ID == "" {
		fm.ID = fallbackID
	}
	return fm
}

// parsedQuery is the intermediate result of decoding one JSON file. We accept
// two shapes: (1) `[{...}, ...]` raw rows; (2) `{"rows": [...]}` wrapper.
type parsedQuery struct {
	id         string
	parsedRows []map[string]any
}

func parseSteampipeOutput(body []byte) (parsedQuery, bool) {
	// Try the raw-array form first.
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err == nil {
		return parsedQuery{id: "anonymous", parsedRows: rows}, true
	}
	// Try the {rows: [...]} wrapper.
	var wrap struct {
		ID   string           `json:"id"`
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(body, &wrap); err == nil && len(wrap.Rows) > 0 {
		id := wrap.ID
		if id == "" {
			id = "anonymous"
		}
		return parsedQuery{id: id, parsedRows: wrap.Rows}, true
	}
	return parsedQuery{}, false
}

func WithQueryPackPath(p string) func(*Attestor) { return func(a *Attestor) { a.queryPackPath = p } }
func WithMaxRowsPerQuery(n int) func(*Attestor)  { return func(a *Attestor) { a.maxRowsPerQuery = n } }

// WithFrontmatter is called by the recipe driver (cilock) after it parses
// the .sql comment block. The frontmatter rides the resulting predicate
// so the Phase 4 scanKSIProjection workflow can route the envelope to the
// matching KSIValidation row(s).
func WithFrontmatter(fm QueryFrontmatter) func(*Attestor) {
	return func(a *Attestor) { a.frontmatter = fm }
}

// WithSQL records the literal SQL the recipe ran. Optional but useful for
// auditor review — the predicate's `sql` field surfaces it verbatim.
func WithSQL(sql string) func(*Attestor) { return func(a *Attestor) { a.sql = sql } }
