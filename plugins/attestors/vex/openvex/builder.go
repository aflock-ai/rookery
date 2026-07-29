// Copyright 2026 The Aflock Authors
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

package openvex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Context is the OpenVEX JSON-LD context this builder emits against. The
// vex attestor's types are byte-compatible with this version.
const Context = "https://openvex.dev/ns/v0.2.0"

// docIDPrefix mirrors the OpenVEX convention for a content-addressed
// document identifier: the canonical serialization of the document
// (with an empty @id) hashed with sha256.
const docIDPrefix = "https://openvex.dev/docs/public/vex-"

// initialDocumentVersion is the version stamped on a freshly authored document.
// Callers re-issuing a document bump it themselves.
const initialDocumentVersion = 1

// purlScheme is the canonical (lowercase) package-URL scheme prefix.
const purlScheme = "pkg:"

// cvePattern / ghsaPattern are the accepted shapes for a vulnerability
// identifier — the two forms judge's vulnerability views join on. Both
// are matched case-insensitively on input and canonicalized on output
// (CVE upper, GHSA body lower). Anything else is rejected rather than
// silently recorded: a statement nobody can join to a finding suppresses
// nothing.
//
// The GHSA groups are drawn from GitHub's own identifier alphabet —
// base32 with the vowels and the visually ambiguous characters (0/1/l,
// etc.) removed, so an ID cannot be misread or mistyped into a different
// one. Accepting the full alphanumeric range instead would admit strings
// like "GHSA-0000-aaaa-bbbb", which look like advisories, match nothing
// in GitHub's database, and would be signed as evidence suppressing a
// vulnerability that does not exist under that ID.
var (
	cvePattern  = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,}$`)
	ghsaPattern = regexp.MustCompile(`(?i)^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
)

// bareSHA256Pattern matches a bare 64-character hex sha256 digest.
var bareSHA256Pattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// digestAlgPattern is what an algorithm token may look like in an
// "<alg>:<hex>" digest. It deliberately excludes '/' and '.' so an OCI
// TAG reference ("ghcr.io/acme/api:v1.2.3") is not mistaken for a digest
// with an exotic algorithm.
var digestAlgPattern = regexp.MustCompile(`^[a-z0-9]+$`)

// validJustifications is the closed set from the OpenVEX 0.2.0 spec.
// Membership is checked explicitly so an unknown value fails at authoring
// time rather than becoming an unparseable statement in signed evidence.
//
// The status enumeration lives in statusFields (validate.go), which is
// keyed by status and therefore already IS the set of valid statuses —
// keeping a second copy here is how the two sides came to disagree.
var validJustifications = map[Justification]bool{
	ComponentNotPresent:                         true,
	VulnerableCodeNotPresent:                    true,
	VulnerableCodeNotInExecutePath:              true,
	VulnerableCodeCannotBeControlledByAdversary: true,
	InlineMitigationsAlreadyExist:               true,
}

// StatementSpec is the authoring-side description of a single triage
// decision: one status, applied to a set of vulnerabilities across a set
// of products. Build fans it out into one OpenVEX Statement per
// vulnerability, which is the shape the spec requires.
type StatementSpec struct {
	// Vulns are vulnerability identifiers (CVE-… or GHSA-…).
	Vulns []string
	// Products are product references. Each is one of:
	//   - an OCI reference with a digest ("ghcr.io/org/img@sha256:<hex>")
	//   - a package URL ("pkg:golang/example.com/mod@v1.2.3")
	//   - a bare sha256 digest, with or without the "sha256:" prefix
	Products []string
	Status   Status
	// Justification is REQUIRED when Status is not_affected and must be
	// empty otherwise — the spec scopes justifications to not_affected.
	Justification   Justification
	ImpactStatement string
	ActionStatement string
}

// DocSpec is the authoring-side description of a whole document.
type DocSpec struct {
	Author     string
	AuthorRole string
	Tooling    string
	Statements []StatementSpec
	// Now supplies the document + statement timestamps. Injectable so
	// output is reproducible under test; nil means time.Now.
	Now func() time.Time
}

// Build validates a DocSpec and renders it into a VEX document.
//
// Validation is fail-closed: every enforced rule below rejects the
// document rather than emitting a weaker one. A VEX statement is a
// security claim that suppresses a finding downstream, so an
// under-specified statement is worse than no statement at all.
//
// Output is deterministic for a fixed clock: vulnerabilities and
// products are de-duplicated and sorted, statements are ordered by
// vulnerability name, and the document @id is the sha256 of the
// canonical serialization of the document itself.
func Build(spec DocSpec) (*VEX, error) {
	author := strings.TrimSpace(spec.Author)
	if author == "" {
		return nil, fmt.Errorf("vex: author is required")
	}
	if len(spec.Statements) == 0 {
		return nil, fmt.Errorf("vex: at least one statement is required")
	}

	now := spec.Now
	if now == nil {
		now = time.Now
	}
	// One instant for the whole document: the document and every
	// statement in it describe the same moment of assessment.
	ts := now().UTC().Truncate(time.Second)

	var statements []Statement
	for i := range spec.Statements {
		built, err := buildStatements(spec.Statements[i], ts)
		if err != nil {
			return nil, err
		}
		statements = append(statements, built...)
	}

	sort.SliceStable(statements, func(i, j int) bool {
		if statements[i].Vulnerability.Name != statements[j].Vulnerability.Name {
			return statements[i].Vulnerability.Name < statements[j].Vulnerability.Name
		}
		return statements[i].Status < statements[j].Status
	})

	doc := &VEX{
		Metadata: Metadata{
			Context:    Context,
			Author:     author,
			AuthorRole: strings.TrimSpace(spec.AuthorRole),
			Tooling:    strings.TrimSpace(spec.Tooling),
			Timestamp:  &ts,
			Version:    initialDocumentVersion,
		},
		Statements: statements,
	}

	id, err := documentID(doc)
	if err != nil {
		return nil, err
	}
	doc.ID = id

	// Self-check against the ingestion floor. The authoring rules above
	// are strictly tighter than Validate's, so this can only fire if the
	// two rule sets drift apart — and it fires HERE, at authoring time,
	// rather than when an attestor later refuses the document.
	if err := Validate(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// buildStatements validates one spec and fans it out to one Statement
// per vulnerability.
func buildStatements(spec StatementSpec, ts time.Time) ([]Statement, error) {
	// The status enumeration and the field-applicability matrix live in
	// one place (CheckStatusFields) and are applied identically here and
	// at the ingestion floor. Authoring used to keep its own copy of
	// these rules, which is how the two came to disagree about whether a
	// not_affected statement could substitute an impact_statement for a
	// justification: this side always required the justification, the
	// floor accepted either.
	if err := CheckStatusFields(spec.Status, spec.Justification, spec.ImpactStatement, spec.ActionStatement, FlagFieldNames); err != nil {
		return nil, fmt.Errorf("vex: %w", err)
	}

	vulns, err := normalizeVulns(spec.Vulns)
	if err != nil {
		return nil, err
	}
	products, err := normalizeProducts(spec.Products)
	if err != nil {
		return nil, err
	}

	out := make([]Statement, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, Statement{
			Vulnerability:   Vulnerability{Name: VulnerabilityID(v)},
			Timestamp:       &ts,
			Products:        products,
			Status:          spec.Status,
			Justification:   spec.Justification,
			ImpactStatement: strings.TrimSpace(spec.ImpactStatement),
			ActionStatement: strings.TrimSpace(spec.ActionStatement),
		})
	}
	return out, nil
}

// normalizeVulns validates, de-duplicates, and sorts vulnerability IDs.
func normalizeVulns(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("vex: at least one --vuln is required")
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v, err := canonicalVulnID(raw)
		if err != nil {
			return nil, err
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

// canonicalVulnID validates one identifier and returns its canonical
// spelling: CVE IDs uppercase, GHSA IDs "GHSA-" plus a lowercase body.
func canonicalVulnID(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	switch {
	case cvePattern.MatchString(v):
		return strings.ToUpper(v), nil
	case ghsaPattern.MatchString(v):
		return "GHSA-" + strings.ToLower(v[len("GHSA-"):]), nil
	default:
		return "", fmt.Errorf("vex: %q is not a valid vulnerability ID (want CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx)", raw)
	}
}

// normalizeProducts parses, de-duplicates, and sorts product references.
func normalizeProducts(in []string) ([]Product, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("vex: at least one --product is required")
	}
	seen := make(map[string]bool, len(in))
	out := make([]Product, 0, len(in))
	for _, raw := range in {
		p, key, err := parseProduct(raw)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Hashes[SHA256] < out[j].Hashes[SHA256]
	})
	return out, nil
}

// parseProduct turns one --product value into a Product plus the
// de-duplication key for it.
//
// Digest canonicalization matters beyond tidiness: judge stores an image
// digest as bare lowercase hex (see judge-api/pkg/archivista/parsers/oci.go
// sha256Hex, which strips the "sha256:" prefix and lowercases). A VEX
// statement carrying "sha256:ABC…" would never join to the ingested
// image, so every accepted spelling — bare hex, "sha256:"-prefixed,
// or the digest half of an OCI "repo@sha256:…" reference — normalizes to
// the same bare lowercase hex under hashes["sha-256"].
func parseProduct(raw string) (Product, string, error) {
	ref := strings.TrimSpace(raw)
	if ref == "" {
		return Product{}, "", fmt.Errorf("vex: empty --product reference")
	}

	// purl: identity is the purl string itself; there is no digest. The
	// purl scheme is case-insensitive and canonically lowercase, so
	// normalize just the scheme — the rest of a purl IS case-sensitive.
	if len(ref) >= len(purlScheme) && strings.EqualFold(ref[:len(purlScheme)], purlScheme) {
		canonical := purlScheme + ref[len(purlScheme):]
		// A "pkg:" prefix is not a package URL. Without this, `--product
		// pkg:` authored a product whose whole identity was the scheme —
		// signed evidence no consumer could join a finding to.
		if err := ValidatePURL(canonical); err != nil {
			return Product{}, "", fmt.Errorf("vex: --product %q: %w", raw, err)
		}
		return Product{Component: Component{
			ID:          canonical,
			Identifiers: map[IdentifierType]string{PURL: canonical},
		}}, canonical, nil
	}

	// OCI reference with a digest: "<repo>@sha256:<hex>".
	if name, digest, ok := strings.Cut(ref, "@"); ok {
		digestHex, err := canonicalSHA256(digest)
		if err != nil {
			return Product{}, "", fmt.Errorf("vex: --product %q: %w", raw, err)
		}
		if strings.TrimSpace(name) == "" {
			return Product{}, "", fmt.Errorf("vex: --product %q has an empty repository", raw)
		}
		id := name + "@sha256:" + digestHex
		return Product{Component: Component{
			ID:     id,
			Hashes: map[Algorithm]Hash{SHA256: Hash(digestHex)},
		}}, id, nil
	}

	// Bare digest, with or without the "sha256:" prefix.
	hexDigest, err := canonicalSHA256(ref)
	if err != nil {
		return Product{}, "", fmt.Errorf("vex: --product %q: %w (want an OCI ref 'repo@sha256:<hex>', a purl 'pkg:…', or a sha256 digest)", raw, err)
	}
	return Product{Component: Component{
		Hashes: map[Algorithm]Hash{SHA256: Hash(hexDigest)},
	}}, "sha256:" + hexDigest, nil
}

// canonicalSHA256 strips an optional "sha256:" prefix and lowercases,
// matching how judge stores image digests.
func canonicalSHA256(in string) (string, error) {
	v := strings.TrimSpace(in)
	if idx := strings.IndexByte(v, ':'); idx >= 0 {
		alg := strings.ToLower(v[:idx])
		// Only treat the prefix as an algorithm when it looks like one;
		// otherwise this is a tag reference, not a digest, and the
		// caller's "not a sha256 digest" message is the right one.
		if digestAlgPattern.MatchString(alg) {
			if alg != "sha256" {
				return "", fmt.Errorf("unsupported digest algorithm %q (only sha256)", v[:idx])
			}
			v = v[idx+1:]
		}
	}
	if !bareSHA256Pattern.MatchString(v) {
		return "", fmt.Errorf("not a sha256 digest")
	}
	return strings.ToLower(v), nil
}

// documentID content-addresses the document: serialize it with an empty
// @id, hash, and prefix. Deterministic for a fixed clock, and any edit to
// the statements changes the identifier.
func documentID(doc *VEX) (string, error) {
	clone := *doc
	clone.ID = ""
	raw, err := json.Marshal(&clone)
	if err != nil {
		return "", fmt.Errorf("vex: canonicalize document: %w", err)
	}
	sum := sha256.Sum256(raw)
	return docIDPrefix + hex.EncodeToString(sum[:]), nil
}

// Marshal renders a document as the indented JSON written to disk. Kept
// here so the CLI and the round-trip tests agree on the exact bytes.
func Marshal(doc *VEX) ([]byte, error) {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func joinStatuses() string {
	return strings.Join([]string{
		string(StatusNotAffected), string(StatusAffected),
		string(StatusFixed), string(StatusUnderInvestigation),
	}, ", ")
}

func joinJustifications() string {
	return strings.Join([]string{
		string(ComponentNotPresent), string(VulnerableCodeNotPresent),
		string(VulnerableCodeNotInExecutePath),
		string(VulnerableCodeCannotBeControlledByAdversary),
		string(InlineMitigationsAlreadyExist),
	}, ", ")
}
