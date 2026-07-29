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
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Validate reports whether doc is a usable OpenVEX document.
//
// It exists because decoding is not validation. Every field of VEX is
// optional to encoding/json, and Go's decoder ignores unknown keys, so
// `{}` — and any unrelated JSON object — unmarshals cleanly into a
// zero-valued VEX. Without this check an attestor reading a file "that
// parses" would digest and SIGN a document that asserts nothing, or one
// whose suppression the spec considers incomplete.
//
// The rules are the OpenVEX 0.2.0 required fields plus its status-specific
// obligations. They are the floor for INGESTING a document from anywhere
// (an explicitly named file, the product set, a third-party tool);
// Build applies these plus its own stricter authoring rules, and every
// document Build emits passes here.
//
// Validation is fail-closed: a document that trips any rule is rejected
// rather than recorded in a weaker form. A VEX statement suppresses a
// vulnerability finding downstream, so a malformed statement is worse
// than no statement at all.
func Validate(doc *VEX) error {
	if doc == nil {
		return fmt.Errorf("vex: no document")
	}
	if err := validateMetadata(&doc.Metadata); err != nil {
		return err
	}
	if len(doc.Statements) == 0 {
		return fmt.Errorf("vex: document has no statements — it asserts nothing")
	}
	for i := range doc.Statements {
		if err := validateStatement(&doc.Statements[i]); err != nil {
			return fmt.Errorf("vex: statement %d: %w", i, err)
		}
	}
	return nil
}

// supportedContexts are the OpenVEX contexts this build can actually
// DECODE, which is the only honest basis for accepting one.
//
// The @context declares the semantics the rest of the document is written
// in. Decoding here uses fixed 0.2.0 structs and, like all of
// encoding/json, silently ignores fields it does not know — so a document
// declaring some other revision would be read through 0.2.0 eyes, with
// any field that revision added dropped on the floor, and then signed as
// though it had been understood. A suppression whose meaning came from a
// spec this build never implemented is precisely the kind of claim that
// must not carry a signature.
//
// This used to accept "https://openvex.dev/ns/<anything>", which is the
// same defect the identity rules were fixed for over several rounds
// — crediting something unverifiable — sitting one level up, at the
// declaration that gives every other rule its meaning. It is the root of
// that family, not a new one.
//
// The set is deliberately just v0.2.0, and the two exclusions are
// evidenced rather than assumed — go-vex, the reference implementation
// (and the library judge-api itself decodes these documents with),
// dispatches on @context in pkg/vex/functions_files.go Open():
//
//   - The BARE "https://openvex.dev/ns" is NOT a version-agnostic
//     spelling. go-vex trims the prefix, finds an empty version, and
//     comments "If version is nil, then we assume v0.0.1" — routing it to
//     the parse001 legacy converter. v0.0.1 is a structurally different
//     document: "vulnerability" is a string, "products" is an array of
//     strings, "version" is a string. Decoding that with these structs is
//     precisely the defect this set exists to prevent, so the bare
//     context is rejected. (It is still the in-toto PREDICATE type — a
//     different field from the document's @context. Conflating the two
//     is what previously let it in here.)
//   - v0.1.0 is rejected by go-vex itself: getLegacyVersionParser returns
//     a parser for "v0.0.1" and nil for everything else, so Open() fails
//     with "unable to get parser for version v0.1.0". Refusing it is
//     parity with the ecosystem's own decoder, not extra strictness.
//
// Adding a version here is a deliberate act: it means someone confirmed
// the types in types.go still decode that revision without loss.
var supportedContexts = map[string]bool{
	// https://openvex.dev/ns/v0.2.0 — what types.go is byte-compatible
	// with, what Build emits, and the only locator go-vex parses with the
	// modern structs.
	Context: true,
}

// joinContexts renders the supported set for an error message, sorted so
// the message does not depend on map order.
func joinContexts() string {
	out := make([]string, 0, len(supportedContexts))
	for c := range supportedContexts {
		out = append(out, strconv.Quote(c))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// requireCanonical rejects a required string value that is empty,
// whitespace-only, or padded with leading/trailing whitespace.
//
// The padding rule is not pedantry: validation reads the DECODED struct
// while the attestor signs the authored BYTES verbatim (see
// loadFromBytes). A value that only passes after TrimSpace is a value
// whose signed spelling was never validated — and for the fields this is
// applied to (join and attribution keys: @context, @id, author,
// vulnerability name, component identity), the padded form is what a
// consumer would have to join on. Rejecting is the fail-closed choice;
// normalizing here would make the validator vouch for bytes other than
// the ones signed, which is the exact defect the bytes channel was built
// to remove.
func requireCanonical(label, v string) error {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return fmt.Errorf("%s is required", label)
	}
	if v != trimmed {
		return fmt.Errorf("%s %q carries leading or trailing whitespace — the signed bytes are the authored bytes, so only the canonical spelling is validated", label, v)
	}
	return nil
}

// validateMetadata enforces the document-level fields OpenVEX marks
// required. A document missing any of them cannot be attributed, ordered
// against a later revision, or identified — all of which a consumer needs
// before it may act on a suppression.
func validateMetadata(m *Metadata) error {
	if err := requireCanonical("vex: @context", m.Context); err != nil {
		return err
	}
	if !supportedContexts[m.Context] {
		return fmt.Errorf("vex: @context %q is not a supported OpenVEX context (want one of %s)", m.Context, joinContexts())
	}
	if err := requireCanonical("vex: @id", m.ID); err != nil {
		return err
	}
	if err := requireCanonical("vex: author", m.Author); err != nil {
		return err
	}
	if m.Timestamp == nil || m.Timestamp.IsZero() {
		return fmt.Errorf("vex: timestamp is required")
	}
	if m.Version < 1 {
		return fmt.Errorf("vex: version must be 1 or greater, got %d", m.Version)
	}
	return nil
}

// validateStatement enforces the per-statement rules, including the two
// status-specific obligations the spec states as MUST: a not_affected
// claim has to carry a fixed justification, and an affected claim has to
// say what is being done about it. See statusFields for the full matrix.
func validateStatement(s *Statement) error {
	if err := requireCanonical("vulnerability name", string(s.Vulnerability.Name)); err != nil {
		return err
	}
	if len(s.Products) == 0 {
		return fmt.Errorf("at least one product is required — a statement about no product suppresses nothing")
	}
	if err := validateProducts(s.Products); err != nil {
		return err
	}

	return CheckStatusFields(s.Status, s.Justification, s.ImpactStatement, s.ActionStatement, JSONFieldNames)
}

// fieldRule is what a status says about one of the three status-specific
// fields.
type fieldRule uint8

const (
	fieldForbidden fieldRule = iota
	fieldOptional
	fieldRequired
)

// statusFields is the OpenVEX 0.2.0 field-applicability matrix, written
// out once so no status can be checked for one field and not another.
//
// The not_affected row is the one worth spelling out. OpenVEX states that
// a not_affected statement MUST carry a status justification, and that it
// MAY additionally carry an impact_statement explaining why the
// vulnerable code cannot be exploited — supplemental prose, not a
// substitute for the fixed, machine-readable reason. This validator used
// to accept either one, which let a suppression through with only free
// text: nothing a consumer could match against the justification
// enumeration, and so nothing it could act on automatically.
//
// Note that go-vex's own Statement.Validate() is laxer here than the spec
// text its type comments quote ("For 'not_affected' status, a VEX
// statement MUST include a status Justification" / "MAY include an
// ImpactStatement") — its code accepts either. This package follows the
// documented MUST, because what it validates is about to be SIGNED.
var statusFields = map[Status]struct {
	justification   fieldRule
	impactStatement fieldRule
	actionStatement fieldRule
}{
	StatusNotAffected:        {justification: fieldRequired, impactStatement: fieldOptional, actionStatement: fieldForbidden},
	StatusAffected:           {justification: fieldForbidden, impactStatement: fieldForbidden, actionStatement: fieldRequired},
	StatusFixed:              {justification: fieldForbidden, impactStatement: fieldForbidden, actionStatement: fieldForbidden},
	StatusUnderInvestigation: {justification: fieldForbidden, impactStatement: fieldForbidden, actionStatement: fieldForbidden},
}

// FieldNames spells the three status-specific fields for error messages.
// Only the LABELS differ between surfaces — the rules above are shared —
// so an operator authoring a document is told which flag to pass while a
// document being ingested is described in the terms it is written in.
type FieldNames struct {
	Justification   string
	ImpactStatement string
	ActionStatement string
}

var (
	// JSONFieldNames names the fields as a document spells them.
	JSONFieldNames = FieldNames{"justification", "impact_statement", "action_statement"}
	// FlagFieldNames names them as `cilock attest vex` spells them.
	FlagFieldNames = FieldNames{"--justification", "--impact-statement", "--action-statement"}
)

// CheckStatusFields enforces the status enumeration and the whole
// field-applicability matrix in one place, so the authoring side and the
// ingestion floor cannot drift apart on which fields a status may carry.
func CheckStatusFields(status Status, justification Justification, impactStatement, actionStatement string, names FieldNames) error {
	rules, known := statusFields[status]
	if !known {
		return fmt.Errorf("unknown status %q (want one of %s)", status, joinStatuses())
	}
	if justification != "" && !validJustifications[justification] {
		return fmt.Errorf("unknown justification %q (want one of %s)", justification, joinJustifications())
	}

	if err := checkField(names.Justification, rules.justification, string(justification), status); err != nil {
		return err
	}
	if err := checkField(names.ImpactStatement, rules.impactStatement, impactStatement, status); err != nil {
		return err
	}
	return checkField(names.ActionStatement, rules.actionStatement, actionStatement, status)
}

// checkField applies one cell of the matrix.
func checkField(name string, rule fieldRule, value string, status Status) error {
	switch rule {
	case fieldRequired:
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("status %q requires %s", status, name)
		}
	case fieldForbidden:
		if strings.TrimSpace(value) != "" {
			// Not a detail to drop silently: the document is asserting
			// something the status cannot mean.
			return fmt.Errorf("%s does not apply to status %q (got %q)", name, status, value)
		}
	case fieldOptional:
	}
	return nil
}

// validateProducts holds every product — and every subcomponent under it
// — to the same identity bar. A subcomponent nobody can join on is the
// same defect as a product nobody can join on, one level down.
func validateProducts(products []Product) error {
	for i := range products {
		if err := validateComponent(&products[i].Component); err != nil {
			return fmt.Errorf("product %d: %w", i, err)
		}
		for j := range products[i].Subcomponents {
			if err := validateComponent(&products[i].Subcomponents[j].Component); err != nil {
				return fmt.Errorf("product %d subcomponent %d: %w", i, j, err)
			}
		}
	}
	return nil
}

// hashHexLen is the expected number of hex digits for each hash algorithm
// in the OpenVEX 0.2.0 closed set. A value of the wrong length is not that
// digest, whatever else it may be.
var hashHexLen = map[Algorithm]int{
	MD5:        32,
	SHA1:       40,
	SHA256:     64,
	SHA384:     96,
	SHA512:     128,
	SHA3224:    56,
	SHA3256:    64,
	SHA3384:    96,
	SHA3512:    128,
	BLAKE2S256: 64,
	BLAKE2B256: 64,
	BLAKE2B512: 128,
	BLAKE3:     64,
}

// hexPattern matches a run of hex digits and nothing else.
var hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// The two CPE bindings NIST defines. Identifier types this build has no
// rule for are not checked at all — see countVerifiableIdentity for why
// they are tolerated but never credited.
const (
	cpe22Prefix = "cpe:/"
	cpe23Prefix = "cpe:2.3:"
)

// cpe23Components is the fixed number of colon-separated components in a
// CPE 2.3 formatted string, counting the "cpe" and "2.3" prefix fields.
const cpe23Components = 13

// cpeParts are the values the CPE "part" component may take: application,
// operating system, hardware — plus the two wildcards.
var cpeParts = map[string]bool{"a": true, "o": true, "h": true, "*": true, "-": true}

// ValidateCPE reports whether raw is a structurally usable CPE name.
//
// "cpe:" is not a CPE, and neither is "cpe:not-a-cpe". Both bindings name
// a product through a fixed set of colon-separated components:
//
//	CPE 2.2 URI:              cpe:/{part}:{vendor}:{product}:…  (up to 7)
//	CPE 2.3 formatted string: cpe:2.3:{part}:{vendor}:{product}:… (exactly 13)
//
// A value carrying the scheme but naming no vendor or product identifies
// nothing, so crediting it as product identity signs a suppression that
// can never be joined to a finding. This is the same rule ValidatePURL
// enforces, one binding over — the prefix check that used to stand here
// was the purl defect left un-fixed in its sibling branch.
func ValidateCPE(raw string) error {
	v := strings.TrimSpace(raw)
	switch lower := strings.ToLower(v); {
	case strings.HasPrefix(lower, cpe23Prefix):
		return validateCPE23(v)
	case strings.HasPrefix(lower, cpe22Prefix):
		return validateCPE22(v)
	default:
		return fmt.Errorf("%q is not a CPE name (want %q… or %q…)", raw, cpe23Prefix, cpe22Prefix)
	}
}

// validateCPE23 checks a formatted string: exactly 13 components, a
// recognised part, and something concrete to match on.
func validateCPE23(v string) error {
	comps := splitCPE(v)
	if len(comps) != cpe23Components {
		return fmt.Errorf("%q has %d components, a CPE 2.3 name has %d", v, len(comps), cpe23Components)
	}
	if !cpeParts[strings.ToLower(comps[2])] {
		return fmt.Errorf("%q has part %q, want one of a, o, h, *, -", v, comps[2])
	}
	return requireConcreteCPE(v, comps[3], comps[4])
}

// validateCPE22 checks a URI binding: a recognised part, and something
// concrete to match on.
//
// Deliberately NO upper bound on the component count. The URI binding
// packs an edition into "~"-separated subfields and percent-encodes
// extras, so a well-formed name in the wild can carry more colon-
// separated pieces than the seven the binding nominally lists — and a
// ceiling would reject that real evidence for no security gain. The
// attack this function closes is a bare "cpe:" or "cpe:not-a-cpe"
// standing in as a product's whole identity, which the part and
// vendor/product requirements below catch on their own. The 2.3 binding
// IS fixed-width and unambiguous, so validateCPE23 does count.
func validateCPE22(v string) error {
	comps := splitCPE(strings.TrimPrefix(v[len(cpe22Prefix)-1:], "/"))
	if part := strings.ToLower(comps[0]); part != "" && !cpeParts[part] {
		return fmt.Errorf("%q has part %q, want one of a, o, h", v, comps[0])
	}
	vendor, product := "", ""
	if len(comps) > 1 {
		vendor = comps[1]
	}
	if len(comps) > 2 {
		product = comps[2]
	}
	return requireConcreteCPE(v, vendor, product)
}

// requireConcreteCPE rejects a name whose vendor AND product are both
// absent or wildcards. Such a name matches everything, which is the same
// as identifying nothing.
func requireConcreteCPE(v, vendor, product string) error {
	if concreteCPEComponent(vendor) || concreteCPEComponent(product) {
		return nil
	}
	return fmt.Errorf("%q names neither a vendor nor a product", v)
}

func concreteCPEComponent(c string) bool {
	c = strings.TrimSpace(c)
	return c != "" && c != "*" && c != "-"
}

// splitCPE splits on colons that are not backslash-escaped. CPE allows a
// literal colon inside a component as "\:", and a naive split would tear
// such a component in half and miscount the result.
func splitCPE(s string) []string {
	out := make([]string, 0, cpe23Components)
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			cur.WriteRune(r)
			escaped = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

// ValidatePURL reports whether raw is a structurally usable package URL.
//
// A "pkg:" prefix is not a package URL. The purl spec shapes an
// identifier as
//
//	pkg:type/namespace/name@version?qualifiers#subpath
//
// where TYPE and NAME are required and everything else is optional. So
// the bare string "pkg:" — and "pkg:golang", which names a type but no
// package — carry the scheme while identifying nothing. Accepting one
// puts a product in signed evidence that no consumer can ever join a
// finding to, which is exactly the suppression-that-suppresses-nothing
// this package exists to reject.
//
// This checks the required structure rather than pulling in a full purl
// parser: rookery deliberately keeps this module's dependency set small
// (see the security-patches trimming in the repo root), and type+name is
// the part that determines whether the identifier can be joined at all.
// Qualifiers and subpath are stripped, not interpreted.
func ValidatePURL(raw string) error {
	v := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(v), purlScheme) {
		return fmt.Errorf("%q is not a package URL (want %q…)", raw, purlScheme)
	}
	rest := v[len(purlScheme):]

	// Subpath and qualifiers are optional trailing sections; neither
	// contributes to identity, so drop them before locating type/name.
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	// Version is optional and trails the last '@'. A scoped npm
	// namespace spells its '@' percent-encoded (%40), so the last '@'
	// is the version separator when one is present.
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[:i]
	}

	typ, remainder, hasName := strings.Cut(rest, "/")
	if strings.TrimSpace(typ) == "" {
		return fmt.Errorf("package URL %q has no type", raw)
	}
	if !hasName {
		return fmt.Errorf("package URL %q has a type but no name", raw)
	}
	// Anything between type and the final segment is the namespace.
	name := remainder
	if i := strings.LastIndexByte(remainder, '/'); i >= 0 {
		name = remainder[i+1:]
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("package URL %q has an empty name", raw)
	}
	return nil
}

// validateComponent enforces that a component carries at least one
// identifier a consumer can actually join a finding on, and that every
// identifier it does carry is well-formed.
//
// Presence is not identity. `{"hashes":{"sha-256":""}}` and
// `{"identifiers":{"purl":""}}` are non-empty maps that identify nothing,
// so a length check alone lets a suppression through with no joinable
// product — the statement then either matches no finding, or matches
// whatever a lenient consumer decides an empty string equals. Both are
// worse than rejecting the document.
//
// The rule, stated once and applied to every keyed identity source:
// CREDIT ONLY WHAT THIS BUILD CAN VERIFY.
//
//   - A value under a kind this build knows must be well-formed, or the
//     document is rejected — it is claiming something demonstrably wrong.
//   - A value under a kind this build does NOT know is skipped: not an
//     error, because real tools decorate components with vendor-specific
//     keys and an extra key is not itself a lie, but not identity
//     either, because nothing here can confirm it means anything.
//
// That second clause used to be justified by "the @context rule admits
// later OpenVEX revisions". It no longer is, and deliberately so: the
// @context is now pinned to the revisions this build can actually decode
// (see supportedContexts), because accepting an unknown revision was the
// same credit-the-unverifiable defect one level up. The behaviour here is
// unchanged — tolerate the key, never count it — but it now rests on
// tolerance for extra keys rather than on a permissiveness that has
// since been closed.
//
// Both keyed sources go through countVerifiableIdentity so the rule
// cannot be applied to one and not the other — which is exactly how the
// hash side ended up correct while the identifier side credited any
// unknown type.
//
// Map iteration is sorted so a document with several problems always
// reports the same one.
func validateComponent(c *Component) error {
	verified := 0

	// @id is not part of the table below. It is a single spec-defined
	// field rather than a map whose keys the document chooses, so there
	// is no "unknown kind" to credit — and OpenVEX defines it as a
	// free-form IRI, which this build deliberately does not constrain
	// further: the builder itself emits OCI references
	// ("ghcr.io/acme/api@sha256:…") as @id, and demanding a URI scheme
	// would reject its own output. It IS held to the canonical-whitespace
	// rule: a present-but-padded @id would be credited here in trimmed
	// form and signed in padded form.
	if c.ID != "" {
		if err := requireCanonical("@id", c.ID); err != nil {
			return err
		}
		verified++
	}

	hashed, err := countVerifiableIdentity("hash", c.Hashes, hashRule)
	if err != nil {
		return err
	}
	verified += hashed

	named, err := countVerifiableIdentity("identifier", c.Identifiers, identifierRule)
	if err != nil {
		return err
	}
	verified += named

	if verified == 0 {
		return fmt.Errorf("no @id, hash, or identifier this build can verify to join on")
	}
	return nil
}

// identityRule checks one identity value for well-formedness.
type identityRule func(string) error

// countVerifiableIdentity walks one map of identity claims in sorted key
// order and reports how many of them this build can actually verify.
//
// ruleFor reports the check for a kind, and whether this build has one
// at all. A kind with no rule is skipped entirely — neither rejected nor
// counted — which is the whole point: an unverifiable claim must never
// be the reason a component passes validation.
func countVerifiableIdentity[K ~string, V ~string](
	label string,
	claims map[K]V,
	ruleFor func(K) (identityRule, bool),
) (int, error) {
	kinds := make([]K, 0, len(claims))
	for kind := range claims {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })

	verified := 0
	for _, kind := range kinds {
		rule, known := ruleFor(kind)
		if !known {
			continue
		}
		// The RAW value is what gets signed, so the raw value is what
		// the rule sees. Trimming a copy here would credit a padded
		// digest or identifier whose signed spelling no consumer can
		// join on — the same validated-one-thing-signed-another defect
		// requireCanonical closes for the metadata fields.
		value := string(claims[kind])
		if strings.TrimSpace(value) == "" {
			return 0, fmt.Errorf("%s %q is empty", label, kind)
		}
		if value != strings.TrimSpace(value) {
			return 0, fmt.Errorf("%s %q value %q carries leading or trailing whitespace — the signed bytes are the authored bytes, so only the canonical spelling is validated", label, kind, value)
		}
		if err := rule(value); err != nil {
			return 0, fmt.Errorf("%s %q: %w", label, kind, err)
		}
		verified++
	}
	return verified, nil
}

// hashRule reports how to check a digest under alg, if this build knows
// the algorithm at all.
func hashRule(alg Algorithm) (identityRule, bool) {
	want, known := hashHexLen[alg]
	if !known {
		return nil, false
	}
	return func(v string) error {
		if len(v) != want || !hexPattern.MatchString(v) {
			return fmt.Errorf("%q is not a %d-digit hex digest", v, want)
		}
		return nil
	}, true
}

// identifierRule reports how to check a software identifier of the given
// type, if this build knows the type at all. An unknown type — anything
// outside the OpenVEX 0.2.0 set — has no rule, so it cannot be the
// identity a component rests on.
//
// The two CPE keys get BINDING-SPECIFIC rules, not the either-binding
// dispatcher: a 2.3 formatted string filed under "cpe22" (or a 2.2 URI
// under "cpe23") is signed evidence whose declared type disagrees with
// its value, and a consumer that keys its parser on the declared type
// would misread it. ValidateCPE stays as the dispatcher for callers that
// hold an unlabeled name.
func identifierRule(typ IdentifierType) (identityRule, bool) {
	switch typ {
	case PURL:
		return ValidatePURL, true
	case CPE22:
		return validateCPE22Name, true
	case CPE23:
		return validateCPE23Name, true
	}
	return nil, false
}

// validateCPE22Name accepts only the CPE 2.2 URI binding.
func validateCPE22Name(raw string) error {
	if !strings.HasPrefix(strings.ToLower(raw), cpe22Prefix) {
		return fmt.Errorf("%q is not a CPE 2.2 URI (want %q…)", raw, cpe22Prefix)
	}
	return validateCPE22(raw)
}

// validateCPE23Name accepts only the CPE 2.3 formatted string binding.
func validateCPE23Name(raw string) error {
	if !strings.HasPrefix(strings.ToLower(raw), cpe23Prefix) {
		return fmt.Errorf("%q is not a CPE 2.3 formatted string (want %q…)", raw, cpe23Prefix)
	}
	return validateCPE23(raw)
}
