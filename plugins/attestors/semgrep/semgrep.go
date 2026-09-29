// Copyright 2026 TestifySec, Inc.
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

// Package semgrep attests Semgrep SAST scans from the tool's native `--json`
// report (schema: semgrep/semgrep-interfaces/semgrep_output_v1).
//
// Semgrep already reaches cilock through the generic sarif attestor, but SARIF
// is a lossy interchange format: the security metadata a policy wants to pin —
// CWE, OWASP, confidence — is flattened into an untyped properties bag, and the
// sarif attestor mints no finding-level subjects for non-image scans. This
// attestor reads the native JSON instead and exposes a rego-friendly Summary
// (typed CWE/OWASP, normalized severity, per-finding subjects) alongside the
// verbatim report for verifiers.
//
// Three facts about the tool, measured on Semgrep OSS 1.119.0, shape the design:
//
//   - extra.fingerprint and extra.lines are the literal string "requires login"
//     on the OSS CLI, so Semgrep's own stable finding id is unusable. Finding
//     identity is computed here (see findingID) and the placeholder never
//     becomes a subject.
//   - findings exit 0 by default (--error flips that; a rule that fails to
//     load exits non-zero), so the exit code says nothing about what was found.
//     The attestor reads results[] and errors[]; any errors[] entry — a rule
//     that failed to load, a file that timed out or partially parsed, whatever
//     level Semgrep logged it at — marks the scan incomplete
//     (Summary.ScanComplete=false) so a policy can refuse rather than read zero
//     findings as clean.
//   - the deprecated severities ERROR/WARNING are still emitted by registry
//     rules next to the current CRITICAL/HIGH/MEDIUM/LOW/INFO, so both
//     vocabularies are normalized to one set of buckets.
//
// Like every JSON-ingest attestor here, it parses a product the wrapped command
// wrote — it never runs or imports Semgrep — and it captures facts, not a
// verdict: severity is a rule author's label; the rego policy decides.
package semgrep

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "semgrep"
	Type    = "https://aflock.ai/attestations/semgrep/v0.1"
	RunType = attestation.PostProductRunType

	// Severity buckets. Lowercase to match the predicate field names rego
	// policies index on (summary.bySeverity.high), as govulncheck does.
	sevCritical = "critical"
	sevHigh     = "high"
	sevMedium   = "medium"
	sevLow      = "low"
	sevInfo     = "info"
	sevUnknown  = "unknown"
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}

	// mimeTypes a `semgrep --json` report can be classified as. A single valid
	// JSON document sniffs as application/json; text/plain covers a report
	// captured by redirecting stdout on a platform whose sniffer is stricter.
	mimeTypes = []string{"application/json", "text/plain"}
)

// This package registers nothing yet: no attestor name and no detector. The
// detection-only catalog entry (attestation/detection/catalog/semgrep.yaml)
// keeps routing `--workload auto -- semgrep` to the sarif attestor exactly as
// before, because run and plan attach any REGISTERED attestor by name, so
// registering "semgrep" without its routing would take `semgrep --sarif` away
// from the sarif attestor. The registration lands with the plugin detector,
// the catalog-entry removal and the run/plan routing, in one change.

// ---- wire format (subset of semgrep_output_v1) ----------------------------

// cliOutput is the top level of a `semgrep --json` report. results, errors and
// paths.scanned are REQUIRED by the schema and are decoded through pointers so
// validateReport can tell "present but empty" (a clean scan) from "absent" (a
// report that is refused).
type cliOutput struct {
	Version string      `json:"version"`
	Results *[]cliMatch `json:"results"`
	Errors  *[]cliError `json:"errors"`
	Paths   *cliPaths   `json:"paths"`
}

type cliPaths struct {
	Scanned *[]string `json:"scanned"`
}

type cliMatch struct {
	CheckID string        `json:"check_id"`
	Path    string        `json:"path"`
	Start   position      `json:"start"`
	End     position      `json:"end"`
	Extra   cliMatchExtra `json:"extra"`
}

type position struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// cliMatchExtra decodes only what the Summary reads. metadata is raw_json in
// the schema (rule-author defined), so its fields are decoded leniently.
// engine_kind is either a string ("OSS"/"PRO") or an array
// (["PRO_REQUIRED", <feature>]); dataflow_trace is kept raw because only its
// presence is recorded.
type cliMatchExtra struct {
	Message         string          `json:"message"`
	Metadata        ruleMetadata    `json:"metadata"`
	Severity        string          `json:"severity"`
	Fingerprint     string          `json:"fingerprint"`
	IsIgnored       json.RawMessage `json:"is_ignored"`
	EngineKind      json.RawMessage `json:"engine_kind"`
	ValidationState string          `json:"validation_state"`
	DataflowTrace   json.RawMessage `json:"dataflow_trace"`
}

// ruleMetadata is the subset of a rule's metadata the predicate lifts. The
// schema types metadata as raw_json — rule authors write whatever they like —
// so it is decoded field by field with type coercion, never as a typed struct:
// a `confidence: 0.9` or a metadata that is not an object must cost the
// attestation nothing but that field. A strict decode here would fail the whole
// document and drop every finding in the report.
type ruleMetadata struct {
	CWE        stringList
	OWASP      stringList
	Category   string
	Confidence string
	Likelihood string
	Impact     string
}

func (r *ruleMetadata) UnmarshalJSON(b []byte) error {
	*r = ruleMetadata{}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil //nolint:nilerr // lenient by design: non-object metadata is "no metadata", never a failed attestation
	}
	_ = r.CWE.UnmarshalJSON(m["cwe"])
	_ = r.OWASP.UnmarshalJSON(m["owasp"])
	r.Category = lenientString(m["category"])
	r.Confidence = lenientString(m["confidence"])
	r.Likelihood = lenientString(m["likelihood"])
	r.Impact = lenientString(m["impact"])
	return nil
}

// lenientString renders a scalar of any JSON type as text: a string unquoted,
// a number or bool as its literal, anything else (null, object, array) empty.
func lenientString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	switch raw[0] {
	case '{', '[':
		return ""
	}
	return string(raw)
}

// rawBool reads is_ignored, which the schema types as boolean but which a
// re-encoding tool may emit as "true"; anything else is false. It reads the
// decoded VALUE, never the bytes, so an escaped spelling of "true" is the
// string "true" whichever parse the raw value came from.
func rawBool(raw json.RawMessage) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	}
	return false
}

type cliError struct {
	Code    int             `json:"code"`
	Level   string          `json:"level"`
	Type    json.RawMessage `json:"type"`
	RuleID  string          `json:"rule_id"`
	Message string          `json:"message"`
	Path    string          `json:"path"`
}

// stringList accepts a JSON string or an array of strings. Rule metadata is
// untyped and rule authors write `cwe: "CWE-89"` and `cwe: ["CWE-89"]` alike;
// anything else (a number, an object, malformed) yields an empty list rather
// than an error — a rule author's typo must not fail the attestation.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*s = nil
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = stringList{one}
		return nil
	}
	var many []any
	if err := json.Unmarshal(b, &many); err != nil {
		*s = nil
		return nil //nolint:nilerr // lenient by design: malformed rule metadata yields an empty list, never a failed attestation
	}
	out := make(stringList, 0, len(many))
	for _, v := range many {
		if str, ok := v.(string); ok {
			out = append(out, str)
		}
	}
	*s = out
	return nil
}

// ---- predicate ------------------------------------------------------------

// Attestor is the semgrep/v0.1 predicate: a rego-friendly Summary plus the
// verbatim report and the digest that pins it to the product cilock captured.
type Attestor struct {
	Summary         Summary              `json:"summary"`
	Report          json.RawMessage      `json:"report"`
	ReportFile      string               `json:"reportFile"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet"`
}

// Summary is the roll-up a policy gates on.
type Summary struct {
	SemgrepVersion string `json:"semgrepVersion,omitempty"`
	// ScanComplete is false whenever errors[] is non-empty — a rule that failed
	// to load, a file that timed out or only partially parsed — regardless of
	// the level Semgrep logged it at. Every entry reduces coverage, so an empty
	// results[] beside a non-empty errors[] is not a clean result.
	ScanComplete  bool              `json:"scanComplete"`
	TotalFindings int               `json:"totalFindings"`
	IgnoredCount  int               `json:"ignoredCount"`
	FilesScanned  int               `json:"filesScanned"`
	BySeverity    SeverityBreakdown `json:"bySeverity"`
	Findings      []Finding         `json:"findings"`
	Errors        []ScanError       `json:"errors"`
}

// SeverityBreakdown counts LIVE (non-ignored) findings by normalized bucket.
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
}

// Finding is one result, with Semgrep's rule metadata lifted into typed fields.
type Finding struct {
	// ID is computed here — sha256 over rule, path, span and message — because
	// Semgrep's own fingerprint is login-gated on the OSS CLI.
	ID     string `json:"id"`
	RuleID string `json:"ruleId"`
	Path   string `json:"path"`
	// FileDigest binds the finding to the BYTES of the file it names: the
	// material digest cilock recorded for Path before the scan ran. Path is
	// caller-controlled text in the report; the digest is what cilock observed.
	// Always present so the shape is stable: null when the path was not among
	// the run's materials (a scan target outside the working directory) — an
	// explicit "not observed", and then no file subject is minted.
	FileDigest       cryptoutil.DigestSet `json:"fileDigest"`
	StartLine        int                  `json:"startLine"`
	StartCol         int                  `json:"startCol"`
	EndLine          int                  `json:"endLine"`
	EndCol           int                  `json:"endCol"`
	Message          string               `json:"message"`
	Severity         string               `json:"severity"`
	RawSeverity      string               `json:"rawSeverity"`
	CWE              []string             `json:"cwe,omitempty"`
	OWASP            []string             `json:"owasp,omitempty"`
	Category         string               `json:"category,omitempty"`
	Confidence       string               `json:"confidence,omitempty"`
	Likelihood       string               `json:"likelihood,omitempty"`
	Impact           string               `json:"impact,omitempty"`
	EngineKind       string               `json:"engineKind,omitempty"`
	ValidationState  string               `json:"validationState,omitempty"`
	IsIgnored        bool                 `json:"isIgnored"`
	HasDataflowTrace bool                 `json:"hasDataflowTrace"`
}

// ScanError is one errors[] entry — a rule or file Semgrep could not process.
type ScanError struct {
	Code    int    `json:"code"`
	Level   string `json:"level"`
	Type    string `json:"type,omitempty"`
	RuleID  string `json:"ruleId,omitempty"`
	Message string `json:"message,omitempty"`
	Path    string `json:"path,omitempty"`
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
	return jsonschema.Reflect(a)
}

// Attest finds the `semgrep --json` report among the step's products, verifies
// its bytes against the recorded product digest, and builds the predicate.
//
// Every product is classified. A product that is not a Semgrep report is not
// ours to judge. One that claims to be a Semgrep report but cannot be attested
// as it stands (cut off mid-write, a required member absent, bytes that differ
// from the recorded digest) is REFUSED with a plain error, never skipped: a
// plain error drops this attestor's payload and fails the run, so a broken
// scan can neither be signed nor pass as "semgrep did not run". Two good
// reports are refused as well, as govulncheck refuses two streams: signing one
// would drop the other's findings, and no rule for choosing is safe.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return attestation.NewSoftError("no products to attest")
	}

	// Sorted iteration so the refusal text never depends on map order.
	paths := make([]string, 0, len(products))
	for p := range products {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var (
		good    []string
		out     cliOutput
		raw     []byte
		refused []string
	)
	for _, path := range paths {
		o, r, refusal, ok := loadReport(ctx, path, products[path])
		switch {
		case refusal != "":
			refused = append(refused, path+": "+refusal)
		case ok:
			good = append(good, path)
			out, raw = o, r
		}
	}
	if len(refused) > 0 {
		return fmt.Errorf("refusing to attest semgrep report(s) that cannot be verified: %s", strings.Join(refused, "; "))
	}
	if len(good) > 1 {
		return fmt.Errorf("found %d semgrep reports (%s); refusing to attest one and drop the others' findings: write one semgrep --json report per step",
			len(good), strings.Join(good, ", "))
	}
	if len(good) == 0 {
		return attestation.NewSoftError("no semgrep JSON output found in products — run `semgrep --json --output semgrep.json …` in the wrapped command to capture results")
	}

	a.Summary = buildSummary(out, ctx.Materials(), ctx.WorkingDir())
	a.Report = json.RawMessage(raw)
	a.ReportFile = good[0]
	a.ReportDigestSet = products[good[0]].Digest
	return nil
}

// loadReport classifies one product. ok is true for a verified Semgrep report.
// refusal is non-empty for a product that claims to be a Semgrep report (see
// reportParser.member) but cannot be attested. Both are zero for a product that is
// not a Semgrep report at all.
//
// One parse, one view: parseReport reads the bytes once into a tree, and the
// classification, the member-name check and the Summary are all derived from
// that tree. There is no second parser of the raw bytes whose reading could
// differ from the one that decides what is signed.
func loadReport(ctx *attestation.AttestationContext, path string, product attestation.Product) (out cliOutput, raw []byte, refusal string, ok bool) {
	if !mimeMatches(product.MimeType) {
		return cliOutput{}, nil, "", false
	}
	fullPath := filepath.Join(ctx.WorkingDir(), path)

	// Read ONCE, then hash and parse that same buffer. Hashing the file and
	// re-opening it to parse would be two reads of a path, which are two files
	// if the report is swapped in between (RACE/TOCTOU).
	reportBytes, err := os.ReadFile(fullPath) //nolint:gosec // G304: path from attestation context products
	if err != nil {
		// Could not read is not "not a report": the bytes were never seen.
		return cliOutput{}, nil, fmt.Sprintf("read: %v", err), false
	}
	// Verify BEFORE classifying: bytes that are not the ones cilock captured
	// say nothing about what was captured. A findings report replaced by `{}`
	// would otherwise drop out as "not a report" and let a clean report beside
	// it be signed alone.
	got, err := cryptoutil.CalculateDigestSetFromBytes(reportBytes, ctx.Hashes())
	if err != nil || got == nil {
		return cliOutput{}, nil, fmt.Sprintf("digest: %v", err), false
	}
	if !got.Equal(product.Digest) {
		return cliOutput{}, nil, "bytes do not match the recorded product digest (modified after capture?)", false
	}

	tree, claims, parseErr := parseReport(reportBytes)
	if !claims {
		return cliOutput{}, nil, "", false // not a Semgrep report, not ours to judge
	}
	if parseErr != nil {
		return cliOutput{}, nil, fmt.Sprintf("does not decode (cut off mid-write?): %v", parseErr), false
	}
	if problem := checkMemberNames(tree, ""); problem != "" {
		return cliOutput{}, nil, problem, false
	}
	// The tree holds no repeated member, so re-encoding it leaves encoding/json
	// nothing to choose between; the struct is a projection of the same view.
	canonical, err := json.Marshal(tree)
	if err != nil {
		return cliOutput{}, nil, fmt.Sprintf("re-encode: %v", err), false
	}
	if err := json.Unmarshal(canonical, &out); err != nil {
		return cliOutput{}, nil, fmt.Sprintf("does not decode: %v", err), false
	}
	if reason := validateReport(out); reason != "" {
		return cliOutput{}, nil, reason, false
	}
	return out, reportBytes, "", true
}

// parseReport reads b as exactly one JSON document into a tree of
// map[string]any, []any and scalars, with numbers kept as json.Number text so
// no conversion can fail. It reports what the stock decoder would read
// silently: a member repeated in an object (encoding/json keeps the last one)
// and a second top-level document.
//
// claims reports a Semgrep marker (see reportParser.member) anywhere in the
// bytes read, including in a member a later repeat overwrote: the tree keeps
// the decoder's last-wins, but a report whose findings a repeat erased is
// still a Semgrep report, and must be refused rather than skipped.
//
// Only a syntax error or the end of input stops the parse, and those stop the
// stock decoder too. A repeated member is recorded and the parse goes on, so
// the parse never reads less than encoding/json does. On a syntax error the
// tree and claims read so far are returned, so a report cut off mid-write can
// still be recognized as one.
func parseReport(b []byte) (tree any, claims bool, err error) {
	p := reportParser{dec: json.NewDecoder(bytes.NewReader(b))}
	p.dec.UseNumber()
	tree, err = p.value(markerOther)
	switch {
	case err != nil:
		return tree, p.claims, err
	case p.repeat != nil:
		return tree, p.claims, p.repeat
	}
	if _, err := p.dec.Token(); !errors.Is(err, io.EOF) {
		return tree, p.claims, errors.New("more than one JSON document")
	}
	return tree, p.claims, nil
}

// markerScope is where a value sits, as far as the Semgrep markers care.
type markerScope int

const (
	markerOther   markerScope = iota
	markerRoot                // the top-level object
	markerResults             // the top-level results array
	markerResult              // one entry of it
)

type reportParser struct {
	dec    *json.Decoder
	repeat error // the first repeated member, if any
	claims bool  // a Semgrep marker was read
	depth  int
}

func (p *reportParser) value(scope markerScope) (any, error) {
	tok, err := p.next()
	if err != nil {
		return nil, err
	}
	top := p.depth == 0
	p.depth++
	defer func() { p.depth-- }()
	switch tok {
	case json.Delim('{'):
		if top {
			scope = markerRoot
		}
		return p.object(scope)
	case json.Delim('['):
		child := markerOther
		if scope == markerResults {
			child = markerResult
		}
		arr := []any{}
		for p.dec.More() {
			v, err := p.value(child)
			arr = append(arr, v)
			if err != nil {
				return arr, err
			}
		}
		_, err := p.next() // ']'
		return arr, err
	}
	return tok, nil
}

func (p *reportParser) object(scope markerScope) (map[string]any, error) {
	obj := map[string]any{}
	for p.dec.More() {
		tok, err := p.next()
		if err != nil {
			return obj, err
		}
		key, _ := tok.(string) // the decoder only yields a string in key position
		if _, dup := obj[key]; dup && p.repeat == nil {
			p.repeat = fmt.Errorf("member %q repeats", key)
		}
		v, err := p.value(p.member(scope, key))
		obj[key] = v // last wins, as encoding/json reads it
		if err != nil {
			return obj, err
		}
	}
	_, err := p.next() // '}'
	return obj, err
}

// member records a Semgrep marker as the member name is read, and returns the
// scope of its value. The markers are a top-level paths member and a check_id
// member on a results entry, matched under strings.EqualFold, the folding
// encoding/json binds fields with, so "Paths" and "CHECK_ID" claim too.
// check_id is the first key Semgrep writes for a finding, so a report cut off
// in the middle of its findings still claims.
func (p *reportParser) member(scope markerScope, key string) markerScope {
	switch {
	case scope == markerRoot && strings.EqualFold(key, "paths"),
		scope == markerResult && strings.EqualFold(key, "check_id"):
		p.claims = true
	case scope == markerRoot && strings.EqualFold(key, "results"):
		return markerResults
	}
	return markerOther
}

// next is dec.Token with an end of input inside a value reported as
// io.ErrUnexpectedEOF: the caller is always inside a value when it asks.
func (p *reportParser) next() (json.Token, error) {
	tok, err := p.dec.Token()
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return tok, err
}

// strictObjects are the report objects decoded into Go structs, addressed by
// member path ("[]" is any array element), each with its struct's JSON member
// names. encoding/json binds a member whose name matches a field under
// bytes.EqualFold (Unicode folding: "Extra", "ſeverity"), so a member spelled
// other than its field is refused rather than read by a rule a verifier may
// not share. The names come from the struct tags so the check cannot drift
// from the decoder. Rule metadata and the other raw members are read by exact
// key and not listed.
var strictObjects = map[string][]string{
	"":                jsonFieldNames(cliOutput{}),
	"paths":           jsonFieldNames(cliPaths{}),
	"results[]":       jsonFieldNames(cliMatch{}),
	"results[].start": jsonFieldNames(position{}),
	"results[].end":   jsonFieldNames(position{}),
	"results[].extra": jsonFieldNames(cliMatchExtra{}),
	"errors[]":        jsonFieldNames(cliError{}),
}

// jsonFieldNames lists the JSON member names encoding/json decodes into v.
func jsonFieldNames(v any) []string {
	t := reflect.TypeOf(v)
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" {
			name = t.Field(i).Name
		}
		names = append(names, name)
	}
	return names
}

// checkMemberNames returns the first member of a strictObjects object, in
// sorted order, whose name folds to a field but is not spelled as it. Members
// are walked under their canonical field name, so a container spelled "Extra"
// has its own members checked as results[].extra.
func checkMemberNames(node any, path string) string {
	switch n := node.(type) {
	case []any:
		for _, e := range n {
			if p := checkMemberNames(e, path+"[]"); p != "" {
				return p
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			canonical := canonicalName(k, strictObjects[path])
			if canonical != k {
				return fmt.Sprintf("member %q in %s is not spelled %q (encoding/json would bind it)", k, displayPath(path), canonical)
			}
			if p := checkMemberNames(n[k], childPath(path, k)); p != "" {
				return p
			}
		}
	}
	return ""
}

func canonicalName(key string, fields []string) string {
	for _, name := range fields {
		if strings.EqualFold(key, name) {
			return name
		}
	}
	return key
}

func childPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func displayPath(p string) string {
	if p == "" {
		return "the top level"
	}
	return p
}

// validateReport checks what the Summary is built from. The schema-required
// members (results, errors, paths.scanned) must be present: an absent member
// is never read as an empty one. EVERY result must carry the identity the
// predicate is built from (a rule id, a path and a 1-based start line);
// checking only results[0] would admit later entries whose findings and
// subjects are built from empty strings.
func validateReport(o cliOutput) string {
	switch {
	case o.Results == nil:
		return "required member results is absent or null"
	case o.Errors == nil:
		return "required member errors is absent or null"
	case o.Paths == nil || o.Paths.Scanned == nil:
		return "required member paths.scanned is absent or null"
	}
	for i, m := range *o.Results {
		if m.CheckID == "" || m.Path == "" || m.Start.Line < 1 {
			return fmt.Sprintf("results[%d] lacks a check_id, a path or a 1-based start line", i)
		}
	}
	return ""
}

// normalizePath maps a report path onto the key space of the run's materials:
// cleaned, and made relative to the working directory when it is absolute and
// inside it. Semgrep writes paths the way it was given the target (./src/a.py,
// or /work/src/a.py for an absolute target) while cilock records materials
// relative to the working directory; without this a finding for a recorded
// file would go unbound. A path outside the working directory is left as-is
// and finds no material.
func normalizePath(p, workDir string) string {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) || workDir == "" {
		return p
	}
	rel, err := filepath.Rel(filepath.Clean(workDir), p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p
	}
	return rel
}

// buildSummary rolls the report up deterministically. Findings and errors are
// put in a TOTAL order (lessFinding / lessError) so identical scans sign
// identical bytes whatever order Semgrep listed them in. materials are the
// run's recorded input digests, used to bind each finding to the bytes of the
// file it names.
//
// ScanComplete is false whenever errors[] is non-empty, regardless of the
// entry's level. Semgrep reports everything it could not fully analyze there —
// a rule that failed to load (level error), a file that timed out or only
// partially parsed (level warn) — and each of those reduces coverage. A policy
// that requires completeness must not accept a scan that skipped a file just
// because Semgrep logged the skip as a warning; the entries are recorded so
// the policy can decide which kinds it tolerates.
func buildSummary(out cliOutput, materials map[string]cryptoutil.DigestSet, workDir string) Summary {
	s := Summary{
		SemgrepVersion: out.Version,
		ScanComplete:   len(*out.Errors) == 0,
		TotalFindings:  len(*out.Results),
		FilesScanned:   len(*out.Paths.Scanned),
		Findings:       make([]Finding, 0, len(*out.Results)),
		Errors:         make([]ScanError, 0, len(*out.Errors)),
	}

	for _, m := range *out.Results {
		f := toFinding(m, materials, workDir)
		if f.IsIgnored {
			s.IgnoredCount++
		} else {
			s.BySeverity.add(f.Severity)
		}
		s.Findings = append(s.Findings, f)
	}
	sort.SliceStable(s.Findings, func(i, j int) bool { return lessFinding(s.Findings[i], s.Findings[j]) })

	for _, e := range *out.Errors {
		s.Errors = append(s.Errors, ScanError{
			Code:    e.Code,
			Level:   e.Level,
			Type:    rawToString(e.Type),
			RuleID:  e.RuleID,
			Message: e.Message,
			Path:    e.Path,
		})
	}
	sort.SliceStable(s.Errors, func(i, j int) bool { return lessError(s.Errors[i], s.Errors[j]) })
	return s
}

// lessError is a total order over errors: every field, then the canonical
// JSON of the whole value so two entries that agree on all compared fields but
// differ anywhere else still order the same way every run.
func lessError(a, b ScanError) bool {
	switch {
	case a.Code != b.Code:
		return a.Code < b.Code
	case a.Level != b.Level:
		return a.Level < b.Level
	case a.Type != b.Type:
		return a.Type < b.Type
	case a.RuleID != b.RuleID:
		return a.RuleID < b.RuleID
	case a.Path != b.Path:
		return a.Path < b.Path
	case a.Message != b.Message:
		return a.Message < b.Message
	}
	return canonicalJSON(a) < canonicalJSON(b)
}

// canonicalJSON is the last-resort sort key: encoding/json emits struct fields
// in declaration order and map keys sorted, so equal values encode equally.
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func toFinding(m cliMatch, materials map[string]cryptoutil.DigestSet, workDir string) Finding {
	// Normalize before anything derives from the path: the material lookup,
	// the file subject, and the finding id, so the same finding has the same
	// identity whether the target was passed as src/, ./src/ or /work/src/.
	m.Path = normalizePath(m.Path, workDir)
	return Finding{
		ID:               findingID(m),
		RuleID:           m.CheckID,
		Path:             m.Path,
		FileDigest:       materials[m.Path],
		StartLine:        m.Start.Line,
		StartCol:         m.Start.Col,
		EndLine:          m.End.Line,
		EndCol:           m.End.Col,
		Message:          m.Extra.Message,
		Severity:         normalizeSeverity(m.Extra.Severity),
		RawSeverity:      m.Extra.Severity,
		CWE:              []string(m.Extra.Metadata.CWE),
		OWASP:            []string(m.Extra.Metadata.OWASP),
		Category:         m.Extra.Metadata.Category,
		Confidence:       m.Extra.Metadata.Confidence,
		Likelihood:       m.Extra.Metadata.Likelihood,
		Impact:           m.Extra.Metadata.Impact,
		EngineKind:       engineKindString(m.Extra.EngineKind),
		ValidationState:  m.Extra.ValidationState,
		IsIgnored:        rawBool(m.Extra.IsIgnored),
		HasDataflowTrace: hasContent(m.Extra.DataflowTrace),
	}
}

// lessFinding is a total order over findings: position (start AND end), rule,
// message, the computed id, then the canonical JSON of the whole value, so no
// two distinct findings ever compare equal and input order can never leak into
// the signed summary.
func lessFinding(a, b Finding) bool {
	switch {
	case a.Path != b.Path:
		return a.Path < b.Path
	case a.StartLine != b.StartLine:
		return a.StartLine < b.StartLine
	case a.StartCol != b.StartCol:
		return a.StartCol < b.StartCol
	case a.EndLine != b.EndLine:
		return a.EndLine < b.EndLine
	case a.EndCol != b.EndCol:
		return a.EndCol < b.EndCol
	case a.RuleID != b.RuleID:
		return a.RuleID < b.RuleID
	case a.Message != b.Message:
		return a.Message < b.Message
	case a.ID != b.ID:
		return a.ID < b.ID
	}
	return canonicalJSON(a) < canonicalJSON(b)
}

func (b *SeverityBreakdown) add(bucket string) {
	switch bucket {
	case sevCritical:
		b.Critical++
	case sevHigh:
		b.High++
	case sevMedium:
		b.Medium++
	case sevLow:
		b.Low++
	case sevInfo:
		b.Info++
	default:
		b.Unknown++
	}
}

// findingID is the stable identity of one finding: sha256 over rule id, path,
// start and end positions and message, NUL-separated so field boundaries can
// never collide. It changes when the finding moves or its message changes and
// is stable across otherwise identical scans — the property Semgrep's
// login-gated fingerprint would have provided.
func findingID(m cliMatch) string {
	parts := []string{
		m.CheckID,
		m.Path,
		fmt.Sprintf("%d:%d", m.Start.Line, m.Start.Col),
		fmt.Sprintf("%d:%d", m.End.Line, m.End.Col),
		m.Extra.Message,
	}
	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(strings.Join(parts, "\x00")), []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		return ""
	}
	return ds[cryptoutil.DigestValue{Hash: crypto.SHA256}]
}

// normalizeSeverity maps both Semgrep vocabularies onto one bucket set. Per the
// schema's own deprecation notes ERROR means HIGH and WARNING means MEDIUM.
func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return sevCritical
	case "HIGH", "ERROR":
		return sevHigh
	case "MEDIUM", "WARNING":
		return sevMedium
	case "LOW":
		return sevLow
	case "INFO":
		return sevInfo
	default:
		return sevUnknown
	}
}

// engineKindString flattens engine_kind, which is "OSS" | "PRO" |
// ["PRO_REQUIRED", <feature>], to its leading token.
func engineKindString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one
	}
	var many []any
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 {
		if str, ok := many[0].(string); ok {
			return str
		}
	}
	return ""
}

// rawToString renders a raw JSON value as a plain string: a JSON string is
// unquoted, anything else is kept as compact JSON text.
func rawToString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one
	}
	// Canonical JSON (compact, object members sorted, numbers as written) so
	// the signed text never depends on the report's formatting: the summary
	// equals any decode of the verbatim report, however it was indented.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return string(raw)
	}
	canonical, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(canonical)
}

// hasContent reports whether an optional raw member is present and not null.
func hasContent(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && !bytes.Equal(raw, []byte("null"))
}

// mimeMatches compares the product MIME base type (before any ";charset")
// against the accepted types.
func mimeMatches(mt string) bool {
	base := mt
	if idx := strings.IndexByte(base, ';'); idx >= 0 {
		base = base[:idx]
	}
	base = strings.TrimSpace(base)
	for _, want := range mimeTypes {
		if base == want {
			return true
		}
	}
	return false
}

// Subjects exposes each LIVE finding, each rule that fired, and each file with a
// live finding, so the attestation can be found by any of them:
//
//	semgrep:finding:<id>   the computed finding id (DigestSet is that sha256)
//	semgrep:rule:<check_id> sha256 of the rule id string (a label)
//	semgrep:file:<path>     the file's CONTENT digest from the run's materials —
//	                        the value the attestation graph joins on. Minted only
//	                        when the path was a recorded material; a file cilock
//	                        did not observe gets no subject, never a name-hash.
//
// Ignored (nosemgrep) findings stay in the Summary as a record of the waiver but
// mint no subjects — a waived finding must not be indexable as a live one.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	addSubject := func(key, value string) {
		if value == "" {
			return
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/semgrep) failed to hash subject %s: %v", key, err)
			return
		}
		subjects[key] = ds
	}

	for _, f := range a.Summary.Findings {
		if f.IsIgnored || f.ID == "" {
			continue
		}
		subjects[fmt.Sprintf("semgrep:finding:%s", f.ID)] = cryptoutil.DigestSet{
			{Hash: crypto.SHA256}: f.ID,
		}
		addSubject(fmt.Sprintf("semgrep:rule:%s", f.RuleID), f.RuleID)
		if len(f.FileDigest) > 0 {
			subjects[fmt.Sprintf("semgrep:file:%s", f.Path)] = f.FileDigest
		}
	}
	return subjects
}
