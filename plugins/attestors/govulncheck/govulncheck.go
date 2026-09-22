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

// Package govulncheck implements an attestor for Go's govulncheck JSON output.
//
// Unlike generic SCA scanners, govulncheck builds a call graph against the
// scanned module's source and reports both "vulnerable code is imported" and
// "vulnerable code is reachable from the user's call graph". The reachability
// signal is the primary differentiator and is preserved verbatim in the
// predicate's raw report field while a summary breakdown is exposed for rego
// policy gating.
//
// Input format: the wire protocol v1.0.0 documented at
// https://pkg.go.dev/golang.org/x/vuln/internal/govulncheck is a stream of
// pretty-printed JSON objects (one Message per object) — NOT line-delimited
// JSON. encoding/json.Decoder.Decode() naturally reads this stream by calling
// Decode repeatedly until io.EOF.
//
// Minimum govulncheck: v1.1.1, and v1.1.4 or later is recommended. A stream is
// attested only when the scan is shown to have completed: the stream carries
// govulncheck's post-fetch "Checking ... against the vulnerabilities..." record
// (see incompleteScan; older releases never emit it) AND the collection's
// command-run shows the scanner exited 0 (see scannerExitRefusal). The -json
// protocol has no terminal record, so the exit status is the only proof that
// nothing failed after the checking record.
package govulncheck

import (
	"bytes"
	"crypto"
	_ "embed"
	"encoding/json"
	"errors"
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
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/invopop/jsonschema"
	"golang.org/x/mod/semver"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "govulncheck"
	Type    = "https://aflock.ai/attestations/govulncheck/v0.1"
	RunType = attestation.PostProductRunType

	// Severity bucket names. Kept lowercase to match the JSON predicate
	// field names downstream rego policies will index on (e.g.
	// `summary.bySeverity.critical`).
	sevCritical = "critical"
	sevHigh     = "high"
	sevMedium   = "medium"
	sevLow      = "low"
	sevUnknown  = "unknown"
)

// Compile-time interface checks.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}

	// mimeTypes are the product MIME types govulncheck JSON can plausibly
	// be classified as. The wire format is a stream of concatenated JSON
	// objects, which fails the gabriel-vasile/mimetype JSON detector (it
	// requires a single valid JSON document in the sniff buffer); in
	// practice the file sniffs as "text/plain; charset=utf-8". Matching is
	// done by prefix (mimeMatches) so the charset suffix doesn't cause a
	// miss. application/json is retained for callers that produce a
	// single-object format (a future govulncheck --pretty=false flag, or a
	// wrapper that re-encodes the stream as a JSON array).
	mimeTypes = []string{"text/plain", "application/json"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// Message is a single envelope from the v1.0.0 govulncheck wire protocol. Each
// Message carries exactly one of Config / SBOM / Progress / OSV / Finding.
// Field types are kept loose (json.RawMessage / nested anonymous structs) so
// future protocol additions don't break the parser; only the fields the
// summary actually reads are typed.
type Message struct {
	Config   *Config         `json:"config,omitempty"`
	SBOM     *SBOM           `json:"SBOM,omitempty"`
	Progress json.RawMessage `json:"progress,omitempty"`
	OSV      *OSV            `json:"osv,omitempty"`
	Finding  *Finding        `json:"finding,omitempty"`
}

// Config carries the scan metadata emitted in the very first Message.
type Config struct {
	ProtocolVersion string `json:"protocol_version"`
	ScannerName     string `json:"scanner_name"`
	ScannerVersion  string `json:"scanner_version"`
	DB              string `json:"db"`
	DBLastModified  string `json:"db_last_modified"`
	GoVersion       string `json:"go_version"`
	ScanLevel       string `json:"scan_level"`
	ScanMode        string `json:"scan_mode"`
}

// SBOM is the per-module manifest produced by govulncheck before findings are
// emitted. Only fields the summary needs are decoded.
type SBOM struct {
	GoVersion string       `json:"go_version"`
	Modules   []SBOMModule `json:"modules"`
	Roots     []string     `json:"roots"`
}

// SBOMModule is one module entry inside the SBOM Message.
type SBOMModule struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// OSV mirrors the subset of the OSV record the summary aggregates. Anything
// not consumed is dropped on the floor — the full record is still preserved
// inside the raw Report bytes for downstream consumers that need it.
type OSV struct {
	SchemaVersion    string         `json:"schema_version"`
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Severity         []OSVSeverity  `json:"severity"`
	Affected         []OSVAffected  `json:"affected"`
	DatabaseSpecific *OSVDBSpec     `json:"database_specific"`
	References       []OSVReference `json:"references"`
}

// OSVSeverity carries a CVSS-style score per the OSV schema. Empty for Go DB
// entries today (the Go vuln team has not yet populated CVSS data).
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAffected is one affected-package range entry. Only the ecosystem-specific
// severity hint and the package path are needed by the summary.
type OSVAffected struct {
	Package          OSVPackage `json:"package"`
	DatabaseSpecific *OSVDBSpec `json:"database_specific"`
}

// OSVPackage identifies a single package targeted by the OSV.
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVDBSpec is the catch-all database_specific bag. Severity may appear here
// in non-Go ecosystems; the Go DB only populates URL and review_status.
type OSVDBSpec struct {
	Severity     string `json:"severity"`
	URL          string `json:"url"`
	ReviewStatus string `json:"review_status"`
}

// OSVReference is one upstream URL classified by type (FIX / REPORT / WEB).
type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Finding is one trace record produced by govulncheck. The trace's depth and
// content classifies the finding into three tiers:
//   - 1 frame, module only      → vulnerable module present in build
//   - 1 frame, with package     → vulnerable package imported
//   - 1 frame, with function    → vulnerable symbol reachable (and any
//     frames beyond [0] are the call stack from
//     the user's code into the vulnerable symbol)
type Finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []Frame `json:"trace"`
}

// Frame is one entry in a Finding's trace. Position is only populated for
// symbol-level frames.
type Frame struct {
	Module   string    `json:"module"`
	Version  string    `json:"version"`
	Package  string    `json:"package"`
	Function string    `json:"function"`
	Receiver string    `json:"receiver"`
	Position *Position `json:"position"`
}

// Position is a source location inside a Frame.
type Position struct {
	Filename string `json:"filename"`
	Offset   int    `json:"offset"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// CondensedFinding is the per-OSV roll-up stored in the predicate. One entry
// per unique OSV id; reachable=true wins if any finding for that OSV had a
// symbol-level trace.
type CondensedFinding struct {
	OSVID        string `json:"osvId"`
	Summary      string `json:"summary"`
	FixedVersion string `json:"fixedVersion,omitempty"`
	Reachable    bool   `json:"reachable"`
	TraceLength  int    `json:"traceLength"`
	// TopPosition is the source position of the user-code caller closest to
	// the vulnerable symbol — i.e. the last frame in the trace whose module
	// is one of the scan roots. Empty if no such frame exists.
	TopPosition string `json:"topPosition,omitempty"`
}

// SeverityBreakdown rolls up unique-OSV counts by severity bucket. Go vuln DB
// entries currently have no severity data, so the "unknown" bucket will hold
// the bulk of real-world counts until upstream populates CVSS scores.
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// Summary is the predicate roll-up exposed for rego policy gating.
type Summary struct {
	GoVersion        string             `json:"goVersion,omitempty"`
	ScannerVersion   string             `json:"scannerVersion,omitempty"`
	ScanLevel        string             `json:"scanLevel,omitempty"`
	ScanMode         string             `json:"scanMode,omitempty"`
	ScanRoots        []string           `json:"scanRoots,omitempty"`
	TotalOSVs        int                `json:"totalOSVs"`
	TotalFindings    int                `json:"totalFindings"`
	ReachableCount   int                `json:"reachableCount"`
	UnreachableCount int                `json:"unreachableCount"`
	BySeverity       SeverityBreakdown  `json:"bySeverity"`
	Findings         []CondensedFinding `json:"findings"`
}

// Attestor reads a govulncheck JSON product, parses the wire stream into
// typed messages, and exposes both the condensed Summary and the full
// per-message Report for downstream verifiers and policies.
//
// The wire format is a stream of concatenated JSON objects, which is NOT a
// single valid JSON document. Storing it as one json.RawMessage would emit
// invalid JSON in the marshaled predicate (the DSSE payload must itself be
// valid JSON), so the stream is decoded into a []json.RawMessage — one entry
// per Message — preserving each message's bytes verbatim while producing a
// valid top-level JSON array. ReportDigestSet still pins the original file's
// byte content for verifiers that want to fetch the source.
type Attestor struct {
	Summary         Summary              `json:"summary"`
	Report          []json.RawMessage    `json:"report"`
	ReportFile      string               `json:"reportFile"`
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
		log.Debugf("(attestation/govulncheck) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects exposes the scan-root modules and any unique reachable OSV ids as
// in-toto subjects so Archivista can index this attestation by either the
// software it scanned or the specific CVE it surfaced.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	addSubject := func(key, value string) {
		if value == "" {
			return
		}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
		if err != nil {
			log.Debugf("(attestation/govulncheck) failed to hash subject %s: %v", key, err)
			return
		}
		subjects[key] = ds
	}

	for _, root := range a.Summary.ScanRoots {
		addSubject(fmt.Sprintf("go:module:%s", root), root)
	}

	for _, f := range a.Summary.Findings {
		if f.Reachable {
			addSubject(fmt.Sprintf("go:vuln:%s", f.OSVID), f.OSVID)
		}
	}

	return subjects
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		// Soft: no products at all is "nothing to do", not a contract
		// violation (mirrors sbom). See the SoftError at the end of this
		// function for the products-present-but-no-govulncheck-JSON case.
		return attestation.NewSoftError("no products to attest")
	}

	completed, rejected := classifyCandidates(ctx, products)

	// Products are a map: keeping whichever completed stream came first would
	// let iteration order choose which findings are signed, and drop the rest.
	// There is no safe way to pick one, so two are refused.
	if len(completed) > 1 {
		paths := make([]string, 0, len(completed))
		for _, c := range completed {
			paths = append(paths, c.path)
		}
		sort.Strings(paths)
		return fmt.Errorf("found %d completed govulncheck scans (%s); refusing to attest one and drop the others' findings: "+
			"write a single govulncheck -json stream per step", len(paths), strings.Join(paths, ", "))
	}
	if len(completed) == 1 {
		c := completed[0]
		a.Summary = buildSummary(c.messages)
		a.Report = c.raws
		a.ReportFile = c.path
		a.ReportDigestSet = c.digest
		if reason := scannerExitRefusal(ctx); reason != "" {
			path := a.ReportFile
			*a = Attestor{}
			return fmt.Errorf("govulncheck scan did not complete: %s: %s; refusing to attest a scan whose completion "+
				"cannot be established", path, reason)
		}
		// Every candidate was classified, so a failed scan beside a completed
		// one (one module of a multi-module scan) is reported whatever the map
		// order, not silently dropped.
		if len(rejected) > 0 {
			sort.Strings(rejected)
			log.Warnf("(attestation/govulncheck) attesting %s; ignoring govulncheck streams whose scan did not complete: %s",
				a.ReportFile, strings.Join(rejected, "; "))
		}
		return nil
	}

	// Fatal, not soft: the wrapped command DID run govulncheck and its
	// stream shows the scan never completed. A plain error drops this
	// attestor's payload from the signed collection
	// (attestation.EvidenceIsRecordable) and fails the run, so a failed scan
	// can never be stored as a clean one.
	if len(rejected) > 0 {
		sort.Strings(rejected)
		return fmt.Errorf("govulncheck scan did not complete: %s; refusing to attest a failed scan as zero findings "+
			"(check govulncheck's exit status and stderr)", strings.Join(rejected, "; "))
	}

	// Soft, not fatal: a build that simply didn't run `govulncheck -json`
	// (e.g. --workload auto adds this attestor for any go.mod project, even
	// a plain `go build`) has nothing to attest — that's "nothing to do",
	// not a contract violation. Mirrors sbom/go-build so `--workload auto`
	// stays usable without every Go build hard-failing. (closes #240)
	return attestation.NewSoftError("no govulncheck JSON output file found in products — run `govulncheck -json` in the wrapped command to capture results")
}

// completedScan is a candidate product that is a govulncheck stream of a
// completed scan.
type completedScan struct {
	path     string
	messages []Message
	raws     []json.RawMessage
	digest   cryptoutil.DigestSet
}

// classifyCandidates reads every JSON product and sorts the govulncheck streams
// into completed scans and, with a diagnosis each, scans that did not complete.
// Every candidate is classified, so the caller's decision does not depend on
// the map's iteration order.
func classifyCandidates(ctx *attestation.AttestationContext, products map[string]attestation.Product) (completed []completedScan, rejected []string) {
	for path, product := range products {
		if product.MimeType == "" || !mimeMatches(product.MimeType) {
			continue
		}
		messages, raws, reason, ok := readStream(ctx, path, product.Digest)
		if !ok {
			continue
		}
		if reason == "" {
			reason = incompleteScan(messages)
		}
		if reason != "" {
			log.Debugf("(attestation/govulncheck) %s is a govulncheck stream but not a completed scan: %s", path, reason)
			rejected = append(rejected, path+": "+reason)
			continue
		}
		completed = append(completed, completedScan{path: path, messages: messages, raws: raws, digest: product.Digest})
	}
	return completed, rejected
}

// openReport opens a candidate report. It is a variable so a test can serve
// different bytes on each open, the way a file swapped mid-read would.
var openReport = func(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G304: path from attestation context products
}

// readStream reads the product at path and returns its parsed govulncheck
// stream, or ok=false (logged) when the file changed since the product
// attestor hashed it or is not a govulncheck stream. A non-empty cutOff means
// the file IS a govulncheck stream (it opens with a valid config record) but
// does not decode to its end: govulncheck stopped writing inside a record, or
// something else (its stderr, via 2>&1) was written after it.
func readStream(ctx *attestation.AttestationContext, path string, digest cryptoutil.DigestSet) (messages []Message, raws []json.RawMessage, cutOff string, ok bool) {
	fullPath := filepath.Join(ctx.WorkingDir(), path)

	// One open, one read: the digest checked against the product and the
	// stream that is parsed and signed are the same bytes. Hashing the path and
	// reopening it to parse would read two files if it were swapped between.
	f, err := openReport(fullPath)
	if err != nil {
		log.Debugf("(attestation/govulncheck) error opening file %s: %v", fullPath, err)
		return nil, nil, "", false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		log.Debugf("(attestation/govulncheck) %s is not a regular file (%v)", fullPath, err)
		return nil, nil, "", false
	}
	reportBytes, err := io.ReadAll(f)
	if err != nil {
		log.Debugf("(attestation/govulncheck) error reading file %s: %v", fullPath, err)
		return nil, nil, "", false
	}
	newDigestSet, err := cryptoutil.CalculateDigestSetFromBytes(reportBytes, ctx.Hashes())
	if newDigestSet == nil || err != nil {
		log.Debugf("(attestation/govulncheck) error calculating digest set from file %s: %v", fullPath, err)
		return nil, nil, "", false
	}
	if !newDigestSet.Equal(digest) {
		log.Debugf("(attestation/govulncheck) integrity error for %s: product digest does not match", path)
		return nil, nil, "", false
	}

	messages, raws, err = parseStreamWithRaw(reportBytes)
	if err != nil {
		if len(messages) > 0 && validateStream(messages) == nil {
			return messages, nil, fmt.Sprintf("the stream is cut off after %d complete records (%v): govulncheck stopped "+
				"writing mid-scan, or other output was written into the file", len(messages), err), true
		}
		log.Debugf("(attestation/govulncheck) parse failed for %s: %v", path, err)
		return nil, nil, "", false
	}
	if err := validateStream(messages); err != nil {
		log.Debugf("(attestation/govulncheck) validation failed for %s: %v", path, err)
		return nil, nil, "", false
	}
	return messages, raws, "", true
}

// Progress texts golang.org/x/vuln emits (internal/vulncheck/vulncheck.go:20-22),
// verified unchanged from v1.1.1 through v1.8.0. They are matched exactly; if
// upstream rewords them, completed scans are refused loudly, never admitted.
const (
	fetchingVulnsMessage    = "Fetching vulnerabilities from the database..."
	checkingSrcVulnsMessage = "Checking the code against the vulnerabilities..."
	checkingBinVulnsMessage = "Checking the binary against the vulnerabilities..."

	// firstCheckingRecordVersion is the first govulncheck that emits the
	// checking record; firstSBOMVersion is the first that emits an SBOM record.
	firstCheckingRecordVersion = "v1.1.1"
	firstSBOMVersion           = "v1.1.4"
)

// incompleteScan returns why the stream is not a completed govulncheck scan,
// or "" when it is.
//
// The proof of completion is the post-fetch checking record for the scan's
// mode. govulncheck emits its SBOM record BEFORE it fetches the vulnerability
// database (x/vuln internal/vulncheck/source.go:60 then :68, binary.go:59 then
// :67), so SBOM roots do not prove a scan: a database fetch failure leaves roots
// and nothing after them, and summarised it reads as totalFindings 0. The
// checking record follows a successful fetch (source.go:78, binary.go:77) and
// precedes every finding. Roots are not required: a binary with no main module
// has none (binary.go:212), and no govulncheck before v1.1.4 emits an SBOM.
//
// This is necessary, not sufficient: a failure AFTER the checking record (a
// failed call-graph build in symbol mode, a write error, a kill) leaves the
// record in place. scannerExitRefusal covers that half.
func incompleteScan(messages []Message) string {
	cfg := messages[0].Config
	var want []string
	switch cfg.ScanMode {
	case "source":
		want = []string{checkingSrcVulnsMessage}
	case "binary":
		want = []string{checkingBinVulnsMessage}
	case "":
		want = []string{checkingSrcVulnsMessage, checkingBinVulnsMessage}
	default:
		return fmt.Sprintf("scan_mode %q scans no code; only source and binary scans are attested", cfg.ScanMode)
	}

	var sawSBOM, sawFetching bool
	for _, m := range messages {
		if m.SBOM != nil {
			sawSBOM = true
		}
		msg := progressMessage(m.Progress)
		if msg == fetchingVulnsMessage {
			sawFetching = true
		}
		for _, w := range want {
			if msg == w {
				return ""
			}
		}
	}

	version := cfg.ScannerVersion
	if !semver.IsValid(version) || semver.Compare(version, firstCheckingRecordVersion) < 0 {
		return fmt.Sprintf("govulncheck %q emits no completion record (the %q progress record was added in %s), so cilock "+
			"cannot tell a completed scan from a failed one; upgrade govulncheck to %s or later",
			version, want[0], firstCheckingRecordVersion, firstSBOMVersion)
	}
	switch {
	case sawFetching:
		return fmt.Sprintf("the stream stops after %q: the vulnerability database fetch failed, so nothing was checked", fetchingVulnsMessage)
	case !sawSBOM && semver.Compare(version, firstSBOMVersion) >= 0:
		return "the stream has a config record but no SBOM record: govulncheck failed while loading packages, so no module was scanned"
	default:
		return fmt.Sprintf("the stream has no %q record: the scan never reached its check phase", want[0])
	}
}

// scannerExitRefusal returns why the collection does not show that the scanner
// exited 0, or "" when it does.
//
// The -json protocol has no terminal record (x/vuln internal/govulncheck: the
// JSON handler has no Flush, and Progress is "informational only"), and a clean
// source scan can end on the checking record itself (vulncheck/source.go:78-88).
// A scan that fails after that record leaves the same prefix, so the stream
// cannot prove completion; govulncheck's exit status can. In -json mode it is 0
// whatever the scan found (exit 3 for findings is text mode only,
// internal/scan/text.go:84) and non-zero on any error or panic.
//
// govulncheck writes its stream to stdout, so the file is always produced by a
// redirect inside the wrapped command, and the status cilock observes is the
// wrapped command's. It is read even under --ignore-command-exit-code, which
// records the status without failing the run. A traced govulncheck process that
// exited non-zero refuses the scan even when a wrapper (`|| true`) exited 0.
// Without tracing, a wrapper that discards the status cannot be seen through.
func scannerExitRefusal(ctx *attestation.AttestationContext) string {
	observed := false
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor.Name() != commandrun.Name {
			continue
		}
		cr, ok := c.Attestor.(commandrun.CommandRunAttestor)
		if !ok || cr.Data() == nil {
			return "the collection's command-run cannot be read, so govulncheck's exit status is unknown"
		}
		data := cr.Data()
		if data.ExitCode != 0 {
			return fmt.Sprintf("the wrapped command %q exited with status %d", strings.Join(data.Cmd, " "), data.ExitCode)
		}
		if c.Error != nil {
			return fmt.Sprintf("command-run failed (%v), so govulncheck's exit status was never observed", c.Error)
		}
		for _, p := range data.Processes {
			if isGovulncheckProcess(p) && p.ExitCode != 0 {
				return fmt.Sprintf("the traced govulncheck process (pid %d, %q) exited with status %d", p.ProcessID, p.Cmdline, p.ExitCode)
			}
		}
		observed = true
	}
	if !observed {
		return "the collection has no command-run, so govulncheck's exit status is unknown; run govulncheck inside `cilock run`"
	}
	return ""
}

// scannerBinary is the executable name of the scanner, which is not the same
// thing as this attestor's Name even though the two strings agree today.
const scannerBinary = "govulncheck"

func isGovulncheckProcess(p commandrun.ProcessInfo) bool {
	if p.Program != "" {
		return filepath.Base(p.Program) == scannerBinary
	}
	return p.Comm == scannerBinary
}

func progressMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var p struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return ""
	}
	return p.Message
}

// parseStream reads the v1.0.0 wire format. The stream is a concatenation of
// JSON objects (encoding/json's Decoder reads them one at a time). Any decode
// error short-circuits with the offset for caller diagnosis.
func parseStream(reportBytes []byte) ([]Message, error) {
	messages, _, err := parseStreamWithRaw(reportBytes)
	return messages, err
}

// parseStreamWithRaw is parseStream that also returns each message's verbatim
// bytes. Used by the attestor to populate Report; tests can keep using the
// simpler parseStream. On a decode error the messages decoded before it are
// returned with the error (and no raws), so a caller can tell a govulncheck
// stream that was cut off from a file that was never one.
func parseStreamWithRaw(reportBytes []byte) ([]Message, []json.RawMessage, error) {
	// First pass: decode into typed Message values.
	dec := json.NewDecoder(bytes.NewReader(reportBytes))
	var messages []Message
	for {
		var m Message
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return messages, nil, fmt.Errorf("decode message %d: %w", len(messages), err)
		}
		messages = append(messages, m)
	}
	if len(messages) == 0 {
		return nil, nil, fmt.Errorf("empty govulncheck stream")
	}

	// Second pass: capture per-message bytes by streaming RawMessage values.
	// We re-decode from a fresh Reader because Decoder buffers internally
	// and there is no stable offset API across messages.
	rawDec := json.NewDecoder(bytes.NewReader(reportBytes))
	raws := make([]json.RawMessage, 0, len(messages))
	for {
		var rm json.RawMessage
		if err := rawDec.Decode(&rm); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, fmt.Errorf("raw decode message %d: %w", len(raws), err)
		}
		raws = append(raws, rm)
	}
	if len(raws) != len(messages) {
		return nil, nil, fmt.Errorf("raw/typed message count mismatch: %d vs %d", len(raws), len(messages))
	}
	return messages, raws, nil
}

// validateStream confirms the parsed stream actually looks like govulncheck
// output: the first Message MUST be a config with the v1.0.0 protocol marker.
// This is the cheapest reliable filter against arbitrary JSON streams.
func validateStream(messages []Message) error {
	if len(messages) == 0 {
		return fmt.Errorf("no messages")
	}
	first := messages[0]
	if first.Config == nil {
		return fmt.Errorf("first message must be a config record; got something else")
	}
	if first.Config.ScannerName != "" && first.Config.ScannerName != "govulncheck" {
		return fmt.Errorf("scanner_name %q is not govulncheck", first.Config.ScannerName)
	}
	if first.Config.ProtocolVersion != "" && !strings.HasPrefix(first.Config.ProtocolVersion, "v1.") {
		return fmt.Errorf("unsupported protocol_version %q (need v1.x)", first.Config.ProtocolVersion)
	}
	return nil
}

// buildSummary aggregates the message stream into the predicate summary.
//
// Reachability rule per the v1.0.0 protocol: a Finding is reachable iff some
// frame in its trace has a Function set (symbol-level analysis). The Go vuln
// team uses three Finding tiers per (OSV, scope) — module-only, package-only,
// and symbol — and emits the most specific tier observed. A single OSV may
// produce multiple Findings (e.g. one module-level + one package-level for
// an imported-but-not-called vuln) so the summary deduplicates by OSV id and
// records the strongest signal (reachable > imported > present).
//
// The function is intentionally a single pass over the message stream
// followed by a fold over per-OSV state; splitting it across helpers would
// require threading 4+ maps and hurt clarity for the reader.
//
//nolint:gocognit,gocyclo,funlen // single-pass aggregator; see comment above.
func buildSummary(messages []Message) Summary {
	s := Summary{}

	osvs := make(map[string]*OSV)
	type findingState struct {
		osvID        string
		fixedVersion string
		reachable    bool
		maxTrace     int
		topPosition  string
	}
	byOSV := make(map[string]*findingState)

	var roots []string

	for _, m := range messages {
		switch {
		case m.Config != nil:
			s.GoVersion = m.Config.GoVersion
			s.ScannerVersion = m.Config.ScannerVersion
			s.ScanLevel = m.Config.ScanLevel
			s.ScanMode = m.Config.ScanMode
		case m.SBOM != nil:
			if len(m.SBOM.Roots) > 0 {
				roots = append(roots, m.SBOM.Roots...)
			}
			// SBOM.go_version overrides config.go_version when both are
			// present (it reflects the actual toolchain used to build the
			// scanned module, not the toolchain that ran govulncheck).
			if s.GoVersion == "" && m.SBOM.GoVersion != "" {
				s.GoVersion = m.SBOM.GoVersion
			}
		case m.OSV != nil:
			if _, ok := osvs[m.OSV.ID]; !ok {
				osvs[m.OSV.ID] = m.OSV
			}
		case m.Finding != nil:
			s.TotalFindings++
			id := m.Finding.OSV
			st, ok := byOSV[id]
			if !ok {
				st = &findingState{osvID: id}
				byOSV[id] = st
			}
			if m.Finding.FixedVersion != "" {
				st.fixedVersion = m.Finding.FixedVersion
			}
			reachable, traceLen, topPos := classifyFinding(m.Finding, roots)
			if reachable {
				st.reachable = true
			}
			if traceLen > st.maxTrace {
				st.maxTrace = traceLen
			}
			if topPos != "" && st.topPosition == "" {
				st.topPosition = topPos
			}
		}
	}

	s.ScanRoots = dedupStrings(roots)
	s.TotalOSVs = len(osvs)

	// Sort OSV ids so the predicate is deterministic across runs against the
	// same input. Findings ordering matters for byte-stable signatures.
	ids := make([]string, 0, len(byOSV))
	for id := range byOSV {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		st := byOSV[id]
		var osvSummary string
		var sevBucket string
		if osv, ok := osvs[id]; ok {
			osvSummary = osv.Summary
			sevBucket = classifySeverity(osv)
		} else {
			sevBucket = sevUnknown
		}

		// Tally by severity using one count per unique OSV id (NOT per
		// finding — a single OSV is one vulnerability regardless of how
		// many trace tiers it produced).
		switch sevBucket {
		case sevCritical:
			s.BySeverity.Critical++
		case sevHigh:
			s.BySeverity.High++
		case sevMedium:
			s.BySeverity.Medium++
		case sevLow:
			s.BySeverity.Low++
		default:
			s.BySeverity.Unknown++
		}

		if st.reachable {
			s.ReachableCount++
		} else {
			s.UnreachableCount++
		}

		s.Findings = append(s.Findings, CondensedFinding{
			OSVID:        id,
			Summary:      osvSummary,
			FixedVersion: st.fixedVersion,
			Reachable:    st.reachable,
			TraceLength:  st.maxTrace,
			TopPosition:  st.topPosition,
		})
	}

	return s
}

// classifyFinding walks the trace and returns:
//   - reachable: true iff any frame has a Function set (symbol-level)
//   - traceLen:  number of frames in the trace
//   - topPos:    the source position of the closest caller in user code
//     (the last frame whose module appears in scanRoots), or
//     empty if no such frame exists
//
// scanRoots may be empty before the SBOM message is processed; in that case
// the fallback is to use the last frame in the trace as the closest caller.
func classifyFinding(f *Finding, scanRoots []string) (reachable bool, traceLen int, topPos string) {
	if f == nil {
		return false, 0, ""
	}
	traceLen = len(f.Trace)
	for _, frame := range f.Trace {
		if frame.Function != "" {
			reachable = true
			break
		}
	}

	// Walk the trace from the bottom (the user's main) upwards looking for
	// the last frame whose module matches a scan root. govulncheck's trace
	// convention is: trace[0] is the vulnerable symbol; trace[len-1] is the
	// user's entrypoint.
	rootSet := make(map[string]bool, len(scanRoots))
	for _, r := range scanRoots {
		rootSet[r] = true
	}
	for i := len(f.Trace) - 1; i >= 0; i-- {
		frame := f.Trace[i]
		if frame.Position == nil || frame.Position.Filename == "" {
			continue
		}
		if rootSet[frame.Module] || len(rootSet) == 0 {
			topPos = fmt.Sprintf("%s:%d", frame.Position.Filename, frame.Position.Line)
			break
		}
	}
	return reachable, traceLen, topPos
}

// classifySeverity returns the lower-case severity bucket for an OSV. Priority
// order:
//  1. OSV.affected[].database_specific.severity (LOW/MEDIUM/HIGH/CRITICAL)
//  2. OSV.database_specific.severity (some non-Go ecosystems)
//  3. OSV.severity[].score (CVSS v3 base score → bucket)
//  4. "unknown" — the Go vuln DB does not populate any of the above today
func classifySeverity(osv *OSV) string {
	if osv == nil {
		return sevUnknown
	}
	for _, aff := range osv.Affected {
		if aff.DatabaseSpecific != nil && aff.DatabaseSpecific.Severity != "" {
			return normalizeSeverity(aff.DatabaseSpecific.Severity)
		}
	}
	if osv.DatabaseSpecific != nil && osv.DatabaseSpecific.Severity != "" {
		return normalizeSeverity(osv.DatabaseSpecific.Severity)
	}
	for _, sev := range osv.Severity {
		// Map CVSS v3 base scores per FIRST.org bands; ignore vector parsing
		// (score-only mapping is enough for buckets).
		if bucket := cvssToBucket(sev.Score); bucket != "" {
			return bucket
		}
	}
	return sevUnknown
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case sevCritical:
		return sevCritical
	case sevHigh:
		return sevHigh
	case "moderate", sevMedium:
		return sevMedium
	case sevLow:
		return sevLow
	default:
		return sevUnknown
	}
}

// cvssToBucket extracts a base score from a CVSS vector or numeric string and
// maps to FIRST.org severity bands. Best-effort: anything we can't parse
// returns "".
func cvssToBucket(score string) string {
	if score == "" {
		return ""
	}
	// Try to extract a numeric score from a vector like
	// "CVSS:3.1/AV:N/.../9.8" — last `/`-segment that parses as a float.
	num := score
	if idx := strings.LastIndex(score, "/"); idx >= 0 && idx < len(score)-1 {
		num = score[idx+1:]
	}
	var f float64
	if _, err := fmt.Sscanf(num, "%f", &f); err != nil {
		return ""
	}
	switch {
	case f >= 9.0:
		return sevCritical
	case f >= 7.0:
		return sevHigh
	case f >= 4.0:
		return sevMedium
	case f > 0:
		return sevLow
	default:
		return ""
	}
}

// mimeMatches returns true iff the product MIME type's base (the part before
// any ";" parameter) matches one of the accepted base types. The product
// attestor records MIME strings verbatim from gabriel-vasile/mimetype, which
// includes parameters like "; charset=utf-8" — exact-equality matching against
// the bare strings would miss those.
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

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
