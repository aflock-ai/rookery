// Copyright 2025 The Witness Contributors
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

package secretscan

import (
	"os"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
	_ "github.com/invopop/jsonschema" // Used for schema generation
)

const (
	// Name is the attestor name used in the attestation registry
	Name = "secretscan"

	// Type is the attestation type URI that identifies this attestor
	Type = "https://aflock.ai/attestations/secretscan/v0.1"

	// RunType specifies when this attestor runs in the pipeline
	// PostProductRunType ensures it runs after all products are generated
	RunType = attestation.PostProductRunType
)

// Verify the Attestor implements the required interfaces at compile time
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

// Attestor scans products and attestations for secrets and sensitive information.
// It implements the attestation.Attestor interface to integrate with the attestation
// attestation pipeline and provides these security features:
//
//  1. Secret Securing: Detected secrets are replaced with cryptographic hashes
//     using configured digest algorithms to prevent secret exposure
//
//  2. Multi-layer Encoding Detection: Can detect secrets hidden through multiple
//     layers of encoding (base64, hex, URL encoding)
//
//  3. Resource Protection: Limits file size and recursion depth to prevent
//     resource exhaustion attacks
//
//  4. False Positive Reduction: Supports allowlisting through regex patterns,
//     specific strings, and path patterns
//
//  5. Configurable Response: Can be set to fail the attestation process when
//     secrets are detected
//
// The attestor runs after all product attestors to analyze both products and
// attestations, adding scanned products as subjects for verifiability.
// ConsumedReport records one scanner report (a SARIF product) that the
// attestor parsed. The report is still SCANNED like every other product —
// nothing in it is trusted, driver.name included — but a finding inside it
// that is the report's own record of a secret the scanner also found
// elsewhere is dropped as an echo rather than double-counted. SHA256 is the
// digest of the bytes actually parsed, checked against the product digest;
// Driver is what the report claims; Results is how many results it lists;
// Deduplicated is how many echoes were dropped.
type ConsumedReport struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Driver       string `json:"driver"`
	Results      int    `json:"results"`
	Deduplicated int    `json:"deduplicated"`
}

type Attestor struct {
	// Configuration options
	failOnDetection bool        // Whether to fail the attestation when secrets are found
	maxFileSizeMB   int         // Maximum file size to scan in MB
	filePerm        os.FileMode // File permissions for temporary files
	allowList       *AllowList  // Patterns to ignore during scanning
	configPath      string      // Path to custom Gitleaks config file
	maxDecodeLayers int         // Maximum layers of encoding to decode

	// Scope (#9313): which files and attestations the scan reads. See scope.go.
	scope                 string    // "products" (default), "tree", or "diff:<base-ref>"
	scanPriorAttestations bool      // Whether prior attestors' JSON is scanned (default true)
	includeGlob           string    // Only scan paths matching this glob ("" means all)
	excludeGlob           string    // Never scan paths matching this glob ("" means none)
	compiledIncludeGlob   glob.Glob // Compiled in Attest from includeGlob
	compiledExcludeGlob   glob.Glob // Compiled in Attest from excludeGlob
	filesScanned          int       // Files read by the detector this run

	// Results and state
	Findings []Finding                       `json:"findings"` // List of detected secrets
	subjects map[string]cryptoutil.DigestSet // Products and files that were scanned

	// Scope records what the scan covered whenever the operator changed it
	// from the default; it is absent on a default scan so existing
	// predicates keep their shape. See ScanScope.
	Scope *ScanScope `json:"scope,omitempty"`

	// ConsumedReports are the secret-scanner reports this attestor read and
	// deliberately did NOT re-scan: a product whose CONTENT is a SARIF
	// document from a secret scanner (gitleaks, trufflehog, ...). Such a
	// report quotes every secret it found, so scanning it again would
	// report each one a second time. Identified by parsing the product,
	// never by filename, and recorded (path + digest) so the signed
	// evidence states exactly which bytes were excluded and why.
	ConsumedReports []ConsumedReport `json:"consumedReports,omitempty"`
	// reportRules maps a parsed report's product path to the lower-cased
	// rule ids its results declare; used by dedupeReportEchoes.
	reportRules map[string]map[string]bool

	// scanErrors accumulates per-file / per-attestor scan failures that
	// would otherwise be silently swallowed. ANY entry here fails Attest
	// with a plain error, whatever failOnDetection says: a crash in
	// gitleaks, an unreadable product or a file that vanished mid-scan
	// leaves the findings list incomplete, and incomplete findings must
	// never be signed as a clean result. failOnDetection governs findings,
	// not coverage — see the Attest error contract.
	scanErrors []error

	// scannedDigests maps a working-directory-relative path to the digests of
	// every byte-buffer THIS attestor actually read and scanned for it, by any
	// route: as a product, as a working-tree file, or as a committed blob. It
	// is how a later reader of the same path knows it would be rescanning
	// identical bytes, so one blob yields one scan, one finding and one count.
	// Only digests of buffers this attestor read itself go in here — never a
	// digest another attestor recorded — so nothing external can suppress a
	// scan by claiming content was already covered.
	scannedDigests map[string][]cryptoutil.DigestSet

	// productDigestMismatches accumulates products whose bytes at scan time
	// were not the bytes the product attestor recorded. Surfaced in the
	// predicate's scope object rather than swallowed: the subject binds to
	// what was read, and a verifier is told the record it would have
	// correlated against disagreed.
	productDigestMismatches []ProductDigestMismatch

	// ownStreams returns the files this process writes its stdout and stderr
	// to; nil means os.Stdout and os.Stderr. A test substitutes its own. See
	// own_output.go.
	ownStreams func() []*os.File
	// afterRead, when set, runs after a file's bytes are read off disk and
	// before anything is decided about them. A test uses it to change the
	// path under the scan; nil in production.
	afterRead func(absPath string)
	// ownOutputSkips are the files skipped as cilock's own untracked output
	// this run, logged once at the end of Attest.
	ownOutputSkips []ownOutputSkip
	// tracked is what git has in the index or HEAD, relative to the working
	// directory, loaded on first need. trackedErr, when set, means nothing
	// can be proven untracked, so nothing is skipped.
	tracked       *trackedIndex
	trackedErr    error
	trackedLoaded bool

	// Context for the attestation
	ctx *attestation.AttestationContext // Reference to attestation context
}

// Finding represents a detected secret with the sensitive data securely replaced
// by cryptographic digests. It provides detailed information about where and how
// the secret was detected while ensuring the actual secret value is never stored.
type Finding struct {
	// RuleID identifies which detection rule triggered the finding
	RuleID string `json:"ruleId"`

	// Description provides a human-readable explanation of the finding
	Description string `json:"description"`

	// Location indicates where the secret was found in the form:
	// "attestation:attestor-name", "product:/path/to/file", or
	// "file:path/to/file" for a working-tree file read under a diff or tree
	// scope that is not a product
	Location string `json:"location"`

	// Line indicates the line number where the secret was found
	Line int `json:"startLine"`

	// Secret contains multiple cryptographic hashes of the secret
	// This allows for verification without exposing the actual secret value
	Secret cryptoutil.DigestSet `json:"secret,omitempty"`

	// Match contains a redacted snippet showing context around the secret
	// The actual secret is truncated to prevent exposure
	Match string `json:"match,omitempty"`

	// Entropy is the information density score (higher values indicate
	// more random/high-entropy content likely to be secrets)
	Entropy float32 `json:"entropy,omitempty"`

	// EncodingPath tracks the sequence of encodings that were applied to
	// hide the secret, listed from outermost to innermost layer
	EncodingPath []string `json:"encodingPath,omitempty"`

	// LocationApproximate indicates if the line number is approximate
	// This is true for secrets found in decoded content since the
	// original line number cannot be precisely determined
	LocationApproximate bool `json:"locationApproximate,omitempty"`
}

// AllowList defines patterns that should be ignored during secret scanning.
// It helps reduce false positives by excluding known safe patterns.
type AllowList struct {
	// Description explains the purpose of this allowlist
	Description string `json:"description,omitempty"`

	// Paths are file path patterns to ignore (regex format)
	Paths []string `json:"paths,omitempty"`

	// Regexes are content patterns to ignore (regex format)
	Regexes []string `json:"regexes,omitempty"`

	// StopWords are specific strings to ignore (exact match)
	StopWords []string `json:"stopWords,omitempty"`
}

// matchInfo holds information about a pattern match in content
type matchInfo struct {
	lineNumber   int    // Line number where the match occurred
	matchContext string // Context surrounding the match
}

// encodingScanner defines the components for handling one encoding type
type encodingScanner struct {
	Name    string                                 // Name of the encoding (base64, hex, url)
	Finder  func(content string) []string          // Function to find encoded strings
	Decoder func(candidate string) ([]byte, error) // Function to decode strings
}
