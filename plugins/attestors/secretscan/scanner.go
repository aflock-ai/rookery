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

// Package secretscan provides functionality for detecting secrets and sensitive information.
// This file (scanner.go) contains core scanning functionality.
package secretscan

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// scanBytes is the core scanning function that handles both direct and recursive scanning
// of content for secrets. It can decode encoded content and recursively search
// through multiple layers of encoding. repoPath is the file's path relative to
// the working directory, or "" for content that is not a repository file
// (a prior attestation, command output), which no gitleaks path allowlist
// may exempt.
func (a *Attestor) scanBytes(contentBytes []byte, sourceIdentifier, repoPath string, detector *detect.Detector, processedInThisScan map[string]struct{}, currentDepth int) ([]Finding, error) { //nolint:gocognit,gocyclo,funlen // multi-layer encoding detection requires complex control flow
	// Safety check to prevent infinite recursion
	if currentDepth > maxScanRecursionDepth {
		return nil, nil
	}

	// Convert bytes to string for processing
	contentStr := string(contentBytes)

	// Initialize findings slice
	findings := []Finding{}

	// Check if content is allowlisted
	if a.configPath == "" && a.allowList != nil {
		if isContentAllowListed(contentStr, a.allowList) {
			return findings, nil
		}
	}

	// Scan current layer with Gitleaks. gitleaks decides [allowlist].paths,
	// the paths of an [[allowlists]] entry (under either condition) and a
	// rule's path from the fragment's FilePath; DetectBytes leaves it empty,
	// so every path exception in an operator's config parsed and exempted
	// nothing. The path is given only for an operator's config: gitleaks'
	// built-in one skips lockfiles, vendored trees and node_modules by path,
	// and the default scan must not narrow without anyone asking it to. A
	// config that extends the built-in one does not inherit those skips
	// either (dropInheritedPathExceptions).
	fragment := detect.Fragment{Raw: contentStr}
	if a.configPath != "" {
		fragment.FilePath = repoPath
	}
	gitleaksFindings := detector.Detect(fragment)
	log.Debugf("(attestation/secretscan) gitleaks found %d raw findings at depth %d for: %s",
		len(gitleaksFindings), currentDepth, sourceIdentifier)

	// Process findings with updated helper that handles locationApproximate
	isApproximate := currentDepth > 0 // Location is approximate if we're in a decoded layer
	processedGLFindings := a.processGitleaksFindings(gitleaksFindings, sourceIdentifier, isApproximate, processedInThisScan)
	findings = append(findings, processedGLFindings...)

	// Add Env Var check only at depth 0 (avoid it for decoded content)
	if currentDepth == 0 {
		sensitiveEnvVars := a.getSensitiveEnvVarsList()
		envFindings := a.ScanForEnvVarValues(contentStr, sourceIdentifier, sensitiveEnvVars)

		// Filter env findings against already processed findings
		for _, finding := range envFindings {
			findingKey := fmt.Sprintf("%s:%d:%s", sourceIdentifier, finding.Line, finding.Secret)
			if _, exists := processedInThisScan[findingKey]; exists {
				continue
			}
			processedInThisScan[findingKey] = struct{}{}
			findings = append(findings, finding)
		}
	}

	// Recursive scanning through encoding layers if configured
	if currentDepth < a.maxDecodeLayers { //nolint:nestif // recursive decoding requires nested layer checks
		// Apply each encoding scanner
		for _, scanner := range defaultEncodingScanners {
			// Find potential encoded strings
			candidates := scanner.Finder(contentStr)

			for _, candidate := range candidates {
				// Decode each candidate
				decodedBytes, err := scanner.Decoder(candidate)

				// Special handling for potential double-encoded values (like output from echo $TOKEN | base64 | base64)
				// For base64 encoded content especially, we want to be more permissive with length checks
				if err == nil && (len(decodedBytes) >= minSensitiveValueLength ||
					(currentDepth > 0 && len(decodedBytes) > 0) ||
					strings.HasSuffix(candidate, "=")) {
					// Trim spaces to handle newlines that might be introduced by echo commands
					decodedBytes = []byte(strings.TrimSpace(string(decodedBytes)))
					decodedStr := string(decodedBytes)

					// Check decoded content for sensitive env var values
					// This can catch encoded env values even without their variable names
					sensitiveEnvVars := a.getSensitiveEnvVarsList()
					envFindings := a.checkDecodedContentForSensitiveValues(
						decodedStr,
						sourceIdentifier,
						scanner.Name,
						sensitiveEnvVars,
						processedInThisScan,
					)

					if len(envFindings) > 0 {
						log.Debugf("(attestation/secretscan) found %d sensitive env values in decoded content at depth %d for: %s",
							len(envFindings), currentDepth, sourceIdentifier)
						findings = append(findings, envFindings...)
					}

					// Recursive call with incremented depth
					recursiveFindings, recErr := a.scanBytes(
						decodedBytes,
						sourceIdentifier,
						repoPath,
						detector,
						processedInThisScan,
						currentDepth+1,
					)

					if recErr != nil {
						log.Debugf("(attestation/secretscan) error in recursive scan: %s", recErr)
						continue
					}

					// Update encoding path for findings
					for i := range recursiveFindings {
						// For recursive findings, we need to add the current encoding type to the path
						// The correct order is from outermost to innermost layer (the reverse of decoding order)
						// So we add the current encoder name to the beginning of the path, not the end
						// This ensures the encodingPath array matches the actual encoding order
						if len(recursiveFindings[i].EncodingPath) > 0 {
							// For existing paths, prepend the current encoding to maintain proper order
							encodingPath := append([]string{scanner.Name}, recursiveFindings[i].EncodingPath...)
							recursiveFindings[i].EncodingPath = encodingPath
						} else {
							// If there's no existing path, just set it to the current encoding
							recursiveFindings[i].EncodingPath = []string{scanner.Name}
						}
						recursiveFindings[i].LocationApproximate = true
					}

					// Add recursive findings to results
					findings = append(findings, recursiveFindings...)
				}
			}
		}
	}

	if len(findings) > 0 {
		log.Debugf("(attestation/secretscan) found %d total findings at depth %d for: %s",
			len(findings), currentDepth, sourceIdentifier)
	}

	return findings, nil
}

// ScanFile scans a single file with Gitleaks detector and filters findings based on allowlist.
// It also checks for hardcoded sensitive environment variable names.
// This method is exported for testing purposes.
func (a *Attestor) ScanFile(filePath string, detector *detect.Detector) ([]Finding, error) {
	// Verify detector is provided
	if detector == nil {
		return nil, fmt.Errorf("nil detector provided")
	}

	// Validate and check file size
	if exceeds, err := a.exceedsMaxFileSize(filePath); err != nil || exceeds {
		return nil, err // If error or exceeds size limit, return immediately
	}

	// Read file content
	content, err := a.readFileContent(filePath)
	if err != nil {
		return nil, err
	}

	// Create a map to track processed findings within this scan tree
	// This helps avoid duplicate findings in deep scanning
	processedInThisScan := make(map[string]struct{})

	// Use scanBytes as the core implementation for scanning content
	return a.scanBytes(content, filePath, filePath, detector, processedInThisScan, 0)
}

// exceedsMaxFileSize checks if a file exceeds the configured size limit
func (a *Attestor) exceedsMaxFileSize(filePath string) (bool, error) {
	// Check file size to avoid loading unnecessarily large files
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false, fmt.Errorf("error getting file info: %w", err)
	}

	// Apply size limit if configured (maxFileSizeMB of 0 means no limit)
	maxSizeBytes := int64(a.maxFileSizeMB) * 1024 * 1024
	if a.maxFileSizeMB > 0 && fileInfo.Size() > maxSizeBytes {
		log.Debugf("(attestation/secretscan) skipping large file: %s (size: %d bytes, max: %d bytes)",
			filePath, fileInfo.Size(), maxSizeBytes)
		return true, nil
	}

	return false, nil
}

// readFileContent reads file content with size limiting
func (a *Attestor) readFileContent(filePath string) ([]byte, error) {
	file, err := os.Open(filePath) //nolint:gosec // G304: file path from attestation context products
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Debugf("(attestation/secretscan) error closing file: %s", err)
		}
	}()

	// Apply the size limit for safety (0 means no limit)
	var reader io.Reader
	if a.maxFileSizeMB > 0 {
		maxSizeBytes := int64(a.maxFileSizeMB) * 1024 * 1024
		reader = io.LimitReader(file, maxSizeBytes)
	} else {
		reader = file
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return content, nil
}

// scanAttestations examines all completed attestors for potential secrets.
// Each attestor is converted to JSON and scanned with the detector.
// Per-attestor scan errors are recorded on the Attestor so that Attest()
// can fail closed when failOnDetection is set — without that, a crash
// in the detector on one attestor would silently return zero findings
// and bypass the protective guard.
func (a *Attestor) scanAttestations(ctx *attestation.AttestationContext, _ string, detector *detect.Detector) error { //nolint:unparam // error return kept for API consistency
	// Get all completed attestors
	completedAttestors := ctx.CompletedAttestors()
	log.Debugf("(attestation/secretscan) scanning %d completed attestors", len(completedAttestors))

	// Process each attestor
	for _, completed := range completedAttestors {
		// Skip attestors that should not be scanned
		if a.shouldSkipAttestor(completed.Attestor) {
			continue
		}

		// Scan the attestor for secrets
		findings, err := a.scanSingleAttestor(completed.Attestor, "", detector)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning attestor %s: %s", completed.Attestor.Name(), err)
			a.scanErrors = append(a.scanErrors, fmt.Errorf("scanning attestor %s: %w", completed.Attestor.Name(), err))
			continue
		}

		// Set location for all findings to identify which attestor they came from
		a.setAttestationLocation(findings, completed.Attestor.Name())

		// Add the findings to our collection
		a.Findings = append(a.Findings, findings...)
	}

	return nil
}

// shouldSkipAttestor determines if an attestor should be skipped during scanning
func (a *Attestor) shouldSkipAttestor(attestor attestation.Attestor) bool {
	// Skip scanning ourselves to avoid recursion
	if attestor.Name() == Name {
		return true
	}

	// Skip other post-product attestors to avoid race conditions
	if attestor.RunType() == RunType {
		log.Debugf("(attestation/secretscan) skipping other post-product attestor: %s", attestor.Name())
		return true
	}

	return false
}

// scanSingleAttestor converts an attestor to JSON and scans it for secrets
func (a *Attestor) scanSingleAttestor(attestor attestation.Attestor, _ string, detector *detect.Detector) ([]Finding, error) {
	// Check for commandrun attestor specifically to access stdout/stderr
	if cmdRunAttestor, ok := attestor.(commandrun.CommandRunAttestor); ok {
		return a.scanCommandRunAttestor(cmdRunAttestor, detector)
	}

	// For other attestors, convert to JSON for scanning
	attestorJSON, err := json.MarshalIndent(attestor, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling attestor %s: %w", attestor.Name(), err)
	}

	// Create a unique identifier for the source
	sourceIdentifier := fmt.Sprintf("attestation_%s.json", attestor.Name())

	// Create a map to track processed findings within this scan tree
	processedInThisScan := make(map[string]struct{})

	// Scan the JSON bytes directly without creating a temporary file
	return a.scanBytes(attestorJSON, sourceIdentifier, "", detector, processedInThisScan, 0)
}

// scanCommandRunAttestor specifically handles scanning the stdout/stderr of
// command run attestors. It returns whatever it managed to scan and records
// every failure in scanErrors rather than returning early, so a crash on
// stdout does not cost the findings from stderr — and, because any scanError
// is fatal in Attest, cannot be mistaken for output that was read and was
// clean.
func (a *Attestor) scanCommandRunAttestor(attestor commandrun.CommandRunAttestor, detector *detect.Detector) ([]Finding, error) {
	// Access the CommandRun data
	cmdData := attestor.Data()
	if cmdData == nil {
		return nil, fmt.Errorf("nil CommandRun data")
	}

	cmdRun := cmdData

	findings := []Finding{}

	// Scan stdout if present
	if cmdRun.Stdout != "" {
		processedInThisScan := make(map[string]struct{})
		stdoutID := "attestation:commandrun:stdout"
		stdoutFindings, err := a.scanBytes([]byte(cmdRun.Stdout), stdoutID, "", detector, processedInThisScan, 0)
		if err != nil {
			// Recorded, not just logged. Command stdout is where secrets leak
			// most often; dropping the error here returned (findings, nil) and
			// the caller signed an empty result for output nobody scanned.
			log.Debugf("(attestation/secretscan) error scanning command stdout: %s", err)
			a.scanErrors = append(a.scanErrors, fmt.Errorf("scanning command stdout: %w", err))
		} else {
			findings = append(findings, stdoutFindings...)
		}
	}

	// Scan stderr if present
	if cmdRun.Stderr != "" {
		processedInThisScan := make(map[string]struct{})
		stderrID := "attestation:commandrun:stderr"
		stderrFindings, err := a.scanBytes([]byte(cmdRun.Stderr), stderrID, "", detector, processedInThisScan, 0)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning command stderr: %s", err)
			a.scanErrors = append(a.scanErrors, fmt.Errorf("scanning command stderr: %w", err))
		} else {
			findings = append(findings, stderrFindings...)
		}
	}

	// Also scan the JSON representation of the command run data
	cmdRunJSON, err := json.MarshalIndent(cmdRun, "", "  ")
	if err != nil {
		log.Debugf("(attestation/secretscan) error marshaling command run data: %s", err)
		a.scanErrors = append(a.scanErrors, fmt.Errorf("marshaling command run data: %w", err))
	} else {
		processedInThisScan := make(map[string]struct{})
		cmdRunID := "attestation:commandrun:json"
		cmdRunFindings, err := a.scanBytes(cmdRunJSON, cmdRunID, "", detector, processedInThisScan, 0)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning command run JSON: %s", err)
			a.scanErrors = append(a.scanErrors, fmt.Errorf("scanning command run JSON: %w", err))
		} else {
			findings = append(findings, cmdRunFindings...)
		}
	}

	return findings, nil
}

// scanProducts examines all products for potential secrets.
// Binary files and directories are automatically skipped.
func (a *Attestor) scanProducts(ctx *attestation.AttestationContext, _ string, detector *detect.Detector) error { //nolint:unparam // error return kept for API consistency
	products := ctx.Products()
	if len(products) == 0 {
		log.Debugf("(attestation/secretscan) no products found to scan")
		return nil
	}

	log.Debugf("(attestation/secretscan) scanning %d products", len(products))

	wd := workingDirSpellings(ctx.WorkingDir())
	for path, product := range products {
		// Honour the operator's path globs. A product left out here is not
		// a subject either: the evidence names only what was read. The globs
		// are relative to the working directory and the product key may be
		// absolute, so both are reduced to one spelling first — see
		// productScopePath for what an unnormalized key cost.
		scopePath := productScopePath(path, wd)
		if !a.pathInScope(scopePath) {
			log.Debugf("(attestation/secretscan) skipping product outside scope: %s", path)
			continue
		}

		// Get absolute path for scanning while preserving original path for records
		absPath := a.getAbsolutePath(path, ctx.WorkingDir())

		// Read once; the same bytes are classified (digested + parsed) and
		// scanned, so what the dedup reasons about is exactly what was
		// scanned. EVERY product is scanned regardless of what it claims
		// to be — a scanner report is only additionally eligible for echo
		// dedup (see dedupeReportEchoes).
		read, scanned, err := a.scanProductBytes(ctx, path, scopePath, absPath, product, detector)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning file %s: %s", path, err)
			a.scanErrors = append(a.scanErrors, fmt.Errorf("scanning product %s: %w", path, err))
			continue
		}
		if !scanned {
			// Nothing was read, so nothing is claimed: no subject, no count.
			continue
		}

		// Set location for all findings to identify which product they came from
		a.setProductLocation(read.Findings, path)

		// Add findings to collection (if any)
		if len(read.Findings) > 0 { // Keep the log statement conditional
			log.Debugf("(attestation/secretscan) found %d findings in product: %s", len(read.Findings), path)
		}
		a.Findings = append(a.Findings, read.Findings...) // Append regardless (appending empty slice is ok)

		// The subject is the digest of the bytes THIS attestor read, not the
		// digest the product attestor recorded. A signed claim binds to what
		// was observed; publishing someone else's digest beside our findings
		// meant that when the file changed between the product snapshot and
		// this read, the subject named bytes nobody scanned.
		//
		// When the two agree — the common case — this is byte-identical to
		// what was always published, so correlation with the product attestor
		// is unchanged. When they do not, the disagreement is stated in the
		// predicate rather than resolved silently in either direction.
		a.subjects[fmt.Sprintf("product:%s", path)] = read.Digests
		if !productDigestAgrees(product.Digest, read.Digests) {
			log.Warnf("(attestation/secretscan) %s is not the bytes the product attestor recorded; publishing the scanned digest and recording the disagreement", path)
			a.productDigestMismatches = append(a.productDigestMismatches, ProductDigestMismatch{
				Path:     path,
				Recorded: product.Digest,
				Scanned:  read.Digests,
			})
		}
		a.filesScanned++
	}

	return nil
}

// scanScopedFiles scans the working-tree files a diff or tree scope adds on
// top of the products, returning the resolved base commit for a diff scope.
// Listing the files can fail (not a repository, unknown base ref) and that
// failure is returned: a diff scan that silently read nothing would satisfy
// a no-secrets policy with a scan of nothing.
func (a *Attestor) scanScopedFiles(ctx *attestation.AttestationContext, spec scopeSpec, detector *detect.Detector) (string, error) {
	workingDir := ctx.WorkingDir()
	if workingDir == "" {
		workingDir = "."
	}
	switch spec.Files {
	case ScopeDiff:
		// Before any listing: if the repository's view of its own history is
		// altered, produce no evidence rather than narrower evidence.
		if err := refuseAlteredHistoryView(ctx, workingDir); err != nil {
			return "", err
		}
		diff, err := diffFiles(ctx, workingDir, spec.BaseRef)
		if err != nil {
			return "", err
		}
		log.Debugf("(attestation/secretscan) diff scope: %d files and %d committed blobs changed since %s (%s)",
			len(diff.Files), len(diff.Blobs), spec.BaseRef, diff.Base)
		a.scanFiles(ctx, diff.Files, detector)
		a.scanCommittedBlobs(ctx, workingDir, diff.Blobs, detector)
		return diff.Base, nil
	case ScopeTree:
		files, err := treeFiles(workingDir)
		if err != nil {
			return "", err
		}
		log.Debugf("(attestation/secretscan) tree scope: %d files under %s", len(files), workingDir)
		a.scanFiles(ctx, files, detector)
	case ScopeProducts:
		// Products only; already scanned.
	}
	return "", nil
}

// scanProductBytes reads a product once, records it as a parsed report when
// classifyReport says so, and scans the same bytes for secrets.
func (a *Attestor) scanProductBytes(ctx *attestation.AttestationContext, path, scopePath, absPath string, product attestation.Product, detector *detect.Detector) (productScan, bool, error) {
	if detector == nil {
		return productScan{}, false, fmt.Errorf("nil detector provided")
	}
	// A directory has no bytes of its own, and reading one is an error that
	// would fail the whole scan. Decided on this attestor's own stat, not on
	// the mime type another attestor recorded. Stat follows symlinks on
	// purpose: a symlinked product still yields its target's bytes, exactly
	// as it did before.
	info, err := os.Stat(absPath)
	if err != nil {
		return productScan{}, false, err
	}
	if info.IsDir() {
		log.Debugf("(attestation/secretscan) skipping directory product: %s", path)
		return productScan{}, false, nil
	}
	if exceeds, err := a.exceedsMaxFileSize(absPath); err != nil || exceeds {
		return productScan{}, false, err
	}
	content, err := a.readFileContent(absPath)
	if err != nil {
		return productScan{}, false, err
	}
	// Binary-ness is decided from the BYTES THAT WERE READ. product.MimeType
	// is another attestor's claim about this file, and trusting it cut both
	// ways: a text file holding a secret could be labelled binary and never
	// read at all, and a binary could be labelled text and recorded as a
	// scanned subject it had no business being.
	if isBinaryFile(http.DetectContentType(content)) {
		log.Debugf("(attestation/secretscan) skipping binary product: %s", path)
		return productScan{}, false, nil
	}
	if rep, rules, ok := classifyReport(path, content, product); ok {
		log.Debugf("(attestation/secretscan) %s parses as a %q report (%d results, sha256 %s); scanning it and deduplicating echoes", path, rep.Driver, rep.Results, rep.SHA256)
		if a.reportRules == nil {
			a.reportRules = map[string]map[string]bool{}
		}
		a.reportRules[path] = rules
		a.ConsumedReports = append(a.ConsumedReports, rep)
	}
	findings, err := a.scanBytes(content, absPath, scopePath, detector, make(map[string]struct{}), 0)
	if err != nil {
		return productScan{}, false, err
	}
	// The digest of the bytes JUST SCANNED. It becomes the subject, and it is
	// what a later reader of the same path — the file on disk, the committed
	// blob, the staged blob — compares against to tell it would be rescanning
	// identical bytes. Computed only after a successful scan: a failed read
	// covered nothing.
	digests, err := cryptoutil.CalculateDigestSetFromBytes(content, ctx.Hashes())
	if err != nil {
		return productScan{}, false, fmt.Errorf("digesting: %w", err)
	}
	a.recordScannedDigests(scopePath, digests)
	return productScan{Findings: findings, Digests: digests}, true, nil
}

// productScan is what reading one product produced: its findings, and the
// digest of the exact bytes they came from.
type productScan struct {
	Findings []Finding
	Digests  cryptoutil.DigestSet
}

// productDigestAgrees reports whether the product attestor's record and the
// bytes this attestor read POSITIVELY agree. It compares only algorithms both
// sides computed, because the two need not use the same set — the product
// attestor has a fallback path that records SHA-256 alone — and it requires at
// least one such algorithm: an overlap of nothing is not agreement, it is an
// inability to check, which is exactly what must not pass silently.
//
// A product recorded with no digest at all is not a disagreement. Nothing was
// claimed, so there is nothing to disagree with; the subject simply gains the
// digest of what was read, where it used to publish nothing.
func productDigestAgrees(recorded, scanned cryptoutil.DigestSet) bool {
	if len(recorded) == 0 {
		return true
	}
	if len(scanned) == 0 {
		// No hash algorithms were configured, so THIS attestor computed
		// nothing to compare with — and neither did any other attestor in the
		// run, whose subjects are equally empty. Asserting a disagreement here
		// would manufacture one for every product in a degenerate config.
		return true
	}
	shared := 0
	for value, hex := range recorded {
		ours, ok := scanned[value]
		if !ok {
			continue
		}
		shared++
		if ours != hex {
			return false
		}
	}
	return shared > 0
}

// classifyReport decides whether the bytes just read for a product are a
// scanner report (a SARIF document) whose own findings may echo secrets the
// scanner finds elsewhere. Nothing in the document is trusted — driver.name
// is attacker-controlled, so it is recorded, never acted on — and the
// product is scanned regardless. What classification buys is dedup only
// (see dedupeReportEchoes).
//
// The digest is of the bytes PARSED, computed here at read time, and must
// equal the product attestor's recorded SHA-256. A mismatch means the file
// changed between the product snapshot and this read; a missing digest means
// nothing pins what was parsed. Either way the product is treated as an
// ordinary file: scanned, never deduplicated.
func classifyReport(path string, content []byte, product attestation.Product) (ConsumedReport, map[string]bool, bool) {
	if product.Digest == nil {
		return ConsumedReport{}, nil, false
	}
	recorded, ok := product.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	if !ok || recorded == "" {
		return ConsumedReport{}, nil, false
	}
	sum := sha256.Sum256(content)
	parsed := hex.EncodeToString(sum[:])
	if parsed != recorded {
		log.Warnf("(attestation/secretscan) %s changed between product snapshot (%s) and scan (%s); treating as an ordinary product", path, recorded, parsed)
		return ConsumedReport{}, nil, false
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(content, &doc); err != nil || doc.Version == "" || len(doc.Runs) == 0 {
		return ConsumedReport{}, nil, false
	}
	rep := ConsumedReport{Path: path, SHA256: parsed}
	rules := map[string]bool{}
	for _, run := range doc.Runs {
		if rep.Driver == "" {
			rep.Driver = strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name))
		}
		rep.Results += len(run.Results)
		for _, r := range run.Results {
			if id := strings.ToLower(strings.TrimSpace(r.RuleID)); id != "" {
				rules[id] = true
			}
		}
	}
	return rep, rules, true
}

// dedupeReportEchoes drops, from each parsed report product, the findings
// that are that report's own record of a secret the scanner ALSO found in
// some other location, so the report neither hides a secret nor
// double-counts one. A finding is an echo only when all three hold: it sits
// inside a parsed report, the report declares a result with the same rule
// id, and the same (rule id, secret sha256) was found by this scan outside
// that report. A secret that exists only inside a "report" — however the
// report labels itself — is a real finding and stays; --fail-on-detection
// fires on it like any other.
func (a *Attestor) dedupeReportEchoes() {
	if len(a.reportRules) == 0 {
		return
	}
	key := func(f Finding) string {
		return f.RuleID + "|" + f.Secret[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	}
	reportLoc := func(f Finding) (string, bool) {
		p := strings.TrimPrefix(f.Location, "product:")
		if p == f.Location {
			return "", false
		}
		_, ok := a.reportRules[p]
		return p, ok
	}
	elsewhere := map[string]bool{}
	for _, f := range a.Findings {
		if _, inReport := reportLoc(f); !inReport {
			elsewhere[key(f)] = true
		}
	}
	dropped := map[string]int{}
	kept := a.Findings[:0]
	for _, f := range a.Findings {
		if p, inReport := reportLoc(f); inReport && a.reportRules[p][f.RuleID] && elsewhere[key(f)] {
			dropped[p]++
			continue
		}
		kept = append(kept, f)
	}
	a.Findings = kept
	for i := range a.ConsumedReports {
		a.ConsumedReports[i].Deduplicated = dropped[a.ConsumedReports[i].Path]
	}
}

// getAbsolutePath converts a path to absolute if it's relative and we have a working directory
func (a *Attestor) getAbsolutePath(path, workingDir string) string {
	if !filepath.IsAbs(path) && workingDir != "" {
		absPath := filepath.Join(workingDir, path)
		log.Debugf("(attestation/secretscan) converting relative path %s to absolute path %s", path, absPath)
		return absPath
	}
	return path
}

// Attest scans attestations and products for potential secrets.
//
// ERROR CONTRACT — secretscan OBSERVES AND RECORDS; it does not decide.
// The gating decision belongs to policy (witness policy / rego), which reads
// this attestation afterwards. So the two error classes mean different things
// and are deliberately typed differently:
//
//	plain error              "I COULD NOT OBSERVE" — temp dir, detector init,
//	                         or any accumulated per-file/per-attestor scan
//	                         failure. The findings list is incomplete by
//	                         definition, so nothing here may be trusted. The
//	                         workflow drops the attestor from the collection.
//	                         This is returned REGARDLESS of fail-on-detection:
//	                         see the two axes spelled out at the check itself.
//
//	attestation.DetectionError
//	                         "I OBSERVED, and what I found matches the
//	                         condition the operator configured me to reject."
//	                         The scan SUCCEEDED. The findings are real evidence
//	                         and the workflow KEEPS them in the signed
//	                         collection; the error only drives the exit code.
//
// A finding must never be reported as a plain error. The workflow filters the
// collection on `completed.Error != nil`, so an attestor that plain-errors on
// a finding DELETES ITS OWN EVIDENCE — a findings-positive scan and a scan
// that never ran become indistinguishable downstream, and the guard fails OPEN
// in the direction of silence. That was the bug; DetectionError is the fix.
//
// Note the ordering below: scan errors are checked BEFORE findings. If any
// scan errored the findings list is incomplete, so the stricter "could not
// observe" classification wins — otherwise an attacker who could induce a
// gitleaks crash would downgrade a blind scan into a trustworthy-looking
// verdict.
//
// Without failOnDetection (the default) FINDINGS are not an error at all:
// they are simply recorded, and policy gates at verify time. Scan ERRORS are
// a different axis and are always fatal; a scan that could not read what it
// was asked to read has no clean result to record.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	// Store the attestation context for later use
	a.ctx = ctx

	// Create a temporary directory for scanning
	tempDir, err := os.MkdirTemp("", "secretscan")
	if err != nil {
		return fmt.Errorf("error creating temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Debugf("(attestation/secretscan) error removing temp dir: %s", err)
		}
	}()

	// Initialize Gitleaks detector
	detector, err := a.initGitleaksDetector()
	if err != nil {
		return fmt.Errorf("error initializing gitleaks detector: %w", err)
	}

	// Resolve what this scan covers before reading anything. A bad scope or
	// glob is a failure to observe, not a narrower scan.
	spec, err := a.compileScope()
	if err != nil {
		return err
	}
	a.filesScanned = 0
	a.scannedDigests = nil
	a.productDigestMismatches = nil
	a.Scope = nil

	// Scan attestations first (non-critical). Skipped when the operator
	// confined the scan to files: the material inventory and command-run
	// output are the bulk of what lives here.
	if a.scanPriorAttestations {
		if err := a.scanAttestations(ctx, tempDir, detector); err != nil {
			log.Debugf("(attestation/secretscan) error scanning attestations: %s", err)
		}
	}

	// Scan products (primary objective)
	if err := a.scanProducts(ctx, tempDir, detector); err != nil {
		log.Debugf("(attestation/secretscan) error scanning products: %s", err)
	}

	// Scan working-tree files beyond the products when asked to.
	baseCommit, err := a.scanScopedFiles(ctx, spec, detector)
	if err != nil {
		return err
	}

	// Say what was covered whenever it is not the default, so the evidence
	// never claims more than it looked at.
	// Products are iterated from a map, so the disagreements come out in
	// whatever order Go felt like. This goes into a SIGNED predicate, which
	// must not differ run to run over the same inputs.
	sort.Slice(a.productDigestMismatches, func(i, j int) bool {
		return a.productDigestMismatches[i].Path < a.productDigestMismatches[j].Path
	})

	// A disagreement has to be reportable even on a wholly default scan, or the
	// one configuration where nobody set an option is the one where the
	// evidence of a changed file goes missing.
	if !a.scopeIsDefault() || len(a.productDigestMismatches) > 0 {
		a.Scope = &ScanScope{
			Files:        spec.Files,
			BaseRef:      spec.BaseRef,
			BaseCommit:   baseCommit,
			Attestations: a.scanPriorAttestations,
			IncludeGlob:  a.includeGlob,
			ExcludeGlob:  a.excludeGlob,

			ProductDigestMismatches: a.productDigestMismatches,

			FilesScanned: a.filesScanned,
		}
	}

	// After everything is scanned: a scanner report's own record of a
	// secret found elsewhere is an echo, not a second leak.
	a.dedupeReportEchoes()

	// COULD NOT OBSERVE. This is checked BEFORE findings and WITHOUT regard to
	// failOnDetection, because the two are DIFFERENT AXES and collapsing them
	// is what made "could not read" indistinguishable from "read and clean":
	//
	//   failOnDetection decides whether a FINDING fails the run. It is the
	//   operator's policy choice about verdicts, and it is legitimately off by
	//   default — policy gates at verify time instead.
	//
	//   A scan error fails the run either way, because it is not a verdict at
	//   all. It says the findings list below is INCOMPLETE, so nothing
	//   downstream may read the absence of a finding as evidence of absence.
	//   An operator who turned the gate off asked not to be blocked by secrets
	//   he was told about. He did not ask to be handed signed evidence for
	//   files nobody managed to read. Gating that on failOnDetection made the
	//   default configuration the unsafe one.
	//
	// It stays a plain error, never a DetectionError: the scan is
	// untrustworthy, so the workflow is right to keep it out of the collection
	// entirely rather than sign a partial result.
	if len(a.scanErrors) > 0 {
		return fmt.Errorf("secret scanning failed: %d scan error(s), first: %w",
			len(a.scanErrors), a.scanErrors[0])
	}

	// OBSERVED. The scan completed and found secrets. This is a verdict on
	// good evidence, not a failure to look, so it is reported as a
	// DetectionError: still fatal (the operator asked to fail closed, and
	// DetectionError is not a SoftError, so the CLI still exits non-zero),
	// but the workflow keeps a.Findings in the signed collection instead of
	// discarding the only record that the secrets were ever seen.
	//
	// Without failOnDetection findings are not an error at all: they are
	// recorded, and policy gates at verify time.
	if a.failOnDetection && len(a.Findings) > 0 {
		return attestation.NewDetectionError(
			fmt.Sprintf("secret scanning failed: found %d secrets", len(a.Findings)))
	}

	return nil
}
