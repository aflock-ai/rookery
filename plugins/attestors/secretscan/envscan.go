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
// This file (envscan.go) handles detection of environment variable values.
package secretscan

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
)

// compiledGlobCache caches compiled glob patterns so they are not recompiled
// on every call to isEnvironmentVariableSensitive. Glob compilation is O(n) in
// pattern length and allocates; caching avoids redundant work when the same
// sensitive-env-var list is checked against many environment variables.
var compiledGlobCache sync.Map
var compiledGlobCacheWrite sync.Mutex

const maxCompiledGlobs = 100

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob library
// can panic on certain patterns that compile successfully but trigger out-of-bounds
// access during matching. We treat panics as non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}

// isEnvironmentVariableSensitive checks if an environment variable is sensitive
// according to the sensitive environment variables list.
// Both exact entries and glob patterns are matched case-insensitively (R3-129).
func isEnvironmentVariableSensitive(key string, sensitiveEnvVars map[string]struct{}) bool { //nolint:gocognit // env var sensitivity check requires glob and case-insensitive matching
	upperKey := strings.ToUpper(key)

	for envVarPattern := range sensitiveEnvVars {
		if strings.Contains(envVarPattern, "*") { //nolint:nestif // glob pattern matching requires nested logic
			// Glob pattern — normalize to uppercase for case-insensitive matching.
			upperPattern := strings.ToUpper(envVarPattern)
			cached, ok := compiledGlobCache.Load(upperPattern)
			if !ok {
				compiled, err := glob.Compile(upperPattern)
				if err != nil {
					continue
				}
				// The cache is optional: after its bound, evaluate new patterns
				// without retaining them. Never omit a sensitivity check.
				compiledGlobCacheWrite.Lock()
				count := 0
				compiledGlobCache.Range(func(_, _ any) bool {
					count++
					return count < maxCompiledGlobs
				})
				if count < maxCompiledGlobs {
					compiledGlobCache.Store(upperPattern, compiled)
				}
				compiledGlobCacheWrite.Unlock()
				cached = compiled
			}
			g, ok := cached.(glob.Glob)
			if !ok {
				continue
			}
			matched, err := safeGlobMatch(g, upperKey)
			if err != nil {
				log.Debugf("glob match error for pattern %q key %q: %v", envVarPattern, key, err)
				continue
			}
			if matched {
				return true
			}
		} else {
			// Exact entry — case-insensitive comparison (R3-129).
			// Without this, entries like AWS_ACCESS_KEY_ID would not match
			// aws_access_key_id since the map lookup is case-sensitive.
			if strings.ToUpper(envVarPattern) == upperKey {
				return true
			}
		}
	}

	return false
}

// getSensitiveEnvVarsList returns the patterns that classify a key as
// sensitive: the default list plus every key the operator added. It reads the
// context's configuration rather than inferring "sensitive" from what the
// environment capturer left out. Under --env-capture-allowlist the capturer
// leaves out every key it was not asked to RECORD, so the inference turned each
// ordinary value ("http" included) into a match rule, while in the default
// obfuscation mode it left out nothing and --env-add-sensitive-key never
// reached the scan. The default list stays in force when the operator disables
// it for the environment attestor: a token recorded unmasked is still a secret,
// and finding it elsewhere matters more, not less.
func (a *Attestor) getSensitiveEnvVarsList() map[string]struct{} {
	sensitiveEnvVars := attestation.DefaultSensitiveEnvList()
	if a.ctx != nil {
		for _, key := range a.ctx.EnvAdditionalKeys() {
			sensitiveEnvVars[key] = struct{}{}
		}
	}
	return sensitiveEnvVars
}

// nonSecretEnvKeys name variables whose values say where the process runs and
// who runs it: locations and identities, never credentials. The obfuscation
// globs are broad on purpose and catch several of them (*PWD* matches PWD and
// OLDPWD, *PAT* matches PATH, *AUTH* matches SSH_AUTH_SOCK and GIT_AUTHOR_*).
// That costs nothing when the action is to mask a value. It is wrong when the
// action is to report every occurrence of the value as a leak, because these
// values appear in every attestation by design: the working directory alone
// denied every push under a no-findings policy. Any key ending in PATH is a
// search path (GOPATH, MANPATH, LD_LIBRARY_PATH) and is treated the same way.
var nonSecretEnvKeys = map[string]struct{}{
	"PWD": {}, "OLDPWD": {}, "HOME": {}, "TMPDIR": {}, "TMP": {}, "TEMP": {}, "SHELL": {},
	"USER": {}, "LOGNAME": {}, "SSH_AUTH_SOCK": {},
	"GIT_AUTHOR_NAME": {}, "GIT_AUTHOR_EMAIL": {}, "GIT_AUTHOR_DATE": {},
}

func isNonSecretEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	_, named := nonSecretEnvKeys[upper]
	return named || strings.HasSuffix(upper, "PATH")
}

// isValueMatchCandidate decides whether an environment value becomes a literal
// match rule. The key must be classified sensitive and not allowed by the
// operator (--env-allow-sensitive-key, compared exactly as the environment
// capturer compares it), it must not be a location or identity, and the value
// must be long enough that finding it is evidence of a leak rather than of a
// common word: CLOUDSDK_PROXY_TYPE=http under a *PROXY* key matched every URL.
func (a *Attestor) isValueMatchCandidate(key, value string, sensitiveEnvVars map[string]struct{}) bool {
	if len(value) < minValueMatchLength || isNonSecretEnvKey(key) {
		return false
	}
	if a.ctx != nil && slices.Contains(a.ctx.EnvExcludeKeys(), key) {
		return false
	}
	return isEnvironmentVariableSensitive(key, sensitiveEnvVars)
}

// findPatternMatchesWithRedaction finds all matches for a regex pattern
// and replaces the actual match with a redaction placeholder
func (a *Attestor) findPatternMatchesWithRedaction(content, patternStr string) []matchInfo {
	// Ensure the pattern is valid before compilation
	// Safely compile the regex - if it fails, return empty results
	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		log.Debugf("(attestation/secretscan) invalid regex pattern: %v", err)
		return []matchInfo{}
	}

	matches := pattern.FindAllStringIndex(content, -1)
	result := []matchInfo{}

	for _, match := range matches {
		// Get line number for this occurrence
		lineNum := len(strings.Split(content[:match[0]], "\n"))

		// Do NOT emit the raw surrounding bytes as "context". A fixed-width
		// window around the match can overlap an ADJACENT secret and leak it
		// into signed evidence (R3-162): searching for one value, the suffix
		// window captured the next value's bytes. The match position is recorded
		// in lineNumber; the context is reduced to the redaction placeholder so
		// no neighbouring secret material can survive.
		result = append(result, matchInfo{
			lineNumber:   lineNum,
			matchContext: redactedValuePlaceholder,
		})
	}

	return result
}

// ScanForEnvVarValues scans file content for plain and encoded environment variable values
func (a *Attestor) ScanForEnvVarValues(content, filePath string, sensitiveEnvVars map[string]struct{}) []Finding {
	findings := []Finding{}
	envVars := os.Environ()

	for _, envPair := range envVars {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}

		key := parts[0]
		value := parts[1]

		if !a.isValueMatchCandidate(key, value, sensitiveEnvVars) {
			continue
		}

		// Search for plain value with safe regex handling
		patternStr := regexp.QuoteMeta(value)

		// Validate the pattern is valid even after QuoteMeta (handles invalid UTF-8)
		if _, err := regexp.Compile(patternStr); err != nil {
			log.Debugf("(attestation/secretscan) skipping invalid regex pattern for env var %s: %v", key, err)
			continue
		}

		matches := a.findPatternMatchesWithRedaction(content, patternStr)
		for _, matchInfo := range matches {
			digestSet, err := a.calculateSecretDigests(value)
			if err != nil {
				log.Debugf("(attestation/secretscan) error calculating digest for env var value %s: %s", key, err)
				continue
			}

			finding := Finding{
				RuleID:      fmt.Sprintf("witness-env-value-%s", strings.ReplaceAll(key, "_", "-")),
				Description: fmt.Sprintf("Sensitive environment variable value detected: %s", key),
				Location:    filePath,
				Line:        matchInfo.lineNumber,
				Match:       truncateMatch(matchInfo.matchContext),
				Secret:      digestSet,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkDecodedContentForSensitiveValues examines decoded content for sensitive environment variable values
// This helps catch encoded sensitive values even without their variable names present
func (a *Attestor) checkDecodedContentForSensitiveValues( //nolint:gocognit,gocyclo,funlen // sensitive value detection requires multiple matching strategies
	decodedContent string,
	sourceIdentifier string,
	encodingType string,
	sensitiveEnvVars map[string]struct{},
	processedInThisScan map[string]struct{},
) []Finding {
	findings := []Finding{}
	envVars := os.Environ()

	// Search for all environment variable values in the decoded content
	for _, envPair := range envVars {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}

		key := parts[0]
		value := parts[1]

		if !a.isValueMatchCandidate(key, value, sensitiveEnvVars) {
			continue
		}

		// Check for the value in the decoded content, considering possible newline additions
		// First check exact match
		exactMatch := strings.Contains(decodedContent, value)

		// Next check with possible trailing newline (common in echo output)
		exactMatchWithNewline := strings.Contains(decodedContent, value+"\n")

		// Partial match: the decoded bytes carry a leading part of the value.
		// This exists for truncated leaks (`echo ${TOKEN:0:24} | base64`).
		//
		// It used to accept any prefix down to 3 characters, which made it a
		// lottery (#9315): decoded content is mostly not text — every sha256 in
		// a material inventory, every h1: line in go.sum, every lockfile
		// integrity hash decodes to 32 bytes of noise — and a 3-byte prefix of
		// SOME sensitive value in the caller's environment turns up in enough
		// noise every time. Which value hit depended on the environment, so the
		// same commit was refused once and accepted on re-mint.
		//
		// A partial match therefore has to carry most of the secret: at least
		// half of it, and never fewer than minPartialMatchLength characters.
		// Half is what rules out the structural prefix every secret of a kind
		// shares (the 36-character HS256 JWT header, PEM armor, "ghp_", "AKIA"),
		// which no fixed length floor can; the floor is what rules out short
		// values whose half is still guessable. Longer prefixes are tried first
		// so the recorded digest is of the longest leaked part.
		partialMatch := false
		partialValue := ""

		for prefixLen := len(value) - 1; prefixLen >= partialMatchFloor(len(value)); prefixLen-- {
			prefix := value[:prefixLen]
			if strings.Contains(decodedContent, prefix) {
				partialMatch = true
				partialValue = prefix
				// Do NOT log secret values — even partial prefixes can aid brute-force attacks
				log.Debugf("(attestation/secretscan) found partial match for env var %s (prefix length %d)", key, prefixLen)
				break
			}
		}

		// Process the match if we found any kind of match
		if exactMatch || exactMatchWithNewline || partialMatch { //nolint:nestif // match reporting requires nested type determination
			// Determine which value to use for reporting
			matchValue := value
			isPartial := false
			if exactMatchWithNewline {
				// For exact match with newline, use full value but note it had a newline
				matchValue = value
				log.Debugf("(attestation/secretscan) exact match with newline for %s", key)
			} else if !exactMatch && partialMatch {
				matchValue = partialValue
				isPartial = true
			}

			// Create a digest set for this value
			digestSet, err := a.calculateSecretDigests(matchValue)
			if err != nil {
				log.Debugf("(attestation/secretscan) error calculating digest for decoded env var value %s: %s", key, err)
				continue
			}

			// Find approximate line number and context
			// Since we're working with decoded content, this is approximate
			lines := strings.Split(decodedContent, "\n")
			lineNumber := 0
			match := fmt.Sprintf("...%s...", truncateMatch(matchValue))

			// Try to find the value in a specific line
			for i, line := range lines {
				if strings.Contains(line, matchValue) {
					lineNumber = i + 1
					// A context window built around the current match can overlap
					// an ADJACENT, DIFFERENT secret and leak its bytes into the
					// signed Finding.Match (R3-162/R3-165). Slicing the window
					// first would cut a neighbour into a fragment that a
					// full-value replace can no longer catch, so we redact every
					// OTHER sensitive value on the FULL line first (collapsing each
					// to a [REDACTED] token), then window around the still-intact
					// current match, then redact the current match itself.
					redactedLine := redactSensitiveValuesExcept(line, matchValue, sensitiveEnvVars)
					if len(redactedLine) < 40 {
						match = strings.ReplaceAll(redactedLine, matchValue, "[REDACTED]")
					} else {
						valueIndex := strings.Index(redactedLine, matchValue)
						startIndex := max(0, valueIndex-10)
						endIndex := min(len(redactedLine), valueIndex+len(matchValue)+10)
						context := redactedLine[startIndex:endIndex]
						match = strings.ReplaceAll(context, matchValue, "[REDACTED]")
					}
					break
				}
			}

			// Create a finding key to avoid duplicates
			partialSuffix := ""
			if isPartial {
				partialSuffix = "-partial"
			}
			findingKey := fmt.Sprintf("%s:%d:%s:%s%s", sourceIdentifier, lineNumber, key, encodingType, partialSuffix)
			if _, exists := processedInThisScan[findingKey]; exists {
				continue
			}
			processedInThisScan[findingKey] = struct{}{}

			// Create a finding for this match
			description := fmt.Sprintf("Encoded sensitive environment variable value detected: %s", key)
			if isPartial {
				description = fmt.Sprintf("Partial encoded sensitive environment variable value detected: %s", key)
			}

			finding := Finding{
				RuleID:              fmt.Sprintf("witness-encoded-env-value-%s%s", strings.ReplaceAll(key, "_", "-"), partialSuffix),
				Description:         description,
				Location:            sourceIdentifier,
				Line:                lineNumber,
				Match:               match,
				Secret:              digestSet,
				EncodingPath:        []string{encodingType},
				LocationApproximate: true,
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// partialMatchFloor is the shortest prefix of a sensitive value of length n
// that the decoded-content path reports as a partial match: half of the value,
// rounded up, and never below minPartialMatchLength. See the comment at the
// partial-match loop in checkDecodedContentForSensitiveValues for why both
// terms are needed.
func partialMatchFloor(n int) int {
	return max(minPartialMatchLength, (n+1)/2)
}

// redactSensitiveValuesExcept replaces every sensitive environment-variable value
// that appears in text with "[REDACTED]", skipping the value equal to exclude
// (the current match, which the caller redacts separately after windowing).
//
// It exists to scrub context windows on the decoded-content path: a window built
// around one secret can overlap an ADJACENT, DIFFERENT secret, and replacing only
// the current match leaves the neighbour's bytes in the signed Finding.Match
// (R3-162/R3-165). Redacting the FULL line for every other sensitive value BEFORE
// the window is sliced means an adjacent secret is collapsed to a [REDACTED] token
// while still whole, so windowing can never carve it into a leaking fragment. The
// sensitivity gate is the same one the scan itself applies, and non-secret context
// is preserved so the Match stays useful.
func redactSensitiveValuesExcept(text, exclude string, sensitiveEnvVars map[string]struct{}) string {
	for _, envPair := range os.Environ() {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		key := parts[0]
		value := parts[1]

		if value == exclude {
			continue
		}
		if len(value) < minSensitiveValueLength {
			continue
		}
		if !isEnvironmentVariableSensitive(key, sensitiveEnvVars) {
			continue
		}
		if strings.Contains(text, value) {
			text = strings.ReplaceAll(text, value, "[REDACTED]")
		}
	}
	return text
}
