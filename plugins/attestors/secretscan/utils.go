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
	"strings"
)

// isBinaryFile determines if a file is binary based on its MIME type
// Binary files are skipped during scanning to avoid false positives and improve performance
func isBinaryFile(mimeType string) bool {
	// Common binary MIME type prefixes
	binaryPrefixes := []string{
		"application/octet-stream",
		"application/x-executable",
		"application/x-mach-binary",
		"application/x-sharedlib",
		"application/x-object",
	}

	for _, prefix := range binaryPrefixes {
		if strings.HasPrefix(mimeType, prefix) {
			return true
		}
	}

	// Executable file MIME type suffixes
	executableSuffixes := []string{
		"/x-executable",
		"/x-sharedlib",
		"/x-mach-binary",
	}

	for _, suffix := range executableSuffixes {
		if strings.HasSuffix(mimeType, suffix) {
			return true
		}
	}

	return false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// truncateMatch returns a redaction-safe preview of a detected secret for the
// human-readable Finding.Match field. The preview is signed into evidence that
// ships to Archivista + CI artifacts, so it must NEVER expose enough of the value
// to reconstruct it — the secret's verifiable identity is the Secret digest set,
// not this field.
//
// It shows at most a short LEADING hint (enough to recognise the secret's type,
// e.g. "ghp_", "AKIA") and elides the rest. It never returns the high-entropy
// trailing bytes, and never returns a short value unchanged. The previous
// implementation returned the value verbatim whenever it was <= 40 chars (a
// classic GitHub PAT is exactly 40) and exposed the trailing bytes of longer
// values — both leaked the secret into signed evidence.
func truncateMatch(match string) string {
	if match == "" {
		return ""
	}
	// Too short to show any prefix without revealing most of the secret.
	if len(match) <= truncatedMatchSegmentLength {
		return redactedValuePlaceholder
	}
	return match[:truncatedMatchSegmentLength] + "..."
}
