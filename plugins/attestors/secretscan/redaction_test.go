package secretscan

import (
	"strings"
	"testing"
)

// TestTruncateMatchNeverLeaksSecret guards the redaction the Finding.Match field
// promises. A detected secret must NEVER appear verbatim (or with its
// high-entropy tail intact) in the signed finding — that evidence is signed and
// shipped to Archivista + CI artifacts, so leaking the value there re-publishes
// the very credential the scan flagged. The secret's verifiable identity lives in
// the Secret digest set; Match is only a human hint.
//
// The pre-fix truncateMatch returned the value unchanged whenever it was
// <= maxMatchDisplayLength (40) chars — which includes a classic 40-char GitHub
// PAT, AWS keys, and most passwords — and exposed the trailing 8 bytes for longer
// values.
func TestTruncateMatchNeverLeaksSecret(t *testing.T) {
	// Values are obviously-fake placeholders — real-looking tokens (ghp_…, AKIA…,
	// xoxb-…) trip secret-scanning push protection. truncateMatch is purely
	// length-based, so only the lengths and distinct prefix/suffix matter here.
	cases := map[string]string{
		"value at the 40-char display limit": "FAKEkey0" + strings.Repeat("z", 24) + "endpart0", // 40
		"id-length value (20 chars)":         "FAKEkey0" + strings.Repeat("z", 4) + "endpart0",  // 20
		"medium value (32 chars)":            "FAKEkey0" + strings.Repeat("z", 16) + "endpart0", // 32
		"long value, distinct tail":          "FAKEkey0" + strings.Repeat("z", 64) + "TAILEND0",
		"tiny value":                         "tiny",
	}
	for name, secret := range cases {
		got := truncateMatch(secret)
		if strings.Contains(got, secret) {
			t.Errorf("%s: truncateMatch output %q contains the full secret", name, got)
		}
		// The trailing bytes are the high-entropy part of most tokens — they must
		// never survive into the redacted preview.
		if len(secret) > truncatedMatchSegmentLength {
			tail := secret[len(secret)-truncatedMatchSegmentLength:]
			if strings.Contains(got, tail) {
				t.Errorf("%s: truncateMatch output %q leaks the secret's trailing bytes %q", name, got, tail)
			}
		}
	}
}
