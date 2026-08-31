package source

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The summary line is a MEASUREMENT INSTRUMENT, not a log message: the
// bounded-verify cost model regresses duration against scope_size to test its
// linearity assumption, and Loki parses the key=value pairs without a schema.
// These tests pin the parts an instrument cannot silently lose.

func TestSearchSummary_CarriesEveryModelParameter(t *testing.T) {
	line := searchSummary("push-tests", "streamed", 42, 550, 531, time.Now().Add(-1500*time.Millisecond))

	for _, key := range []string{"scope_size=42", "candidates=550", "verified_ok=531", `collection="push-tests"`, "mode=streamed"} {
		if !strings.Contains(line, key) {
			t.Errorf("summary missing %q — a model parameter with no line is an ASSUMED parameter again; got: %s", key, line)
		}
	}
	// duration must be present, numeric, and on the same line as scope_size —
	// the linearity regression needs both from ONE record, which is the whole
	// reason this line exists instead of two.
	m := regexp.MustCompile(`duration_ms=(\d+)`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("no numeric duration_ms in: %s", line)
	}
	if m[1] == "0" {
		t.Errorf("a 1.5s-old start rendered duration_ms=0; the clock is not being read")
	}
}

func TestSearchSummary_KeyValueFormIsParseable(t *testing.T) {
	// Loki-side parsing is `logfmt`-shaped: space-separated key=value with the
	// collection quoted. A collection name containing spaces must stay ONE
	// field, or every later key shifts position.
	line := searchSummary(`name with spaces`, "slice", 1, 2, 2, time.Now())
	if !strings.Contains(line, `collection="name with spaces"`) {
		t.Fatalf("collection not quoted; a space would shear the record: %s", line)
	}
}

func TestVerifiedOKCount_CountsOnlyErrorFreeResults(t *testing.T) {
	results := []CollectionVerificationResult{
		{},                                       // ok
		{Errors: []error{errors.New("bad sig")}}, // failed
		{},                                       // ok
		{Errors: []error{errors.New("x"), errors.New("y")}}, // failed
	}
	if got := verifiedOKCount(results); got != 2 {
		t.Fatalf("verifiedOKCount = %d, want 2", got)
	}
	if got := verifiedOKCount(nil); got != 0 {
		t.Fatalf("verifiedOKCount(nil) = %d, want 0", got)
	}
}
