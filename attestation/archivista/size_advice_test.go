package archivista

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// REGRESSION GUARD. Attaching advice to the budget errors must not flatten
// their error chain: callers match ErrRetryBudgetExhausted with errors.Is, and
// the first draft of this change rebuilt the message with fmt.Sprintf, which
// compiles, reads fine, and silently breaks every one of those callers. The
// suffix form exists specifically so both %w verbs survive.
func TestSizeAdviceSuffix_PreservesErrorChain(t *testing.T) {
	attemptErr := errors.New("post https://example/upload: deadline exceeded")
	for _, size := range []int{1024, 17988881} {
		err := fmt.Errorf("%w after %d attempts in %s: %w%s",
			ErrRetryBudgetExhausted, 2, "4m0s", attemptErr, sizeAdviceSuffix(size, nil))

		if !errors.Is(err, ErrRetryBudgetExhausted) {
			t.Errorf("size=%d: errors.Is(err, ErrRetryBudgetExhausted) is false — callers' sentinel check broke", size)
		}
		if !errors.Is(err, attemptErr) {
			t.Errorf("size=%d: the underlying attempt error is no longer reachable", size)
		}
	}
}

// A small envelope gets no advice: appending "your envelope may be large" to
// every failure trains people to ignore the line that matters.
func TestSizeAdvice_SilentBelowThreshold(t *testing.T) {
	for _, size := range []int{0, 1024, 1 << 20, largeEnvelopeBytes - 1} {
		if got := sizeAdvice(size); got != "" {
			t.Fatalf("sizeAdvice(%d) = %q, want empty — advice below the threshold is noise", size, got)
		}
	}
}

// At and above the threshold the advice must name the SIZE, the CAUSE, and a
// REMEDY. The measured incident (2026-08-30) was an 18MB envelope whose bulk
// was an untracked node_modules tree; the operator saw only
// "budget_exhausted", which points nowhere near the cause.
//
// This case passes NO payload, so it is the fallback arm. It used to assert
// that --attestor-product-exclude-glob was offered as the remedy; that
// assertion is deliberately inverted now. Measurement showed the flag cannot
// move a material-dominated envelope (product was 414 bytes of ~4 MiB), so
// prescribing it here sent operators to a lever that does nothing. Without a
// decoded payload we have no measurement, so the message must say it is
// GUESSING rather than name a remedy it cannot justify.
func TestSizeAdvice_NamesSizeCauseAndRemedy(t *testing.T) {
	got := sizeAdviceMeasured(17988881, nil)
	if got == "" {
		t.Fatal("sizeAdvice returned nothing for an 18MB envelope")
	}
	for _, want := range []string{"17.2 MiB", "node_modules", "guess"} {
		if !strings.Contains(got, want) {
			t.Errorf("advice missing %q; got:\n%s", want, got)
		}
	}
	// The un-measured arm must not prescribe a flag it cannot justify.
	if strings.Contains(got, "--attestor-product-exclude-glob") {
		t.Errorf("the guessing arm must not prescribe the product exclude glob: it cannot move a "+
			"material-dominated envelope, which is the common case; got:\n%s", got)
	}
	// It must cite the 4 MiB evidence-edge cap, which is the real cliff:
	// past it the envelope stops being readable by the edge evaluator.
	if !strings.Contains(got, "4.0 MiB") {
		t.Errorf("advice must cite the 4 MiB evidence-edge read cap; got:\n%s", got)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{4 << 20, "4.0 MiB"},
		{17988881, "17.2 MiB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The advice rides on the terminal budget-exhausted error, because that is the
// failure an oversized envelope actually produces — a slow upload that runs
// out of budget, not a rejection that names size.
func TestBudgetExhaustedErrorCarriesSizeAdvice(t *testing.T) {
	small := decorateWithSizeAdvice("upload failed", 1024, nil)
	if strings.Contains(small, "node_modules") {
		t.Fatalf("small-envelope error must not carry size advice: %q", small)
	}
	big := decorateWithSizeAdvice("upload failed", 17988881, nil)
	if !strings.Contains(big, "upload failed") {
		t.Fatalf("decoration dropped the original message: %q", big)
	}
	if !strings.Contains(big, "17.2 MiB") {
		t.Fatalf("decorated error must name the size: %q", big)
	}
}
