package archivista

import (
	"fmt"
	"strings"
)

// largeEnvelopeBytes is where an envelope stops being routine.
//
// The number is not a guess and not a round number chosen for looks: it is the
// pushgate's own envelope read cap, defined twice and deliberately mirrored —
// MAX_RESPONSE_BYTES in jade/factory/edge/git/evidence.js and maxEnvelopeBytes
// in jade/factory/edge/git/bodylimit.go, both 4 MiB. Envelope JSON is served
// from Archivista, which makes it tenant-controlled, and the verification work
// it demands (JSON decode, base64, per-signature crypto) is proportional to
// the bytes accepted — so the cap is a DoS bound on attacker-controlled input,
// not a performance tuning knob.
//
// Past it the envelope cannot be read by the pushgate's EDGE FALLBACK
// verification path. It says nothing about the platform-verdict path, which is
// how a push is normally evaluated, and nothing about whether the upload will
// succeed. Those are three separate things and this threshold only speaks to
// the middle one; the message keeps them apart.
//
// Warning at this size is still right for uploads, because the size that
// forfeits the fallback is also comfortably past the size that starts costing
// real upload time.
const largeEnvelopeBytes = 4 << 20

// humanBytes renders a byte count the way an operator reads one. Uploads are
// reported in raw bytes elsewhere in this file because those lines are grepped
// by tooling; this one is for a person.
func humanBytes(n int) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := int64(n) / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// sizeAdvice returns operator-facing guidance for an oversized envelope, or ""
// when the size is unremarkable.
//
// WHY THIS EXISTS. Measured 2026-08-30: a green 28-check gate produced an
// 18 MiB envelope and died with
//
//	archivista upload failed: classification=terminal reason=budget_exhausted
//	attempts=2 elapsed=4m0s bytes=17988881
//
// Every field in that line is true and none of them says what went wrong. The
// bulk was an untracked node_modules tree captured by the material attestor,
// which walks the entire working directory; the operator's actual remedy was
// to delete a directory. An error that reports a timeout for a problem that is
// really "you attested 600,000 files you did not mean to attest" costs a
// diagnosis cycle every time someone hits it.
//
// The advice deliberately names the usual cause rather than describing the
// general class. A message that says "consider reducing the envelope size" is
// the same as no message.
func sizeAdvice(size int) string {
	if size < largeEnvelopeBytes {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "the envelope is %s. Two separate consequences, and they are not the same problem:\n",
		humanBytes(size))
	b.WriteString("  - it uploads slowly, which is the usual reason this retry budget runs out;\n")
	fmt.Fprintf(&b, "  - it is over the %s the pushgate will read of one envelope, so it cannot be "+
		"verified by the edge fallback path (the platform verdict path is unaffected).\n",
		humanBytes(largeEnvelopeBytes))
	b.WriteString("  the usual cause is a dependency or build directory captured as materials/products — " +
		"node_modules, dist, target, vendor, .venv — which the material attestor records because it walks " +
		"the whole working directory.\n")
	b.WriteString("  remedies: remove build output from the working tree before attesting, " +
		"narrow the capture with --attestor-product-exclude-glob, " +
		"or raise the ceiling with --archivista-upload-retry-budget if the size is genuinely intended.")
	return b.String()
}

// sizeAdviceSuffix is sizeAdvice as a trailing fragment for an error format
// string, or "" when the size is unremarkable.
//
// It is a SUFFIX rather than a wrapper on purpose: the budget errors carry two
// %w verbs (the ErrRetryBudgetExhausted sentinel callers match with errors.Is,
// and the underlying attempt error), and rebuilding those messages as flat
// strings to attach advice would silently break every caller's sentinel check.
// Appending text cannot disturb an error chain.
func sizeAdviceSuffix(size int) string {
	advice := sizeAdvice(size)
	if advice == "" {
		return ""
	}
	return "\n  " + advice
}

// decorateWithSizeAdvice appends sizeAdvice to a plain message. Used where
// there is no error chain to preserve.
func decorateWithSizeAdvice(msg string, size int) string {
	return msg + sizeAdviceSuffix(size)
}
