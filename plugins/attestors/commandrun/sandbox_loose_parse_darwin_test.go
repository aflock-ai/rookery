//go:build darwin

package commandrun

import "testing"

// The loose reading that decides "this report is about an operation we do
// not trace" can itself be captured. With a comm of "x(1) allow foo" and an
// exec path containing a newline, the strict grammar fails (so the
// ambiguity check never sees the line), and the loose one then binds the
// planted header, reads the op as "foo", calls the line irrelevant and
// silently drops the kernel's real process-exec* report. A loose reading
// that is not unique cannot license a skip.
func TestCapturedLooseParseIsNotIrrelevant(t *testing.T) {
	t.Parallel()
	const captured = "Sandbox: x(1) allow foo sh(4242) allow process-exec* /tmp/a\nb"
	if irrelevantReport(captured) {
		t.Fatal("a planted header licensed skipping the line; the build's real exec vanishes from the evidence with nothing counted")
	}
	// Genuinely irrelevant, one reading only: still skipped, or every
	// machine-wide file-read would refuse the trace.
	for _, msg := range []string{
		"Sandbox: passd(98302) deny(1) file-read-data /Library/Preferences/x.plist",
		"Sandbox: cfprefsd(120) allow mach-lookup com.apple.cfprefsd.daemon",
	} {
		if !irrelevantReport(msg) {
			t.Errorf("%q: an unambiguous untraced operation was not skipped", msg)
		}
	}
}
