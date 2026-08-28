//go:build darwin

package commandrun

import (
	"testing"
	"time"
)

// The drain canary is a BARRIER, and a barrier is only worth anything if
// something waits behind it. Canary reports deliberately do not refresh the
// quiet clock, so when the build's last real report was already older than
// the window, awaitQuiet returned IMMEDIATELY after the canary was sent —
// zero quiet time — and a build report the log stream delivered out of order
// was killed with the collector. The baseline resets when the canary is
// observed, so a full window of silence must follow it.
func TestDrainRequiresAQuietWindowAfterTheCanary(t *testing.T) {
	s := drainSession()
	s.lastInTree = time.Now().Add(-time.Hour) // long since quiet
	s.noteDrainBarrier()
	if since := time.Since(s.lastInTree); since > quietWindow {
		t.Fatalf("the barrier left the quiet clock %v old; awaitQuiet would return without waiting", since)
	}
	start := time.Now()
	if err := s.awaitQuiet(time.Now().Add(drainDeadline)); err != nil {
		t.Fatalf("awaitQuiet after the barrier: %v", err)
	}
	if waited := time.Since(start); waited < quietWindow {
		t.Fatalf("awaitQuiet returned after %v, less than the %v window; a late report would be lost", waited, quietWindow)
	}
}
