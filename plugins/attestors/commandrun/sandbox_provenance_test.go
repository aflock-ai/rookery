//go:build darwin

package commandrun

import (
	"io"
	"strings"
	"testing"
)

// A log record is only a sandbox report if the KERNEL emitted it.
//
// The collector's stream predicate selects on senderImagePath containing
// "sandbox", and the reader once decoded only the message text. os_log is an
// ordinary API, so a same-uid process could emit two sandbox-shaped lines and
// have fabricated execs accepted into the SIGNED process tree — no key, no
// privileges, nothing to defeat. That was demonstrated end to end against an
// earlier revision of this file.
//
// The provenance fields are what separate a real report from an imitation, and
// processID is the load-bearing one: the logging system stamps it from the
// emitter's real identity rather than taking it from the message, so a user
// process cannot claim 0.
func TestOnlyKernelEmittedReportsAreAccepted(t *testing.T) {
	const (
		kernel = kernelProcessImagePath
		kext   = sandboxKextImagePath
	)
	zero, one, evil := 0, 1, 84421

	cases := []struct {
		name    string
		procImg string
		sender  string
		pid     *int
		uid     *int
		want    bool
	}{
		{"a genuine kext report", kernel, kext, &zero, &zero, true},

		// The attack, in the shape it was actually demonstrated: a user
		// process emitting sandbox-shaped text.
		{"a user process imitating the kext", "/usr/bin/curl", kext, &evil, &one, false},

		// Each field alone, to prove none is decorative. A binary living under
		// a path containing "sandbox" satisfies the STREAM predicate by itself,
		// which is why senderImagePath cannot be the only check.
		{"right sender, wrong emitter pid", kernel, kext, &evil, &zero, false},
		{"right sender, non-root uid", kernel, kext, &zero, &one, false},
		{"right pid, imitation sender path", kernel, "/tmp/sandbox-helper", &zero, &zero, false},
		{"right pid, wrong process image", "/usr/local/bin/thing", kext, &zero, &zero, false},

		// ABSENT must not read as zero. A record omitting the field entirely is
		// the cheapest forgery of all if the decoder defaults it — which is why
		// these are pointers rather than ints.
		{"absent pid", kernel, kext, nil, &zero, false},
		{"absent uid", kernel, kext, &zero, nil, false},
		{"absent both", kernel, kext, nil, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := acceptedFromKernel(tc.procImg, tc.sender, tc.pid, tc.uid)
			if got != tc.want {
				t.Fatalf("acceptedFromKernel(%q, %q, %v, %v) = %v, want %v — "+
					"a record that is not from the kernel must never enter the signed tree",
					tc.procImg, tc.sender, tc.pid, tc.uid, got, tc.want)
			}
		})
	}
}

// The helper being correct means nothing if the reader does not call it. This
// drives real ndjson through the production read loop — the same function the
// collector's stdout feeds — and asserts on the events that reach the tree.
//
// Testing the helper alone would have missed the failure mode that already bit
// this codebase once: a fix applied to a struct tag while production went
// through a different marshaller entirely, leaving the bug live behind a green
// test.
func TestReaderRefusesForgedReportsEndToEnd(t *testing.T) {
	// A genuine kext report and a forgery, identical in message text. Only the
	// provenance fields differ, which is precisely the attacker's position:
	// they control the text completely and the provenance not at all.
	genuine := `{"processImagePath":"/kernel",` +
		`"senderImagePath":"/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",` +
		`"processID":0,"userID":0,"timestamp":"2026-08-20 11:04:02.113000-0400",` +
		`"eventMessage":"Sandbox: sh(84400) allow process-exec* /bin/echo"}`

	forged := `{"processImagePath":"/usr/bin/python3","senderImagePath":"/tmp/sandbox-helper",` +
		`"processID":84421,"userID":501,"timestamp":"2026-08-20 11:04:02.114000-0400",` +
		`"eventMessage":"Sandbox: sh(84401) allow process-exec* /usr/bin/curl"}`

	// The cheapest forgery: omit provenance entirely and hope the decoder
	// defaults it to the values it is checking for.
	bare := `{"eventMessage":"Sandbox: sh(84402) allow process-exec* /usr/bin/nc",` +
		`"timestamp":"2026-08-20 11:04:02.115000-0400"}`

	// The banner log stream prints before the ndjson, plus a genuinely
	// malformed line: neither is a forgery and neither may be counted as one.
	banner := `Filtering the log data using "senderImagePath CONTAINS[c] sandbox"`
	malformed := `{"eventMessage": TRUNCATED`

	feed := strings.Join([]string{banner, genuine, forged, bare, malformed, ""}, "\n")

	s := &sandboxSession{
		stdout:     io.NopCloser(strings.NewReader(feed)),
		readerDone: make(chan struct{}),
		facts:      map[int]procFacts{},
		pinned:     map[imageIdentity]pinnedImage{},
		canaryPIDs: map[int]procFacts{},
	}
	s.stopping.Store(true) // reading a fixed buffer to EOF is not an early end
	s.read()
	<-s.readerDone

	for _, img := range s.pinned {
		_ = img.file.Close()
	}

	if len(s.events) != 1 {
		t.Fatalf("events reaching the tree = %d, want 1 (only the kernel-emitted report)", len(s.events))
	}
	if got := s.events[0].detail; got != "/bin/echo" {
		t.Errorf("surviving event = %q, want /bin/echo — a forged exec entered the signed tree", got)
	}
	if s.forged != 2 {
		t.Errorf("forged = %d, want 2 (the imitation and the bare record)", s.forged)
	}
	if s.unparsed != 1 {
		t.Errorf("unparsed = %d, want 1 (the truncated line) — malformed input must not be reported as forgery", s.unparsed)
	}
}
