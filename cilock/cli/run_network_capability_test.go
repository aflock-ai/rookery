// Copyright 2026 TestifySec, Inc.
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

package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// AN EMPTY EGRESS LIST MEANS NOTHING UNLESS THE CHANNEL THAT WOULD HAVE
// REPORTED EGRESS IS KNOWN TO WORK.
//
// stampNetworkObservation already refuses to claim anything when the trace
// captured NOTHING (no capture mode) — a failed backend must not read as an
// affirmative observation of zero connections. The macOS backend introduces a
// case that test does not cover: the trace succeeds, has a capture mode, and
// produces execs and files, while its NETWORK reports specifically were never
// proven to arrive. The attestor says so in
// Summary.Diagnostics.Darwin.NetworkObserved, which it establishes with a
// live probe rather than by reading the sandbox profile it asked for.
//
// Nothing consumed that flag. So a backend that accepted the profile and then
// emitted no network reports at all — probe binary missing, capability quietly
// dropped — handed cilock an empty egress list for a build that could have
// fetched anything, and cilock stamped NoExternalNetworkEgressObserved on it.
// The capture mode was non-empty, so the existing guard passed it through.
//
// The verdict must be the same as for a trace that captured nothing: make NO
// claim. Unobserved is not observed-empty.
func TestStampNetworkObservation_DarwinNetworkUnprovenMakesNoClaim(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{
		CaptureMode: "sandbox-report",
		Diagnostics: commandrun.TraceDiagnostics{
			Darwin: &commandrun.DarwinTraceDiagnostics{
				// The trace worked; the network half of it was never proven.
				NetworkObserved: false,
			},
		},
	}
	// No connections recorded — which is exactly the ambiguity: it could mean
	// the build fetched nothing, or that nothing was ever going to be reported.
	cr.Processes = []commandrun.ProcessInfo{{ProcessID: 100, Program: "/bin/sh"}}

	s := &options.RunSummary{}
	stampNetworkObservation(s, []attestation.Attestor{cr})

	if s.NoExternalNetworkEgressObserved {
		t.Errorf("cilock claimed no external egress was observed on a trace whose NETWORK channel was never " +
			"proven — an unobserved channel is not an observation of nothing, and this is the claim a " +
			"hermeticity policy acts on")
	}
}

// The same backend with the network channel PROVEN keeps its claim: this is
// the case the flag exists to distinguish, and a guard that refused both would
// make a macOS hermeticity verdict unreachable rather than honest.
func TestStampNetworkObservation_DarwinNetworkProvenKeepsTheClaim(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{
		CaptureMode: "sandbox-report",
		Diagnostics: commandrun.TraceDiagnostics{
			Darwin: &commandrun.DarwinTraceDiagnostics{NetworkObserved: true},
		},
	}
	cr.Processes = []commandrun.ProcessInfo{{ProcessID: 100, Program: "/bin/sh"}}

	s := &options.RunSummary{}
	stampNetworkObservation(s, []attestation.Attestor{cr})

	if !s.NoExternalNetworkEgressObserved {
		t.Errorf("a darwin trace with a PROVEN network channel and no connections must still be able to " +
			"report no observed egress; otherwise the verdict is unreachable on this platform")
	}
	if s.Tracing != "sandbox-report" {
		t.Errorf("Tracing label = %q, want sandbox-report", s.Tracing)
	}
}

// A non-darwin trace carries no darwin diagnostics at all, and must not be
// caught by the new guard.
func TestStampNetworkObservation_NonDarwinUnaffected(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "ebpf-readtap"} // Darwin nil
	cr.Processes = []commandrun.ProcessInfo{{ProcessID: 100, Program: "/bin/sh"}}

	s := &options.RunSummary{}
	stampNetworkObservation(s, []attestation.Attestor{cr})

	if !s.NoExternalNetworkEgressObserved {
		t.Errorf("a linux trace with no connections must still report no observed external egress")
	}
}

// The unattributed-exec gaps reach an operator, because the attestation's own
// entries carry no image identity and an image-deny policy therefore cannot
// match them. Refusing on them is not an option — an exec whose child exited
// before its facts could be polled is the measured residual of a
// report-channel tracer on a loaded machine, and refusing every such trace
// would make the backend unusable. So the requirement is that the gap is
// VISIBLE where a person looks, not that it is fatal.
func TestStampNetworkObservation_SurfacesUnattributedExecs(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{
		CaptureMode: "sandbox-report",
		Diagnostics: commandrun.TraceDiagnostics{
			Darwin: &commandrun.DarwinTraceDiagnostics{
				NetworkObserved: true,
				ForgedRecords:   4,
				UnprovenExecs: []commandrun.UnprovenExec{
					{PID: 4242, Timestamp: "2026-08-28T04:00:00Z"},
					{PID: 4243, Timestamp: "2026-08-28T04:00:01Z"},
				},
			},
		},
	}
	cr.Processes = []commandrun.ProcessInfo{{ProcessID: 100, Program: "/bin/sh"}}

	s := &options.RunSummary{}
	stampNetworkObservation(s, []attestation.Attestor{cr})

	if s.UnattributedExecs != 2 {
		t.Errorf("UnattributedExecs = %d, want 2 — an exec the trace saw but could not attribute is invisible "+
			"to an image policy (the entries carry no image identity), so the count is the only thing that "+
			"tells an operator the gap exists", s.UnattributedExecs)
	}
	// And it stays a report, not a verdict.
	if !s.NoExternalNetworkEgressObserved {
		t.Errorf("an unattributed exec must not by itself destroy the network observation — they are " +
			"different claims about different channels")
	}

	// Forgery reaches the operator too. os_log is an ordinary unprivileged
	// API, so a tree could be fabricated with two log calls and no key —
	// demonstrated end to end against an earlier revision of this backend.
	// The records are rejected on kernel-sender provenance, which is why the
	// run stays attestable; refusing instead would hand any local process a
	// way to break every build on a shared machine with one log line. But
	// "rejected" is not "unremarkable", and it was previously visible only in
	// a counter nothing read.
	if s.ForgedReportRecords != 4 {
		t.Errorf("ForgedReportRecords = %d, want 4 — something was writing kernel-shaped sandbox messages "+
			"into the log while the build ran, which is either a bug or an attempt to fabricate evidence, "+
			"and an operator has to be able to see it", s.ForgedReportRecords)
	}
}
