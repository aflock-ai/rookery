// jade:ring local
// Copyright 2026 The Rookery Contributors
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

package commandrun

import (
	"encoding/json"
	"strings"
	"testing"
)

func gapKinds(c *TraceCoverage) map[string]TraceGap {
	out := map[string]TraceGap{}
	for _, g := range c.Gaps {
		out[g.Kind] = g
	}
	return out
}

func TestDeriveTraceCoverage_CleanEBPFWithFanotifyIsComplete(t *testing.T) {
	c := deriveTraceCoverage(traceCoverageInput{
		Backend:  TraceBackendEBPF,
		Fanotify: fanotifyOutcome{State: fanotifyActive},
	})
	if !c.Complete || len(c.Gaps) != 0 || c.Tracer != TraceBackendEBPF {
		t.Fatalf("clean eBPF+fanotify coverage = %+v, want complete with no gaps", c)
	}
}

func TestDeriveTraceCoverage_FanotifyStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  fanotifyOutcome
		want string
	}{
		{"disabled", fanotifyOutcome{State: fanotifyDisabled, Reason: "CILOCK_FANOTIFY=off"}, GapFanotifyDisabled},
		{"unavailable", fanotifyOutcome{State: fanotifyUnavailable, Reason: "FanotifyInit: operation not permitted"}, GapFanotifyUnavailable},
		// Nothing recorded which state fanotify was in: fail closed.
		{"unknown", fanotifyOutcome{}, GapFanotifyStateUnknown},
	} {
		for _, backend := range []string{TraceBackendEBPF, TraceBackendPtrace} {
			t.Run(tc.name+"/"+backend, func(t *testing.T) {
				c := deriveTraceCoverage(traceCoverageInput{Backend: backend, Fanotify: tc.out})
				g, ok := gapKinds(c)[tc.want]
				if !ok || c.Complete {
					t.Fatalf("coverage %+v: want gap %q and complete=false", c, tc.want)
				}
				if tc.out.Reason != "" && !strings.Contains(g.Detail, tc.out.Reason) {
					t.Errorf("gap detail %q does not carry the reason %q", g.Detail, tc.out.Reason)
				}
			})
		}
	}
}

func TestDeriveTraceCoverage_LinuxCountersBecomeCountedGaps(t *testing.T) {
	c := deriveTraceCoverage(traceCoverageInput{
		Backend:  TraceBackendEBPF,
		Fanotify: fanotifyOutcome{State: fanotifyActive},
		Diagnostics: TraceDiagnostics{
			RingbufOpenatDrops:     3,
			RingbufReadTapDrops:    1,
			FanotifyTimeouts:       2,
			FanotifyQueueOverflows: 1,
			FanotifyDigestsCapHit:  4,
			UnhashedOpensTotal:     5,
		},
	})
	k := gapKinds(c)
	if c.Complete {
		t.Fatal("counted losses must make coverage incomplete")
	}
	for kind, want := range map[string]uint64{GapEventsDropped: 4, GapFanotifyEventsLost: 7, GapOpensUnhashed: 5} {
		if k[kind].Count != want {
			t.Errorf("%s count = %d, want %d (gaps %+v)", kind, k[kind].Count, want, c.Gaps)
		}
	}
}

func TestDeriveTraceCoverage_PtraceIsNeverComplete(t *testing.T) {
	c := deriveTraceCoverage(traceCoverageInput{
		Backend:     TraceBackendPtrace,
		Fanotify:    fanotifyOutcome{State: fanotifyActive},
		Diagnostics: TraceDiagnostics{PtraceSyscallStopsLost: 2},
	})
	k := gapKinds(c)
	if c.Complete {
		t.Fatal("ptrace has untraced syscalls; coverage must not claim complete")
	}
	if _, ok := k[GapSyscallsUntraced]; !ok {
		t.Errorf("missing %s: %+v", GapSyscallsUntraced, c.Gaps)
	}
	if k[GapSyscallStopsLost].Count != 2 {
		t.Errorf("%s count = %d, want 2", GapSyscallStopsLost, k[GapSyscallStopsLost].Count)
	}
}

func TestDeriveTraceCoverage_UnknownOrEmptyTracerFailsClosed(t *testing.T) {
	for _, b := range []string{"", "dtrace"} {
		c := deriveTraceCoverage(traceCoverageInput{Backend: b, Fanotify: fanotifyOutcome{State: fanotifyActive}})
		if c.Complete {
			t.Errorf("backend %q: coverage claims complete", b)
		}
		if _, ok := gapKinds(c)[GapTracerUnknown]; !ok {
			t.Errorf("backend %q: want %s, got %+v", b, GapTracerUnknown, c.Gaps)
		}
	}
}

func TestDeriveTraceCoverage_Darwin(t *testing.T) {
	// A realistic clean macOS run (numbers from the native probe): still
	// structurally partial, and says why.
	d := &DarwinTraceDiagnostics{
		ExecReports: 4, ForkReports: 2, ObservedChildren: 2,
		ExecDigestBinding: "path-at-collector-open-time",
		NetworkObserved:   true,
	}
	c := deriveTraceCoverage(traceCoverageInput{
		Backend:     TraceBackendDarwinSandbox,
		Diagnostics: TraceDiagnostics{Darwin: d},
	})
	k := gapKinds(c)
	if c.Complete {
		t.Fatal("macOS sandbox tracing cannot confirm exec success; must not claim complete")
	}
	for _, want := range []string{GapExecSuccessUnconfirmed, GapExecDigestUnbound, GapFileReadsUnobserved, GapNetworkHostsUnobservable} {
		if _, ok := k[want]; !ok {
			t.Errorf("missing %s: %+v", want, c.Gaps)
		}
	}
	for _, not := range []string{GapNetworkUnobserved, GapProcessesUnproven, GapForkReportsUnmatched, GapFanotifyStateUnknown} {
		if _, ok := k[not]; ok {
			t.Errorf("unexpected %s on a clean run: %+v", not, c.Gaps)
		}
	}

	// Counters become counted gaps.
	d2 := *d
	d2.UnprovenPIDs = 3
	d2.ForkReports = 5
	d2.FileReadsObserved = true
	d2.FileContentScope = "/w"
	c2 := deriveTraceCoverage(traceCoverageInput{Backend: TraceBackendDarwinSandbox, Diagnostics: TraceDiagnostics{Darwin: &d2}})
	k2 := gapKinds(c2)
	if k2[GapProcessesUnproven].Count != 3 {
		t.Errorf("processes-unproven = %+v", k2[GapProcessesUnproven])
	}
	if k2[GapForkReportsUnmatched].Count != 3 {
		t.Errorf("fork-reports-unmatched = %+v, want count 3 (5 forks, 2 observed)", k2[GapForkReportsUnmatched])
	}
	if g, ok := k2[GapFileReadsScoped]; !ok || !strings.Contains(g.Detail, "/w") {
		t.Errorf("file-reads-scoped = %+v", g)
	}
	if _, ok := k2[GapFileReadsUnobserved]; ok {
		t.Error("file reads were observed; unobserved gap must not appear")
	}

	// No darwin block at all: fail closed.
	c3 := deriveTraceCoverage(traceCoverageInput{Backend: TraceBackendDarwinSandbox})
	if _, ok := gapKinds(c3)[GapDiagnosticsMissing]; !ok || c3.Complete {
		t.Errorf("missing darwin diagnostics: %+v", c3)
	}
}

// complete=false must be ON THE WIRE: an omitted false reads as absent, and a
// policy written as "deny if complete is false" would pass it.
func TestTraceCoverageCompleteFalseIsSerialized(t *testing.T) {
	b, err := json.Marshal(&TraceCoverage{Tracer: TraceBackendPtrace})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"complete":false`) {
		t.Fatalf("serialized coverage %s lacks complete:false", b)
	}
}

// The summary is what reaches the signed v0.2 body, so coverage must survive
// ToV02 + marshal.
func TestTraceCoverageSurvivesV02Wire(t *testing.T) {
	rc := New(WithCommand([]string{"true"}))
	rc.Summary = &TraceSummary{Coverage: &TraceCoverage{
		Tracer: TraceBackendPtrace,
		Gaps:   []TraceGap{{Kind: GapSyscallsUntraced, Detail: "x"}},
	}}
	b, err := json.Marshal(rc)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Summary struct {
			Coverage *TraceCoverage `json:"coverage"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body.Summary.Coverage == nil || body.Summary.Coverage.Tracer != TraceBackendPtrace ||
		len(body.Summary.Coverage.Gaps) != 1 || body.Summary.Coverage.Complete {
		t.Fatalf("coverage did not survive the wire: %s", b)
	}
}
