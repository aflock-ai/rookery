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

import "fmt"

// Trace coverage: one place in the signed predicate that says what the tracer
// that ran could NOT see, with the same field and meaning on every platform.
// Design: docs/design/trace-coverage.md (monorepo root).
//
// Every backend is partial in some way. Before this, the evidence of that
// was spread across summary.diagnostics, and part of it could not be read at
// all: fanotifyAvailable is omitempty, so an absent value meant disabled,
// unavailable, or idle. A policy that wants a complete trace now reads
// summary.coverage.complete. A policy that accepts known limits allows a
// named set of gap kinds and denies every other kind.

// Backend names as recorded in summary.traceModeDetail / _meta.traceBackend.
const (
	TraceBackendEBPF          = "ebpf"
	TraceBackendPtrace        = "ptrace+seccomp"
	TraceBackendDarwinSandbox = "sandbox-exec+oslog"
)

// Gap kinds. Stable vocabulary: a policy matches on these strings.
const (
	GapTracerUnknown = "tracer-unknown"

	// Linux (eBPF and ptrace).
	GapFanotifyDisabled     = "fanotify-disabled"
	GapFanotifyUnavailable  = "fanotify-unavailable"
	GapFanotifyStateUnknown = "fanotify-state-unknown"
	GapEventsDropped        = "events-dropped"
	GapFanotifyEventsLost   = "fanotify-events-lost"
	GapOpensUnhashed        = "opens-unhashed"
	GapSyscallsUntraced     = "syscalls-untraced"
	GapSyscallStopsLost     = "syscall-stops-lost"

	// macOS sandbox-report backend.
	GapDiagnosticsMissing       = "diagnostics-missing"
	GapExecSuccessUnconfirmed   = "exec-success-unconfirmed"
	GapExecDigestUnbound        = "exec-digest-unbound"
	GapFileReadsUnobserved      = "file-reads-unobserved"
	GapFileReadsScoped          = "file-reads-scoped"
	GapFileReadsUnproven        = "file-reads-unproven"
	GapNetworkUnobserved        = "network-unobserved"
	GapNetworkHostsUnobservable = "network-hosts-unobservable"
	GapProcessesUnproven        = "processes-unproven"
	GapUnprovenExecsOmitted     = "unproven-execs-omitted"
	GapAncestryUnresolved       = "ancestry-unresolved"
	GapDescendantsUnobserved    = "descendants-unobserved"
	GapProcessesReparented      = "processes-reparented"
	GapProcessesGroupOnly       = "processes-group-only"
	GapReportsUnattributed      = "reports-unattributed"
	GapReportsUnreadable        = "reports-unreadable"
	GapImagesUnhashed           = "images-unhashed"
	GapExecsUndigested          = "execs-undigested"
	GapNetworkReportsUnproven   = "network-reports-unproven"
	GapPIDReuse                 = "pid-reuse"
	GapForkReportsUnmatched     = "fork-reports-unmatched"
)

// TraceCoverage states which tracer produced the trace and every known way
// the trace is incomplete. Complete is true only when Gaps is empty, and is
// always serialized (no omitempty), so a false can never read as absent.
// A predicate with no coverage at all (an older producer) must be treated
// as incomplete by any policy that requires completeness.
type TraceCoverage struct {
	Tracer   string     `json:"tracer"`
	Complete bool       `json:"complete"`
	Gaps     []TraceGap `json:"gaps,omitempty"`
}

// TraceGap is one known blind spot. Count is set when the gap is a number of
// lost or unproven events; Detail says what was not seen, in words.
type TraceGap struct {
	Kind   string `json:"kind"`
	Count  uint64 `json:"count,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type traceCoverageInput struct {
	Backend     string
	Diagnostics TraceDiagnostics
	Fanotify    fanotifyOutcome
}

// ptraceUntracedSyscalls names what the ptrace handler set does not observe
// (tracing_linux.go handleSyscall). Kept next to the gap so the claim and the
// code it describes are reviewed together.
const ptraceUntracedSyscalls = "the ptrace backend records execve, execveat, openat and the network/file-op " +
	"syscalls it has handlers for; open(2), openat2, creat, and io_uring file access are not recorded, and an " +
	"execveat through a descriptor or relative path is recorded without its program path"

// deriveTraceCoverage computes coverage from facts already in the predicate
// (the backend and diagnostics) plus the fanotify outcome. It is pure so a
// verifier can recompute it, and it fails closed: an unknown backend, a
// missing diagnostics block, or an unrecorded fanotify state is a gap.
func deriveTraceCoverage(in traceCoverageInput) *TraceCoverage {
	c := &TraceCoverage{Tracer: in.Backend}
	add := func(kind string, count uint64, detail string) {
		c.Gaps = append(c.Gaps, TraceGap{Kind: kind, Count: count, Detail: detail})
	}
	addCount := func(kind string, count uint64, detail string) {
		if count > 0 {
			add(kind, count, detail)
		}
	}
	d := in.Diagnostics

	switch in.Backend {
	case TraceBackendEBPF, TraceBackendPtrace:
		switch in.Fanotify.State {
		case fanotifyActive:
		case fanotifyDisabled:
			add(GapFanotifyDisabled, 0, fmt.Sprintf("fanotify integrity gate disabled (%s); file digests are hashed "+
				"from the path at open time, not kernel-synchronous", orUnstated(in.Fanotify.Reason)))
		case fanotifyUnavailable:
			add(GapFanotifyUnavailable, 0, fmt.Sprintf("fanotify integrity gate unavailable: %s; file digests are "+
				"hashed from the path at open time, not kernel-synchronous", orUnstated(in.Fanotify.Reason)))
		default:
			add(GapFanotifyStateUnknown, 0, "no record of whether the fanotify integrity gate ran")
		}
		addCount(GapEventsDropped, d.RingbufOpenatDrops+d.RingbufReadTapDrops,
			"eBPF ring-buffer events dropped under pressure; the opens they carried are not in the trace")
		addCount(GapFanotifyEventsLost, d.FanotifyTimeouts+d.FanotifyQueueOverflows+d.FanotifyDigestsCapHit,
			"fanotify events timed out, overflowed the kernel queue, or exceeded the digest cap")
		addCount(GapOpensUnhashed, d.UnhashedOpensTotal,
			"opens recorded without a content digest (see processes[].unhashedOpens for reasons)")
		if in.Backend == TraceBackendPtrace {
			add(GapSyscallsUntraced, 0, ptraceUntracedSyscalls)
			addCount(GapSyscallStopsLost, d.PtraceSyscallStopsLost,
				"syscall stops whose registers or arguments could not be read (process killed while stopped)")
		}
	case TraceBackendDarwinSandbox:
		deriveDarwinCoverage(d.Darwin, add, addCount)
	default:
		add(GapTracerUnknown, 0, fmt.Sprintf("tracer %q has no known coverage model", in.Backend))
	}

	c.Complete = len(c.Gaps) == 0
	return c
}

func deriveDarwinCoverage(dd *DarwinTraceDiagnostics, add, addCount func(string, uint64, string)) {
	if dd == nil {
		add(GapDiagnosticsMissing, 0, "macOS trace carries no diagnostics.darwin block")
		return
	}
	add(GapExecSuccessUnconfirmed, 0, "the sandbox report channel reports permitted execs; it cannot confirm execve succeeded")
	add(GapExecDigestUnbound, 0, "exec digests are read from the path when the collector opens it ("+
		orUnstated(dd.ExecDigestBinding)+"), not from the image the kernel loaded")
	if dd.FileReadsObserved {
		add(GapFileReadsScoped, 0, "file reads are observed only under "+orUnstated(dd.FileContentScope))
	} else {
		add(GapFileReadsUnobserved, 0, "file reads were not observed (enable with --trace-file-content)")
	}
	addCount(GapFileReadsUnproven, dd.UnprovenFileReadReports, "file-read reports whose ownership could not be proven")
	if !dd.NetworkObserved {
		add(GapNetworkUnobserved, 0, "the network report channel was not proven to deliver")
	}
	if !dd.NetworkHostsObservable {
		add(GapNetworkHostsUnobservable, 0, "network endpoints carry ports only; hosts are not observable")
	}
	addCount(GapProcessesUnproven, dd.UnprovenPIDs, "processes whose kernel facts vanished before they could be read")
	addCount(GapUnprovenExecsOmitted, dd.UnprovenExecsOmitted, "unproven exec reports beyond the listed cap")
	addCount(GapAncestryUnresolved, dd.UnresolvedAncestry, "processes whose parent chain could not be resolved")
	addCount(GapDescendantsUnobserved, dd.UnobservedDescendants, "descendants seen at exit that produced no report")
	addCount(GapProcessesReparented, dd.ReparentedAfterRoot, "processes reparented to launchd after the root started")
	addCount(GapProcessesGroupOnly, dd.GroupOnlyPIDs, "processes in the root's process group whose descent was not proven")
	addCount(GapReportsUnattributed, dd.UnattributedReports, "exec/fork reports dropped because ownership could not be proven")
	addCount(GapReportsUnreadable, dd.CollectorRecordsUnreadable+dd.UnparseableOwnReports, "reports that could not be read")
	addCount(GapImagesUnhashed, dd.ImagesUnhashed, "exec'd images whose bytes could not be digested")
	addCount(GapExecsUndigested, dd.AttributedExecsUndigested, "in-tree execs without an image digest")
	addCount(GapNetworkReportsUnproven, dd.NetworkReportsUnprovenOwnership, "network reports whose ownership could not be decided")
	addCount(GapPIDReuse, dd.PidReuseDetected, "pids that changed incarnation during the run")
	if dd.ForkReports > dd.ObservedChildren {
		add(GapForkReportsUnmatched, dd.ForkReports-dd.ObservedChildren,
			"fork reports exceed the children observed; some children left no other trace")
	}
}

func orUnstated(s string) string {
	if s == "" {
		return "reason not stated"
	}
	return s
}
