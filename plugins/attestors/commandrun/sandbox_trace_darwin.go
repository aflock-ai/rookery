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

//go:build darwin

// macOS process-tree capture via the Seatbelt sandbox's REPORT channel.
//
// WHY THIS EXISTS. Before this file, enableTracing was an empty
// //go:build !linux stub, so a REAL macOS attestation carried only `cmd` and
// `exitcode` — decoded from a signed DSSE off an actual run, the predicate's
// top-level keys were [_meta cmd comms digests exitcode paths processes] with
// processes EMPTY and comms/digests/paths null. A policy that pins a command
// was therefore defeated by one line of indirection: pin ["npm","test"], edit
// package.json so "test" is "exit 0", and nothing in the attestation could
// contradict the claim. The agent producing the attestation is the adversary
// here — it wants the gate green and takes the cheapest shortcut available.
//
// We cannot make forgery impossible: the agent holds the signing key, which is
// definitional. The goal is to make cheating cost MORE than doing the work and
// leave it DETECTABLE. A fabricated 12,000-entry process tree is real work;
// {"exitcode":0} is not.
//
// WHY SEATBELT AND NOT DYLD INTERPOSITION. The product constraint is that a
// user installs NOTHING beyond cilock — no Docker, no daemon, no root, no
// Apple entitlement, no TCC prompt. That rules out ES (Endpoint Security needs
// an entitlement) and dtrace (SIP). DYLD_INSERT_LIBRARIES is installed-nothing
// but is defeated by exactly the processes that matter: SIP-protected platform
// binaries (/bin/sh, /usr/bin/awk) drop the injected library, so a build that
// shells out is invisible. sandbox-exec ships on every Mac, and children
// INHERIT the sandbox (man 7 sandbox), so the whole descendant tree reports —
// SIP-protected binaries included. Measured on macOS 15.7.7/arm64: a real
// `go test -race` cold rebuild reported 12,291 execs; 8-way parallel 4,000
// execs gave 4,000/4,000 distinct pids with no coalescing; overhead 112s vs
// 106s (~5.7%).
//
// THE SANDBOX HERE IS NOT A SECURITY BOUNDARY. The profile is `(allow
// default)` plus `(with report)` on the exec/fork operations: it permits
// everything the command could already do and only asks the kernel to narrate
// it. Confining the build is a different feature with a different blast
// radius; do not confuse the two.
//
// THREE THINGS THIS MUST NEVER DO, each learned the expensive way:
//  1. sandbox-exec is DEPRECATED (man 1 sandbox-exec). It works today and
//     Apple can remove it tomorrow. Its absence or failure must degrade
//     HONESTLY — refuse to attest rather than attest a lie.
//  2. SANDBOXES DO NOT NEST. Wrapping a build that itself uses sandbox-exec
//     (Bazel's darwin-sandbox) fails with "sandbox_apply: Operation not
//     permitted" (exit 71). That must fail LOUDLY, never silently run
//     untraced while emitting an attestation that looks traced.
//  3. The log collector MUST start OUTSIDE the sandbox and BEFORE the
//     command; `log` refuses to run inside one.
package commandrun

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"golang.org/x/sys/unix"
)

// Tool paths are absolute and package VARIABLES rather than constants so a
// test can point them at a missing/failing binary and prove the refusal path
// actually refuses. Absolute because a PATH-resolved `sandbox-exec` would let
// anything earlier on PATH silently become the thing that "traced" the build.
var (
	sandboxExecPath = "/usr/bin/sandbox-exec"
	logToolPath     = "/usr/bin/log"

	// sandboxProfile is the observation profile, applied via -p (an inline
	// string) rather than -f: no temp file to write, clean up, or have
	// rewritten under us between the write and the exec.
	//
	// `(allow default)` is deliberate — see the file header. The exec/fork
	// pair is what was measured at 4,000/4,000 capture.
	//
	// networkReportRule is what makes HERMETICITY claimable here at all. It is
	// a VARIABLE, and the capability flag in the attestation is derived from
	// this string at run time (see sandboxProfileReportsNetwork) rather than
	// asserted, so a profile that loses the rule reports "we did not watch"
	// and cilock withholds the hermeticity claim instead of inheriting a
	// stale one. A test deletes the rule and watches the egress evidence
	// disappear, which is the only way to know the line is load-bearing.
	sandboxProfile = `(version 1)(allow default)(allow process-exec* (with report))` +
		`(allow process-fork (with report))` + networkReportRule
)

// networkReportRule asks the kernel to narrate network operations through the
// same report channel the exec/fork rules already use. Verbatim lines it
// produces on macOS 15.7.7/arm64:
//
//	Sandbox: curl(38711) allow network-outbound /private/var/run/mDNSResponder
//	Sandbox: curl(38711) allow network-outbound
//	Sandbox: curl(38711) allow network-outbound remote:*:443
//	Sandbox: Python(58360) allow network-bind    /private/tmp/docker.sock
//	Sandbox: Python(44431) allow network-inbound local:*:57793
const networkReportRule = `(allow network* (with report))`

// networkProbePath is the binary the network canary uses. A base-system tool
// on every macOS this backend supports; if it is missing the capability is
// reported unavailable rather than assumed.
var networkProbePath = "/usr/bin/nc"

// sandboxProfileReportsNetwork reports whether the profile THIS RUN applied
// actually asked for network reports. Read from the profile string rather than
// hardcoded, so the attestation's networkObserved flag cannot drift away from
// what the kernel was told.
func sandboxProfileReportsNetwork() bool {
	return strings.Contains(sandboxProfile, networkReportRule)
}

const (
	// darwinTraceBackend names this backend in the attestation's
	// _meta.traceBackend / summary.traceModeDetail, next to Linux's
	// "ebpf" and "ptrace+seccomp". A verifier reading a stored
	// attestation must be able to tell WHICH observer produced the tree
	// without guessing from the host OS.
	darwinTraceBackend = "sandbox-exec+oslog"

	// logPredicate selects the Sandbox kext's report messages. Kept broad
	// (this is the predicate the 4,000/4,000 measurement used) and filtered
	// in Go, so a change in how the kext labels subsystem/category cannot
	// silently empty the stream.
	logPredicate = `senderImagePath CONTAINS[c] "sandbox"`

	// The exact provenance a genuine Sandbox kext report carries. Measured on
	// macOS 15.7.7; see acceptedFromKernel for why every field is required.
	kernelProcessImagePath = "/kernel"
	sandboxKextImagePath   = "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"

	// maxSandboxEvents bounds memory for a pathological build. Hitting it
	// makes the trace FAIL rather than emit a truncated tree that reads as
	// complete — a tree missing its second half is exactly the shape a cheat
	// produces, so we must not manufacture that shape by accident.
	maxSandboxEvents = 1 << 20

	// canaryTimeout bounds the readiness/drain handshakes. `log stream`
	// attached and delivered the canary in ~7-12ms on the reference machine;
	// seconds of headroom costs nothing on the happy path.
	canaryTimeout = 15 * time.Second

	// probeWindow is how long one probe is given before another is published.
	// Sized well above the measured delivery latency so a healthy machine
	// never publishes a second probe, and short enough that a probe lost to a
	// not-yet-attached stream is replaced quickly.
	probeWindow = 400 * time.Millisecond

	// drainDeadline bounds the post-exit quiet wait. Exhausting it FAILS the
	// trace (see drain) rather than shipping whatever had arrived by then.
	drainDeadline = 3 * time.Second

	// quietWindow is how long the stream must go without a new in-tree
	// report before the drain considers the tail delivered. Belt to the
	// canary barrier's braces.
	quietWindow = 250 * time.Millisecond
)

// Operation names as the kext prints them. `process-exec*` is what the report
// line literally contains (the kernel echoes the wildcard rule name), and
// `process-exec-interpreter` is the separate report a shebang script produces
// for its interpreter — that second one is how /bin/sh shows up, i.e. the
// precise case DYLD interposition cannot see.
const (
	opExec            = "process-exec"
	opExecStar        = "process-exec*"
	opExecInterpreter = "process-exec-interpreter"
	opFork            = "process-fork"
	// opUnparseable marks a kernel sandbox report whose text did not fit the
	// report grammar (a path with a newline in it, a format drift). Nothing
	// about it is known but the pid, and that is enough to decide whether
	// its loss would be THIS build's loss: see buildDarwinTree.
	opUnparseable = "unparseable-report"
)

// The network operations, as the kext prints them. `network-outbound` is the
// one that can pull an undeclared input into a build; the other two are the
// serving side and are recorded but never counted against hermeticity.
const (
	opNetworkOutbound = "network-outbound"
	opNetworkInbound  = "network-inbound"
	opNetworkBind     = "network-bind"
)

func isNetworkOp(op string) bool {
	return op == opNetworkOutbound || op == opNetworkInbound || op == opNetworkBind
}

// darwinNetworkSyscall maps a sandbox network operation onto the syscall name
// the NetworkConnection contract uses, which is what cilock's hermeticity
// filter switches on (only "connect" is a fetch vector).
//
// IMPRECISION, STATED: `network-outbound` covers connect() AND a sendto() on
// an unconnected socket — measured, a UDP sendto with no connect() still
// reports `network-outbound remote:*:5353`. Both are the build reaching out,
// which is what the hermeticity question asks, so both are recorded as
// "connect". The predicate's darwin note says so rather than leaving a reader
// to assume a literal connect(2).
func darwinNetworkSyscall(op string) string {
	switch op {
	case opNetworkOutbound:
		return "connect"
	case opNetworkBind:
		return "bind"
	case opNetworkInbound:
		return "accept"
	}
	return ""
}

// sandboxEvent is one parsed report line.
//
// NOTE ON comm: this is the process's image name at the INSTANT of the report,
// which for an exec is the image name BEFORE the exec — i.e. for a freshly
// forked child it is the PARENT's name (`bash(16171) allow process-exec*
// /usr/bin/true`). It is real observed data, but it is NOT the process's own
// name, which is why it never lands in ProcessInfo.Comm. See buildDarwinTree.
type sandboxEvent struct {
	pid        int
	comm       string
	op         string
	detail     string // exec'd image path; empty for fork
	timestamp  string // verbatim from the log record; never reparsed
	duplicates int    // extra occurrences the kernel coalesced into this report
	// denied means the sandbox REFUSED the operation: the exec never ran, the
	// connect never reached the network. Recorded so the decision travels
	// with the event -- a denied attempt recorded as an executed image would
	// let a no-op build imitate a process tree out of refused execs.
	denied bool
	// pin identifies the image bytes THIS exec loaded, assigned when the
	// report arrived. The digest is looked up by this id rather than by
	// detail, because a path is a name that can be made to point at other
	// bytes between two execs, and an exec digest naming the wrong bytes is
	// worse than no digest at all.
	pin pinID
	// canary means THIS report was proven to be one of our own probes when it
	// arrived: the pid was a registered canary and the canary's kernel
	// incarnation still owned it (see canaryStillOwnsPID). Stamped per event
	// rather than looked up per pid at tree-build time, because a pid is only
	// a name — after the pid space wraps onto a dead probe's pid, later
	// reports under it belong to some new process, and skipping them "as the
	// canary" would hand a fork-heavy build a blessed pid to hide execs under.
	canary bool
}

// pinID identifies one pinned image inode within a session. Zero means NO PIN:
// an exec whose image could not be opened carries no digest rather than
// borrowing the digest of whatever else was pinned under the same path.
type pinID uint64

// imageIdentity is what the bytes of an exec'd image are, as the kernel
// identifies them. Not the path: a path is a name, and the whole reason to pin
// is that names can be repointed.
//
// gen is the inode generation number, so a recycled inode number reads as a
// different identity rather than the same one.
type imageIdentity struct {
	dev int32
	ino uint64
	gen uint32
}

// pinnedImage is an exec'd image held open by fd, with the id every exec event
// that loaded these bytes carries.
//
// sha256 is the CONTENT at report time. An fd pins an inode, not bytes, and
// macOS does not enforce ETXTBSY, so the same inode can be rewritten in place
// between the exec and the end-of-run digest; metadata (mtime) is forgeable
// with utimes, so time comparison cannot detect that honestly. The bytes are
// therefore hashed WHEN THE REPORT ARRIVES, and hashPinnedImages verifies the
// end-of-run read against this sum in the same pass — an inode whose content
// moved is refused a digest (counted, surfacing as imagesUnhashed) rather
// than signed with bytes that never ran.
type pinnedImage struct {
	id     pinID
	file   *os.File
	sha256 [sha256.Size]byte
	// hashedAt is when sha256 was computed. An unchanged stamp only proves
	// the inode was untouched once the clock has moved past the filesystem's
	// timestamp granularity: HFS+ and several network filesystems report
	// whole seconds, so an in-place rewrite that kept the size can carry the
	// SAME ctime as the read that hashed it. See stampSettled.
	hashedAt time.Time
	// stamp is the inode's ctime and size when its bytes were last hashed.
	// ctime is set by the kernel on every content or metadata change and,
	// unlike mtime, has no utimes(2) to forge it with — so an unchanged stamp
	// proves the inode was not touched since the hash, which is what lets a
	// repeat exec of /bin/sh reuse the pin without reading it again. A moved
	// stamp proves nothing either way (a hard link or chmod moves it too), so
	// it triggers a rehash, and the BYTES decide.
	stamp inodeStamp
}

// inodeStamp is the part of an inode's identity that changes when its content
// does, read from the same fd that pins it.
type inodeStamp struct {
	ctimeSec  int64
	ctimeNsec int64
	size      int64
}

// procFacts are kernel-read facts about a pid, polled at FIRST sighting.
//
// Polling at first sighting is what makes tree membership provable rather than
// inferred. It also has to win a race against the process exiting AND being
// reaped: a child stays visible to sysctl as a zombie only until its parent
// waits on it, and a shell reaps immediately. Sequential children win that
// race (2,001/2,001 and 501/501 on the reference machine); backgrounded ones
// do not — measured 2026-08-27 under load, 25–38% of the children of a
// 1,500-way `/usr/bin/true &` storm were gone before their report arrived.
// Nothing an unprivileged observer can do closes that window (kqueue
// NOTE_TRACK is ENOTSUP on XNU, and a kern.proc.pgrp snapshot costs 300µs+
// per call, longer than the child lives), so a lost poll is a stated
// outcome — the pid is unproven, its execs are listed without attribution
// (UnprovenExecs) — rather than a rare corner.
type procFacts struct {
	ppid int
	pgid int
	// startSec/startUsec are the process's kernel start time — the pid's
	// INCARNATION. A pid is only a name: after the pid space wraps, a new
	// process inherits an old pid, and facts cached for the first incarnation
	// would attribute the second one's work (or discard it as a canary). The
	// start time is what tells two incarnations apart.
	startSec  int64
	startUsec int32
	ok        bool // false = the poll lost the race; treat as UNPROVEN, never assume
}

// samePidIncarnation reports whether a fresh poll describes the SAME process
// the cached facts do, by kernel start time.
func samePidIncarnation(cached, current procFacts) bool {
	return cached.startSec == current.startSec && cached.startUsec == current.startUsec
}

// reconcileFacts decides what a pid's facts are after a NEW report arrived for
// a pid whose facts were already cached.
//
// If the pid still names the same incarnation (or is already gone — late
// reports for an exited process are normal), the cached facts stand. If a
// LIVE process with a different start time now owns the pid, the pid was
// recycled and NEITHER incarnation's membership is provable from here: the
// cached ancestry belongs to a dead process, and events keyed by this pid can
// no longer be told apart. The facts are POISONED to unproven — which fails
// toward non-hermetic for network activity (see recordUnprovenNetwork) and
// toward a smaller tree for execs — rather than letting the new process
// inherit the old chain, which would let a stranger (or a deliberately
// pid-wrapping build) put its work inside the signed tree.
func reconcileFacts(cached, current procFacts) (procFacts, bool) {
	if !cached.ok || !current.ok || samePidIncarnation(cached, current) {
		return cached, false
	}
	return procFacts{}, true
}

// syncBuffer is the collector's stderr sink. It must be mutex-guarded rather
// than a plain bytes.Buffer: os/exec's copy goroutine writes into it for as
// long as the collector lives, while the error paths here read it to explain a
// failure that is happening RIGHT NOW. The race detector caught exactly that
// pair; deferring the read until Wait() would trade a race for an error
// message that arrives after it is useful.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// sandboxSession owns the out-of-sandbox log collector for one traced command.
type sandboxSession struct {
	collector *exec.Cmd
	stdout    io.ReadCloser
	stderr    syncBuffer

	readerDone chan struct{}
	stopping   atomic.Bool
	// endedEarly is set when the collector's stdout hit EOF before we asked
	// it to stop — logd died, `log` was killed, the pipe broke. It means the
	// tail of the tree is unknown, which must fail the trace, not shrink it.
	endedEarly atomic.Bool

	// Everything below is mu-guarded. readerErr in particular is written by
	// the reader goroutine and read by harvest() while that goroutine may
	// still be running, so it needs the lock like the rest of them.
	mu         sync.Mutex
	readerErr  error
	events     []sandboxEvent
	facts      map[int]procFacts
	lastInTree time.Time
	unparsed   uint64
	// unattributable counts kernel sandbox reports that neither grammar
	// could read a pid out of. Not a count to publish and move on from:
	// harvest refuses the trace on it, because such a report may be this
	// build's exec or connect and nothing can say otherwise.
	unattributable uint64
	// networkProven records that a probe's NETWORK operation came back
	// through the report channel — see networkCanary. Without it the
	// attestation says network observation is unavailable rather than
	// inheriting the profile's intent.
	networkProven bool
	// argv0Normalized records that the wrapper will hand the child the
	// resolved path where the caller asked for a bare name. See
	// argv0Normalized in tracing_darwin.go.
	argv0Normalized bool
	// strangerChain caches provenStranger's verdict per pid.
	strangerChain map[int]bool
	// ambiguous counts reports carrying two readings of the kernel's header
	// (see ambiguousHeader). Like unattributable, harvest refuses on it: the
	// line may be this build's exec under a name chosen to hide it.
	ambiguous uint64
	// forged counts records that LOOKED like sandbox reports but did not come
	// from the kernel. See acceptedFromKernel — a non-zero value here means
	// something on this machine was writing sandbox-shaped messages into the
	// unified log while the build ran, which is either a bug or an attack, and
	// either way the operator wants to know.
	forged uint64
	capHit bool
	// pinned holds one open fd per distinct image INODE exec'd during the
	// session, keyed by kernel identity rather than by path, so two execs of
	// the same path with different bytes are two pins.
	pinned map[imageIdentity]pinnedImage
	// retiredPins counts pins whose inode was rewritten while the session
	// ran (see pin). Their fds are closed the moment they retire — an fd
	// held for a digest that will be refused anyway is only a way for a
	// tracee that rewrites one inode in a loop to exhaust cilock's
	// descriptor table — and each one is refused a digest at the end.
	retiredPins uint64
	nextPinID   pinID
	pinFailures uint64
	// lastProbePid and pidWrapped implement the pid-counter watch. XNU hands
	// out pids from one monotonically increasing counter that wraps at
	// PID_MAX, so within a session a pid can only be RECYCLED after that
	// counter wrapped — and our own probes, published at readiness, every
	// wrapProbeInterval while the command runs, and at drain, sample the
	// counter: a probe pid below the previous probe's is proof of a wrap.
	// A wrapped session fails closed (see harvest), because every pid-keyed
	// claim in it — ancestry, canary exclusion, late-report attribution —
	// rests on a pid naming one process for the whole session.
	lastProbePid int
	pidWrapped   bool
	wrapWatchErr error
	wrapWatch    chan struct{}
	wrapDone     chan struct{}
	wrapStop     sync.Once
	// pidReuse counts pids observed to change incarnation mid-session; their
	// facts are poisoned to unproven when it happens (see reconcileFacts).
	pidReuse uint64
	// canaryPIDs are our own readiness/drain probes, keyed by pid with the
	// probe's kernel INCARNATION (start time, polled while the probe was still
	// alive) as the value. cilock forks the probes itself, so their parent
	// chain leads to cilock rather than to the traced root; their reports are
	// excluded from the tree so a probe cannot be counted as the build's work
	// or as an unproven gap in it. The incarnation is what keeps that
	// exclusion honest: a pid recycled onto some other process after the probe
	// died stops being a canary (canaryStillOwnsPID retires it), rather than
	// staying a blessed pid whose activity is skipped for the whole session.
	canaryPIDs map[int]procFacts

	// rootPid and ourPids scope the drain's quiet detection to reports that
	// COULD belong to this build. The stream is machine-wide; without the
	// scope, any other sandboxed app's chatter would hold the quiet window
	// open and a fail-closed drain would refuse honest builds on busy
	// machines. rootPid is published by trace() the moment Start returns;
	// ourPids grows incrementally as kernel-read parent edges reach the root.
	// This set is a HEURISTIC for drain timing only — final tree membership
	// is decided from scratch by resolveTreeMembers.
	rootPid int
	ourPids map[int]bool
	// rootFacts is the root's kernel incarnation, read the moment trace()
	// publishes it. Its start time is the line that separates "was already
	// running when the build began" from "appeared during it", which is what
	// decides whether a process hanging off launchd is a stranger or a
	// descendant whose parent exited (see reparentedAfterRoot).
	rootFacts procFacts
	// rootUID is the root's uid, read with rootFacts while the root is
	// alive; the exit sweep compares launchd's orphans against it after the
	// root is gone from the table.
	rootUID uint32
	// unobserved is what the process-table sweep found at exit: descendants
	// that never reported (see sweepUnobservedDescendants).
	unobserved map[int]procFacts
}

// reportedComms maps every pid that reported to the comm its reports
// carried (the last one seen: a pid that exec'd reports under the new name
// afterwards).
func (s *sandboxSession) reportedComms() map[int]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]string, len(s.facts))
	for i := range s.events {
		if s.events[i].comm != "" {
			out[s.events[i].pid] = s.events[i].comm
		}
	}
	return out
}

// factsSnapshot copies s.facts under the lock. The collector's reader
// goroutine writes s.facts for every machine-wide report until shutdown, and
// the exit sweep runs while it is still live: reading the map beside that
// writer is `fatal error: concurrent map read and map write`, which no
// recover catches and which would kill the build after the command ran.
func (s *sandboxSession) factsSnapshot() map[int]procFacts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.facts)
}

// canarySet returns the probe pids as a set, for the tree resolution that
// runs after the session is otherwise finished with.
func (s *sandboxSession) canarySet() map[int]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]bool, len(s.canaryPIDs))
	for pid := range s.canaryPIDs {
		out[pid] = true
	}
	return out
}

// noteArgv0Normalized records whether the wrapper rewrites argv[0].
func (s *sandboxSession) noteArgv0Normalized(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.argv0Normalized = v
}

// noteUnobservedDescendants records the sweep's result on the session.
func (s *sandboxSession) noteUnobservedDescendants(found map[int]procFacts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unobserved = found
}

// startSandboxSession starts the log collector and proves it is live before
// the caller is allowed to run anything. Every failure returns an error; there
// is no partial-success path, because a session that "mostly" started produces
// a tree with an unknowable hole in the front.
func startSandboxSession() (*sandboxSession, error) {
	if _, err := os.Stat(sandboxExecPath); err != nil {
		return nil, fmt.Errorf("macOS process tracing needs %s (sandbox-exec), which is not usable: %w",
			sandboxExecPath, err)
	}
	if _, err := os.Stat(logToolPath); err != nil {
		return nil, fmt.Errorf("macOS process tracing needs %s (the unified-log reader), which is not usable: %w",
			logToolPath, err)
	}

	// #nosec G204 -- both the binary path and every argument are package
	// constants; nothing here is caller- or environment-controlled.
	col := exec.Command(logToolPath, "stream", "--style", "ndjson", "--predicate", logPredicate)
	s := &sandboxSession{
		readerDone: make(chan struct{}),
		facts:      make(map[int]procFacts, 256),
		pinned:     make(map[imageIdentity]pinnedImage, 64),
		canaryPIDs: make(map[int]procFacts, 4),
		ourPids:    make(map[int]bool, 64),
		collector:  col,
	}
	col.Stderr = &s.stderr
	pipe, err := col.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("macOS process tracing: log stream stdout: %w", err)
	}
	s.stdout = pipe
	if err := col.Start(); err != nil {
		return nil, fmt.Errorf("macOS process tracing: could not start %s stream: %w", logToolPath, err)
	}
	go s.read()

	// Readiness is PROVEN, not slept for: run a throwaway command under the
	// same profile and wait until its exec shows up in the stream. One probe
	// settles three questions at once — the stream is live, the profile is
	// accepted by this OS version, and we are not already inside a sandbox
	// (nesting fails here, before the user's command has run).
	if err := s.canary("readiness"); err != nil {
		s.shutdown()
		return nil, err
	}
	// Exec reports are proven; network reports are a SEPARATE capability and
	// are proven separately. See networkCanary.
	s.networkCanary()
	return s, nil
}

// canary publishes sandboxed no-ops until it observes one of them come back
// through the stream.
//
// It RETRIES rather than probing once, because `log stream` attaches
// asynchronously: a probe that fires before the stream is live produces a
// report nobody is listening for, and that single report is gone forever.
// Waiting out the timeout on it made the handshake flaky under load — a
// spurious refusal of an honest build, which is the failure mode this attestor
// can least afford. Republishing costs one /usr/bin/true per window.
func (s *sandboxSession) canary(phase string) error {
	deadline := time.Now().Add(canaryTimeout)
	for time.Now().Before(deadline) {
		pid, err := s.publishProbe(phase)
		if err != nil {
			return err
		}
		window := time.Now().Add(probeWindow)
		for time.Now().Before(window) {
			if s.sawPID(pid) {
				return nil
			}
			if s.endedEarly.Load() {
				return fmt.Errorf("macOS process tracing: the %s collector exited during the %s probe "+
					"(stderr: %q); the report channel is gone, so no process tree can be captured",
					logToolPath, phase, strings.TrimSpace(s.stderr.String()))
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	return fmt.Errorf("macOS process tracing: %s probes ran but none was reported by %s within %s "+
		"(collector stderr: %q). The unified-log channel this attestor observes through is not "+
		"delivering sandbox reports, so no process tree can be captured",
		phase, logToolPath, canaryTimeout, strings.TrimSpace(s.stderr.String()))
}

// publishProbe runs one sandboxed /usr/bin/true and returns its pid. A probe
// that cannot APPLY the sandbox is fatal immediately and separately from the
// timeout: that is the nesting case, and the operator needs to be told which
// of the two happened.
func (s *sandboxSession) publishProbe(phase string) (int, error) {
	// #nosec G204 -- fixed binary, fixed profile constant, fixed /usr/bin/true.
	c := exec.Command(sandboxExecPath, "-p", sandboxProfile, "--", "/usr/bin/true")
	var probeErr bytes.Buffer
	c.Stderr = &probeErr
	if err := c.Start(); err != nil {
		return 0, fmt.Errorf("macOS process tracing: %s probe could not start %s: %w", phase, sandboxExecPath, err)
	}
	pid := c.Process.Pid
	// The probe's kernel incarnation is read NOW, while the process is
	// guaranteed alive (Wait has not run, so even a finished probe is still a
	// visible zombie). It is the only moment the probe's start time can be
	// read at all, and it is what later tells "a late report from our probe"
	// apart from "the kernel recycled this pid onto someone else".
	s.mu.Lock()
	s.canaryPIDs[pid] = pollProcFacts(pid)
	s.noteProbePid(pid)
	s.mu.Unlock()

	if err := c.Wait(); err != nil {
		return 0, fmt.Errorf("macOS process tracing: %s probe failed (%w): %s\n"+
			"This is what a NESTED sandbox looks like ('sandbox_apply: Operation not permitted'): "+
			"sandboxes do not nest, so cilock cannot trace a command that is itself already sandboxed. "+
			"Re-run outside the outer sandbox, or disable tracing for this step — an untraced run must "+
			"not produce an attestation that implies a process tree was observed",
			phase, err, strings.TrimSpace(probeErr.String()))
	}
	return pid, nil
}

// noteProbePid samples the kernel's pid counter through one of our own
// probes. Caller holds s.mu. Probes are published in order, so a pid below
// the previous probe's can only mean the counter wrapped between them.
func (s *sandboxSession) noteProbePid(pid int) {
	if s.lastProbePid != 0 && pid < s.lastProbePid {
		s.pidWrapped = true
	}
	s.lastProbePid = pid
}

// wrapProbeInterval bounds how long the pid counter goes unsampled while the
// command runs. A wrap that escapes the watch needs the whole pid space
// (PID_MAX, 99,999 on macOS) consumed between two consecutive probes: at 5s
// that is a sustained 20,000 process creations per second machine-wide,
// which is stated here as the residual rather than claimed impossible.
const wrapProbeInterval = 5 * time.Second

// startWrapWatch publishes a probe every wrapProbeInterval until stopped, so
// a long build cannot outrun the readiness-to-drain comparison: those two
// probes alone would miss a counter that wrapped AND advanced past the
// readiness pid again.
func (s *sandboxSession) startWrapWatch() {
	s.wrapWatch = make(chan struct{})
	s.wrapDone = make(chan struct{})
	go func() {
		defer close(s.wrapDone)
		t := time.NewTicker(wrapProbeInterval)
		defer t.Stop()
		for {
			select {
			case <-s.wrapWatch:
				return
			case <-t.C:
				if _, err := s.publishProbe("pid-wrap watch"); err != nil {
					s.mu.Lock()
					s.wrapWatchErr = err
					s.mu.Unlock()
					return
				}
			}
		}
	}()
}

// stopWrapWatch ends the periodic probes and waits for an in-flight one, so
// no probe is published after the drain canary. Safe to call twice.
func (s *sandboxSession) stopWrapWatch() {
	// THE UNSTARTED CASE IS CHECKED BEFORE THE ONCE, NOT INSIDE IT. Inside,
	// an early return still CONSUMES the guard: a stop that ran before any
	// start would leave the real stop — the one after startWrapWatch spawned
	// the ticker goroutine — a no-op, leaking a goroutine that goes on
	// publishing probes into the machine-wide log stream for the life of the
	// process, seeding reports into whatever session reads the stream next.
	if s.wrapWatch == nil {
		return
	}
	s.wrapStop.Do(func() {
		close(s.wrapWatch)
		<-s.wrapDone
	})
}

// sawPID answers "has a report for this pid arrived yet".
//
// A stale facts entry from an EARLIER incarnation of this pid could answer
// "seen" before the probe's own report arrives — but a probe pid that was
// already in the map is one the counter handed out twice, which is a wrap,
// and noteProbePid has by then marked the session to fail closed regardless
// of what this handshake concludes. It reads the facts
// map, which record() keys by every pid it has seen, rather than scanning the
// event slice: the drain handshake polls this every 5ms while holding the
// reader's lock, and an O(events) scan there would stall the reader exactly
// when a 12,000-exec build has the most events queued behind it.
func (s *sandboxSession) sawPID(pid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, seen := s.facts[pid]
	return seen
}

// sawNetworkFromPID reports whether a NETWORK operation from this pid came
// back through the stream.
// sawNetworkOpFromPID asks whether ONE SPECIFIC operation class came back from
// a probe, rather than "any network report at all".
//
// That distinction is the whole capability question. The verdict keys on two
// classes — an outbound connect is a fetch, an ACCEPTED inbound connection is
// an undeclared input channel — and proving one says nothing about the other.
// A probe that only connects can set "the network channel works" while inbound
// reports never arrive, and a build being fed from outside would then publish
// an empty egress list under an affirmative negative claim.
func (s *sandboxSession) sawNetworkOpFromPID(pid int, op string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.events {
		if s.events[i].pid == pid && s.events[i].op == op {
			return true
		}
	}
	return false
}

// heldProbe is a sandboxed probe that cannot act until it has been registered
// as a canary.
type heldProbe struct {
	pid     int
	cmd     *exec.Cmd
	release func()
}

// startHeldProbe launches a probe BLOCKED on a read from a pipe, registers its
// pid, and returns it unreleased.
//
// Registration must beat the probe's first report. A loopback operation
// completes in microseconds, and a report landing before canaryPIDs holds the
// pid is stamped ev.canary=false permanently — after which our own probe's
// traffic is attributed to the build root as egress, and a hermetic build
// comes back non-hermetic on scheduler luck. `exec` replaces the shell in the
// SAME pid, so the pid registered here is the pid that acts, and the
// incarnation read at registration survives the exec.
func (s *sandboxSession) startHeldProbe(script string) (heldProbe, bool) {
	r, w, err := os.Pipe()
	if err != nil {
		return heldProbe{}, false
	}
	// #nosec G204 -- fixed binary, fixed profile constant, fixed loopback arguments.
	c := exec.Command(sandboxExecPath, "-p", sandboxProfile, "--", "/bin/sh", "-c", script, networkProbePath)
	c.Stdout, c.Stderr = nil, nil
	c.Stdin = r
	if err := c.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return heldProbe{}, false
	}
	_ = r.Close() // the child holds its own copy
	pid := c.Process.Pid
	s.mu.Lock()
	s.canaryPIDs[pid] = pollProcFacts(pid)
	s.noteProbePid(pid)
	s.mu.Unlock()
	return heldProbe{pid: pid, cmd: c, release: func() { _ = w.Close() }}, true
}

// freeLoopbackPort asks the kernel for an unused loopback port and hands it
// straight back, so the probe pair has somewhere to meet. The gap between
// closing and the listener binding is a race, but losing it only costs the
// capability proof — networkObserved stays false and the verdict is withheld —
// never a wrong answer.
func freeLoopbackPort() (int, bool) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, false
	}
	defer func() { _ = l.Close() }()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, false
	}
	return addr.Port, true
}

func (s *sandboxSession) sawNetworkFromPID(pid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.events {
		if s.events[i].pid == pid && isNetworkOp(s.events[i].op) {
			return true
		}
	}
	return false
}

// networkCanary proves the channel actually DELIVERS network reports, rather
// than inferring it from the profile text.
//
// The readiness probe runs /usr/bin/true: it proves exec reports arrive and
// says nothing about network ones. A backend that accepts the profile but
// stops emitting network-* events would then produce an empty egress list on
// a build that fetched the world, and cilock — which keys its hermeticity
// claim on networkObserved — would sign it as hermetic. So one probe makes a
// connection whose report MUST come back: a connect to 127.0.0.1:1, which is
// refused by the loopback stack in microseconds, leaves the machine never,
// and reaches no service. Failure is NOT fatal: it means the capability is
// unavailable, which the attestation states (networkObserved=false) and
// cilock reads as "make no hermeticity claim".
// networkCanary proves the channel actually DELIVERS network reports, rather
// than inferring it from the profile text — and proves it for BOTH operation
// classes the verdict keys on.
//
// The readiness probe runs /usr/bin/true: it proves exec reports arrive and
// says nothing about network ones. A backend that accepted the profile but
// stopped emitting network-* events would hand back an empty egress list on a
// build that fetched the world, and cilock keys its hermeticity claim on
// networkObserved.
//
// Proving only OUTBOUND is not enough, and that gap was live until this
// change: cilock counts an outbound connect as a fetch AND an accepted inbound
// connection as an undeclared input channel, so an outbound-only proof lets
// "the network channel works" be true while inbound reports never arrive — and
// a build being fed from outside then publishes an empty egress list under an
// affirmative no-egress claim. That is the same hole this probe exists to
// close, one operation class over.
//
// Measured on macOS 15.7.7/arm64 before it was built, because a previous
// attempt at this shipped nothing and silently zeroed the verdict: a sandboxed
// listener emits BOTH network-bind and network-inbound, and the connecting
// process emits network-outbound under its own pid —
//
//	Sandbox: nc(34518) allow network-bind     local:*:45123
//	Sandbox: nc(34518) allow network-inbound  local:*:45123
//	Sandbox: nc(34521) allow network-outbound remote:*:45123
//
// so a LISTENER probe and a CONNECTOR probe, both registered as canaries
// before either can act, prove both classes without either one's traffic ever
// being booked as the build's.
// waitForLoopbackPort reports whether something is accepting on the port
// before the deadline. Used to sequence the probe pair from cilock, which is
// not sandboxed and therefore contributes no reports.
func waitForLoopbackPort(port int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func (s *sandboxSession) networkCanary() {
	if _, err := os.Stat(networkProbePath); err != nil {
		return
	}
	deadline := time.Now().Add(probeWindow * 4)
	port, ok := freeLoopbackPort()
	if !ok {
		return
	}
	// -k so the listener survives the readiness dial below and is still there
	// for the connector. EXEC, not a subshell: the pid registered as a canary
	// has to be the pid that acts, or its reports are attributed to an
	// unregistered child and booked as the BUILD's traffic.
	listener, ok := s.startHeldProbe(`read _ 2>/dev/null; exec "$0" -l -k 127.0.0.1 ` + strconv.Itoa(port))
	if !ok {
		return
	}
	// RELEASED BEFORE THE CONNECTOR IS EVEN STARTED, so it has the whole of
	// the connector's own startup to bind. Releasing both together is what
	// made the earlier attempt fail: the connector raced a listener that had
	// not bound yet.
	listener.release()
	// WAIT FOR THE LISTENER TO BE BOUND, from cilock itself rather than by
	// retrying inside the probe. This dial is unsandboxed, so it produces no
	// sandbox report of its own and cannot be mistaken for the build's
	// traffic; with -k it does not consume the listener either. Losing this
	// race costs only the capability proof, never a wrong answer.
	if !waitForLoopbackPort(port, probeWindow) {
		s.reapProbe(listener)
		return
	}

	// A SINGLE exec'd connect, with no retry loop. An earlier revision looped
	// in the shell — `"$0" -z ...` inside a while — which FORKS nc as a child,
	// so network-outbound was reported against a pid that was never
	// registered. Measured: the connector produced process-fork and no
	// outbound at all, which is why this probe pair silently proved nothing.
	// Readiness is established above instead, from a process that emits no
	// sandbox reports.
	connector, ok := s.startHeldProbe(`read _ 2>/dev/null; exec "$0" -z -G 1 127.0.0.1 ` + strconv.Itoa(port))
	if !ok {
		s.reapProbe(listener)
		return
	}
	connector.release()
	_ = connector.cmd.Wait()
	// The listener has done its job once someone has connected; it would
	// otherwise hold the port for the life of the run.
	s.reapProbe(listener)

	for time.Now().Before(deadline) {
		outbound := s.sawNetworkOpFromPID(connector.pid, opNetworkOutbound)
		// An accept is reported against the LISTENER, but both are consulted:
		// what matters is that an inbound report came back through the channel
		// from a process we know is ours, not which of the two the kernel
		// attributed the accepted socket to.
		inbound := s.sawNetworkOpFromPID(listener.pid, opNetworkInbound) ||
			s.sawNetworkOpFromPID(connector.pid, opNetworkInbound)
		if outbound && inbound {
			s.mu.Lock()
			s.networkProven = true
			s.mu.Unlock()
			return
		}
		if s.endedEarly.Load() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// reapProbe stops a probe and collects it, so a listener never outlives the
// run holding a port.
func (s *sandboxSession) reapProbe(p heldProbe) {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

// isCanaryPid reports whether the pid is a currently-registered probe.
// Caller holds s.mu.
func (s *sandboxSession) isCanaryPid(pid int) bool {
	_, ok := s.canaryPIDs[pid]
	return ok
}

// canaryStillOwnsPID decides whether a report under a registered canary pid is
// really the probe's, by kernel incarnation. Caller holds s.mu.
//
// The probe's start time was read at publish. When a LIVE process with a
// DIFFERENT start time owns the pid now, the kernel has recycled it: the
// canary is RETIRED — its registration deleted, the new owner's facts cached,
// the recycle counted — and this report (and every later one) goes through
// ordinary kernel-proven attribution instead of being skipped as a probe.
// A failed poll cannot retire anything: every probe is reaped by Wait before
// its report arrives, so an unreadable pid is the NORMAL late-report shape,
// and the registration stands.
func (s *sandboxSession) canaryStillOwnsPID(pid int, ci procFacts) bool {
	if !ci.ok {
		// No incarnation could be read at publish; there is nothing to compare
		// against, so the registration cannot be disproven.
		return true
	}
	live := pollProcFacts(pid)
	if !live.ok || samePidIncarnation(ci, live) {
		return true
	}
	delete(s.canaryPIDs, pid)
	s.facts[pid] = live
	s.pidReuse++
	return false
}

// wrap rewrites the command to run under the observation profile.
//
// argv[0] CHANGES: sandbox-exec execs the target with the argv it was handed,
// so the child sees its resolved path as argv[0] rather than whatever the
// caller put in Args[0]. Commands that branch on argv[0] (busybox-style
// multi-call binaries) would see a different name. Recorded here rather than
// papered over.
func (s *sandboxSession) wrap(c *exec.Cmd) {
	// sandbox-exec execs the target under its resolved path, so argv[0]
	// becomes c.Path. That is the same NAME as the caller's argv[0] for every
	// ordinary invocation (exec.Command("go") → "go" vs ".../bin/go"), and a
	// multi-call binary dispatches on that name. An argv[0] whose basename
	// differs from the executable's is a request to run the binary under an
	// alias this wrapper cannot preserve; enableTracing refuses it before the
	// session exists rather than trace behavior the caller did not ask for.
	args := make([]string, 0, len(c.Args)+4)
	args = append(args, sandboxExecPath, "-p", sandboxProfile, "--", c.Path)
	// os/exec treats a nil or single-element Args as "argv is just Path", and
	// argv0Preserved accepts that shape — so there may be nothing to carry
	// through. c.Args[1:] on a nil slice panics, inside enableTracing, before
	// the command has run.
	if len(c.Args) > 1 {
		args = append(args, c.Args[1:]...)
	}
	c.Path = sandboxExecPath
	c.Args = args
}

// read consumes the collector's ndjson and does the two time-critical things
// inline, because both lose to a race if deferred: poll a new pid's kernel
// facts while it is still visible, and pin an exec'd image's inode with an
// open fd before anything can replace the file at that path.
func (s *sandboxSession) read() {
	defer close(s.readerDone)
	sc := bufio.NewScanner(s.stdout)
	// Report lines carry full paths; the default 64KiB token limit is
	// generous but a deep path plus a coalescing prefix can approach it.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		// `log stream` prints a human banner ("Filtering the log data using
		// ...") before the ndjson. Anything that is not an object is not
		// ours to interpret.
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec struct {
			EventMessage string `json:"eventMessage"`
			Timestamp    string `json:"timestamp"`
			// PROVENANCE. Decoded because the message text alone is forgeable:
			// os_log is an ordinary API, so any process can emit a line that
			// parses as a sandbox report. Without these fields the tree could
			// be fabricated with two os_log calls, no key and no privileges —
			// which was demonstrated end to end against an earlier revision.
			ProcessImagePath string `json:"processImagePath"`
			SenderImagePath  string `json:"senderImagePath"`
			ProcessID        *int   `json:"processID"`
			UserID           *int   `json:"userID"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			s.mu.Lock()
			s.unparsed++
			s.mu.Unlock()
			continue
		}
		// Only a line SHAPED like a sandbox report is a candidate for the
		// provenance check: the log predicate is a sender-name match, and an
		// ordinary framework log line from a user process is not a forgery
		// attempt, it is just not a report.
		if !looksLikeSandboxReport(rec.EventMessage) {
			continue
		}
		if !acceptedFromKernel(rec.ProcessImagePath, rec.SenderImagePath, rec.ProcessID, rec.UserID) {
			s.mu.Lock()
			s.forged++
			s.mu.Unlock()
			continue
		}
		if ambiguousHeader(rec.EventMessage) {
			s.mu.Lock()
			s.ambiguous++
			s.mu.Unlock()
			continue
		}
		ev, ok := parseSandboxReport(rec.EventMessage)
		if !ok {
			// A kernel-originated sandbox report this parser could not read
			// is NOT silently gone: a path with a newline defeats the
			// anchored grammar, and so would a format change in a new OS.
			// If its pid can still be read it is recorded as unparseable and
			// fails the trace when the pid is this build's (or undecidable);
			// a report about a proven stranger is merely counted.
			//
			// Only a line about an operation we TRACE counts. A readable
			// report naming an operation the profile never asked for
			// (another sandbox user's mach-lookup, a logged file read) is
			// irrelevant and must not become a refusal of this build — but a
			// report about an op we do trace that the strict grammar could
			// not read is evidence going missing, and takes the path below.
			if irrelevantReport(rec.EventMessage) {
				continue
			}
			if pid, isReport := unparseableReportPid(rec.EventMessage); isReport {
				s.record(sandboxEvent{pid: pid, op: opUnparseable, timestamp: rec.Timestamp})
			} else {
				// A kernel report with not even a pid to attribute it by (a
				// comm with a newline defeats both grammars). Whose it is
				// cannot be decided, and an undecidable report refuses the
				// trace at harvest: its exec or connect may be this build's.
				s.mu.Lock()
				s.unattributable++
				s.mu.Unlock()
			}
			continue
		}
		ev.timestamp = rec.Timestamp
		s.record(ev)
	}
	if err := sc.Err(); err != nil {
		s.mu.Lock()
		s.readerErr = err
		s.mu.Unlock()
	}
	if !s.stopping.Load() {
		s.endedEarly.Store(true)
	}
}

func (s *sandboxSession) record(ev sandboxEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= maxSandboxEvents {
		s.capHit = true
		return
	}
	if cached, seen := s.facts[ev.pid]; !seen {
		s.facts[ev.pid] = pollProcFacts(ev.pid)
	} else if cached.ok {
		// Re-poll on every later sighting: a pid wrap inside one session
		// would otherwise hand the new process the old incarnation's proven
		// ancestry. One sysctl per event, microseconds, and only for pids
		// whose facts could admit something to the tree.
		if facts, recycled := reconcileFacts(cached, pollProcFacts(ev.pid)); recycled {
			s.facts[ev.pid] = facts
			s.pidReuse++
		}
	}
	if ci, isCanary := s.canaryPIDs[ev.pid]; isCanary {
		ev.canary = s.canaryStillOwnsPID(ev.pid, ci)
	}
	if isExecOp(ev.op) && ev.detail != "" && !ev.denied {
		// A denied exec loaded no bytes; pinning the path would digest an
		// image that never ran.
		at, ok := reportTime(ev.timestamp)
		ev.pin = s.pin(ev.detail, at, ok)
	}
	s.events = append(s.events, ev)
	s.noteActivity(ev.pid)
}

// noteActivity refreshes the drain's quiet clock for a report that could be
// this build's, and grows the incremental member set. Caller holds s.mu.
//
// Three shapes refresh the clock: the root or an already-linked descendant; a
// pid whose kernel-read parent is one of those (linked now); and a pid whose
// facts could not be read — unknown is not provably foreign, and the drain
// must not go quiet while possibly-ours reports are still arriving. A pid
// PROVEN foreign (facts read, chain elsewhere) does not touch the clock, which
// is what keeps a fail-closed drain usable on a Mac where Safari narrates its
// own traffic the whole time. Before trace() publishes the root pid, every
// report refreshes the clock — the conservative direction.
func (s *sandboxSession) noteActivity(pid int) {
	if s.rootPid == 0 {
		s.lastInTree = time.Now()
		return
	}
	f := s.facts[pid]
	switch {
	case pid == s.rootPid || s.ourPids[pid]:
		s.lastInTree = time.Now()
	case f.ok && (f.ppid == s.rootPid || s.ourPids[f.ppid]):
		s.ourPids[pid] = true
		s.lastInTree = time.Now()
	case !f.ok && !s.isCanaryPid(pid):
		s.lastInTree = time.Now()
	case f.ok && !s.isCanaryPid(pid) && startedAfter(f, s.rootFacts) && !s.provenStranger(pid):
		// Readable, not linked, but it STARTED AFTER THE ROOT: its
		// parent's report may simply not have arrived yet, or its parent
		// exited before the poll and launchd adopted it. Both are decided
		// unproven at snapshot time, so the drain must not go quiet on
		// them either — a drain that finished on this pid's silence would
		// have killed the collector with its next exec or connect in
		// flight. Only a process that predates the root is provably not
		// this build's, and only that one leaves the clock alone.
		s.lastInTree = time.Now()
	}
}

// startedAfter reports whether f's kernel start time is later than root's.
// Both must be readable; an unreadable root decides nothing here (trace()
// refuses such a run at start).
func startedAfter(f, root procFacts) bool {
	if !f.ok || !root.ok {
		return false
	}
	return f.startSec > root.startSec || (f.startSec == root.startSec && f.startUsec > root.startUsec)
}

// provenStranger reports whether pid's ancestry PROVES it is not this
// build's: the chain reaches a process that was already running when the
// root started, or cilock itself.
//
// The log stream is machine-wide, so without this every app launched during
// a build refreshed the drain clock and could keep the quiet window from
// ever closing — failing an honest attestation on a busy machine. Only a
// PROOF of non-descent silences a pid; an unreadable ancestor leaves it
// undecidable, which still holds the drain open, because a lost late report
// is the worse error. The verdict is cached, so this costs one bounded walk
// per pid per session, and it reads only facts already collected —
// pollProcFacts is never called here, on the collector's hot path, under
// the lock. Caller holds s.mu.
func (s *sandboxSession) provenStranger(pid int) bool {
	if v, done := s.strangerChain[pid]; done {
		return v
	}
	if s.strangerChain == nil {
		s.strangerChain = map[int]bool{}
	}
	selfPid := os.Getpid()
	verdict := false
	cur := s.facts[pid]
	for hops := 0; cur.ok && hops <= maxAncestryHops; hops++ {
		pp := cur.ppid
		if pp == s.rootPid || s.ourPids[pp] {
			break // ours: not a stranger
		}
		if pp == selfPid {
			verdict = true
			break
		}
		next, known := s.facts[pp]
		if !known || !next.ok {
			break // undecidable: not proven either way
		}
		if startedBefore(next, s.rootFacts) {
			verdict = true // an ancestor that predates the build
			break
		}
		cur = next
	}
	s.strangerChain[pid] = verdict
	return verdict
}

// noteRoot publishes the traced root's pid to the collector, links any
// already-seen descendants to it, and starts the quiet clock.
func (s *sandboxSession) noteRoot(rootPid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rootPid = rootPid
	// ONE snapshot for both. Two reads let a fast root exit between them:
	// the facts land, the uid read fails, and rootUID silently stays 0 —
	// after which the exit sweep filters launchd orphans by uid 0 and misses
	// the user's own detached descendant. trace() refuses when the facts are
	// missing, so a single read makes "facts known" and "uid known" the same
	// condition instead of two that can disagree.
	if kp, err := readKinfo(rootPid); err == nil && kp != nil {
		s.rootFacts = factsOfKinfo(kp)
		s.rootUID = kp.Eproc.Ucred.Uid
	}
	// Reports can arrive between Start and this call; link what the facts
	// already prove, iterating to a fixpoint since report order does not put
	// parents first.
	for changed := true; changed; {
		changed = false
		for pid, f := range s.facts {
			if s.ourPids[pid] || !f.ok {
				continue
			}
			if f.ppid == rootPid || s.ourPids[f.ppid] {
				s.ourPids[pid] = true
				changed = true
			}
		}
	}
	s.lastInTree = time.Now()
}

// pin holds an open fd on an exec'd image and returns the id of the bytes it
// pinned, so the digest computed later is the digest of the inode that was
// EXECUTED rather than of whatever occupies that path when the build finishes.
//
// IDENTITY IS THE INODE, NOT THE PATH, and the returned id is what ties one
// exec EVENT to one set of bytes. Answering by path once and trusting it
// afterwards is the same failure in slower motion: run /tmp/tool, rename
// different bytes over /tmp/tool, run it again, and a path-keyed pin reports
// the first inode's digest for BOTH execs — naming bytes that never ran and
// omitting the bytes that did, the exact inversion an exec digest exists to
// prevent. So every exec report opens the path and asks the kernel which inode
// it landed on; only a repeat of the SAME inode reuses an existing pin.
//
// Residual race, stated rather than hidden: the bytes are hashed when the
// REPORT arrives, single-digit milliseconds after the exec, and the end-of-run
// digest is verified against that hash (see hashPinnedImages) — so an in-place
// rewrite of the same inode after the report is DETECTED and the digest
// refused, and the only unprovable window is report-delivery latency itself.
// That is the same class of window Linux's openat-time path-hash carries, and
// it is why exec events are tagged digestSource "collector-open-path-hash" rather
// than claimed as exact.
// reportTime parses a kernel report's timestamp. An unparseable one yields
// the zero time, which callers treat as "no time to compare against".
func reportTime(ts string) (time.Time, bool) {
	// The unified log's ndjson stamp, measured from a live `log show
	// --style ndjson` on macOS 15: "2026-08-27 21:37:05.747383-0500" — a
	// space separator, fractional seconds, and NO space before the zone.
	// The first cut of this function listed RFC3339 and a Go-default layout
	// with " -0700 MST"; none of them matched, so every parse returned the
	// zero time and the caller's replaced-image check SILENTLY never ran.
	// That is why the caller now fails closed on !ok rather than skipping.
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999-0700",
		"2006-01-02 15:04:05-0700",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// pin opens the image at path and holds it. reportedAt is when the KERNEL
// said the exec happened; it is what lets pin notice that the bytes now at
// that path are not the bytes that ran.
func (s *sandboxSession) pin(path string, reportedAt time.Time, haveReportTime bool) pinID {
	f, err := openImage(path)
	if err != nil {
		s.pinFailures++
		return 0
	}
	id, stamp, err := imageIdentityOf(f)
	if err != nil {
		_ = f.Close()
		s.pinFailures++
		return 0
	}
	// THE RENAME-OVER, which is the one shape the report's path binding
	// cannot otherwise survive: exec disallowed image A, then rename allowed
	// image B over that path before this open runs. B is unchanged from here
	// to the end of the run, so B's digest would be signed as the image that
	// executed — and no later check could tell, because nothing in the
	// report names the vnode.
	//
	// A rename or a create sets the inode's ctime, and the file that ACTUALLY
	// ran existed before the kernel reported the exec. So an inode whose
	// ctime is LATER than the report's own timestamp is provably not what
	// ran: refuse it a digest rather than describe the wrong bytes. The exec
	// then counts as attributed-but-undigested, which refuses the trace.
	// (Residual, stated: a swap performed with the ORIGINAL inode preserved —
	// writing B's bytes into A's inode — is the in-place rewrite case, which
	// the end-of-run content check already catches.)
	// FAIL CLOSED. Without a usable report time there is nothing to compare
	// the inode's ctime against, so the replaced-image case cannot be ruled
	// out — and a check that cannot run must not pass by default. No digest.
	if !haveReportTime {
		_ = f.Close()
		s.pinFailures++
		return 0
	}
	if ctime := time.Unix(stamp.ctimeSec, stamp.ctimeNsec); ctime.After(reportedAt) {
		_ = f.Close()
		s.pinFailures++
		return 0
	}
	if existing, ok := s.pinned[id]; ok {
		if existing.stamp == stamp && stampSettled(stamp, existing.hashedAt) {
			// Untouched since it was hashed: the same bytes, already held
			// open by an earlier exec of this path or of any other name for
			// it. Release the duplicate fd and reuse the pin.
			_ = f.Close()
			return existing.id
		}
		// The inode was touched since the pin. Whether its BYTES changed is
		// the question, and only reading them answers it: a hard link or a
		// chmod moves the stamp and changes nothing this exec loaded, while
		// an in-place rewrite means what THIS exec loaded is not what the
		// earlier pin measured, and reusing that pin would name the wrong
		// bytes for one of the two execs.
		if sum, err := sha256Of(f); err == nil && sum == existing.sha256 {
			existing.stamp = stamp
			existing.hashedAt = time.Now()
			s.pinned[id] = existing
			_ = f.Close()
			return existing.id
		}
		// Rewritten. The earlier pin is retired and its digest refused —
		// the bytes its exec loaded are gone, and writing them back later
		// does not bring them back — and this exec gets a pin of its own.
		_ = existing.file.Close()
		s.retiredPins++
		delete(s.pinned, id)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			s.pinFailures++
			return 0
		}
	}
	// The cap is checked HERE, not at entry: it bounds the fds held on
	// DISTINCT inodes, and a repeat exec of an already-pinned image took the
	// reuse path above without reaching this point. Checking at entry lost
	// the per-exec digest of every further exec of an inode already held
	// once 4,096 distinct images were open — a run that execs one tool in a
	// deep loop — and refused the trace for it (attributedExecsUndigested).
	if len(s.pinned) >= maxPinnedImages {
		_ = f.Close()
		s.pinFailures++
		return 0
	}
	// Hash the content NOW, while it is as close to the executed bytes as
	// this channel allows (report-delivery latency, single-digit ms). The
	// end-of-run digest is verified against this sum, so an in-place rewrite
	// of the pinned inode after this point is detected rather than signed.
	// Inline cost: one read of each DISTINCT image per session; repeats of
	// the same inode reuse the pin above without rehashing.
	sum, err := sha256Of(f)
	if err != nil {
		_ = f.Close()
		s.pinFailures++
		return 0
	}
	img := pinnedImage{id: s.nextPinID + 1, file: f, stamp: stamp, sha256: sum, hashedAt: time.Now()}
	s.nextPinID++
	s.pinned[id] = img
	return s.nextPinID
}

// maxPinnedImages caps the open fds one session holds on DISTINCT exec'd
// images. A repeat exec of an inode already pinned holds nothing new and is
// never counted against it. A variable so the cap can be tested at 1.
var maxPinnedImages = 4096

// sha256Of reads an open image from its current offset to EOF.
func sha256Of(f *os.File) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxImageBytes+1))
	if err != nil {
		return sum, err
	}
	if n > maxImageBytes {
		return sum, fmt.Errorf("image exceeds %d bytes; not hashed", maxImageBytes)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// maxImageBytes bounds how much of one exec'd image is read to hash it. The
// path in a report is the tracee's to arrange: pointed at a FIFO or a device
// it would read forever and wedge the collector, and a multi-gigabyte file
// would stall every later report behind one hash. A larger image is refused
// a digest (counted in imagesUnhashed), never read. A variable so a test can
// shrink it.
var maxImageBytes int64 = 1 << 30

// openImage opens a reported exec path for hashing without letting the
// tracee choose what "reading it" means. The path is the tracee's to
// arrange after the fact: a FIFO would block open(2) or the read forever, a
// device would read forever, either wedging the collector goroutine and
// with it shutdown. O_NONBLOCK makes a FIFO open return at once, and the
// fstat refuses anything but a regular file before a byte is read. Symlinks
// ARE followed — /opt/homebrew/bin/go is one — and a link retargeted after
// the exec is the same stated residual as a path rewritten after it.
func openImage(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s is not a regular file (mode %#o); refusing to read it", path, st.Mode&unix.S_IFMT)
	}
	// A regular file ignores O_NONBLOCK, so the flag can stay.
	return os.NewFile(uintptr(fd), path), nil
}

// imageIdentityOf reads the kernel's identity for the inode behind an open fd,
// and the stamp that tells whether that inode has been rewritten since.
func imageIdentityOf(f *os.File) (imageIdentity, inodeStamp, error) {
	fi, err := f.Stat()
	if err != nil {
		return imageIdentity{}, inodeStamp{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return imageIdentity{}, inodeStamp{}, fmt.Errorf("fstat on %s returned %T, not a darwin stat", f.Name(), fi.Sys())
	}
	return imageIdentity{dev: st.Dev, ino: st.Ino, gen: st.Gen},
		inodeStamp{ctimeSec: st.Ctimespec.Sec, ctimeNsec: st.Ctimespec.Nsec, size: st.Size}, nil
}

// kinfoOf reads one pid's kinfo_proc and DISTINGUISHES "no such process"
// from "could not ask". kern.proc.pid answers a missing pid with a
// zero-length result and no error; x/sys's SysctlKinfoProc folds that into
// EIO, which is indistinguishable from a genuine failure — and a liveness
// check that reads a failure as "gone" would sign while a descendant is
// still running. (nil, nil) is the definitive absence; a non-nil error is
// indeterminate and the caller decides what that means for it.
func kinfoOf(pid int) (*unix.KinfoProc, error) {
	raw, err := unix.SysctlRaw("kern.proc.pid", pid)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) != unix.SizeofKinfoProc {
		return nil, fmt.Errorf("kern.proc.pid %d returned %d bytes, want %d", pid, len(raw), unix.SizeofKinfoProc)
	}
	kp := *(*unix.KinfoProc)(unsafe.Pointer(&raw[0]))
	return &kp, nil
}

// readKinfo is kinfoOf behind a variable so the survivor check's response to
// an indeterminate kernel answer can be tested without one.
var readKinfo = kinfoOf

// ctimeGranularity is the coarsest whole-timestamp resolution this code will
// assume a filesystem might have. APFS records nanoseconds; HFS+ and several
// network filesystems record whole seconds.
const ctimeGranularity = time.Second

// stampSettled reports whether an unchanged ctime+size is proof the inode was
// not touched since it was hashed. It is only proof once the clock has moved
// a full granularity past the hash: within that window a rewrite keeping the
// size can carry an identical stamp, and A→B→A would then reuse A's pin for
// B's exec and pass the end-of-run content check for both.
func stampSettled(stamp inodeStamp, hashedAt time.Time) bool {
	if hashedAt.IsZero() {
		return false
	}
	return hashedAt.Sub(time.Unix(stamp.ctimeSec, stamp.ctimeNsec)) >= ctimeGranularity
}

// pollProcFacts reads a pid's parent and process group straight from the
// kernel. Failure is recorded as UNPROVEN (ok=false) and never guessed at: an
// unprovable pid is dropped from the tree and counted, because attributing a
// stranger's process to this build is a worse outcome than a smaller tree.
func pollProcFacts(pid int) procFacts {
	// kinfoOf DIRECTLY, not the readKinfo variable: this runs on the
	// collector's goroutine for every report, and routing the hot path
	// through a package-level variable let a test that stubs it corrupt an
	// unrelated live trace. Only the end-of-run checks, which no other
	// session is inside, read through the variable.
	kp, err := kinfoOf(pid)
	if err != nil || kp == nil {
		return procFacts{}
	}
	return factsOfKinfo(kp)
}

// factsOfKinfo reads the facts out of one kinfo_proc snapshot, so every
// caller that needs more than one field takes them from the same instant.
func factsOfKinfo(kp *unix.KinfoProc) procFacts {
	return procFacts{
		ppid:      int(kp.Eproc.Ppid),
		pgid:      int(kp.Eproc.Pgid),
		startSec:  kp.Proc.P_starttime.Sec,
		startUsec: kp.Proc.P_starttime.Usec,
		ok:        true,
	}
}

// sandboxReportRe parses the kext's report line:
//
//	Sandbox: bash(16171) allow process-exec* /usr/bin/true
//	Sandbox: passd(98302) deny(1) file-read-data /Library/Preferences/x.plist
//	3 duplicate reports for Sandbox: sh(16165) allow process-exec* /bin/bash
//	Sandbox: curl(38711) allow network-outbound remote:*:443
//
// THE HEADER IS BOUND TO THE KERNEL'S TRIPLE, NOT THE LAST ONE ON THE LINE.
// The comm is the process's to choose and may contain parentheses, but XNU
// caps it at MAXCOMLEN (16 bytes), and "(1) allow process-fork " — the
// shortest triple this grammar accepts — is 22 bytes, so a comm cannot hold
// a triple ahead of the kernel's. The comm group is therefore bounded and
// NON-greedy, the op is restricted to the ops this backend knows, and
// everything after the op is opaque detail. A greedy comm bound to the LAST
// triple instead, so executing a file named "/tmp/tool(200) allow
// process-fork" turned the real exec into a fork by pid 200 (image and
// digest gone), and a socket named "…(7) allow network-bind" turned an
// outbound connect into an ignored bind. The duplicate prefix is parsed
// rather than skipped: the kernel coalesces identical rapid reports, and
// dropping those lines would silently lose events instead of counting them.
var sandboxReportRe = regexp.MustCompile(
	`^(?:(\d+) duplicate reports? for )?Sandbox: ` + boundedComm + `\((\d+)\) (allow|deny\(\d+\)) ` +
		`(process-exec\*?|process-exec-interpreter|process-fork|network-outbound|network-inbound|network-bind)(?: (.*))?$`)

// boundedComm is the comm field: at most 2*MAXCOMLEN+1 bytes — XNU's
// p_name, the widest name this channel can print (a 22-byte
// "cilock-catalog-planner" appears in this repo's own runs) — and NON-GREEDY,
// so it prefers the EARLIEST "(pid) decision op" triple on the line.
//
// The bound alone is not a proof of unambiguity: 33 bytes is wide enough to
// hold "(1) allow process-fork " (22), so a process CAN name itself to put a
// well-formed triple ahead of the kernel's. That is what ambiguousHeader
// catches — see there — rather than something the grammar can decide alone.
const boundedComm = `([^\n]{0,33}?)`

// greedyComm is the same field preferring the LAST triple. Comparing the two
// readings is how a line with more than one candidate header is detected.
const greedyComm = `([^\n]{0,33})`

// sandboxReportAnyOpRe is the SAME bounded header with the operation left
// open. It answers one question — "is this a kernel report this backend
// simply does not care about (another sandbox user's mach-lookup, a
// file-read the profile logs)?" — and is asked ONLY after the strict grammar
// has already failed, so a line carrying a real exec or connect has been
// taken by sandboxReportRe before this can skip it. Asked first, a process
// named "x(1) allow zz" could hide its own exec behind an unknown op.
// sandboxReportGreedyRe reads the same line preferring the LAST candidate
// triple. See ambiguousHeader.
var sandboxReportGreedyRe = regexp.MustCompile(
	`^(?:(\d+) duplicate reports? for )?Sandbox: ` + greedyComm + `\((\d+)\) (allow|deny\(\d+\)) ` +
		`(process-exec\*?|process-exec-interpreter|process-fork|network-outbound|network-inbound|network-bind)(?: (.*))?$`)

// ambiguousHeader reports whether a line carries more than one reading of
// the kernel's header — the earliest candidate triple and the latest
// disagree about whose report this is.
//
// THE ATTACK: a process names itself "x(1) allow process-fork" (23 bytes,
// inside p_name), so the kernel prints
//
//	Sandbox: x(1) allow process-fork(4242) allow process-exec* /tmp/evil
//
// and the earliest triple reads as a FORK BY PID 1 while the kernel's own
// says pid 4242 exec'd /tmp/evil. Nothing in the text says which is the
// kernel's, so neither reading may be signed and neither may be dropped:
// the line is counted and the trace refuses. An ordinary report — including
// one whose DETAIL contains a triple, since a comm long enough to reach it
// exceeds the bound — has exactly one reading and is unaffected.
func ambiguousHeader(msg string) bool {
	first := sandboxReportRe.FindStringSubmatch(msg)
	if first == nil {
		return false
	}
	last := sandboxReportGreedyRe.FindStringSubmatch(msg)
	if last == nil {
		return false
	}
	// THE POSITION, not just the values. Comparing pid, decision and
	// operation alone missed a decoy chosen to agree on all three: a process
	// named "x(4242) allow process-exec* decoy" in front of the kernel's own
	// "(4242) allow process-exec* /tmp/real" yields two headers with
	// identical values, and the strict parser takes the FIRST — so the image
	// path recorded is the planted "decoy" and the executed image never
	// appears at all. The comm each reading selects IS the position, so
	// comparing it catches that; the value comparisons stay because a
	// reading that differs only in allow vs deny would otherwise file the
	// build's own permitted egress as refused.
	return first[2] != last[2] || first[3] != last[3] || first[4] != last[4] || first[5] != last[5]
}

var sandboxReportAnyOpRe = regexp.MustCompile(
	`^(?:\d+ duplicate reports? for )?Sandbox: ` + boundedComm + `\(\d+\) (?:allow|deny\(\d+\)) ([A-Za-z0-9*_-]+)`)

// sandboxReportAnyOpGreedyRe is the same loose reading preferring the LAST
// candidate header, so a skip is licensed only by a UNIQUE loose reading.
var sandboxReportAnyOpGreedyRe = regexp.MustCompile(
	`^(?:\d+ duplicate reports? for )?Sandbox: ` + greedyComm + `\(\d+\) (?:allow|deny\(\d+\)) ([A-Za-z0-9*_-]+)`)

// irrelevantReport reports whether msg is a readable kernel report about an
// operation this backend does not trace. The op must be readable AND not one
// of ours: a report naming an operation we DO trace, which the strict grammar
// nonetheless could not read (a path with a newline), is evidence going
// missing and must reach the unparseable path instead of being skipped here.
func irrelevantReport(msg string) bool {
	if sandboxReportRe.MatchString(msg) {
		// The strict grammar can read it as one of ours. Not irrelevant,
		// whatever the first triple on the line says — this is the check
		// that makes the function safe no matter what order it is asked in.
		return false
	}
	m := sandboxReportAnyOpRe.FindStringSubmatch(msg)
	if m == nil {
		return false
	}
	// The loose reading can be captured too, and this path runs precisely
	// when the strict grammar failed — so the ambiguity check upstream never
	// saw the line. A comm of "x(1) allow foo" in front of a real
	// process-exec* whose path contains a newline would otherwise read as an
	// untraced "foo" and license dropping the kernel's own report. Only a
	// unique loose reading may license a skip; anything else falls through
	// to the unparseable path and refuses.
	last := sandboxReportAnyOpGreedyRe.FindStringSubmatch(msg)
	if last == nil || last[2] != m[2] {
		return false
	}
	op := m[2]
	return !isExecOp(op) && op != opFork && !isNetworkOp(op)
}

// acceptedFromKernel reports whether a log record genuinely came from the
// Sandbox kext, rather than from a process imitating it.
//
// THE ATTACK THIS CLOSES: the collector's predicate selects on senderImagePath
// containing "sandbox", and the reader used to decode only the message text. A
// same-uid process could therefore call os_log twice with sandbox-shaped text
// and have fabricated execs accepted into the SIGNED process tree — no key, no
// privileges, no need to defeat anything. Demonstrated end to end.
//
// Genuine kext reports are emitted BY THE KERNEL, measured on macOS 15.7.7:
//
//	processImagePath  /kernel
//	processID         0
//	userID            0
//	senderImagePath   /System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox
//
// A user process cannot forge processID 0 — the field is stamped by the logging
// system from the emitter's real identity, not taken from the message. That is
// what makes this check worth more than the text it guards.
//
// All four are required. Any one alone is weaker than it looks: senderImagePath
// is a CONTAINS match at the predicate, so a binary living under a path with
// "sandbox" in it satisfies the stream filter on its own.
//
// The pid/uid fields are POINTERS so that an ABSENT field is distinguishable
// from a zero one. Absent must not read as 0 here — that would invert the check
// and accept exactly the records it exists to refuse.
func acceptedFromKernel(processImagePath, senderImagePath string, pid, uid *int) bool {
	if pid == nil || *pid != 0 {
		return false
	}
	if uid == nil || *uid != 0 {
		return false
	}
	if processImagePath != kernelProcessImagePath {
		return false
	}
	return senderImagePath == sandboxKextImagePath
}

// looksLikeSandboxReport reports whether msg has the kernel report's leading
// shape, with or without the coalescing prefix.
func looksLikeSandboxReport(msg string) bool {
	if strings.HasPrefix(msg, "Sandbox: ") {
		return true
	}
	return duplicateReportPrefixRe.MatchString(msg)
}

var duplicateReportPrefixRe = regexp.MustCompile(`^\d+ duplicate reports? for Sandbox: `)

// unparseableReportPidRe reads only the pid out of a report line the full
// grammar rejected. The comm before the pid is the process's to choose, so
// the pid is bound to the whole "(pid) decision known-op" triple, and the
// comm is bounded: XNU caps it at MAXCOMLEN (16 bytes), so a comm cannot
// itself contain "(1) allow process-exec* " (24 bytes) ahead of the real
// triple, and the first triple within the bound is the kernel's.
var unparseableReportPidRe = regexp.MustCompile(
	`^(?:\d+ duplicate reports? for )?Sandbox: ` + boundedComm + `\((\d+)\) (?:allow|deny\(\d+\)) ` +
		`(?:process-exec\*?|process-exec-interpreter|process-fork|network-outbound|network-inbound|network-bind)\b`)

// unparseableReportPidGreedyRe reads the same line preferring the LAST
// candidate header, so a pid is only recovered when both readings agree.
var unparseableReportPidGreedyRe = regexp.MustCompile(
	`^(?:\d+ duplicate reports? for )?Sandbox: ` + greedyComm + `\((\d+)\) (?:allow|deny\(\d+\)) ` +
		`(?:process-exec\*?|process-exec-interpreter|process-fork|network-outbound|network-inbound|network-bind)\b`)

// unparseableReportPid reports whether msg is a sandbox report the grammar
// rejected but whose pid is still readable, and that pid.
func unparseableReportPid(msg string) (int, bool) {
	if !strings.HasPrefix(msg, "Sandbox:") && !strings.Contains(msg, " Sandbox: ") {
		return 0, false
	}
	m := unparseableReportPidRe.FindStringSubmatch(msg)
	if m == nil {
		return 0, false
	}
	// This path runs exactly when the strict grammar FAILED — an exec path
	// with a newline in it — so the ambiguity check upstream never saw the
	// line. A process named "x(1) allow process-fork " would otherwise hand
	// this parser pid 1, launchd, and the build's own unreadable exec would
	// be filed as a stranger's and dropped. A pid is recoverable only when
	// both readings of the line name the same one; otherwise the report is
	// unattributable and refuses the trace.
	last := unparseableReportPidGreedyRe.FindStringSubmatch(msg)
	if last == nil || last[2] != m[2] {
		return 0, false
	}
	pid, err := strconv.Atoi(m[2])
	if err != nil {
		return 0, false
	}
	return pid, true
}

func parseSandboxReport(msg string) (sandboxEvent, bool) {
	m := sandboxReportRe.FindStringSubmatch(msg)
	if m == nil {
		return sandboxEvent{}, false
	}
	op := m[5]
	if !isExecOp(op) && op != opFork && !isNetworkOp(op) {
		// An operation the profile never asked to be reported (another
		// sandbox user's file-read-data, say). Readable, irrelevant, not a
		// loss — distinct from a line the grammar could not read at all.
		return sandboxEvent{}, false
	}
	pid, err := strconv.Atoi(m[3])
	if err != nil {
		return sandboxEvent{}, false
	}
	dup := 0
	if m[1] != "" {
		dup, _ = strconv.Atoi(m[1])
	}
	// The DECISION is evidence, not formatting. Our own observation profile
	// allows everything (with report), so a deny is another sandbox refusing
	// an operation -- most often a nested profile a descendant applied -- and
	// what it proves is that the operation did NOT happen.
	return sandboxEvent{pid: pid, comm: m[2], op: op, detail: m[6], duplicates: dup, denied: m[4] != "allow"}, true
}

func isExecOp(op string) bool {
	return op == opExec || op == opExecStar || op == opExecInterpreter
}

// darwinEndpointKind classifies how much of a network report's destination the
// kernel actually named. It exists so the diagnostics can size each shape's
// pile separately — the three shapes have genuinely different evidentiary
// weight and collapsing them would hide the one that matters.
type darwinEndpointKind int

const (
	// endpointUnixPath — the kernel named a UNIX socket path, in full. This is
	// the ONE shape this backend observes completely.
	endpointUnixPath darwinEndpointKind = iota
	// endpointPortOnly — an IP socket. The port is real; the host is not
	// observable (see darwinEndpoint).
	endpointPortOnly
	// endpointUnnamed — a bare `network-outbound` with no destination at all.
	endpointUnnamed
	// endpointUnrecognized — a destination shape this parser does not know.
	endpointUnrecognized
)

// sandboxSocketFilterRe matches the kernel's socket filter notation, which is
// what the report prints in place of a destination:
//
//	remote:*:443     an outbound IP connection to port 443
//	local:*:57793    the serving side, bound/accepted on port 57793
//	local:*:0        a bind to an ephemeral port
//
// The middle group is the host and is `*` in every case measured — see
// darwinEndpoint for why that is a property of the channel, not of the sample.
// It is captured anyway so that a macOS which starts naming hosts is used
// rather than ignored.
var sandboxSocketFilterRe = regexp.MustCompile(`^(?:remote|local):(.*):([0-9]+|\*)$`)

// darwinEndpoint is the destination of one network report, carrying only what
// the kernel actually said.
//
// THE BLIND SPOT, MEASURED TWICE AND THE WHOLE REASON THIS TYPE EXISTS. The
// Seatbelt report names THE FILTER THAT MATCHED, not the destination. A
// connection to the literal IP 93.184.215.14 — no DNS anywhere in the path —
// still reports `remote:*:443`, and an IPv6 connection to
// [2606:4700:4700::1111]:80 reports `remote:*:80`, the same shape as IPv4. So
// this backend can answer "was there outbound egress, and on what port" and
// CANNOT answer "to which host" — nor even "over which IP version", which is
// why the family is recorded as FamilyInetUnspecified rather than a guessed
// AF_INET.
//
// A loopback connection is reported as `remote:*:<port>` too, identically to an
// external one, so locality is not observable here either. That is safe in one
// direction only: cilock already counts loopback against hermeticity (a
// localhost proxy can fetch external inputs), so recording every IP endpoint as
// un-located is the conservative reading, not a convenient one.
//
// The address is therefore HostNotObservable — a string that cannot be mistaken
// for a resolved host, since parentheses are legal in neither a DNS name nor an
// IP literal, and net.ParseIP rejects it so nothing downstream can mis-classify
// it as loopback or route to it.
type darwinEndpoint struct {
	family  string
	address string
	port    int
	kind    darwinEndpointKind
}

// parseDarwinEndpoint turns a report's destination field into an endpoint.
//
// The empty case is not a parse failure: a bare `network-outbound` with no
// destination is a real, reproducible shape. Measured on macOS 15.7.7, a
// process that called getaddrinfo("example.com") and never connected to
// anything produced exactly two reports — the mDNSResponder socket connect and
// one bare line — so in the benign case the bare line is the name-RESOLUTION
// path.
//
// IT STILL COUNTS AS EGRESS, under FamilyNotObservable: the kernel proved an
// outbound operation happened and named nothing about it, and "measured once
// as the resolver" is a statement about one benign program, not about every
// operation that can produce this shape. Name resolution is itself a two-way
// remote channel — the names a build queries leave the machine and the answers
// come back as undeclared inputs — so even the benign reading does not make
// the operation hermetic-safe. An earlier revision mapped this to AF_UNSPEC so
// the egress filter would skip it; that turned "we could not see where this
// went" into "this went nowhere", which is the exact projection of absence
// this attestor exists to prevent. The pile is still sized separately in
// DarwinTraceDiagnostics.NetworkReportsWithoutDestination so a verifier can
// tell resolver-shaped noise from unrecognized-format drift.
func parseDarwinEndpoint(detail string) darwinEndpoint {
	if detail == "" {
		return darwinEndpoint{family: FamilyNotObservable, address: HostNotObservable, kind: endpointUnnamed}
	}
	// A UNIX socket is named in full. Passed through verbatim so cilock's
	// existing rule — only container-runtime control sockets are an input-fetch
	// vector — does the judging, with no darwin-specific allowlist of its own.
	if strings.HasPrefix(detail, "/") {
		return darwinEndpoint{family: FamilyUnix, address: detail, kind: endpointUnixPath}
	}
	m := sandboxSocketFilterRe.FindStringSubmatch(detail)
	if m == nil {
		// An unrecognized destination is the case where "we did not look" must
		// not become "there was none": record it as an IP endpoint with an
		// unnameable host so it COUNTS against hermeticity, and count it so
		// the format drift is visible.
		return darwinEndpoint{
			family:  FamilyInetUnspecified,
			address: HostNotObservable,
			kind:    endpointUnrecognized,
		}
	}
	return darwinEndpoint{
		family:  FamilyInetUnspecified,
		address: observedHostOr(m[1]),
		port:    observedPort(m[2]),
		kind:    endpointPortOnly,
	}
}

// observedHostOr returns the host the kernel named, or the not-observable
// marker when it named the wildcard (every case measured on 15.7.7) or nothing.
func observedHostOr(host string) string {
	if host == "" || host == "*" {
		return HostNotObservable
	}
	return host
}

// observedPort returns the port the kernel named, or 0 when it named the
// wildcard. Zero is the same "absent" the NetworkConnection contract already
// uses (`port,omitempty`), so an unported endpoint renders as a bare host.
func observedPort(port string) int {
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}

// drain proves the tail of the stream arrived instead of sleeping and hoping.
// A second canary is published AFTER the traced command exits; once we see it,
// every report the kernel emitted before it has also been delivered. The quiet
// window that follows guards against out-of-order delivery — and it FAILS
// CLOSED: possibly-ours reports still flowing seconds after the command exited
// and its process group was reaped mean something this attestation cannot
// describe is still acting, and an attestation cut at an arbitrary moment of
// that activity would present an incomplete tree as complete. The quiet clock
// only ticks for reports that could be this build's (see noteActivity), so
// unrelated sandboxed apps cannot exhaust the deadline.
func (s *sandboxSession) drain() error {
	if err := s.canary("drain"); err != nil {
		return err
	}
	// The canary is a BARRIER, and a barrier is only worth something if
	// something waits behind it. Canary reports deliberately do not refresh
	// the quiet clock (a build must not be able to hide behind our own
	// probes), so when the last real report was already older than the
	// window, awaitQuiet returned the instant the canary came back — zero
	// quiet time — and a build report the stream delivered out of order
	// behind the canary died with the collector. Reset the baseline here so
	// a full window of silence must follow the barrier.
	s.noteDrainBarrier()
	return s.awaitQuiet(time.Now().Add(drainDeadline))
}

// noteDrainBarrier restarts the quiet window at the moment the drain canary
// was observed.
func (s *sandboxSession) noteDrainBarrier() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastInTree = time.Now()
}

// awaitQuiet waits for the possibly-ours report stream to go quiet, failing
// closed when the deadline exhausts first.
func (s *sandboxSession) awaitQuiet(deadline time.Time) error {
	for time.Now().Before(deadline) {
		s.mu.Lock()
		quiet := time.Since(s.lastInTree) > quietWindow
		s.mu.Unlock()
		if quiet {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("macOS process tracing: reports attributable to this build were still arriving %s after "+
		"the command exited and its process group was reaped — something the command started is still acting, "+
		"so the process tree cannot be captured completely and this run is not attestable", drainDeadline)
}

// shutdown stops the collector and releases every pinned fd. Safe to call
// twice; trace() defers it so a failure anywhere still tears down.
func (s *sandboxSession) shutdown() {
	if !s.stopping.CompareAndSwap(false, true) {
		return
	}
	if s.collector.Process != nil {
		_ = s.collector.Process.Kill()
	}
	<-s.readerDone
	_ = s.collector.Wait()
	s.stopWrapWatch()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, img := range s.pinned {
		_ = img.file.Close()
	}
}

// harvest returns the captured events after checking the two conditions that
// make a tree untrustworthy rather than merely small.
func (s *sandboxSession) harvest() ([]sandboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.harvestLocked()
}

// harvestAndSnapshot takes the events, the facts and the image digests under
// ONE acquisition of s.mu.
//
// Two separate acquisitions was a real hole, not a tidiness point. The
// collector's reader goroutine runs until shutdown and `log stream` is
// machine-wide, so reports keep arriving the whole time. A report landing
// between harvest's unlock and snapshot's lock reaches s.facts — so the
// snapshot HAS its pid — while the events copy taken a moment earlier does
// NOT have its exec or connect. The tree is then built with a process present
// and the thing it did missing, which is exactly the shape of evidence this
// backend refuses everywhere else: a gap that reads as an absence.
//
// The drain before this establishes quiet, but quiet is a heuristic about
// timing and this is a guarantee about ordering. They are not substitutes.
func (s *sandboxSession) harvestAndSnapshot(hashes []cryptoutil.DigestValue) ([]sandboxEvent, treeSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events, err := s.harvestLocked()
	if err != nil {
		return nil, treeSnapshot{}, err
	}
	return events, s.snapshotLocked(hashes), nil
}

// harvestLocked is harvest's body. Caller holds s.mu.
func (s *sandboxSession) harvestLocked() ([]sandboxEvent, error) {
	if s.endedEarly.Load() {
		return nil, fmt.Errorf("macOS process tracing: the %s stream ended before the command did "+
			"(stderr: %q) — the process tree is truncated by an unknown amount, so this run is not attestable",
			logToolPath, strings.TrimSpace(s.stderr.String()))
	}
	if s.capHit {
		return nil, fmt.Errorf("macOS process tracing: more than %d sandbox reports; the captured tree would be "+
			"truncated and a truncated tree is indistinguishable from a command that did less work",
			maxSandboxEvents)
	}
	if s.readerErr != nil && !errors.Is(s.readerErr, io.EOF) {
		return nil, fmt.Errorf("macOS process tracing: reading the report stream failed: %w", s.readerErr)
	}
	if s.wrapWatchErr != nil {
		return nil, fmt.Errorf("macOS process tracing: the pid-counter watch stopped mid-run, so a recycled pid "+
			"could have gone unnoticed and no pid-keyed claim in this run is provable: %w", s.wrapWatchErr)
	}
	if s.ambiguous > 0 {
		return nil, fmt.Errorf("macOS process tracing: %d kernel sandbox report(s) can be read two ways — a process "+
			"named so that its own name contains a second \"(pid) decision operation\" header — so which process the "+
			"report describes cannot be decided, and one of the readings may be this build's exec; this run is not attestable",
			s.ambiguous)
	}
	if s.unattributable > 0 {
		return nil, fmt.Errorf("macOS process tracing: %d kernel sandbox report(s) could not be attributed to any process "+
			"(no pid could be read from them) — one may be this build's exec or connection, so this run is not attestable",
			s.unattributable)
	}
	if s.pidWrapped {
		return nil, errors.New("macOS process tracing: the kernel's pid counter wrapped while the command ran — " +
			"a pid can now name two different processes within this session, so ancestry, probe exclusion and " +
			"late-report attribution are all unprovable and this run is not attestable; re-run the step")
	}
	out := make([]sandboxEvent, len(s.events))
	copy(out, s.events)
	return out, nil
}
