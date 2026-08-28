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

// The darwin half of the tracing hooks. sandbox_trace_darwin.go owns the
// observation channel; this file owns the attestor contract — the same four
// entry points the Linux tracer implements, producing the same predicate
// fields so a policy written against a Linux attestation reads a macOS one.

package commandrun

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"golang.org/x/sys/unix"
)

// darwinSessions maps a command to its live observation session.
//
// Keyed by *exec.Cmd rather than stashed on CommandRun because enableTracing
// takes only the command — a signature shared with the Linux build, which this
// file must not change out from under. The entry is removed by trace(), which
// is the single consumer.
var darwinSessions sync.Map // *exec.Cmd -> *sandboxSession

// enableTracing wraps the command in the observation sandbox, after proving
// the observation channel works.
//
// It CANNOT return an error (the Linux signature has none), so a setup failure
// is published through c.Err — os/exec's own "this command must not run"
// channel. Start() then returns that error verbatim, runCmd propagates it, and
// the attestor fails without the command ever executing. That ordering is the
// point: the alternative shape, where the command runs and tracing quietly
// didn't, is the exact failure this attestor exists to prevent.
func enableTracing(c *exec.Cmd) {
	if err := argv0Preserved(c); err != nil {
		c.Err = err
		return
	}
	sess, err := startSandboxSession()
	if err != nil {
		c.Err = err
		return
	}
	sess.noteArgv0Normalized(argv0Normalized(c))
	sess.wrap(c)
	darwinSessions.Store(c, sess)
	// The delay is read HERE, on the caller's goroutine, and handed to the
	// reaper. Reading it inside the goroutine let a still-sleeping reaper from
	// an earlier command race a test that was adjusting the value — a real
	// data race the detector caught, and one that would equally bite any host
	// that reconfigured tracing while a command was in flight.
	go reapUnstartedSession(c, sess, darwinUnstartedReapDelay)
}

// argv0Preserved refuses an invocation whose argv[0] the sandbox wrapper
// cannot keep: sandbox-exec execs the target as c.Path, so only an argv[0]
// with the executable's own name survives the wrap unchanged in meaning.
func argv0Preserved(c *exec.Cmd) error {
	if len(c.Args) == 0 {
		// os/exec passes Path as argv[0] when Args is empty, which is
		// exactly what the wrapper supplies: nothing changes.
		return nil
	}
	if c.Args[0] == "" {
		// An explicitly empty argv[0] is the one value the wrapper cannot
		// reproduce: without it the child sees "", with it the resolved
		// path. Whatever the caller meant by that, it is not what would run.
		return fmt.Errorf("macOS process tracing: argv[0] is empty, and sandbox-exec runs the target under its " +
			"resolved path — the traced process would see an argv[0] the caller did not ask for, so this " +
			"invocation is refused rather than traced under a different one")
	}
	if filepath.Base(c.Args[0]) == filepath.Base(c.Path) {
		return nil
	}
	return fmt.Errorf("macOS process tracing: argv[0] %q is not the executable's name %q — sandbox-exec runs the "+
		"target under its resolved path, which would change what a multi-call binary or alias does, so this "+
		"invocation is refused rather than traced under a different name", c.Args[0], filepath.Base(c.Path))
}

// argv0Normalized reports whether the wrapper will REWRITE argv[0] — the
// caller asked for a name and sandbox-exec will supply the resolved path.
//
// This is the ordinary shape (exec.Command("tool") gives Args[0] "tool" and
// Path "/usr/bin/tool"), so it cannot be refused without refusing nearly
// every invocation; and it is not nothing, since a program can read argv[0]
// to locate its resources. It is therefore recorded and stated in the signed
// note rather than silently normalised.
func argv0Normalized(c *exec.Cmd) bool {
	return len(c.Args) > 0 && c.Args[0] != c.Path
}

// reapUnstartedSession releases the collector when the command never starts.
//
// trace() is the session's only consumer and runCmd calls it only after a
// successful Start, so a Start failure (bad c.Dir, exec fault) would otherwise
// strand a `log stream` child for the lifetime of the host process — invisible
// in a CLI that exits immediately after, but a real leak in a long-lived
// process such as the test binary.
//
// THE MAP IS THE ONLY SYNCHRONIZATION POINT, deliberately. An earlier revision
// peeked at c.Process to ask "did Start run?", but exec.Cmd.Start writes that
// field with no lock this goroutine shares — a data race, and one whose stale
// read could reap a session whose command was mid-Start. LoadAndDelete
// arbitrates instead: runCmd calls trace() immediately after a successful
// Start, and trace() takes the session out of the map at entry, so by the time
// this timer fires the entry only exists if the command never started (or a
// Start has been wedged for the whole delay — in which case reaping is still
// safe, because trace() then FAILS CLOSED on the missing session rather than
// signing an untraced run).
func reapUnstartedSession(c *exec.Cmd, sess *sandboxSession, delay time.Duration) {
	time.Sleep(delay)
	if _, taken := darwinSessions.LoadAndDelete(c); !taken {
		return
	}
	log.Debugf("(sandbox-trace) command never started; releasing the report collector")
	sess.shutdown()
}

// darwinUnstartedReapDelay is a variable so the leak test does not have to
// wait out the production value.
var darwinUnstartedReapDelay = 30 * time.Second

// applyTraceePrivilegeDrop is a no-op on darwin. The Linux implementation
// drops SUDO_UID-derived elevation and applies PR_SET_NO_NEW_PRIVS via
// setpriv(1); neither has a darwin equivalent, and cilock does not need
// elevation here — the sandbox report channel works entirely as a normal user,
// which is the whole reason this backend fits the "install nothing" constraint.
func applyTraceePrivilegeDrop(_ *exec.Cmd) {}

// preStartTracingSetup has nothing to do on darwin: enableTracing already
// started the collector and proved it live (it must run BEFORE the sandbox
// exists, since `log` refuses to run inside one), and it reports failure
// through c.Err.
func (r *CommandRun) preStartTracingSetup() error { return nil }

// trace waits for the wrapped command, drains the report stream, and turns the
// reports into the same ProcessInfo records the Linux tracer produces.
func (rc *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	raw, ok := darwinSessions.LoadAndDelete(c)
	if !ok {
		// Reaching here means the command was started without the sandbox
		// wrap while tracing was requested. Refuse: the caller is about to
		// sign a predicate whose shape says a tree was observed.
		_ = c.Wait()
		return nil, errors.New("macOS process tracing: no observation session for this command — " +
			"it ran untraced, so no process tree can be attested for it")
	}
	sess, ok := raw.(*sandboxSession)
	if !ok {
		_ = c.Wait()
		return nil, fmt.Errorf("internal: tracing session for this command is %T, not a sandbox session", raw)
	}
	defer sess.shutdown()

	rc.resolvedCaptureMode = string(attestation.CaptureTrace)
	rc.resolvedTraceBackend = darwinTraceBackend

	rootPid := c.Process.Pid
	rootPgid := observeRootPgid(rootPid)
	rootSid, err := sidOf(rootPid)
	if err != nil {
		_ = c.Wait()
		return nil, fmt.Errorf("macOS process tracing: the root's session id could not be read (%v); the exit sweep for "+
			"unreported descendants keys on it, so this run is not attestable", err)
	}
	// Publish the root to the collector so the drain's quiet detection can
	// tell this build's reports from the machine-wide noise.
	sess.noteRoot(rootPid)
	if !sess.rootFacts.ok {
		// Every start-time rule below (reparented, unresolved, the exit
		// sweep) compares against the root's incarnation. Without it those
		// rules silently decide nothing, and a detached descendant would be
		// read as a stranger. Refuse instead.
		_ = c.Wait()
		return nil, errors.New("macOS process tracing: the root's kernel facts could not be read at start; " +
			"nothing that hangs off launchd can be told from a detached descendant without them, so this run is not attestable")
	}
	// Sample the pid counter for as long as the command runs (see
	// noteProbePid); the watch stops before the drain canary so the last
	// probe of the session is the drain's own.
	sess.startWrapWatch()

	waitErr := c.Wait()
	sess.stopWrapWatch()
	if err := rc.recordExitStatus(waitErr); err != nil {
		return nil, err
	}
	// The kernel's view BEFORE the reap. A fork-only child — never exec'd,
	// never touched the network, so no report names it — exists only in this
	// table, and reapDarwinProcessGroup below SIGKILLs the whole group: read
	// after the kill, the sweep would have destroyed the very process it
	// exists to find. A failure here is not fatal on its own (the post-drain
	// read is the one the sweep cannot do without), but it is recorded so the
	// rows are not silently fewer.
	preReap, preReapErr := listAllProcs()
	if preReapErr != nil {
		log.Debugf("(sandbox-trace) pre-reap process table unreadable: %v", preReapErr)
	}
	// The command has exited; reap its process group so a descendant that
	// inherited the group cannot keep acting after the evidence is signed.
	// Anything the kill catches emits its last reports BEFORE the drain
	// canary below, so nothing observable is lost — and a descendant that
	// LEFT the group survives this on purpose, which the check after
	// membership resolution turns into a refusal rather than a blind spot.
	if err := reapDarwinProcessGroup(rootPgid); err != nil {
		return nil, err
	}
	if err := sess.drain(); err != nil {
		return nil, err
	}
	// After the drain, so every member's reports are in and every member
	// has forked whatever it was going to: a forked child that never exec'd
	// and never touched the network produced NO report and is invisible to
	// the collector, yet it runs the parent's code and can outlive the
	// command. The kernel process table still shows it, and its SESSION
	// still says whose it is — the reap kills its parent and launchd adopts
	// it, but setpgid does not change the session id it inherited from the
	// root. (setsid does; that child is a stated residual.)
	table, err := listAllProcs()
	if err != nil {
		return nil, fmt.Errorf("macOS process tracing: the kernel process table could not be read at exit (%v); an "+
			"unreported descendant could not be looked for, so this run is not attestable", err)
	}
	if preReapErr != nil {
		return nil, fmt.Errorf("macOS process tracing: the kernel process table could not be read before the "+
			"command's process group was reaped (%v); a forked child that never exec'd would have been killed "+
			"before it could be counted, so this run is not attestable", preReapErr)
	}
	postDrain := table
	table = mergeProcTables(preReap, table)
	sess.noteUnobservedDescendants(sweepUnobservedDescendants(rootPid, rootPgid, rootSid, sess.rootUID, sess.rootFacts, sess.factsSnapshot(), sess.reportedComms(), table, sidOf))
	// ONE acquisition for both, so a report cannot land between them and leave
	// the tree with a process present and the thing it did missing.
	events, snap, err := sess.harvestAndSnapshot(actx.Hashes())
	if err != nil {
		return nil, err
	}
	members, unproven, groupOnly := resolveTreeMembers(rootPid, rootPgid, snap.facts, snap.canaries)
	// A kernel-proven descendant still alive here outlived both the command
	// and the group reap — it deliberately detached (setsid/setpgid) and can
	// exec, fetch, and modify artifacts AFTER this attestation is signed.
	// A tree signed while part of it is still running is incomplete in a way
	// no diagnostic can repair, so this fails closed.
	// Asked BEFORE liveness, because liveness cannot answer it: a member
	// outside the reap's group may already have done its post-drain work and
	// exited by the time anything checks whether it is running.
	// BOTH snapshots, not the merged table. A descendant can leave the group
	// AFTER the pre-reap read — the reap's kill(-pgid) then misses it, it
	// works on past the drain, and if it exits before the liveness check
	// nothing else would ever see it. mergeProcTables keeps the FIRST row for
	// a pid, i.e. the pre-reap incarnation still showing the old group, so the
	// merge is exactly the wrong input for this question.
	bothSnapshots := append(append([]kinfoFacts{}, preReap...), postDrain...)
	// EVERY POSSIBLY-OURS PID, not only the proven members. members comes from
	// the POISONED facts, so a reparented or unresolved pid is not in it, and a
	// pid swept out of the process table never reported so was never in facts
	// at all. Those are exactly the processes this check exists for: the
	// undecided liveness check below asks whether they are STILL RUNNING, and
	// a detached process that did its post-drain work and exited answers "no"
	// while having acted after the evidence was gathered. Being SEEN detached
	// is the only question that can be answered in time, so it is asked of
	// everything the tree could not rule out.
	//
	// Measured before widening it, because a new refusal is a new way to fail
	// an honest build: across 12 real traces at load up to 60, reparented,
	// unresolved and unobserved were ALL ZERO. These buckets are empty in
	// practice, so this costs nothing in false refusals and closes the gap.
	possiblyOurs := make(map[int]bool, len(members)+len(snap.reparented)+len(snap.unresolved)+len(snap.unobserved))
	for pid := range members {
		possiblyOurs[pid] = true
	}
	for _, m := range []map[int]procFacts{snap.reparented, snap.unresolved, snap.unobserved} {
		for pid := range m {
			if !snap.canaries[pid] {
				possiblyOurs[pid] = true
			}
		}
	}
	if detached := detachedMembersAtExit(bothSnapshots, possiblyOurs, rootPid, rootPgid); len(detached) > 0 {
		return nil, fmt.Errorf("macOS process tracing: %d process(es) this trace could not rule out as the "+
			"command's (pids %v) had left its process group before it exited — the group reap cannot reach them, "+
			"so they could act after the report stream was drained and be gone before anything could check, and "+
			"this run is not attestable", len(detached), detached)
	}
	survivors, err := survivingDarwinMembers(rootPid, members, snap.facts)
	if err != nil {
		return nil, err
	}
	if len(survivors) > 0 {
		return nil, fmt.Errorf("macOS process tracing: %d kernel-proven descendant(s) of the command are still "+
			"running after it exited and its process group was reaped (pids %v) — a detached process can keep "+
			"acting after the evidence is signed, so the process tree cannot be attested as complete", len(survivors), survivors)
	}
	// The same question for the processes whose descent could not be decided:
	// one that appeared after the root started, hangs off launchd, and is
	// still running is exactly what a double-forked fetcher looks like.
	undecided := maps.Clone(snap.reparented)
	maps.Copy(undecided, snap.unresolved)
	maps.Copy(undecided, snap.unobserved)
	orphans, err := survivingDarwinMembers(rootPid, keysOf(undecided), undecided)
	if err != nil {
		return nil, err
	}
	if len(orphans) > 0 {
		return nil, fmt.Errorf("macOS process tracing: %d process(es) that appeared after the command started and "+
			"were reparented to launchd are still running after it exited (pids %v) — whether they are the "+
			"command's own detached descendants cannot be decided from here, and a process that may be the "+
			"build's can keep acting after the evidence is signed, so this run is not attestable", len(orphans), orphans)
	}
	in := darwinTreeInput{
		rootPid:  rootPid,
		events:   events,
		members:  members,
		canaries: snap.canaries,
		facts:    snap.facts,
		digests:  snap.digests,
		swept:    snap.unobserved,
	}
	diag := &DarwinTraceDiagnostics{
		ExecDigestBinding: execDigestBindingCollectorOpen,
		Argv0Normalized:   sess.argv0Normalized,
		// The sweep's fork-only descendants are unproven pids too. They
		// produced no report, so buildDarwinTree cannot emit them, and
		// counting them ONLY in unobservedDescendants left the signed
		// guidance "a complete tree requires unprovenPids == 0" true while
		// a forked child was missing from the tree. They are disjoint from
		// `unproven` (which comes from pids that DID report), so this adds
		// rather than double-counts, and the breakdown stays available in
		// unobservedDescendants.
		UnprovenPIDs:               unproven + uint64(len(snap.unobserved)),
		ReparentedAfterRoot:        uint64(len(snap.reparented)),
		UnresolvedAncestry:         uint64(len(snap.unresolved)),
		UnobservedDescendants:      uint64(len(snap.unobserved)),
		GroupOnlyPIDs:              groupOnly,
		CollectorRecordsUnreadable: snap.unparsed,
		ForgedRecords:              snap.forged,
		ImagesUnhashed:             snap.pinFailures,
		PidReuseDetected:           snap.pidReuse,
		// Read from the profile THIS RUN applied rather than hardcoded, so the
		// claim "we watched the network" cannot outlive the rule that made it
		// true. cilock keys its hermeticity gate on this field.
		// BOTH halves: the profile asked for network reports AND a probe's
		// own network operation came back through the channel. The profile
		// text alone proves intent, not delivery.
		NetworkObserved: sandboxProfileReportsNetwork() && sess.networkProven,
		// Never true on this backend, and stated rather than left to be
		// inferred from an endpoint list full of "(host-not-observable)".
		NetworkHostsObservable: false,
	}

	procs := buildDarwinTree(in, diag)
	if err := refuseUnobservedRoot(procs, rootPid); err != nil {
		return nil, err
	}
	if err := refuseIncompleteTree(diag); err != nil {
		return nil, err
	}
	if p := findProcess(procs, rootPid); p != nil {
		p.ExitCode = rc.ExitCode
		// The root's parent is cilock itself — we forked it, so this one
		// edge is known rather than polled.
		p.ParentPID = os.Getpid()
	}
	// Last question before this becomes evidence: is anything of ours still
	// running? Asked here rather than only before the hashing, because that
	// hashing is a window a descendant can be forked in.
	if err := refuseLateDescendants(rootPid, rootPgid, rootSid, sess, listAllProcs, sidOf); err != nil {
		return nil, err
	}
	diag.Note = darwinTraceLimitations
	rc.darwinTraceDiag = diag
	log.Debugf("(sandbox-trace) tree: processes=%d execs=%d forks=%d unattributed=%d unproven-pids=%d "+
		"group-only-pids=%d net=%d net-unattributed=%d net-no-destination=%d",
		len(procs), diag.ExecReports, diag.ForkReports, diag.UnattributedReports, diag.UnprovenPIDs,
		diag.GroupOnlyPIDs, diag.NetworkReports, diag.NetworkReportsUnattributed,
		diag.NetworkReportsWithoutDestination)

	if rc.ExitCode != 0 {
		return procs, fmt.Errorf("exit status %v", rc.ExitCode)
	}
	return procs, nil
}

// execOutcomePermittedNotConfirmed is what every exec event on this backend
// carries in SyscallEvent.Outcome: the sandbox ALLOWED the exec, and whether
// execve then succeeded is not observable through the report channel. It is
// the machine-readable form of a limitation the note could only state in
// prose, so a policy can tell this backend's weaker semantics from the Linux
// backends' without parsing English.
const execOutcomePermittedNotConfirmed = "permitted-not-confirmed"

// execDigestBindingCollectorOpen names, inside the signed predicate, what an
// exec digest on this backend IS: the bytes at the reported path WHEN THE
// COLLECTOR OPENED IT, verified unchanged from there to the end of the run.
//
// The label was "path-at-report-time" and that overstated it. The collector
// opens the path after the report is DELIVERED, so the bytes measured are
// the ones at that path when this process looked, not when the kernel
// reported the exec. The ctime-vs-report check refuses an inode created
// after the report's own timestamp, which catches the ordinary replace, but
// it does not close the race: a whole-second filesystem admits a replacement
// inside the same tick, and retargeting a symlink at a pre-existing inode
// leaves an older ctime. A label claiming report-time binding would have a
// reader trusting a property this cannot deliver, so it states the weaker
// truth.
//
// It is NOT the vnode the kernel loaded either — that binding needs Endpoint
// Security, which the install-nothing constraint rules out — and a verifier
// must not read programDigest here as the executed bytes proven.
const execDigestBindingCollectorOpen = "path-at-collector-open-time"

// refuseUnobservedRoot refuses a trace that never saw the command itself exec.
//
// EVERY OTHER COMPLETENESS CHECK HERE IS A COUNT OF THINGS THAT WENT WRONG,
// and a report channel that delivered NOTHING for the root trips none of them:
// no unattributed reports, no unproven pids, no undigested execs, all zero
// because there was nothing to count. Meanwhile the readiness and network
// canaries are separate processes with their own reports, so they can succeed
// while the command's own report is lost — leaving a capture mode set,
// networkObserved true, and an EMPTY tree. cilock then reads an empty egress
// list off that and stamps an affirmative "no external egress observed" on a
// build it never actually watched.
//
// The root's exec is the one report this backend can require by construction:
// the traced command is exec'd under the profile, so if the channel is working
// at all its report arrives. Demanding it turns "we saw nothing" back into a
// refusal instead of a clean bill of health — the same correction made for the
// network capability flag, one level up.
func refuseUnobservedRoot(procs []ProcessInfo, rootPid int) error {
	p := findProcess(procs, rootPid)
	if p == nil {
		return fmt.Errorf("macOS process tracing: the traced command (pid %d) produced no report at all — the "+
			"report channel delivered nothing for the process this attestation is about, so an empty tree would "+
			"be signed as an observation of a command that did nothing, and this run is not attestable", rootPid)
	}
	for i := range p.SyscallEvents {
		if p.SyscallEvents[i].Syscall == "execve" {
			return nil
		}
	}
	return fmt.Errorf("macOS process tracing: no exec was observed for the traced command (pid %d) — its own "+
		"exec report never arrived or could not be attributed, so nothing establishes that the command this "+
		"attestation describes ever ran, and this run is not attestable", rootPid)
}

// refuseIncompleteTree is the post-build gate on the diagnostics: a signed
// tree must not be an incomplete account presented as a complete one.
// WHY A NON-EMPTY UnprovenExecs DOES NOT REFUSE, since this is the question
// reviewers keep arriving at and the answer belongs next to the gate.
//
// An unproven exec is a report whose pid could not be tied to the tree because
// the process exited before its kernel facts could be polled. That is not an
// anomaly, it is this backend's ordinary residual, and the cost of refusing on
// it was MEASURED rather than asserted (macOS 15, this machine, load 10-26,
// real traces):
//
//	execs per run   runs   runs with >=1 unproven
//	           20      10                       0
//	          200      10                       1
//	          500       6                       2
//	         2000       6                       3
//
// That is a per-exec loss rate near 0.05%, and it COMPOUNDS: the chance a run
// contains at least one is 1-(1-p)^N, so it climbs from 0% at 20 execs to
// ~50% at 2000. A real `jade test` execs in the thousands, where the same
// rate puts refusal above 99%. Refusing on any non-empty list would therefore
// not fail a tolerable share of honest builds — it would fail essentially ALL
// of them, and an unusable tracer gets switched off, which is worse for the
// evidence than a stated gap.
//
// (An earlier revision of this comment claimed "one run in six". That number
// was wrong: it came from a flaky TEST at high load, not from this counter,
// and the measurement above replaces it.)
//
// The gap is therefore made VISIBLE rather than fatal, in three places that a
// consumer cannot miss: the entries are listed individually (so the account is
// complete), UnprovenExecsOmitted refuses if that list ever TRUNCATES (so a
// bounded list cannot hide one), and cilock's run summary reports the count as
// unattributed_execs so it reaches an operator without reading the predicate.
// The entries deliberately carry no image identity — the report stream is
// machine-wide and an unproven pid's owner is unknown by construction, so
// naming an image would attribute a stranger's program to this build, which is
// a worse failure than an anonymous gap.
func refuseIncompleteTree(diag *DarwinTraceDiagnostics) error {
	if diag.UnprovenExecsOmitted > 0 {
		// A bounded list that overflowed is not a complete account of what
		// was observed, and an image-deny policy reading it could approve a
		// run whose forbidden exec sits past the cap. Refuse.
		return fmt.Errorf("macOS process tracing: %d unattributed exec report(s) beyond the %d the attestation "+
			"can carry — the list a policy would inspect is incomplete, so this run is not attestable; "+
			"a build producing this many unattributable execs needs its fork storm looked at", diag.UnprovenExecsOmitted, maxUnprovenExecs)
	}
	if diag.AttributedExecsUndigested > 0 {
		// An exec in the tree with no digest is an image this build ran
		// that the evidence cannot name. Signing it would let a digest
		// policy approve a run whose forbidden image simply vanished — or
		// was rewritten — before it could be measured. Refuse.
		return fmt.Errorf("macOS process tracing: %d exec(s) attributed to this build carry no image digest — the "+
			"image was gone before its report arrived, exceeded the %d-byte pin bound, or was rewritten in place "+
			"after it ran — so an image policy could not be evaluated against the bytes that executed, and this "+
			"run is not attestable", diag.AttributedExecsUndigested, maxImageBytes)
	}
	if diag.CollectorRecordsUnreadable > 0 {
		// The line was not valid JSON, so nothing about it could be read —
		// not its pid, not even whether it was a sandbox report. That is
		// UNKNOWN ownership, not proven-foreign, and unknown fails toward
		// ours everywhere else here; a malformed record also usually means
		// the stream was truncated, which is data loss whoever it belonged
		// to. It was previously folded into UnparsedRecords, whose contract
		// is "provably a stranger's", so the gap was described as somebody
		// else's and refused nothing.
		return fmt.Errorf("macOS process tracing: %d record(s) from the kernel log stream could not be decoded "+
			"at all — not their pid, not whether they were sandbox reports — so an exec or connection of this "+
			"build's may be inside one of them and the stream may have been truncated, and this run is not "+
			"attestable", diag.CollectorRecordsUnreadable)
	}
	if diag.UnparseableOwnReports > 0 {
		return fmt.Errorf("macOS process tracing: %d sandbox report(s) from this build (or from a process whose "+
			"ownership could not be decided) could not be interpreted — a path with a newline, or a report format "+
			"this version does not know — and an exec or connection may be missing from the evidence, so this run "+
			"is not attestable", diag.UnparseableOwnReports)
	}
	return nil
}

// darwinTraceLimitations travels INSIDE the signed predicate so a verifier
// learns this backend's blind spots from the attestation itself rather than
// from our source tree.
const darwinTraceLimitations = "sandbox report channel: exec'd image paths are observed, and openedFiles " +
	"carries those images only; argv, per-process exit codes and file reads are NOT observable here and are " +
	"omitted rather than reconstructed, so an absent path is not evidence a file was untouched. When " +
	"argv0Normalized is true the wrapper supplied the executable's RESOLVED PATH as argv[0] where the caller had " +
	"asked for a bare name (the ordinary shape of exec.Command); a program that reads argv[0] to locate its " +
	"resources therefore saw the path, not the name. An argv[0] naming a DIFFERENT executable, and an empty one, " +
	"are refused rather than traced. An allow " +
	"exec report proves the sandbox PERMITTED the exec, not that execve then succeeded — a permitted exec " +
	"can still fail (ENOENT, ENOEXEC) after the report, so an exec event is an attempt the kernel allowed, " +
	"with the image digest read from the inode at that path WHEN THE COLLECTOR OPENED IT, which is after report " +
	"delivery (execDigestBinding = path-at-collector-open-time): it is NOT the vnode the kernel loaded. An inode " +
	"created after the report's own timestamp is refused a digest, which catches the ordinary replace, but it does " +
	"NOT close the race — a whole-second filesystem admits a replacement inside the same tick, and retargeting a " +
	"symlink at a pre-existing inode leaves an older ctime — so this is collector-time evidence and a digest-deny " +
	"policy must treat it as such. For the same reason this backend leaves program's DIGEST and exeDigest " +
	"EMPTY: those fields read as \"these bytes ran\" to every consumer, and it CANNOT CORROBORATE THAT ANY EXEC " +
	"SUCCEEDED: nothing in the channel " +
	"reports execve's return value, and a later report from the same pid proves only that the pid lived, not which " +
	"image it is running (a failed exec leaves the OLD image reporting, and it may share the new one's name). Each " +
	"exec SYSCALL EVENT still carries the digest pinned at its own report, where the claim is local and explicit — " +
	"an exec of this image was permitted, with these bytes at that path when the report arrived — so a policy that " +
	"wants image evidence reads the events and decides what an attempt is worth. No exec here is evidence that its " +
	"bytes ran. Operations the sandbox REFUSED are excluded " +
	"from the tree and counted in deniedReports. A process that exec'd and exited before its kernel facts " +
	"could be read has NO parent edge and is NOT in the tree; its exec is listed in unprovenExecs as a bare pid " +
	"and timestamp, with NO image identity of any kind: the stream is machine-wide, such a process's owner is " +
	"unknown by construction, and publishing a path hash or a content digest would disclose that another user of " +
	"this machine ran something. A policy that forbids an image MUST fail closed on a non-empty unprovenExecs, " +
	"while a policy that needs a complete tree requires unprovenPids == 0 and must compare forkReports against " +
	"observedChildren ITSELF: a child that forked, acted and exited before its parent leaves no report and is gone " +
	"from the process table before either sweep reads it, and the kernel's fork report is the only trace. Those two " +
	"counts are published raw rather than subtracted, because the difference is NOT exact — a posix_spawn child " +
	"emits no fork report and would cancel a genuinely missing one — so agreement between them is not proof of " +
	"completeness, only disagreement is proof of incompleteness. unprovenPids counts the " +
	"sweep's fork-only descendants too: a child that never exec'd and never used the network produces no report at " +
	"all, cannot be emitted as a process, and is counted there rather than being silently absent. Every exec INSIDE " +
	"the tree carries an image digest: one that could not be digested refuses the attestation rather than being " +
	"signed without it. A process that " +
	"appeared after the command started and hangs off launchd — a descendant whose parent exited, or an app " +
	"launched mid-build — is treated the same way, unproven rather than foreign, and counted in " +
	"reparentedAfterRoot; one still running when the command exits refuses the attestation. " +
	darwinNetworkLimitations

// darwinNetworkLimitations is the part of the note a verifier MUST read before
// interpreting network.connections or an empty egress list. It is appended to
// the signed note rather than kept in a source comment for the obvious reason:
// whoever reads a stored macOS attestation is not reading this file.
const darwinNetworkLimitations = "network: outbound/inbound/bind operations ARE observed — and networkObserved " +
	"is set only when a live probe pair got BOTH an inbound accept and an outbound connect back through the " +
	"channel, so it reports proven delivery rather than the profile's intent. But the kernel " +
	"reports THE FILTER THAT MATCHED rather than the destination, so for every IP endpoint the PORT is real " +
	"and the HOST IS NOT OBSERVABLE — recorded as address \"" + HostNotObservable + "\" with family " +
	FamilyInetUnspecified + " (IPv4 vs IPv6 is not observable either, and a loopback connection is " +
	"indistinguishable from an external one). The endpoint list is PORT-ONLY BY CONSTRUCTION: it must not be " +
	"read as a set of resolved hosts, and a short list is not evidence of a narrowly-scoped build. " +
	"\"connect\" here covers connect() and sendto() alike, which the report does not distinguish. UNIX socket " +
	"paths ARE observed in full. Bare outbound reports naming no destination COUNT as egress under family " +
	FamilyNotObservable + ": in the benign case they are the name-resolution path (a process that only called " +
	"getaddrinfo produced exactly one), but an observed outbound operation nobody could describe cannot be " +
	"certified as one that reached nothing — and name resolution itself moves data both ways. They are sized " +
	"separately in networkReportsWithoutDestination so a verifier can see how much of the egress is that shape"

// recordExitStatus mirrors the Linux tracers: a non-zero exit is recorded and
// returned as an error, while a wait failure that is not an exit status is
// fatal to the trace.
func (rc *CommandRun) recordExitStatus(waitErr error) error {
	if waitErr == nil {
		rc.ExitCode = 0
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		rc.ExitCode = exitErr.ExitCode()
		return nil
	}
	return fmt.Errorf("wait tracee: %w", waitErr)
}

// reapDarwinProcessGroup SIGKILLs the traced command's process group after the
// command itself has exited. configureProcessReaping put the root in its own
// group, so this reaches exactly the descendants that stayed where the kernel
// put them; ESRCH means there was nobody left, which is the normal case.
func reapDarwinProcessGroup(pgid int) error {
	if pgid <= 0 {
		return nil
	}
	// ESRCH means the group is already gone, which is the ordinary case and
	// exactly what we wanted. ANY OTHER ERROR means the group may still be
	// running and we have no way to stop it: a descendant could then act
	// after the reports are harvested and exit while the images are being
	// hashed, so its work would be missing from evidence that claims to be
	// complete. Logging and continuing made that outcome silent.
	if err := unix.Kill(-pgid, unix.SIGKILL); err != nil && err != unix.ESRCH {
		return fmt.Errorf("macOS process tracing: the command's process group %d could not be reaped (%v) — a "+
			"descendant may still be running and could act after the evidence was gathered, so this run is not "+
			"attestable", pgid, err)
	}
	return nil
}

// launchdPid is where XNU reparents an orphan.
const launchdPid = 1

// maxAncestryHops bounds the parent-chain walk in poisonUnresolvedAncestry.
// A real build's tree is a few dozen deep; a chain longer than this that has
// not yet reached a proof of non-descent is not trusted to be a stranger's,
// so exceeding it fails the pid closed (unresolved) rather than open.
const maxAncestryHops = 64

// reparentedAfterRoot reports whether f describes a process that hangs off
// launchd and STARTED AFTER THE ROOT DID.
//
// A readable parent chain that does not reach the root is not proof of
// non-descent. A descendant can double-fork or setsid, let its intermediate
// parent exit, and be reparented to launchd before its facts are polled: the
// poll then reads ppid 1 and the process would be classified proven-foreign,
// its fetch dropped as a stranger's and the build signed hermetic. Every
// process on the machine hangs off launchd eventually, so ppid alone cannot
// be the test; the start time is. A launchd child that was running before
// the root existed is a stranger (Safari, the terminal); one that appeared
// after the root started is a process whose descent this tracer cannot
// decide either way — and undecidable fails toward unproven, which is
// non-hermetic for its network and a listed, unattributed exec for its
// images. A fresh app the user launched mid-build lands in the same bucket;
// that is the cost of not letting a detached fetcher hide.
func reparentedAfterRoot(f, root procFacts) bool {
	if !f.ok || !root.ok || f.ppid != launchdPid {
		return false
	}
	return f.startSec > root.startSec || (f.startSec == root.startSec && f.startUsec >= root.startUsec)
}

// poisonReparented replaces the facts of every reparented-after-root pid
// with unproven ones, in place, and returns the originals keyed by pid.
func poisonReparented(facts map[int]procFacts, root procFacts) map[int]procFacts {
	out := map[int]procFacts{}
	for pid, f := range facts {
		if reparentedAfterRoot(f, root) {
			out[pid] = f
			facts[pid] = procFacts{}
		}
	}
	return out
}

// poisonUnresolvedAncestry finds the non-member pids whose facts were read
// but whose ancestry cannot be DECIDED, and poisons them to unproven.
//
// Readable facts prove only that pid's own parent edge. "Not a member" is
// proof of non-descent only when the chain is followed to something that
// is provably not this build: an ancestor that was already running before
// the root existed (Safari, the terminal, launchd's own children from
// before the build), or cilock itself. A chain that runs into a process
// whose facts could not be read — an intermediate that exited before its
// poll, or one that appeared after the root and was never seen — is
// UNRESOLVED: the pid may be a descendant behind a short-lived parent, and
// dropping its connect as a stranger's would sign an empty egress list over
// egress that may be ours. Unresolved fails toward unproven, exactly like a
// pid whose own poll lost the race. `poll` reads a pid this session never
// saw a report from; the kernel is asked once per such ancestor.
func poisonUnresolvedAncestry(facts map[int]procFacts, rootPid int, root procFacts, poll func(int) procFacts) map[int]procFacts {
	members := map[int]bool{rootPid: true}
	for changed := true; changed; {
		changed = false
		for pid, f := range facts {
			if members[pid] || !f.ok {
				continue
			}
			if members[f.ppid] {
				members[pid] = true
				changed = true
			}
		}
	}
	selfPid := os.Getpid()
	polled := map[int]procFacts{}
	ancestor := func(pid int) (procFacts, bool) {
		if f, ok := facts[pid]; ok {
			return f, true
		}
		if f, ok := polled[pid]; ok {
			return f, false
		}
		f := poll(pid)
		polled[pid] = f
		return f, false
	}
	unresolved := map[int]procFacts{}
	for pid, f := range facts {
		if !f.ok || members[pid] || pid == rootPid || pid == selfPid {
			continue
		}
		cur := f
		hops := 0
		for {
			pp := cur.ppid
			if hops > maxAncestryHops {
				// The chain is longer than any real build's and we have not
				// reached a proof of non-descent. A tracee can fork past the
				// cap behind a reparented or unreadable ancestor; treating
				// the cap as "not ours" (the earlier code did) would drop a
				// deep descendant's exec and network reports as a stranger's.
				// Undecidable fails toward unproven.
				unresolved[pid] = f
				facts[pid] = procFacts{}
				break
			}
			if pp <= launchdPid || pp == selfPid || members[pp] {
				break // provably not ours (launchd, cilock) — or a cycle, which is not a proof of descent
			}
			pf, seen := ancestor(pp)
			if !pf.ok {
				// An ancestor nothing could be read about: undecidable.
				unresolved[pid] = f
				facts[pid] = procFacts{}
				break
			}
			if !seen && !startedBefore(pf, root) {
				// An ancestor this session never saw a report from, yet it
				// appeared after the root started: it could be a descendant
				// whose reports were coalesced or lost. Undecidable.
				unresolved[pid] = f
				facts[pid] = procFacts{}
				break
			}
			if !seen {
				break // an ancestor that predates the build: a stranger's chain
			}
			cur = pf
			hops++
		}
	}
	return unresolved
}

// refuseLateDescendants asks, ONE LAST TIME AFTER THE EVIDENCE IS BUILT,
// whether anything that could be this build's is still running.
//
// The earlier check runs before the images are hashed, and hashing a large
// tree is not instant. In that window a member can fork a successor and
// exit: the member then reads as gone, and the successor is in neither the
// exit snapshot nor any report-derived map, so a trace that only asked
// early would sign as complete while a process of this build's could still
// rewrite the artifacts it just measured. The table is therefore read again
// here, the same descendant predicate applied to it, and anything alive —
// a member, or a candidate the fresh table reveals that the first sweep did
// not see — refuses.
//
// `list` and `sid` are parameters for testing.
// The residual is irreducible and the same class as report latency: a fork
// between this scan and the signature.
func refuseLateDescendants(rootPid, rootPgid, rootSid int, sess *sandboxSession,
	list func() ([]kinfoFacts, error), sid func(int) (int, error)) error {
	table, err := list()
	if err != nil {
		return fmt.Errorf("macOS process tracing: the kernel process table could not be re-read after the evidence "+
			"was built (%v); a descendant forked while the images were hashed could not be looked for, so this "+
			"run is not attestable", err)
	}
	// EVERY live row is re-evaluated, not just the ones the first table did
	// not contain. A pid present earlier but never accounted for — a
	// detached grandchild sitting behind an unobserved intermediate that has
	// since exited and been reparented — would otherwise be discarded here
	// as "already seen" while it was still running. Anything the earlier
	// sweep DID account for is already dead by this point: the orphan check
	// above refuses on a live one, so re-examining costs a comparison and
	// buys the case it was written for.
	facts := sess.factsSnapshot()
	late := sweepUnobservedDescendants(rootPid, rootPgid, rootSid, sess.rootUID, sess.rootFacts, facts,
		sess.reportedComms(), table, sid)
	live, err := survivingDarwinMembers(rootPid, keysOf(late), late)
	if err != nil {
		return err
	}
	// The member set is RE-RESOLVED from the fresh facts, not inherited. A
	// descendant that first reported AFTER the tree was built is in this
	// snapshot but not in the caller's `members`, and the sweep above skips
	// it precisely because it is now a reported pid — so with the stale set
	// neither check would ever look at it, and it could still be running.
	// That is the hole this whole function exists to close.
	//
	// The facts are POISONED FIRST, exactly as snapshot does it, and that is
	// the difference between the two exclusions meeting in a hole and meeting
	// in a refusal. A descendant that reported AND whose parent chain no
	// longer reaches the root — it double-forked and launchd adopted it, or
	// its intermediate parent exited before its facts could be polled — is
	// skipped by the sweep above (it is a reported pid) and skipped by the
	// member resolve below (its ppid is not in the tree), so nothing asked
	// the kernel whether it was still running.
	//
	// This is NOT a new refusal class. buildDarwinTree already unions
	// reparented + unresolved + unobserved and refuses on any of them that
	// is still alive (the "undecided orphans" check above); all that happens
	// here is the SAME policy applied to the SECOND reading, the one taken
	// after the images were hashed. Without it the tree reports those pids
	// unproven while the trace reports the run complete, which is the
	// contradiction the sweep found.
	canaries := sess.canarySet()
	detached := map[int]procFacts{}
	for _, poisoned := range []map[int]procFacts{
		poisonReparented(facts, sess.rootFacts),
		poisonUnresolvedAncestry(facts, rootPid, sess.rootFacts, pollProcFacts),
	} {
		for pid, f := range poisoned {
			// Our own network probe is reaped by the canary's Wait; it is not
			// a descendant of the traced command and refusing over it would
			// refuse every run.
			if !canaries[pid] {
				detached[pid] = f
			}
		}
	}
	// Keyed off the ORIGINALS the poisoners handed back, not off facts: the
	// poisoning zeroed those entries, and survivingDarwinMembers needs the
	// recorded start time to tell a live descendant from a recycled pid.
	loose, err := survivingDarwinMembers(rootPid, keysOf(detached), detached)
	if err != nil {
		return err
	}
	freshMembers, _, _ := resolveTreeMembers(rootPid, rootPgid, facts, canaries)
	stragglers, err := survivingDarwinMembers(rootPid, freshMembers, facts)
	if err != nil {
		return err
	}
	if len(loose) > 0 {
		return fmt.Errorf("macOS process tracing: %d process(es) (pids %v) reported during the run, are still "+
			"running, and their parent chain no longer reaches the command — detached or orphaned behind an "+
			"intermediate that exited — so a process this trace cannot rule out as the build's can rewrite what "+
			"was just measured, and this run is not attestable", len(loose), loose)
	}
	if len(stragglers) > 0 {
		return fmt.Errorf("macOS process tracing: %d descendant(s) (pids %v) were still running when the evidence "+
			"finished being built — including any that first reported after the tree was resolved — so a process "+
			"of this build's could act after it is signed and this run is not attestable", len(stragglers), stragglers)
	}
	if len(live) > 0 {
		return fmt.Errorf("macOS process tracing: %d process(es) appeared after the command's exit was swept and are "+
			"still running (pids %v) — a member that forked a successor and exited while the evidence was being "+
			"built leaves a process able to rewrite what was just measured, so this run is not attestable",
			len(live), live)
	}
	return nil
}

// mergeProcTables unions two readings of the process table, keeping the
// FIRST row for a pid — the pre-reap incarnation, which is the one the sweep
// must judge, since anything the reap killed cannot be re-read.
func mergeProcTables(first, second []kinfoFacts) []kinfoFacts {
	seen := make(map[int]bool, len(first)+len(second))
	out := make([]kinfoFacts, 0, len(first)+len(second))
	for _, rows := range [][]kinfoFacts{first, second} {
		for _, row := range rows {
			if seen[row.pid] {
				continue
			}
			seen[row.pid] = true
			out = append(out, row)
		}
	}
	return out
}

// sweepUnobservedDescendants lists processes the report channel never
// mentioned that the kernel nonetheless shows attached to this build: started
// after the root, and either parented by a pid in the tree or sharing the
// root's process group. A descendant that detached with setsid AND whose
// parent has already exited hangs off launchd and is indistinguishable here
// from an app the user launched; that is a stated residual, not a guess.
// `list` reads the whole process table; it is called once, after the
// command exits and before its group is reaped.
func sweepUnobservedDescendants(rootPid, rootPgid, rootSid int, rootUID uint32, root procFacts, facts map[int]procFacts, commOf map[int]string, table []kinfoFacts, sid func(int) (int, error)) map[int]procFacts {
	out := map[int]procFacts{}
	if !root.ok {
		return out
	}
	members := map[int]bool{rootPid: true}
	for changed := true; changed; {
		changed = false
		for pid, f := range facts {
			if !members[pid] && f.ok && members[f.ppid] {
				members[pid] = true
				changed = true
			}
		}
	}
	selfPid := os.Getpid()
	// The sweep runs the moment the command exits, which can be before a
	// member's own exec report has been delivered; the process table does
	// not wait for the log. A parent that sits in the root's process group
	// is the build's for the purpose of this sweep (a setpgid intruder's
	// children would land here too, and refusing over a stranger's live
	// process is the safe direction).
	inGroup := map[int]bool{}
	for _, p := range table {
		if rootPgid != 0 && p.facts.ok && p.facts.pgid == rootPgid && !startedBefore(p.facts, root) {
			inGroup[p.pid] = true
		}
	}
	// The names the tree's own reports carried — the comm of every member
	// that reported, read from the reports rather than the table, because
	// the member that forked the orphan has usually exited by now. A
	// double-forked, setsid'd orphan runs the same image as that member, so
	// its comm is one of these; an app the user launched is not.
	treeComms := map[string]bool{}
	for pid, comm := range commOf {
		if comm != "" && (pid == rootPid || members[pid] || inGroup[pid]) {
			treeComms[comm] = true
		}
	}
	for _, p := range table {
		if p.pid == rootPid || p.pid == selfPid || !p.facts.ok {
			continue
		}
		if _, seen := facts[p.pid]; seen {
			continue
		}
		if startedBefore(p.facts, root) {
			continue
		}
		if members[p.facts.ppid] || inGroup[p.facts.ppid] || (rootPgid != 0 && p.facts.pgid == rootPgid) {
			out[p.pid] = p.facts
			continue
		}
		// The session the root INHERITED — configureProcessReaping gives it a
		// new process group, never a new session — so every other process the
		// same shell or runner starts shares it. Session equality alone
		// therefore swept in unrelated concurrent work and, when it was still
		// alive at exit, refused the whole attestation; a machine running two
		// builds from one terminal could never produce a macOS trace.
		//
		// It speaks only for a process the root's own lineage LOST: one whose
		// parent has already exited, so launchd adopted it and no parent edge
		// can reach the tree. A process whose parent is alive and is not ours
		// is the shell's other child, and one whose parent IS ours was already
		// admitted by lineage or by the group above.
		//
		// A pid that vanished between the table read and this call is not a
		// live descendant; any other failure (EPERM for another user's
		// process) means it is not ours to read, and not ours.
		if p.facts.ppid == launchdPid && p.uid == rootUID {
			if s, err := sid(p.pid); err == nil && rootSid > 0 && s == rootSid {
				out[p.pid] = p.facts
				continue
			}
		}
		// The double-fork: a child that setsid'd AND whose parent already
		// exited hangs off launchd in a fresh session, exactly like an app the
		// user launched — except that it runs the tree's own image (its comm
		// is one a tree member reported under), it has no controlling
		// terminal (a terminal command the user typed would), and it runs as
		// this user. All three together, started after the root, is undecidable
		// rather than foreign; a stranger's process matching all three is the
		// stated residual, and refusing over it is the safe direction.
		if p.facts.ppid == launchdPid && p.noTTY && p.uid == rootUID && treeComms[p.comm] {
			out[p.pid] = p.facts
		}
	}
	// A descendant the sweep discovers is a descendant, so ITS children are
	// this build's too. One pass only admitted rows whose parent was already
	// known, leaving a grandchild behind an unobserved intermediate
	// invisible — and the late scan then skipped it as already seen. Iterate
	// to a fixpoint over the rows admitted so far.
	for changed := true; changed; {
		changed = false
		for _, p := range table {
			if p.pid == rootPid || p.pid == selfPid || !p.facts.ok {
				continue
			}
			if _, already := out[p.pid]; already {
				continue
			}
			if _, seen := facts[p.pid]; seen {
				continue
			}
			if startedBefore(p.facts, root) {
				continue
			}
			if _, parentSwept := out[p.facts.ppid]; parentSwept {
				out[p.pid] = p.facts
				changed = true
			}
		}
		if changed {
			continue
		}
		break
	}
	return out
}

// sidOf reads a pid's session id.
func sidOf(pid int) (int, error) {
	return unix.Getsid(pid)
}

// kinfoFacts is one process-table row as sweepUnobservedDescendants reads it.
type kinfoFacts struct {
	pid   int
	facts procFacts
	uid   uint32
	// noTTY is true when the process has no controlling terminal — what a
	// setsid'd child looks like, and what a GUI app looks like too.
	noTTY bool
	comm  string
}

// listAllProcs reads the kernel process table once. A failure is the
// caller's to refuse on: an empty table would read as "no descendants".
func listAllProcs() ([]kinfoFacts, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make([]kinfoFacts, 0, len(kps))
	for i := range kps {
		kp := &kps[i]
		out = append(out, kinfoFacts{
			pid: int(kp.Proc.P_pid),
			facts: procFacts{
				ppid: int(kp.Eproc.Ppid), pgid: int(kp.Eproc.Pgid),
				startSec: kp.Proc.P_starttime.Sec, startUsec: kp.Proc.P_starttime.Usec, ok: true,
			},
			uid:   kp.Eproc.Ucred.Uid,
			noTTY: kp.Eproc.Tdev == -1 || kp.Eproc.Tdev == 0,
			comm:  unix.ByteSliceToString(kp.Proc.P_comm[:]),
		})
	}
	return out, nil
}

// startedBefore reports whether f's kernel start time precedes root's.
func startedBefore(f, root procFacts) bool {
	return f.startSec < root.startSec || (f.startSec == root.startSec && f.startUsec < root.startUsec)
}

// keysOf lists a facts map's pids as a membership set.
func keysOf(m map[int]procFacts) map[int]bool {
	out := make(map[int]bool, len(m))
	for pid := range m {
		out[pid] = true
	}
	return out
}

// detachedMembersAtExit lists processes that had LEFT the root's process group
// while the command was still running.
//
// `members` is every pid the caller could not rule out as this build's — the
// proven tree AND the undecidable buckets (reparented, unresolved, swept). A
// proven member is not the only thing that can detach and act.
//
// reapDarwinProcessGroup kills -rootPgid, so a member in another group is
// not reachable by it: it can keep working after the drain and exit before
// survivingDarwinMembers looks, at which point the liveness check reads it
// as gone and its post-drain execs and connections are simply missing from
// evidence that claims to be complete. Being SEEN detached in the pre-reap
// snapshot is therefore enough to refuse — whether it is still alive later
// is exactly the question that cannot be answered in time.
//
// A member that changed groups and exited before the snapshot is not here,
// and does not need to be: everything it did arrived as reports before it
// died.
func detachedMembersAtExit(preReap []kinfoFacts, members map[int]bool, rootPid, rootPgid int) []int {
	if rootPgid == 0 {
		return nil
	}
	// DEDUPED: the caller passes two snapshots concatenated, so a pid detached
	// in both reads would otherwise be named twice and inflate the count.
	seen := map[int]bool{}
	var out []int
	for _, row := range preReap {
		if row.pid == rootPid || !row.facts.ok || !members[row.pid] || seen[row.pid] {
			continue
		}
		if row.facts.pgid != rootPgid {
			seen[row.pid] = true
			out = append(out, row.pid)
		}
	}
	sort.Ints(out)
	return out
}

// darwinStatZombie is XNU's SZOMB p_stat: the process is dead and merely
// unreaped. A zombie cannot act, so it is not a survivor.
const darwinStatZombie = 5

// survivingDarwinMembers returns the tree members (root excluded) that are
// STILL RUNNING — same pid, same kernel start time, not a zombie — after the
// command exited and its group was reaped.
//
// Only a DEFINITIVE answer lets a member pass: the kernel saying there is no
// such pid, a different incarnation at that pid, or a zombie. A read that
// FAILED says nothing about the process, and treating it as "gone" would
// sign the attestation while a known descendant may still be acting; that
// read is returned as an error and the trace refuses.
func survivingDarwinMembers(rootPid int, members map[int]bool, facts map[int]procFacts) ([]int, error) {
	var out []int
	for pid := range members {
		if pid == rootPid {
			continue
		}
		cached, ok := facts[pid]
		if !ok || !cached.ok {
			continue // no incarnation to compare; already counted as unproven
		}
		kp, err := readKinfo(pid)
		if err != nil {
			return nil, fmt.Errorf("macOS process tracing: whether descendant pid %d is still running could not be "+
				"determined (%v); a tree cannot be attested as complete while a member's liveness is unknown", pid, err)
		}
		if kp == nil || kp.Proc.P_stat == darwinStatZombie {
			continue
		}
		if kp.Proc.P_starttime.Sec == cached.startSec && kp.Proc.P_starttime.Usec == cached.startUsec {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out, nil
}

// observeRootPgid returns the traced root's process-group id, or 0 when the
// root is not its own group leader.
//
// It is DIAGNOSTIC ONLY: resolveTreeMembers admits nobody on it, and uses it
// solely to count the pids that shared this group without a proven parent
// chain. configureProcessReaping sets Setpgid, so the root's pgid equals its
// pid by construction; a root that is somehow not a leader would have a group
// full of cilock's other children (a concurrent lane's canary, say), and
// counting those as near-misses would be noise, so the counter is switched off
// with 0 instead.
func observeRootPgid(rootPid int) int {
	pg, err := unix.Getpgid(rootPid)
	if err != nil {
		// The command already exited. rootPid is what Setpgid guarantees, and
		// a wrong guess here can only mis-count a diagnostic, never admit a
		// process to the tree.
		return rootPid
	}
	if pg != rootPid {
		return 0
	}
	return pg
}

// resolveTreeMembers decides which pids belong to THIS build, from kernel
// facts only.
//
// A pid is a member when the kernel-read parent chain reaches the root. Every
// edge is read from the kernel at that pid's first sighting, never guessed: a
// pid whose poll lost the race stays out of the tree and is counted in
// unproven.
//
// PROCESS-GROUP EQUALITY IS NOT ADMISSION, and the difference is the whole
// security value of this function. POSIX setpgid lets any process in the same
// session join an existing process group, so sharing the root's group is
// something a stranger can arrange for itself in one syscall — it is not
// evidence that this build started anything. An agent under gate pressure
// starts a helper, calls setpgid(0, tracee), and every exec and every
// connection that helper makes would be signed as this build's work, with no
// parent edge to give it away. Pids in that position are excluded and counted
// in groupOnly instead.
//
// The report stream is machine-wide, which is what makes over-attribution the
// dangerous direction: another cilock run on the same Mac emits byte-identical
// exec reports. A smaller tree understates what a build did; a tree with a
// stranger in it says the build did something it never did.
func resolveTreeMembers(rootPid, rootPgid int, facts map[int]procFacts, canaries map[int]bool) (members map[int]bool, unproven, groupOnly uint64) {
	members = map[int]bool{rootPid: true}
	selfPid := os.Getpid()
	for pid, f := range facts {
		// Our own probes are reaped by the canary's Wait before their report
		// arrives, so their polls always fail. Counting those would report a
		// permanent, meaningless gap in every attestation.
		if !f.ok && pid != rootPid && !canaries[pid] {
			unproven++
		}
	}
	// Parentage is transitive, and the report order does not guarantee a
	// parent is seen before its child, so iterate to a fixpoint.
	for changed := true; changed; {
		changed = false
		for pid, f := range facts {
			if members[pid] || canaries[pid] || pid == selfPid || !f.ok {
				continue
			}
			if members[f.ppid] {
				members[pid] = true
				changed = true
			}
		}
	}
	// Counted after the fixpoint so the number means "shared the group and the
	// parent chain never reached the root" — a process this attestation does
	// not describe, and the one shape a setpgid intruder would take.
	if rootPgid != 0 {
		for pid, f := range facts {
			if members[pid] || canaries[pid] || pid == selfPid || !f.ok {
				continue
			}
			if f.pgid == rootPgid {
				groupOnly++
			}
		}
	}
	return members, unproven, groupOnly
}

// treeSnapshot is the session state buildDarwinTree reads, copied out from
// under the collector.
type treeSnapshot struct {
	facts map[int]procFacts
	// reparented holds the ORIGINAL facts of every pid that appeared after
	// the root started and now hangs off launchd (see reparentedAfterRoot);
	// in facts those pids are poisoned to unproven. Kept so the survivor
	// check can still ask the kernel whether one of them is alive.
	reparented map[int]procFacts
	// unresolved holds the ORIGINAL facts of pids whose facts were read but
	// whose parent chain runs through a process nothing could be read about
	// (see poisonUnresolvedAncestry); in facts they are poisoned to
	// unproven. Kept, like reparented, so the survivor check can still ask
	// the kernel whether one of them is alive.
	unresolved map[int]procFacts
	// unobserved holds descendants the kernel process table showed at exit
	// that never produced a report at all (see sweepUnobservedDescendants).
	unobserved  map[int]procFacts
	canaries    map[int]bool
	digests     map[pinID]cryptoutil.DigestSet
	unparsed    uint64
	forged      uint64
	pinFailures uint64
	pidReuse    uint64
}

// snapshot copies everything the tree build reads out of the live session while
// holding s.mu, and digests the pinned images in the same critical section.
//
// THE MAPS ARE COPIES, and that is the difference between a trace and a
// crashed build. The collector's reader goroutine runs until shutdown and
// writes s.facts for every machine-wide report that arrives — `log stream` is
// machine-wide and this Mac runs many sandboxed daemons, so reports for
// unrelated pids keep landing the whole time the tree is being built. Handing
// buildDarwinTree the live maps would put an unsynchronised map read beside a
// map write, which the Go runtime answers with `fatal error: concurrent map
// read and map write`: not a panic something can recover, so the build dies
// after the wrapped command already ran and produces no attestation at all.
func (s *sandboxSession) snapshot(hashes []cryptoutil.DigestValue) treeSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked(hashes)
}

// snapshotLocked is snapshot's body. Caller holds s.mu.
func (s *sandboxSession) snapshotLocked(hashes []cryptoutil.DigestValue) treeSnapshot {
	// Digesting first, so pinFailures below counts the failures it adds.
	digests := s.hashPinnedImages(hashes)
	// The canary SET holds the pids still registered as probes — a pid the
	// incarnation check retired (canaryStillOwnsPID) is absent, so nothing
	// downstream can keep excluding a recycled pid's work on its name alone.
	canaries := make(map[int]bool, len(s.canaryPIDs))
	for pid := range s.canaryPIDs {
		canaries[pid] = true
	}
	facts := maps.Clone(s.facts)
	reparented := poisonReparented(facts, s.rootFacts)
	unresolved := poisonUnresolvedAncestry(facts, s.rootPid, s.rootFacts, pollProcFacts)
	return treeSnapshot{
		facts:       facts,
		reparented:  reparented,
		unresolved:  unresolved,
		unobserved:  maps.Clone(s.unobserved),
		canaries:    canaries,
		digests:     digests,
		unparsed:    s.unparsed,
		forged:      s.forged,
		pinFailures: s.pinFailures,
		pidReuse:    s.pidReuse,
	}
}

// hashPinnedImages digests every exec'd image from the fd pinned at report
// time, so the bytes measured are the inode that ran rather than whatever
// occupies that path afterwards. Caller holds s.mu.
//
// Keyed by pin id, which is what each exec EVENT carries. A path key would
// collapse two execs of one path onto one digest, and the second exec is
// exactly the one an attacker controls.
func (s *sandboxSession) hashPinnedImages(hashes []cryptoutil.DigestValue) map[pinID]cryptoutil.DigestSet {
	out := make(map[pinID]cryptoutil.DigestSet, len(s.pinned))
	for _, img := range s.pinned {
		// An fd pins an inode, not bytes: macOS does not enforce ETXTBSY, so
		// the inode can have been rewritten in place since the exec (and
		// mtime is forgeable with utimes, so timestamps cannot catch it).
		// The bytes were sha256'd at REPORT time; tee this read through the
		// same hash and refuse an inode whose content moved. A dropped
		// digest (counted, surfacing as imagesUnhashed) says "we cannot
		// prove which bytes ran"; a digest of rewritten bytes would
		// confidently name bytes that never ran.
		//
		// The SIZE is asked first. A tracee can grow its own executable
		// with one sparse truncate — terabytes of zeros that cost it nothing
		// and would cost this read everything — and an inode whose size
		// moved since the pin cannot hold the bytes that ran, so it is
		// refused WITHOUT being read. (Not the ctime: a rename over the path
		// or a chmod moves ctime and changes no byte, and those pins must
		// keep their digests.) The read that does happen is bounded by the
		// same limit the pin used.
		if fi, err := img.file.Stat(); err != nil || fi.Size() != img.stamp.size {
			s.pinFailures++
			continue
		}
		if _, err := img.file.Seek(0, io.SeekStart); err != nil {
			s.pinFailures++
			continue
		}
		verify := sha256.New()
		ds, err := cryptoutil.CalculateDigestSet(io.TeeReader(io.LimitReader(img.file, maxImageBytes+1), verify), hashes)
		if err != nil {
			s.pinFailures++
			continue
		}
		if !bytes.Equal(verify.Sum(nil), img.sha256[:]) {
			s.pinFailures++
			continue
		}
		out[img.id] = ds
	}
	// Retired pins are refused outright: their inode was rewritten under an
	// exec that came later, and the bytes the earlier exec loaded are gone.
	s.pinFailures += s.retiredPins
	return out
}

// darwinTreeInput is everything buildDarwinTree needs, gathered under the
// session lock and then read without it.
type darwinTreeInput struct {
	rootPid  int
	events   []sandboxEvent
	members  map[int]bool
	canaries map[int]bool
	facts    map[int]procFacts
	digests  map[pinID]cryptoutil.DigestSet
	// swept are the descendants the exit sweep found that never reported.
	// They account for forks whose child produced no report of its own.
	swept map[int]procFacts
}

// buildDarwinTree turns attributed reports into ProcessInfo records.
//
// ONE RECORD PER PID, matching the Linux tracers, with every exec that pid
// performed kept as a syscall event. A pid routinely execs more than one image
// — `./script.sh` reports the script, then process-exec-interpreter /bin/sh,
// then /bin/bash — and collapsing that to a single Program field would drop
// /bin/sh, which is precisely the SIP-protected evidence this backend exists
// to capture.
func buildDarwinTree(in darwinTreeInput, diag *DarwinTraceDiagnostics) []ProcessInfo {
	byPID := make(map[int]*ProcessInfo, len(in.members))
	order := make([]int, 0, len(in.members))
	lastPin := make(map[int]pinID, len(in.members))

	for i := range in.events {
		ev := &in.events[i]
		if ev.op == opUnparseable {
			// A report the grammar could not read. Its loss is this build's
			// loss when the pid is a member or cannot be decided; a proven
			// stranger's is merely counted. trace() refuses on the former.
			if in.members[ev.pid] || !in.facts[ev.pid].ok {
				diag.UnparseableOwnReports++
			} else {
				diag.UnparsedRecords++
			}
			continue
		}
		// A DENIED operation did not happen: the sandbox refused it, so it is
		// neither an executed image, nor a fork edge, nor egress — including
		// on the unproven-ownership path below, which must not turn a refused
		// connect into counted egress. In-tree denials are counted so a
		// verifier sees that something tried; everything else joins the
		// unattributed pile.
		if ev.denied {
			if in.members[ev.pid] {
				diag.DeniedReports++
			} else {
				diag.UnattributedReports++
			}
			continue
		}
		// Canary exclusion is decided PER EVENT, from the stamp record() made
		// when the report arrived: a report is the probe's only while the
		// probe's kernel incarnation still owned the pid. Excluding by pid for
		// the whole session would let the kernel recycle a dead probe's pid
		// onto a build process and have every one of its execs skipped as
		// "our probe" — a blessed pid to hide work under.
		//
		// Network activity is never skipped, stamped or not: the probes are
		// sandboxed /usr/bin/true runs that never touch the network, so a
		// network report under any canary pid — still registered or already
		// retired — is somebody else's, and it takes the unproven-ownership
		// path, which records the egress rather than hiding it. Over-inclusion
		// there fails toward NON-hermetic, the safe direction.
		if isNetworkOp(ev.op) && ev.canary {
			// PROVEN to be one of our own probes when it arrived (the pid was
			// registered AND still held the incarnation we registered), so it
			// is the tracer's traffic, not the build's. The network canary
			// makes a deliberate loopback connect to prove the report channel
			// delivers network events at all — recording that as the build's
			// unproven egress would make every traced run non-hermetic, which
			// is exactly what it did the first time.
			continue
		}
		if isNetworkOp(ev.op) && in.canaries[ev.pid] {
			// Registered as a probe pid, but NOT proven ours at report time:
			// the incarnation changed, so this may be a real process that
			// inherited the pid. Its operation cannot be attributed and must
			// not be dropped.
			recordUnprovenNetwork(byPID, &order, in.rootPid, ev, diag)
			continue
		}
		if ev.canary {
			// Proven to be our own probe's report when it arrived.
			continue
		}
		// NETWORK REPORTS GO THROUGH THE SAME KERNEL-PROVEN ATTRIBUTION AS
		// EXECS, and they need it more. The stream is machine-wide, and where
		// a stranger's exec is merely a process we would wrongly credit, a
		// stranger's connection is egress we would wrongly blame — every other
		// sandboxed app on the Mac narrates its own traffic, so a build that
		// touched nothing would come back non-hermetic because Safari was
		// open. PROVEN-foreign reports are dropped and counted, never
		// admitted. But "proven foreign" and "could not be proven" are
		// different facts with opposite failure directions: a pid whose
		// kernel facts vanished before the poll might be this build's own
		// short-lived child, and dropping its connect would sign an empty
		// egress list over egress that may be ours. Ownership that cannot be
		// DECIDED fails toward non-hermetic instead.
		if !in.members[ev.pid] {
			switch {
			case isNetworkOp(ev.op) && in.facts[ev.pid].ok:
				diag.NetworkReportsUnattributed++
			case isNetworkOp(ev.op):
				recordUnprovenNetwork(byPID, &order, in.rootPid, ev, diag)
			case isExecOp(ev.op) && ev.detail != "" && !in.facts[ev.pid].ok:
				// Ownership could not be DECIDED, and an exec is the one
				// report shape whose loss hides work: the image is listed
				// without a parent edge (see UnprovenExecs) rather than
				// dropped. Proven-foreign execs — facts read, chain
				// elsewhere — stay in the unattributed count.
				recordUnprovenExec(ev, diag)
			default:
				diag.UnattributedReports++
			}
			continue
		}
		// Counted only for reports this build owns. Before the network rule
		// existed this sat above the membership check, which quietly credited
		// this build with strangers' coalesced repeats; with the network
		// stream's much larger discard pile that would stop being a rounding
		// error.
		diag.CoalescedDuplicates += uint64(ev.duplicates)
		p, ok := byPID[ev.pid]
		if !ok {
			p = &ProcessInfo{ProcessID: ev.pid, ParentPID: provenParent(ev.pid, in)}
			byPID[ev.pid] = p
			order = append(order, ev.pid)
		}
		switch {
		case ev.op == opFork:
			diag.ForkReports++
		case isNetworkOp(ev.op):
			diag.NetworkReports++
			recordDarwinNetwork(p, ev, diag)
		default:
			diag.ExecReports++
			recordDarwinExec(p, ev, in.digests)
			lastPin[ev.pid] = ev.pin
			// An attributed exec with no digest is signed as "this build
			// ran an image we cannot name": the pin failed (image gone,
			// over the bound, cap reached) or the end-of-run check refused
			// it (rewritten under the pin). Counted here, refused in
			// refuseIncompleteTree.
			if _, ok := in.digests[ev.pin]; !ok {
				diag.AttributedExecsUndigested++
			}
		}
	}

	// ExeDigest is the image the process was RUNNING when it finished, which
	// is the last one it exec'd; Program/ProgramDigest name the image it was
	// launched as. Same split the Linux tracer records from /proc/<pid>/exe
	// versus the execve argument.
	// ExeDigest and ProgramDigest are NOT populated on this backend.
	//
	// They are generic predicate fields: every consumer reads them as "this
	// is the image the process ran", and on this channel that claim cannot be
	// made — an allow report says the sandbox PERMITTED an exec, execve's
	// return value is not observable, and a failed exec leaves the previous
	// image running. Publishing a digest there and disclaiming it in a
	// free-text note puts the burden on every reader to have read the note;
	// the field does not fail closed, it fails silently in the consumer.
	//
	// The per-exec SYSCALL EVENTS still carry each attempt's pinned digest,
	// where the semantics are explicit and local ("an exec of this image was
	// permitted, with these bytes at that path when the report arrived"). A
	// policy that wants image evidence reads those and decides what an
	// attempt is worth; nothing silently inherits a stronger claim.
	_ = lastPin
	// ForkReports is accumulated in the event loop above; ObservedChildren is
	// its counterpart, published beside it rather than subtracted from it.
	diag.ObservedChildren = countObservedChildren(in)
	return orderedProcesses(in.rootPid, order, byPID)
}

// maxUnprovenExecs bounds the unproven exec list. A fork storm that loses a
// third of its children to the poll race produces hundreds; anything past
// this is counted, not listed, so the list's size cannot exhaust the
// predicate or read as complete when it is not.
// countObservedChildren counts the distinct non-root pids this build was
// seen to have — members, plus pids whose facts could not be read (unproven
// rather than foreign), plus the ones the exit sweep found.
//
// It is published BESIDE forkReports rather than subtracted from it. The
// subtraction that used to live here implied an exactness the channel cannot
// support: a posix_spawn child (no fork report) cancels a fork whose child
// vanished, and the difference reads zero over a real hole. Two honest
// numbers let a policy see the discrepancy and decide; one dishonest number
// hid it. Neither is a proof of completeness on its own — a build where they
// agree can still have lost a child that both forked and vanished.
func countObservedChildren(in darwinTreeInput) uint64 {
	seen := map[int]bool{}
	for i := range in.events {
		ev := &in.events[i]
		if ev.pid == in.rootPid || ev.canary || in.canaries[ev.pid] {
			continue
		}
		if in.members[ev.pid] || !in.facts[ev.pid].ok {
			seen[ev.pid] = true
		}
	}
	for pid := range in.swept {
		if pid != in.rootPid {
			seen[pid] = true
		}
	}
	return uint64(len(seen))
}

const maxUnprovenExecs = 4096

// recordUnprovenExec lists an exec report whose pid's kernel facts were never
// read, with whatever digest the pin made of the image at report time.
func recordUnprovenExec(ev *sandboxEvent, diag *DarwinTraceDiagnostics) {
	if len(diag.UnprovenExecs) >= maxUnprovenExecs {
		diag.UnprovenExecsOmitted++
		return
	}
	// A GAP, and nothing more. Being able to READ an image is not permission
	// to publish that someone ran it: the report stream is machine-wide, an
	// unproven pid's owner is unknown BY CONSTRUCTION — unproven is exactly
	// "we could not read whose it is" — and a world-readable binary belonging
	// to another user of this machine would otherwise have its execution
	// disclosed in a remote attestation, by a dictionary-testable path hash
	// and the bytes' digest. A policy that forbids an image fails closed on
	// the gap instead.
	diag.UnprovenExecs = append(diag.UnprovenExecs, UnprovenExec{PID: ev.pid, Timestamp: ev.timestamp})
}

// recordUnprovenNetwork records a network report whose ownership could not be
// decided as egress nobody could describe, attached to the ROOT process.
//
// The root is the attachment point because the connection cannot honestly be
// attributed to the pid on the report — that pid's identity is exactly what
// could not be proven — while the FACT of the observed operation must survive
// into the predicate. Only outbound operations become connections ("connect"
// is the one syscall cilock counts); inbound/bind under an unprovable pid say
// nothing about what the build fetched and are counted without being recorded.
func recordUnprovenNetwork(byPID map[int]*ProcessInfo, order *[]int, rootPid int, ev *sandboxEvent, diag *DarwinTraceDiagnostics) {
	diag.NetworkReportsUnprovenOwnership++
	// BOTH DIRECTIONS, because cilock treats both as channels. An outbound is
	// a fetch; an ACCEPTED inbound is an undeclared input channel (the peer
	// was already running, so its own outbound report is a stranger's and is
	// dropped — ignore the build's inbound too and a helper outside the tree
	// can feed the build while the run reads hermetic). Recording only
	// outbound left that hole open for exactly the pid this function exists
	// for: a short-lived child that accepts input and is gone before the poll.
	//
	// A BIND IS DELIBERATELY NOT RECORDED, and the asymmetry is the point.
	// Attributing an unproven operation to the root is a FALSE ATTRIBUTION,
	// accepted only because it fails the verdict toward non-hermetic. cilock
	// ignores bind outright ("serving, not fetching"), so a bind entry would
	// buy no safety and would claim the root opened a listener nobody proved
	// it opened. The counter above still carries it.
	call := darwinNetworkSyscall(ev.op)
	if ev.op != opNetworkOutbound && ev.op != opNetworkInbound {
		return
	}
	root, ok := byPID[rootPid]
	if !ok {
		root = &ProcessInfo{ProcessID: rootPid}
		byPID[rootPid] = root
		*order = append(*order, rootPid)
	}
	if root.Network == nil {
		root.Network = &NetworkActivity{}
	}
	// The ENDPOINT is discarded even though the report carries one. Ownership
	// is what could not be proven, not the address — but pinning a specific
	// destination or port on the root asserts that this build reached THAT
	// host, which is precisely what nobody established. For inbound it would
	// be worse: cilock keys its waiver on "inbound:<addr>:<port>", so a
	// stranger's port preserved here could be waived by a rule the operator
	// wrote for the build's own test listener. Coarse is the safe direction.
	root.Network.Connections = append(root.Network.Connections, NetworkConnection{
		Syscall:   call,
		Family:    FamilyNotObservable,
		Address:   HostNotObservable,
		FD:        FDNotObservable,
		Timestamp: ev.timestamp,
	})
}

// provenParent returns the kernel-read parent pid, but ONLY when that parent
// is itself in this build's tree.
//
// A process whose parent already exited is reparented to launchd, and a poll
// that lost the race returns nothing at all. Both cases yield 0 — which
// ProcessInfo.ParentPID documents as "unknown" — rather than a plausible pid
// that would draw an edge the kernel never confirmed.
func provenParent(pid int, in darwinTreeInput) int {
	f, ok := in.facts[pid]
	if !ok || !f.ok || !in.members[f.ppid] {
		return 0
	}
	return f.ppid
}

// recordDarwinNetwork attaches one attributed network report to the process
// that made it, in the SAME NetworkConnection shape the Linux tracers emit, so
// cilock's hermeticity filter reads a macOS attestation with no darwin-specific
// branch — and so a darwin-specific branch cannot quietly become a second,
// looser filter.
//
// What it must never do is drop an endpoint it could not fully name. cilock
// skips an inet connection whose host is empty, so an unnamed endpoint would
// vanish and `Hermetic = len(NetworkEgress) == 0` would come back TRUE for a
// build that downloaded half the internet. Hence HostNotObservable: an address
// that is unmistakably not a host, but is still an address, so the connection
// is counted and reads honestly to whoever sees "(host-not-observable):443".
func recordDarwinNetwork(p *ProcessInfo, ev *sandboxEvent, diag *DarwinTraceDiagnostics) {
	call := darwinNetworkSyscall(ev.op)
	if call == "" {
		return
	}
	ep := parseDarwinEndpoint(ev.detail)
	// Sized separately for the outbound direction only — these two counters
	// exist to qualify the EGRESS evidence, and a bind that named nothing says
	// nothing about what the build fetched.
	if ev.op == opNetworkOutbound {
		switch ep.kind {
		case endpointUnnamed:
			diag.NetworkReportsWithoutDestination++
		case endpointUnrecognized:
			diag.NetworkReportsUnrecognizedDestination++
		case endpointUnixPath, endpointPortOnly:
			// Fully or partly named; nothing to qualify.
		}
	}
	if p.Network == nil {
		p.Network = &NetworkActivity{}
	}
	p.Network.Connections = append(p.Network.Connections, NetworkConnection{
		Syscall: call,
		Family:  ep.family,
		Address: ep.address,
		Port:    ep.port,
		// The report channel does not carry file descriptors. Zero would be a
		// real fd (stdin), so the connection says "unknown" out loud.
		FD:        FDNotObservable,
		Timestamp: ev.timestamp,
		// Hostname stays EMPTY. It means "TLS SNI read from the ClientHello",
		// which this backend never sees; putting the not-observable marker
		// there would manufacture exactly the resolved-host claim the address
		// is carefully avoiding.
	})
}

func recordDarwinExec(p *ProcessInfo, ev *sandboxEvent, digests map[pinID]cryptoutil.DigestSet) {
	d, haveDigest := digests[ev.pin]
	if p.Program == "" && ev.detail != "" {
		// Program names the first image an exec was ATTEMPTED with, which is
		// observable. ProgramDigest is deliberately left empty — see the note
		// in buildDarwinTree: a digest in that field reads as "these bytes
		// ran" to every consumer, and this channel cannot support it.
		p.Program = ev.detail
	}
	// OPENEDFILES IS LEFT EMPTY ON THIS BACKEND, and that is a deliberate
	// removal rather than an oversight.
	//
	// It used to receive this digest, described as "the digest taken from the
	// inode the kernel loaded". That was the same overstatement the per-event
	// field was renamed to stop making, one level further down and harder to
	// see: OpenedFiles is a GENERIC, cross-platform map that on Linux holds
	// real read-time digests, and its consumers — bindScriptsToTrace here, and
	// the product attestor, which iterates it — read a digest in it as the
	// bytes that were actually read. This backend cannot support that: the
	// collector opens the reported path AFTER report delivery and follows
	// symlinks, so a symlink retargeted at a pre-existing inode yields B's
	// digest for A's exec (TestSymlinkRetargetToOlderInodeIsNotCaught proves
	// it), and no per-entry caveat can travel inside a map[string]DigestSet.
	//
	// So it is withheld, exactly as ProgramDigest and ExeDigest are and for
	// exactly the same reason: a generic field that reads as "these bytes
	// ran" must be EMPTY when the backend cannot establish that, because a
	// free-text caveat elsewhere does not make a generic field fail closed —
	// it fails silently in the reader instead. The measurement is not lost;
	// each exec EVENT carries it as PathDigestAtCollectorOpen, where the name
	// states what it binds and a policy can decide what an observation of a
	// path is worth.
	//
	// SCOPE, and a verifier MUST read it this way: on this backend
	// OpenedFiles contains exec'd images and NOTHING ELSE. The sandbox report
	// channel is not asked for file reads here, so the absence of a path is
	// not evidence the command did not read it.
	//
	// OpenedFiles is keyed by PATH, so a pid that exec'd one path twice over
	// different bytes leaves the LAST measurement here. Every measurement
	// still reaches the predicate: each exec EVENT below carries the digest of
	// the inode IT loaded, so a path exec'd as A→B→C keeps B on B's own event
	// — the middle bytes are exactly the ones an attacker would put there, and
	// first/last fields (ProgramDigest/ExeDigest) cannot hold them. A reader
	// after per-exec measurements must use the events rather than this map.
	// The observed comm goes in the event detail, NOT in ProcessInfo.Comm.
	// At an exec the kernel reports the image name from BEFORE the exec, so a
	// freshly forked child running /usr/bin/true reports as "bash". Writing
	// that into Comm would label every process with its parent's name — a
	// confident wrong answer, which is worse than an empty field.
	sev := SyscallEvent{
		Syscall: "execve",
		Path:    ev.detail,
		Detail:  fmt.Sprintf("%s (reporting comm %q)", ev.op, ev.comm),
		// STATED IN THE EVENT, not only in the limitations note. An allow
		// report proves the sandbox PERMITTED this exec; execve's return value
		// is not observable here, so a permitted exec that then failed with
		// ENOENT or ENOEXEC is indistinguishable from one that ran. A policy
		// reading `syscall: "execve"` as "this image ran" is reading a claim
		// this backend cannot make, and a caveat in a free-text note does not
		// reach it.
		Outcome:   execOutcomePermittedNotConfirmed,
		Timestamp: ev.timestamp,
	}
	// DigestSource is set ONLY beside an actual digest: its contract says ""
	// means "no digest captured", and naming a source for a measurement that
	// does not exist would dress an evidence gap up as evidence. An exec whose
	// image could not be pinned (pin 0, counted in imagesUnhashed) therefore
	// carries neither field — a stated gap, never a borrowed digest.
	if haveDigest {
		sev.PathDigestAtCollectorOpen = d
		sev.DigestSource = "collector-open-path-hash"
	}
	p.SyscallEvents = append(p.SyscallEvents, sev)
}

// orderedProcesses emits the root first, then the rest by pid, so two runs of
// the same build produce byte-identical predicate ordering.
func orderedProcesses(rootPid int, order []int, byPID map[int]*ProcessInfo) []ProcessInfo {
	sorted := make([]int, len(order))
	copy(sorted, order)
	sort.Ints(sorted)
	out := make([]ProcessInfo, 0, len(sorted))
	if p, ok := byPID[rootPid]; ok {
		out = append(out, *p)
	}
	for _, pid := range sorted {
		if pid == rootPid {
			continue
		}
		out = append(out, *byPID[pid])
	}
	return out
}

func findProcess(procs []ProcessInfo, pid int) *ProcessInfo {
	for i := range procs {
		if procs[i].ProcessID == pid {
			return &procs[i]
		}
	}
	return nil
}
