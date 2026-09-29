// Copyright 2021 The Witness Contributors
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

//go:build linux

package commandrun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"golang.org/x/sys/unix"
)

const MAX_PATH_LEN = 4096

type ptraceContext struct {
	parentPid           int
	mainProgram         string
	processes           map[int]*ProcessInfo
	exitCode            int
	hash                []cryptoutil.DigestValue
	environmentCapturer attestation.EnvironmentCapturer
	// tlsPendingFDs tracks file descriptors that connected to port 443
	// so we can extract TLS SNI from the first write on that fd.
	// Key: "pid:fd". The value names the RECORD the connection was filed
	// under, not just an index: the fd survives an exec, and after one the
	// pid's current record is a different image with its own Connections.
	tlsPendingFDs map[string]pendingTLS

	// replaced holds the records of images a later exec on the same pid
	// replaced (see recordForExec). They ran; the record says so.
	replaced []*ProcessInfo
	// execRecorded marks pids whose current record already describes a
	// successful exec.
	execRecorded map[int]bool
	// reaped marks tids whose exit the trace loop has waited for. Their ids
	// are free for the kernel to reuse, so killTracees must never signal
	// them.
	reaped map[int]bool
	// seen marks every tid a wait in the trace loop has reported, recorded
	// or not. A tid whose stop the loop consumed and never resumed is
	// reported no more, so killTracees can only reach it through this set.
	seen map[int]bool

	// fsVerityState is the opportunistic fs-verity sealing state for
	// the trace. Set by runCmd before tracing starts when
	// CILOCK_FSVERITY enables it. nil when disabled.
	fsVerityState *fsVerityState

	// cacheMatcher classifies opened paths as build-internal cache/temp.
	// When set, the eBPF hasher skips hashing matching read opens: they
	// are content-addressed storage (Go module cache, GOCACHE, /tmp)
	// pinned by lockfiles, not meaningful materials, and hashing them on
	// a cold build both wastes cycles and produces churning-file TOCTOU
	// failures that would otherwise count as drops/gaps. nil = hash all.
	cacheMatcher *attestation.CachePathMatcher

	// There is deliberately NO per-file digest memo here. See the
	// "no digest memo" note above digestForPath: every open this attestor
	// hashes at all, it hashes afresh, which costs roughly 3.5-4x on the
	// hashing path (measured; see that note for the workload).

	// testDuringHashedRead, when set, runs inside digestOpenFile between the
	// pre-read fstat and the hash -- the window a write has to land in to be
	// invisible to a bracket that is not settled. Tests use it to mutate the
	// world mid-measurement; production leaves it nil.
	testDuringHashedRead func()

	// pendingExec holds the program path each thread passed to execve, read
	// at syscall ENTRY (the only point the argument is in the tracee's
	// memory), until the PTRACE_EVENT_EXEC stop confirms the exec succeeded
	// and the new image is loaded. Keyed by the calling thread's tid.
	pendingExec map[int]string

	// syscallStopsLost counts syscall stops whose registers or arguments
	// could not be read (typically: the thread was SIGKILLed while stopped).
	// Each is an event this trace did not record. Published as
	// diagnostics.ptraceSyscallStopsLost (a hard drop for
	// --require-zero-drops) and a coverage gap; never fatal.
	syscallStopsLost uint64

	// mu guards the processes map and the ProcessInfo entries within
	// it. Required for the eBPF tracing path, where multiple hash
	// workers update process state concurrently. Uncontended in the
	// serial ptrace path.
	mu sync.Mutex
}

// No digest memo, and no sound way to reintroduce one here
// --------------------------------------------------------
//
// Earlier revisions of this file memoised digests for the life of a trace.
// The key was first (path, size, mtime), then -- after four review rounds --
// the kernel's own (dev, ino, ctime, size) guarded by an age rule. Every one
// of those keys rests on a single premise: that some field the kernel
// maintains moves whenever the file's contents move. That premise is false,
// and no key built on stat(2) can repair it.
//
// A tracee that holds a writable MAP_SHARED mapping of a file changes the
// file's bytes by storing into memory. The kernel stamps ctime and mtime in
// the write FAULT that first makes a clean page writable -- not in the
// stores that follow, while the page is already dirty and the PTE already
// writable. Once that one fault is taken, the tracee can rewrite the file as
// often as it likes with ctime, mtime, dev, ino and size all unchanged. Two
// stats cannot see it, and waiting longer before the first stat does not
// help: waiting changes WHEN a stamp is read, not WHETHER one was ever
// written. mapped_write_linux_test.go stages exactly this and asserts the
// invisibility rather than assuming it.
//
// So a memo keyed on anything stat(2) reports can be made to serve one
// file's digest for another file's bytes, for the remainder of the trace, by
// an unprivileged same-uid tracee. That is precisely the failure this
// repository has shipped once before: an attestation binding a digest that
// never corresponded to the bytes that ran. The answer is not a cleverer
// key. It is to hash on every read, so an attacker has to win a race on each
// one instead of poisoning a map once (Codex review of judge#9044, round 8).
//
// THE PRICE, measured on the path this change actually alters. Replaying a
// build-shaped open sequence -- 5000 opens over 400 real Go source files
// (mean 8.6 KB), a 92% repeat rate, every file aged past the settle window so
// neither arm pays it -- the hashing path went from a median of 34-40 ms to
// 136-142 ms across two independent five-run samples. Roughly 3.5-4x, on the
// repeat rate most favourable to a memo. Larger materials would widen the
// absolute gap, since the memo's saving scales with bytes hashed.
//
// That figure is the HASHING PATH, not trace wall clock. Hashing sits
// alongside ptrace/BPF event handling and record keeping in a real trace, so
// the whole-trace cost is smaller -- and this change did not measure it. An
// earlier draft of this note quoted "18-23% of trace wall clock"; that came
// from outside this change and was never reproduced against this repo's
// workload, so it is not repeated here. Two things are certain and they are
// enough: the memo is the difference between hashing once and hashing every
// time, and a memo that can return a digest for bytes that were never
// executed is not worth any amount of it.
//
// The price is stated here rather than amortised into a footnote because it
// is the whole trade. Buying it back needs an actual content-stability
// mechanism rather than a better observation: a reflink or filesystem
// snapshot taken before the read, or fs-verity, which
// makes the contents immutable and kernel-checked on every read. (An IMA
// measurement alone is not one -- it records a hash, it does not hold the
// bytes still.) None is available on the filesystems this runs on today;
// judge#9054 tracks carrying the distinction on the wire if one becomes so.
//
// SCOPE. "No memo" is about digests, and it is exact: no digest this
// attestor produces is ever served from a previous read. It is NOT a claim
// that every openat is hashed. Both trace backends keep a per-process
// short-circuit -- a path a process has already recorded is not recorded
// again (see handleSyscall's SYS_OPENAT arm and recordEBPFOpenat) -- so a
// second open of the same path by the same process is skipped rather than
// answered from a memo. That is pre-existing, it is a decision about what to
// RECORD rather than a cache of what was measured, and it is deliberately
// not changed here: hashing every repeat open of every path costs far more
// than the measurement above, and recordEBPFOpenat already keeps the FIRST
// digest and raises a SyscallEvent when a later read of a path disagrees.

// digestOpenFile is bracketedDigest with this trace's hash set and its test
// hook. The measurement itself lives in file_hashing.go, which builds on every
// platform.
func (p *ptraceContext) digestOpenFile(f *os.File) (cryptoutil.DigestSet, error) {
	return bracketedDigest(f, p.hash, p.testDuringHashedRead)
}

// digestForPath returns the digest set for `path`, hashing it on every call.
// Returns (nil, false) when the file is missing, unreadable, not a regular
// file, or -- the case that matters -- when a change WAS observed across the
// read. A false here means the caller records NO digest for this path, which
// is the same contract the eBPF side gives a TOCTOUError: a refusal records
// nothing rather than a placeholder a verifier cannot tell from a real
// entry. It does not mean the digests it does return are proven; see
// observedUnchanged for what the checks cover and what they miss.
//
// The path is resolved once, by the open, and never again: the bytes and the
// stats both come from that one descriptor.
//
// Concurrent access (eBPF path): the hasher pool calls this from multiple
// worker goroutines. It holds no shared state, so it needs no lock.
func (p *ptraceContext) digestForPath(path string) (cryptoutil.DigestSet, bool) {
	f, err := openForHashing(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	d, err := p.digestOpenFile(f)
	if err != nil {
		return nil, false
	}
	return d, true
}

// traceModeNamePtrace is the CILOCK_TRACE_MODE value selecting ptrace.
// Used in three places (enableTracing, the trace-mode test, the
// startup log) — promote to a const to satisfy goconst.
const traceModeNamePtrace = "ptrace"

func enableTracing(_ *exec.Cmd, _ ...bool) {
	// Deliberately empty on Linux. Whether the child starts under ptrace
	// depends on the RESOLVED backend, which only preStartTracingSetup knows
	// (auto mode probes eBPF first). Deciding here from the raw
	// CILOCK_TRACE_MODE request was the bug: in auto mode with eBPF
	// unavailable the tracer resolved to ptrace, but the child was started
	// WITHOUT PTRACE_TRACEME, ran untraced to completion, and runTrace then
	// hit ESRCH on the reaped pid ("attestor command-run failed: no such
	// process") in every unprivileged container.
}

// pinTracerThread locks the calling goroutine to its OS thread when c will
// start under PTRACE_TRACEME, and returns the unlock. Call it before
// c.Start() and unlock after the trace. A TRACEME child is traced by the
// THREAD that forked it, and the kernel accepts ptrace requests for it from
// that thread only (ptrace_check_attach: child->parent == current). Unpinned,
// the scheduler could move the goroutine between the fork and runTrace's own
// lock; every request then failed with ESRCH and the child was left in
// ptrace-stop (#10481). syscall.SysProcAttr.Ptrace documents the same rule.
func pinTracerThread(c *exec.Cmd) (unpin func()) {
	if c.SysProcAttr == nil || !c.SysProcAttr.Ptrace {
		return func() {}
	}
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// configureTraceeForMode is the single place the child's ptrace flag is
// decided, from the backend that was actually resolved.
func configureTraceeForMode(c *exec.Cmd, mode traceMode) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &unix.SysProcAttr{}
	}
	c.SysProcAttr.Ptrace = mode == traceModePtrace
}

// applyTraceePrivilegeDrop ensures the traced child runs with the
// invoker's real (un-elevated) uid/gid when cilock was started via
// sudo. Without this, a tracee inherits the root + caps that cilock
// needs for BPF / fanotify, defeating the purpose of attestation
// (the tracee could escalate via its inherited caps). The cilock
// PARENT keeps its caps; only the forked child is downgraded.
//
// No-op when:
//   - SUDO_UID/SUDO_GID env vars are absent (running native, not
//     via sudo) — the parent's uid IS the user's uid.
//   - cilock isn't running as root (no elevation to drop FROM).
//   - The Credential field is already set (caller explicitly chose).
//
// Errors during env parsing are non-fatal: log + skip the drop and
// surface a diagnostic. The build proceeds with parent's uid, but
// honesty requires the operator know we couldn't downgrade.
func applyTraceePrivilegeDrop(c *exec.Cmd) {
	if os.Getuid() != 0 {
		return
	}
	if c.SysProcAttr == nil {
		c.SysProcAttr = &unix.SysProcAttr{}
	}
	if c.SysProcAttr.Credential != nil {
		return
	}
	sudoUidStr := os.Getenv("SUDO_UID")
	sudoGidStr := os.Getenv("SUDO_GID")
	if sudoUidStr == "" || sudoGidStr == "" {
		return
	}
	sudoUid, err := strconv.ParseUint(sudoUidStr, 10, 32)
	if err != nil {
		log.Debugf("(tracee-priv-drop) invalid SUDO_UID=%q: %v", sudoUidStr, err)
		return
	}
	sudoGid, err := strconv.ParseUint(sudoGidStr, 10, 32)
	if err != nil {
		log.Debugf("(tracee-priv-drop) invalid SUDO_GID=%q: %v", sudoGidStr, err)
		return
	}
	if sudoUid == 0 {
		// Sudo run as root user; nothing to downgrade to.
		return
	}
	c.SysProcAttr.Credential = &syscall.Credential{
		Uid:         uint32(sudoUid),
		Gid:         uint32(sudoGid),
		NoSetGroups: true,
	}
	// AmbientCaps left at the zero value — child will not inherit
	// any of cilock's elevated capabilities through the ambient set.
	c.SysProcAttr.AmbientCaps = nil

	// PR_SET_NO_NEW_PRIVS via setpriv(1) prefix. setpriv is part of
	// util-linux and present on every modern Linux distro. Calling
	// prctl(PR_SET_NO_NEW_PRIVS, 1) before exec makes a setuid /
	// file-capability binary fail to elevate. Closes the
	// "compromised toolchain re-escalates via setuid /bin/su" vector.
	//
	// We wrap the original command rather than re-exec'ing cilock
	// because (a) Go stdlib doesn't expose PR_SET_NO_NEW_PRIVS in
	// SysProcAttr, (b) setpriv is well-tested + battle-hardened,
	// (c) wrapping is more transparent to the verifier (the
	// argv shows what was wrapped).
	//
	// Skipped (with log) when setpriv isn't on PATH — older /
	// minimal images.
	if setpriv, err := exec.LookPath("setpriv"); err == nil {
		newArgs := make([]string, 0, len(c.Args)+3)
		newArgs = append(newArgs, setpriv, "--no-new-privs", "--")
		newArgs = append(newArgs, c.Args...)
		c.Path = setpriv
		c.Args = newArgs
	} else {
		log.Debugf("(tracee-priv-drop) setpriv not in PATH; PR_SET_NO_NEW_PRIVS not applied")
	}
}

// preStartTracingSetup is invoked from runCmd BEFORE c.Start(). For
// eBPF mode this opens the consumer (attaching kprobes globally) so
// that the moment the child runs its first openat, the kernel-side
// probe is already in place. Without this pre-open the test race
// where the child finishes before kprobes attach is real and easy
// to hit on small programs like /bin/cat.
//
// Returns the human-readable trace-mode error if eBPF was requested
// but unavailable so runCmd can short-circuit before forking the
// child.
func (r *CommandRun) preStartTracingSetup(c *exec.Cmd) error {
	mode, err := selectTraceMode()
	if err != nil {
		return err
	}
	// Resolve ONCE. trace() dispatches on this recorded backend rather than
	// probing again: a second probe both repeated the fallback warning and
	// could disagree with the first, leaving the child started for one
	// backend and traced by the other.
	r.resolvedTraceBackend = mode.String()
	configureTraceeForMode(c, mode)
	if mode != traceModeEBPF {
		return nil
	}
	if r.ebpfConsumer != nil {
		return nil // already open (test re-entry)
	}
	consumer, err := openEBPFConsumer()
	if err != nil {
		return fmt.Errorf("eBPF tracing requested but failed to attach kprobes: %w", err)
	}
	// Seed the in-kernel bootstrap signal so the to-be-forked tracee's
	// subtree is watched. BootstrapRoot fires a sentinel prctl whose kprobe
	// records cilock's KERNEL-GLOBAL tgid as the root — namespace-agnostic,
	// so capture works in nested PID namespaces (Docker/colima/K8s), not just
	// the host namespace. Enable the filter NOW (before c.Start) so the
	// child's first openat (typically /lib/ld-linux.so) is captured.
	if err := consumer.BootstrapRoot(); err != nil {
		_ = consumer.Close()
		return fmt.Errorf("eBPF filter setup: %w", err)
	}
	if err := consumer.EnableFilter(); err != nil {
		_ = consumer.Close()
		return fmt.Errorf("eBPF filter enable: %w", err)
	}
	// V2: read-tap is ON BY DEFAULT in trace mode. It's the only mode
	// that produces correct digests for short-lived processes opening
	// relative paths (cc1/javac/many compilers). The pre-V2 path-hash
	// fallback re-opens the file from cilock's cwd after the syscall —
	// which is wrong for any tracee with a different cwd, and silently
	// drops the digest when the fd is closed before userspace can read
	// /proc/<pid>/fd/<fd>. Read-tap streams content from kernel ringbuf
	// as the tracee reads, so digests are authoritative regardless of
	// process lifetime or path resolution.
	//
	// V2 attestation-correctness pivot: read-tap is OFF by default.
	//
	// Read-tap is enabled by default now that classification-critical
	// events (openat, execve, fileOps) live in their own ringbuf — the
	// high-volume read-tap chunks can no longer evict them. Read-tap
	// gives us the strictly stronger correctness: we hash exactly the
	// bytes the kernel returned to the tracee on read(), not the
	// bytes that happened to be on disk at openat-event-time. The
	// openat-time path-hash (via the capture pool) remains as the
	// fallback for files where read-tap didn't complete the full read
	// before the tracee exited.
	// Read-tap is permanently OFF. Experiments (local 6.8 + GHA Azure 6.17
	// Hugo) proved it net-negative: it nearly DOUBLED the materials set with
	// pure GOCACHE/module-cache + /tmp cgo-temp NOISE (it never honored the
	// cache-skip fanotify applies), made materials non-deterministic, and
	// caused all the partial-read fallbacks + the 1GiB ringbuf. fanotify
	// (default-on, synchronous, zero-drop) is the authoritative materials
	// source; the openat-time path-hash remains as the no-fanotify fallback.
	// EnableReadTap is intentionally never called (the tap content path is
	// being removed; this locks in the validated default).
	r.ebpfConsumer = consumer
	return nil
}

func (r *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	pctx := &ptraceContext{
		parentPid:           c.Process.Pid,
		mainProgram:         c.Path,
		processes:           make(map[int]*ProcessInfo),
		hash:                actx.Hashes(),
		environmentCapturer: actx.EnvironmentCapturer(),
		tlsPendingFDs:       make(map[string]pendingTLS),
		fsVerityState:       r.fsVerityState,
		cacheMatcher:        r.cacheMatcher,
	}

	// Dispatch on the backend preStartTracingSetup resolved before
	// c.Start(): the child was started for THAT backend (under ptrace or
	// not), so tracing it with any other would be tracing a different run.
	// No recorded backend means the child's tracing was never configured;
	// refuse rather than guess.
	mode, ok := traceModeFromBackend(r.resolvedTraceBackend)
	if !ok {
		if c.Process != nil {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
		return nil, fmt.Errorf("tracing: backend %q was not resolved before the command started; refusing to trace an unconfigured child", r.resolvedTraceBackend)
	}
	requested := strings.ToLower(strings.TrimSpace(os.Getenv(EnvVarTraceMode)))
	logTraceModeStartup(mode, requested)

	// Record the resolved capture mode + concrete backend so the run summary
	// reports them honestly. This fixes a latent bug: resolvedCaptureMode was
	// never assigned anywhere, so summary.captureMode was always empty even on
	// a successful trace. Set from the RESOLVED mode (not the env request) so
	// auto-select runs still name their backend ("ebpf"/"ptrace+seccomp"),
	// which downstream hermeticity derivation needs.
	r.resolvedCaptureMode = string(attestation.CaptureTrace)

	switch mode {
	case traceModeEBPF:
		return r.runEBPFTrace(c, actx, pctx)
	case traceModePtrace:
		// Fall through to the existing ptrace path.
	}

	err := pctx.runTrace()
	r.ptraceSyscallStopsLost = pctx.syscallStopsLost
	if err != nil {
		// runCmd waits on the child next. A tracee left in ptrace-stop
		// would hold that wait forever, and a half-traced build is no
		// record to keep running for.
		pctx.killTracees()
		return nil, err
	}

	r.ExitCode = pctx.exitCode

	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), &exitStatusError{Code: pctx.exitCode}
	}

	return pctx.procInfoArray(), nil
}

func (p *ptraceContext) runTrace() error { //nolint:gocognit // ptrace event loop has many distinct event branches that read clearer inline
	defer p.retryOpenedFiles()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status := unix.WaitStatus(0)
	_, err := unix.Wait4(p.parentPid, &status, 0, nil)
	if err != nil {
		return err
	}
	// A child started with PTRACE_TRACEME stops with SIGTRAP after its
	// execve. Anything else means it was never under ptrace and has already
	// run (and been reaped) untraced: say so, instead of letting
	// PtraceSetOptions surface a bare ESRCH for the reaped pid.
	if !status.Stopped() {
		return fmt.Errorf("ptrace: traced command (pid %d) was not stopped under ptrace at start (wait status %#x): "+
			"it ran untraced, so there is no trace to attest", p.parentPid, uint32(status))
	}
	if p.pendingExec == nil {
		p.pendingExec = make(map[int]string)
	}
	// Only the thread that forked the tracee may send it requests. Say so
	// by name rather than let the first request fail with a bare ESRCH.
	if tracer, self := tracerPidOf(p.parentPid), unix.Gettid(); tracer != self {
		return fmt.Errorf("ptrace: tracer thread %d is not the tracee's tracer (TracerPid %d); "+
			"the command was started from another thread", self, tracer)
	}

	if err := unix.PtraceSetOptions(p.parentPid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		return err
	}

	// The root's execve happened before tracing began, so no syscall stop
	// will ever report it. The tracee is held at its post-exec stop right
	// now with the new image loaded, which is exactly the state recordExec
	// needs to bind the image it measures to this process.
	p.recordExec(p.parentPid, p.mainProgram)
	if err := unix.PtraceSyscall(p.parentPid, 0); err != nil {
		return err
	}

	for {
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			return err
		}
		p.markSeen(pid)
		if ptraceLoopFault != nil {
			if err := ptraceLoopFault(pid, p.tracedPids()); err != nil {
				return err
			}
		}
		// Record per-process exit code on the matching ProcessInfo so
		// downstream policy can see which traced child exited with what.
		// Issue #47: previously only the parent's exit was captured at
		// the CommandRun-struct level; per-child exits were silently
		// dropped along with the subsequent (failing) PtraceSyscall.
		if status.Exited() {
			pInfo := p.getProcInfo(pid)
			pInfo.ExitCode = status.ExitStatus()
			if pid == p.parentPid {
				p.exitCode = status.ExitStatus()
				return nil
			}
			p.markReaped(pid)
			continue
		}
		if status.Signaled() {
			pInfo := p.getProcInfo(pid)
			// shell convention: 128 + signal number for signal-killed
			pInfo.ExitCode = 128 + int(status.Signal())
			if pid == p.parentPid {
				p.exitCode = 128 + int(status.Signal())
				return nil
			}
			p.markReaped(pid)
			continue
		}

		sig := status.StopSignal()
		// since we set PTRACE_O_TRACESYSGOOD any traps triggered by ptrace will have its signal set to SIGTRAP|0x80.
		// If we catch a signal that isn't a ptrace'd signal we want to let the process continue to handle that signal, so we inject the thrown signal back to the process.
		// If it was a ptrace SIGTRAP we suppress the signal and send 0
		injectedSig := int(sig)
		isPtraceTrap := (unix.SIGTRAP | unix.PTRACE_EVENT_STOP) == sig
		if status.Stopped() && isPtraceTrap {
			injectedSig = 0
			p.handleSyscallStop(pid)
		}
		// PTRACE_EVENT_EXEC: the exec SUCCEEDED and the new image is mapped;
		// the tracee is stopped, so /proc/<pid>/{exe,comm,cmdline} now
		// describe the new program and cannot change under the measurement.
		// Recording at execve ENTRY instead read the OLD image: the shell's
		// digest was signed as cat's, labelled mapped-image.
		if status.Stopped() && sig == unix.SIGTRAP && status.TrapCause() == unix.PTRACE_EVENT_EXEC {
			injectedSig = 0
			p.handleExecEvent(pid)
		}

		if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
			log.Debugf("(tracing) got error from ptrace syscall: %v", err)
		}
	}
}

// handleSyscallStop processes one syscall stop. A stop whose registers or
// arguments cannot be read (ESRCH: the thread was killed while stopped;
// EFAULT: an argument pointer the kernel will reject anyway) is COUNTED as a
// lost event and the trace continues. One vanished process must never fail
// the attestor, and must never vanish silently either.
//
// Every syscall stop first drops this thread's pending exec path. An exec's
// stops run entry (path kept) -> PTRACE_EVENT_EXEC (path consumed) -> exit on
// success, and entry -> exit on failure, so ANY later syscall stop from the
// thread means the exec that kept the path is over. Dropping it here, before
// the registers are read, holds even when this stop is itself lost: a failed
// exec's path can never survive to name the thread's next exec.
func (p *ptraceContext) handleSyscallStop(pid int) {
	delete(p.pendingExec, pid)
	if err := p.nextSyscall(pid); err != nil {
		p.syscallStopsLost++
		log.Debugf("(tracing) syscall stop for pid %d not recorded: %v", pid, err)
	}
}

// handleExecEvent records a successful exec at its PTRACE_EVENT_EXEC stop.
// The event message is the tid that called execve (it differs from pid when
// a non-leader thread exec'd), which is where the entry-time path was kept.
// Only the CALLER's path may name this exec. Any other thread's entry belongs
// to a different exec attempt, so with no path from the caller the program is
// recorded as unknown ("") rather than borrowed.
func (p *ptraceContext) handleExecEvent(pid int) {
	caller := pid
	if msg, err := unix.PtraceGetEventMsg(pid); err == nil && msg != 0 {
		caller = int(msg) //nolint:gosec // G115: a tid fits in int
	}
	program := p.pendingExec[caller]
	delete(p.pendingExec, caller)
	delete(p.pendingExec, pid)
	p.recordExec(pid, program)
}

// recordExec reads the new program's kernel facts and measures its image.
// Callers guarantee the tracee is STOPPED after a successful exec (its
// initial post-exec stop, or PTRACE_EVENT_EXEC), which is what binds the
// /proc reads and the mapped-image measurement to this exec.
func (p *ptraceContext) recordExec(pid int, program string) {
	procInfo := p.recordForExec(pid)

	exeLocation := fmt.Sprintf("/proc/%d/exe", pid)
	commLocation := fmt.Sprintf("/proc/%d/comm", pid)
	envinLocation := fmt.Sprintf("/proc/%d/environ", pid)
	cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", pid)
	status := fmt.Sprintf("/proc/%d/status", pid)

	// read status file and set attributes on success
	statusFile, err := os.ReadFile(status) //nolint:gosec
	if err == nil {
		procInfo.SpecBypassIsVuln = getSpecBypassIsVulnFromStatus(statusFile)
		ppid, err := getPPIDFromStatus(statusFile)
		if err == nil {
			procInfo.ParentPID = ppid
		}
	}

	// Reset, then read: a value that cannot be read for THIS exec must not
	// be the previous program's.
	procInfo.Comm = ""
	comm, err := os.ReadFile(commLocation) //nolint:gosec
	if err == nil {
		procInfo.Comm = cleanString(string(comm))
	}

	environ, err := os.ReadFile(envinLocation) //nolint:gosec
	if err == nil && p.environmentCapturer != nil {
		allVars := strings.Split(string(environ), "\x00")

		capturedEnv := p.environmentCapturer.Capture(allVars)
		env := make([]string, 0, len(capturedEnv))
		for k, v := range capturedEnv {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}

		procInfo.Environ = strings.Join(env, " ")
	}

	procInfo.Cmdline = ""
	cmdline, err := os.ReadFile(cmdlineLocation) //nolint:gosec // G304: reading /proc/<pid>/cmdline
	if err == nil {
		procInfo.Cmdline = procCmdline(string(cmdline))
	}

	p.measureExecutedImage(procInfo, exeLocation, program)
}

// recordForExec returns the record a successful exec on pid fills.
//
// A record describes ONE image. When the pid's record already describes an
// earlier exec, that image ran, so its record is kept (with the opens,
// network and file activity it made) and the new image gets a fresh record
// under the same pid. Resetting the one record in place used to drop the
// earlier image from the evidence entirely and file its activity under its
// successor: `sh -c 'x; exec y'` was signed as a run in which sh never
// executed. Only the ptrace backend calls this, and only at a stop the kernel
// raises for an exec that SUCCEEDED, so a failed attempt never splits a
// record.
//
// The kept record carries no exit code: that image did not exit, it was
// replaced. The pid's exit is recorded on the image that was running.
func (p *ptraceContext) recordForExec(pid int) *ProcessInfo {
	if p.execRecorded == nil {
		p.execRecorded = make(map[int]bool)
	}
	cur := p.getProcInfo(pid)
	if !p.execRecorded[pid] {
		p.execRecorded[pid] = true
		return cur
	}
	p.replaced = append(p.replaced, cur)
	next := &ProcessInfo{
		ProcessID:   pid,
		ParentPID:   cur.ParentPID,
		OpenedFiles: make(map[string]cryptoutil.DigestSet),
	}
	p.processes[pid] = next
	return next
}

// pendingTLS is a port-443 connection awaiting its ClientHello: the record
// the connection is filed under and its index in that record's Connections.
type pendingTLS struct {
	rec  *ProcessInfo
	conn int
}

// keepExecPath holds the path an exec entry named until that exec's
// PTRACE_EVENT_EXEC stop consumes it, or the thread's next syscall stop drops
// it (handleSyscallStop).
func (p *ptraceContext) keepExecPath(tid int, program string) {
	if p.pendingExec == nil {
		p.pendingExec = make(map[int]string)
	}
	p.pendingExec[tid] = program
}

func (p *ptraceContext) retryOpenedFiles() {
	// after tracing, look through opened files to try to resolve any newly
	// created files. The root pid's records are every image it ran, not only
	// the last: an image a later exec replaced keeps its own opens.
	roots := []*ProcessInfo{p.getProcInfo(p.parentPid)}
	for _, rec := range p.replaced {
		if rec.ProcessID == p.parentPid {
			roots = append(roots, rec)
		}
	}
	for _, procInfo := range roots {
		for file, digestSet := range procInfo.OpenedFiles {
			if digestSet != nil {
				continue
			}

			newDigest, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)

			if err != nil {
				delete(procInfo.OpenedFiles, file)
				continue
			}

			procInfo.OpenedFiles[file] = newDigest
		}
	}
}

func (p *ptraceContext) nextSyscall(pid int) error {
	regs := unix.PtraceRegs{}
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		return err
	}

	if msg == unix.PTRACE_EVENTMSG_SYSCALL_ENTRY {
		if err := p.handleSyscall(pid, regs); err != nil {
			return err
		}
	}

	return nil
}

func (p *ptraceContext) handleSyscall(pid int, regs unix.PtraceRegs) error { //nolint:gocognit,gocyclo,funlen
	argArray := getSyscallArgs(regs)
	syscallId := getSyscallId(regs)

	switch syscallId {
	case unix.SYS_EXECVE:
		// Entry only: the path argument lives in the tracee's memory now and
		// is gone after the exec. Everything that describes the NEW program
		// is read at the PTRACE_EVENT_EXEC stop (handleExecEvent); at entry
		// /proc/<pid> still describes the image being replaced, and an exec
		// that fails never produces that stop, so it records nothing. A read
		// that fails is remembered as "" (argv[0] unknown for this exec).
		program, err := p.readSyscallReg(pid, argArray[0], MAX_PATH_LEN)
		if err != nil {
			program = ""
		}
		p.keepExecPath(pid, program)

	case unix.SYS_EXECVEAT:
		// execveat(dirfd, pathname, argv, envp, flags). Handled for the same
		// reason as execve: an exec with no entry record would otherwise be
		// named by nothing, or by a path some earlier attempt left behind. An
		// ABSOLUTE pathname names the program regardless of dirfd. A relative
		// one resolves against a descriptor, and an empty one (AT_EMPTY_PATH,
		// fexecve) names no path at all; both are kept as "" (program
		// unknown) rather than as a guess at what the kernel resolved.
		program := ""
		if path, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN); err == nil && strings.HasPrefix(path, "/") {
			program = path
		}
		p.keepExecPath(pid, program)

	case unix.SYS_OPENAT:
		file, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		if err != nil {
			return err
		}

		procInfo := p.getProcInfo(pid)
		// Per-process short-circuit: if this process has already opened
		// this exact path, skip the stat+hash. `go build`'s compile and
		// link processes each re-open the same stdlib files dozens of
		// times — recording the second-onward opens adds nothing.
		if _, seen := procInfo.OpenedFiles[file]; seen {
			return nil
		}

		// Hashed on every first-open-per-process. Files that several
		// traced processes open in parallel (compile workers in `go
		// build`'s graph) are therefore hashed several times; the
		// per-process short-circuit above is the only de-duplication
		// left, because it keys on "this process already recorded this
		// path" rather than on any claim about the file's contents.
		digestSet, ok := p.digestForPath(file)
		if !ok {
			// Best-effort: a missing/unreadable file still records as
			// "opened" with nil digest so the --trace product filter can
			// see it. This matches the original PathError behavior.
			procInfo.OpenedFiles[file] = nil
			return nil
		}
		procInfo.OpenedFiles[file] = digestSet

	case unix.SYS_SOCKET:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)

		domain := int(argArray[0])
		sockType := int(argArray[1])
		protocol := int(argArray[2])

		procInfo.Network.Sockets = append(procInfo.Network.Sockets, SocketInfo{
			Family:   socketFamilyName(domain),
			Type:     socketTypeName(sockType),
			Protocol: protocol,
			FD:       -1, // fd not available at syscall entry
		})

	case unix.SYS_CONNECT:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)

		conn, err := p.parseSockaddr(pid, argArray[1], argArray[2], "connect")
		if err != nil {
			// The connect() HAPPENED. Dropping it here is the one loss this
			// backend cannot afford: cilock reads an empty connection list as
			// `Hermetic = true`, so a sockaddr this tracer could not read —
			// an addrlen outside the accepted range, a ProcessVMReadv that
			// failed — would publish "reached nothing" over a build that
			// reached something. Recorded as unobservable, it reaches the
			// consumer as egress nobody can name.
			//
			// connect() specifically, because it is the syscall whose ABSENCE
			// becomes a hermeticity claim; bind() and sendto() below are not
			// counted as egress either way.
			log.Debugf("(tracing) failed to parse connect sockaddr: %v", err)
			procInfo.Network.Connections = append(procInfo.Network.Connections,
				UnobservedConnection("connect", int(argArray[0])))
			return nil // non-fatal
		}
		conn.FD = int(argArray[0])
		procInfo.Network.Connections = append(procInfo.Network.Connections, *conn)

		// Track TLS connections for SNI extraction on next write
		if conn.Port == 443 && (conn.Family == FamilyIPv4 || conn.Family == FamilyIPv6) {
			key := fmt.Sprintf("%d:%d", pid, conn.FD)
			p.tlsPendingFDs[key] = pendingTLS{rec: procInfo, conn: len(procInfo.Network.Connections) - 1}
		}

		// Heuristic: connect to port 53 is likely DNS
		if conn.Port == 53 {
			procInfo.Network.DNSLookups = append(procInfo.Network.DNSLookups, DNSLookup{
				ServerAddress: conn.Address,
				ServerPort:    conn.Port,
			})
		}

	case unix.SYS_BIND:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)

		conn, err := p.parseSockaddr(pid, argArray[1], argArray[2], "bind")
		if err != nil {
			log.Debugf("(tracing) failed to parse bind sockaddr: %v", err)
			return nil
		}
		conn.FD = int(argArray[0])
		procInfo.Network.Connections = append(procInfo.Network.Connections, *conn)

	case unix.SYS_SENDTO:
		// sendto(fd, buf, len, flags, dest_addr, addrlen)
		// Only record if dest_addr is non-null (UDP sends with explicit destination)
		if argArray[4] != 0 {
			procInfo := p.getProcInfo(pid)
			p.ensureNetwork(procInfo)

			conn, err := p.parseSockaddr(pid, argArray[4], argArray[5], "sendto")
			if err != nil {
				log.Debugf("(tracing) failed to parse sendto sockaddr: %v", err)
				return nil
			}
			conn.FD = int(argArray[0])
			procInfo.Network.Connections = append(procInfo.Network.Connections, *conn)
		}

	case unix.SYS_SENDMSG:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)
		log.Debugf("(tracing) pid %d called sendmsg on fd %d", pid, int(argArray[0]))

	// --- File mutation syscalls ---

	case unix.SYS_WRITE, 18: // 18 = SYS_PWRITE64 on amd64
		fd := int(argArray[0])
		byteCount := int(argArray[2])

		// TLS SNI extraction: if this fd has a pending TLS connect, peek at
		// the write buffer for a ClientHello and extract the SNI hostname.
		//nolint:nestif // three-level nesting is the shape of the SNI lookup
		if byteCount > 11 && byteCount < 16384 {
			key := fmt.Sprintf("%d:%d", pid, fd)
			if pend, ok := p.tlsPendingFDs[key]; ok {
				delete(p.tlsPendingFDs, key) // only try once per fd
				if hostname := p.extractTLSSNI(pid, argArray[1], byteCount); hostname != "" {
					procInfo, connIdx := pend.rec, pend.conn
					if procInfo.Network != nil && connIdx < len(procInfo.Network.Connections) {
						procInfo.Network.Connections[connIdx].Hostname = hostname
						log.Debugf("(tracing) TLS SNI: pid %d fd %d → %s", pid, fd, hostname)
					}
				}
			}
		}

		// Track writes by resolving fd to path via /proc/pid/fd/N
		// Only track writes to real files (skip stdout/stderr/pipes: fd 0,1,2)
		if fd > 2 && byteCount > 0 {
			path := p.resolveFD(pid, fd)
			if path != "" && !strings.HasPrefix(path, "pipe:") && !strings.HasPrefix(path, "socket:") && !strings.HasPrefix(path, "anon_inode:") {
				procInfo := p.getProcInfo(pid)
				p.ensureFileOps(procInfo)
				procInfo.FileOps.Writes = append(procInfo.FileOps.Writes, FileWrite{
					Path:      path,
					Bytes:     byteCount,
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				})
			}
		}

	case unix.SYS_RENAMEAT2:
		// renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
		oldPath, err1 := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		newPath, err2 := p.readSyscallReg(pid, argArray[3], MAX_PATH_LEN)
		if err1 == nil && err2 == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Renames = append(procInfo.FileOps.Renames, FileRename{
				OldPath:   oldPath,
				NewPath:   newPath,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case unix.SYS_UNLINKAT:
		// unlinkat(dirfd, pathname, flags)
		path, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		if err == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Deletes = append(procInfo.FileOps.Deletes, FileDelete{
				Path:      path,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case unix.SYS_FCHMODAT:
		// fchmodat(dirfd, pathname, mode, flags)
		path, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		if err == nil {
			mode := uint32(argArray[2])
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.PermChanges = append(procInfo.FileOps.PermChanges, FilePermChange{
				Path:      path,
				Mode:      mode,
				SetExec:   mode&0111 != 0, // any execute bit set
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	// --- Security-sensitive syscalls ---

	case unix.SYS_MEMFD_CREATE:
		// memfd_create(name, flags) — fileless execution: creates anonymous executable memory
		name, _ := p.readSyscallReg(pid, argArray[0], 256)
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "memfd_create",
			Detail:    fmt.Sprintf("anonymous memory file: %s (flags: %d) — used for fileless code execution", name, int(argArray[1])),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_PTRACE:
		// If the traced process itself calls ptrace — anti-debugging or process injection
		request := int(argArray[0])
		targetPid := int(argArray[1])
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "ptrace",
			Detail:    fmt.Sprintf("ptrace request=%d target_pid=%d — anti-debugging or process injection", request, targetPid),
			Args:      []int{request, targetPid},
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_MOUNT:
		// mount(source, target, filesystemtype, mountflags, data)
		source, _ := p.readSyscallReg(pid, argArray[0], MAX_PATH_LEN)
		target, _ := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		fstype, _ := p.readSyscallReg(pid, argArray[2], 256)
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "mount",
			Detail:    fmt.Sprintf("mount %s on %s (type: %s) — potential container escape", source, target, fstype),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_CLONE, unix.SYS_CLONE3:
		// Track clone flags for namespace manipulation detection
		flags := int(argArray[0])
		suspicious := false
		var flagNames []string
		if flags&unix.CLONE_NEWNS != 0 {
			flagNames = append(flagNames, "CLONE_NEWNS")
			suspicious = true
		}
		if flags&unix.CLONE_NEWPID != 0 {
			flagNames = append(flagNames, "CLONE_NEWPID")
			suspicious = true
		}
		if flags&unix.CLONE_NEWNET != 0 {
			flagNames = append(flagNames, "CLONE_NEWNET")
			suspicious = true
		}
		if flags&unix.CLONE_NEWUSER != 0 {
			flagNames = append(flagNames, "CLONE_NEWUSER")
			suspicious = true
		}
		if suspicious {
			procInfo := p.getProcInfo(pid)
			procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
				Syscall:   "clone",
				Detail:    fmt.Sprintf("clone with namespace flags: %s — potential container escape or sandbox evasion", strings.Join(flagNames, "|")),
				Args:      []int{flags},
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	// --- Tier 1 additions from security research ---

	case unix.SYS_DUP3, 33: // 33 = SYS_DUP2 on amd64 (not defined on arm64)
		// dup2(oldfd, newfd) — critical for reverse shell detection
		// Pattern: socket→connect→dup2(sockfd,0)→dup2(sockfd,1)→dup2(sockfd,2)→execve("/bin/sh")
		oldFD := int(argArray[0])
		newFD := int(argArray[1])
		// Only record when redirecting a SOCKET to stdin/stdout/stderr
		// Pipe redirects (pip subprocess I/O) are normal and noisy
		if newFD <= 2 {
			oldPath := p.resolveFD(pid, oldFD)
			if strings.HasPrefix(oldPath, "socket:") {
				procInfo := p.getProcInfo(pid)
				target := []string{"stdin", "stdout", "stderr"}[newFD]
				procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
					Syscall:   "dup2",
					Detail:    fmt.Sprintf("redirected SOCKET fd %d (%s) to %s — reverse shell pattern", oldFD, oldPath, target),
					Args:      []int{oldFD, newFD},
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				})
			}
		}

	case unix.SYS_MPROTECT:
		// mprotect(addr, len, prot) — making memory executable
		// Pattern: mmap(RW)→write(shellcode)→mprotect(RX) = fileless payload
		prot := int(argArray[2])
		if prot&unix.PROT_EXEC != 0 {
			procInfo := p.getProcInfo(pid)
			procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
				Syscall:   "mprotect",
				Detail:    fmt.Sprintf("made memory executable (addr=%#x len=%d prot=%d) — fileless payload indicator", argArray[0], int(argArray[1]), prot),
				Args:      []int{int(argArray[0]), int(argArray[1]), prot},
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case unix.SYS_PRCTL:
		// prctl(option, ...) — process self-modification
		option := int(argArray[0])
		procInfo := p.getProcInfo(pid)
		var detail string
		switch option {
		case 15: // PR_SET_NAME
			name, _ := p.readSyscallReg(pid, argArray[1], 16)
			detail = fmt.Sprintf("PR_SET_NAME: renamed process to '%s' — hiding malicious process identity", name)
		case 4: // PR_SET_DUMPABLE
			detail = fmt.Sprintf("PR_SET_DUMPABLE=%d — may prevent forensic core dumps", int(argArray[1]))
		case 38: // PR_SET_NO_NEW_PRIVS
			detail = fmt.Sprintf("PR_SET_NO_NEW_PRIVS=%d — seccomp setup", int(argArray[1]))
		default:
			// Only log notable prctl options
			return nil
		}
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "prctl",
			Detail:    detail,
			Args:      []int{option, int(argArray[1])},
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_SETSID:
		// setsid() — create new session, detach from terminal
		// Used to daemonize malicious processes
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "setsid",
			Detail:    "created new session — daemonizing to detach from install process tree",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_SETNS:
		// setns(fd, nstype) — join existing namespace
		nstype := int(argArray[1])
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "setns",
			Detail:    fmt.Sprintf("joined namespace (fd=%d type=%d) — container escape or sandbox evasion", int(argArray[0]), nstype),
			Args:      []int{int(argArray[0]), nstype},
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE:
		// Kernel module loading — rootkit installation
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "init_module",
			Detail:    "attempted to load kernel module — rootkit installation",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}

	return nil
}

// ensureNetwork initializes the NetworkActivity struct if nil.
// measureExecutedImage runs the whole executed-image lifecycle for ONE execve
// on the ptrace backend: drop the previous exec's answer, measure the new
// image, pair the named path with its own digest, and downgrade with a reason
// when the mapped image could not be proven.
//
// It is one function because the four steps are only correct in this order and
// only as a set. Spread across the syscall handler they were not: the reset
// was missing entirely, so a second exec that failed its proof kept the FIRST
// exec's digest -- the guarded write did not fire, and the downgrade below it
// is conditional on ExeDigest being nil, so it did not fire either. The record
// for exec 2 was signed carrying exec 1's bytes under the mapped-image label.
// Having it in one testable place is what lets a test drive two execs in a row
// (see TestMeasureExecutedImage_ASecondExecNeverInheritsTheFirstsDigest);
// the handler itself needs a live traced process and a real ptrace stop, so
// nothing was able to cover the sequence while it lived inline.
//
// SYS_EXECVE hashes the new program's bytes both via /proc/<pid>/exe
// (post-execve) and via the literal argv[0] path (the file the user named).
// For 99% of execve calls these are the same file, so this hashes the same
// bytes twice. That duplication is deliberate: the two are separate
// resolutions of separate names, and a memo that collapsed them would be
// keyed on stat fields a tracee can hold still through a writable mapping.
// See the no-memo note above digestForPath.
//
// This backend HAS the BOUND property: it reads /proc/<pid>/exe while the
// tracee is stopped at the execve return, so the pid cannot exec again
// underneath the measurement. That is a kernel-enforced stop, not a fact
// re-derived from a mutable pathname, which is exactly what the eBPF backend
// lacks.
//
// PROTECTED still has to be proven rather than assumed. A stopped tracee can
// still be killed by an unrelated process, and once the last executing
// reference is gone ETXTBSY lapses and the same inode can be rewritten in
// place under our descriptor. So measure through one descriptor and require
// the image to still be mapped on both sides of the read.
func (p *ptraceContext) measureExecutedImage(procInfo *ProcessInfo, exeLocation, program string) {
	// Every execve replaces the pid's image, so a digest an earlier exec on
	// this pid recorded describes an image that is gone. Drop it WITH its
	// label before measuring the new one. The eBPF backend has always done
	// this; the ptrace backend did not.
	procInfo.setExeDigest(nil, "", "")

	// The program pair belongs to the previous exec for exactly the same
	// reason, and it is reset UNCONDITIONALLY -- including when program is
	// "" because argv[0] could not be read out of the tracee.
	//
	// Resetting only when a new path is known was the same omission one field
	// over. With program == "" the pair kept the previous exec's path and
	// digest; the mapped-image proof then failed, and the downgrade below --
	// which reads ProgramDigest, not program -- copied the PREVIOUS program's
	// digest into THIS exec's ExeDigest and signed it. An empty Program is an
	// honest "argv[0] could not be read"; the previous exec's path is a false
	// statement about this one.
	procInfo.setProgram(program, nil)

	if d, ok := p.provenMappedImage(exeLocation, stillMapping(exeLocation)); ok {
		procInfo.setExeDigest(d, ExeDigestSourceMappedImage, "")
	}

	if program != "" {
		// Re-pairs the same path with the digest of that path.
		d, _ := p.digestForPath(program)
		procInfo.setProgram(program, d)
	}

	// When the measurement could not be proven, fall back to the named path's
	// bytes, LABELLED and with the reason recorded, rather than leaving
	// ExeDigest empty. An empty field and a downgraded one are both honest,
	// but the downgrade carries more: it tells a verifier the producer looked,
	// could not prove the claim, and said so.
	if procInfo.ExeDigest == nil && procInfo.ProgramDigest != nil {
		procInfo.setExeDigest(procInfo.ProgramDigest, ExeDigestSourcePathHash, ExeDigestDowngradeUnprotected)
	}
}

func (p *ptraceContext) ensureNetwork(procInfo *ProcessInfo) {
	if procInfo.Network == nil {
		procInfo.Network = &NetworkActivity{}
	}
}

// ensureFileOps initializes the FileActivity struct if nil.
func (p *ptraceContext) ensureFileOps(procInfo *ProcessInfo) {
	if procInfo.FileOps == nil {
		procInfo.FileOps = &FileActivity{}
	}
}

// resolveFD resolves a file descriptor to a path via /proc/pid/fd/N.
func (p *ptraceContext) resolveFD(pid, fd int) string {
	link := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return target
}

// parseSockaddr reads a sockaddr struct from the traced process memory and
// extracts the address family, IP/path, and port.
func (p *ptraceContext) parseSockaddr(pid int, addrPtr uintptr, addrLen uintptr, syscallName string) (*NetworkConnection, error) {
	size := int(addrLen) //nolint:gosec // kernel sockaddr length, bounded by the check below
	if size < 2 || size > 128 {
		return nil, fmt.Errorf("sockaddr size %d out of range", size)
	}

	data := make([]byte, size)
	localIov := unix.Iovec{
		Base: &data[0],
		Len:  getNativeUint(size),
	}
	remoteIov := unix.RemoteIovec{
		Base: addrPtr,
		Len:  size,
	}

	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil {
		return nil, fmt.Errorf("ProcessVMReadv for sockaddr: %w", err)
	}

	family := binary.LittleEndian.Uint16(data[0:2])

	conn := &NetworkConnection{
		Syscall:   syscallName,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	switch family {
	case unix.AF_INET:
		if size < 8 {
			return nil, fmt.Errorf("AF_INET sockaddr too short: %d", size)
		}
		port := binary.BigEndian.Uint16(data[2:4])
		ip := net.IPv4(data[4], data[5], data[6], data[7])
		conn.Family = FamilyIPv4
		conn.Address = ip.String()
		conn.Port = int(port)

	case unix.AF_INET6:
		if size < 28 {
			return nil, fmt.Errorf("AF_INET6 sockaddr too short: %d", size)
		}
		port := binary.BigEndian.Uint16(data[2:4])
		ip := net.IP(data[8:24])
		conn.Family = FamilyIPv6
		conn.Address = ip.String()
		conn.Port = int(port)

	case unix.AF_UNIX:
		// Path starts at offset 2, null-terminated
		pathEnd := bytes.IndexByte(data[2:], 0)
		if pathEnd < 0 {
			pathEnd = len(data) - 2
		}
		conn.Family = FamilyUnix
		conn.Address = string(data[2 : 2+pathEnd])

	default:
		// socketFamilyName, not a bare "AF_%d": a domain the kernel names and
		// this vocabulary classifies (AF_NETLINK, AF_VSOCK) must arrive at the
		// consumer under that name. A numeric fallback is unclassifiable, and
		// an unclassifiable family conservatively breaks hermeticity — correct
		// for a domain nobody can vouch for, but wrong for AF_NETLINK, which
		// appears on every Linux build and reaches only the local kernel.
		conn.Family = socketFamilyName(int(family))
		conn.Address = fmt.Sprintf("raw:%x", data)
	}

	return conn, nil
}

func socketFamilyName(family int) string {
	switch family {
	case unix.AF_INET:
		return FamilyIPv4
	case unix.AF_INET6:
		return FamilyIPv6
	case unix.AF_UNIX:
		return FamilyUnix
	case unix.AF_UNSPEC:
		// connect() with an AF_UNSPEC sockaddr is the DISCONNECT idiom — it
		// dissolves a connected UDP socket's association, and glibc's resolver
		// uses it. It reaches nothing, so it maps to FamilyUnspecified
		// (classed non-remote) rather than to the numeric fallback. Left as
		// "AF_0" it would be unclassified, a consumer would conservatively
		// count it, and every build that resolves a hostname would go
		// non-hermetic.
		//
		// The contract this name rests on is that the CALLER read the domain.
		// ptrace honours it: parseSockaddr takes sa_family out of the tracee's
		// own memory and errors when it cannot, and that error path records
		// FamilyNotObservable instead. The eBPF connect decoder cannot yet —
		// see parseSockaddrEBPF, which documents the gap and why it is not
		// closable from Go.
		return FamilyUnspecified
	case unix.AF_NETLINK:
		return FamilyNetlink
	case unix.AF_VSOCK:
		// Remote-capable: a guest reaches its hypervisor host over AF_VSOCK.
		// Naming it keeps it out of the numeric fallback, where it was
		// unclassifiable and cilock's egress filter dropped it.
		return FamilyVSock
	default:
		// A domain this vocabulary has no name for. It stays numeric ON
		// PURPOSE: the predicate reports what the kernel said, and a consumer
		// reading a family it cannot classify must treat it as possible egress
		// rather than invent a classification here.
		return fmt.Sprintf("AF_%d", family)
	}
}

func socketTypeName(sockType int) string {
	// Mask off SOCK_NONBLOCK and SOCK_CLOEXEC flags
	base := sockType & 0xf
	switch base {
	case unix.SOCK_STREAM:
		return "SOCK_STREAM"
	case unix.SOCK_DGRAM:
		return "SOCK_DGRAM"
	case unix.SOCK_RAW:
		return "SOCK_RAW"
	case unix.SOCK_SEQPACKET:
		return "SOCK_SEQPACKET"
	default:
		return fmt.Sprintf("SOCK_%d", base)
	}
}

func (ctx *ptraceContext) getProcInfo(pid int) *ProcessInfo {
	procInfo, ok := ctx.processes[pid]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:   pid,
			OpenedFiles: make(map[string]cryptoutil.DigestSet),
		}

		ctx.processes[pid] = procInfo
	}

	return procInfo
}

func (ctx *ptraceContext) procInfoArray() []ProcessInfo {
	processes := make([]ProcessInfo, 0, len(ctx.processes)+len(ctx.replaced))
	for _, procInfo := range ctx.processes {
		processes = append(processes, *procInfo)
	}
	for _, procInfo := range ctx.replaced {
		processes = append(processes, *procInfo)
	}

	return processes
}

func (ctx *ptraceContext) readSyscallReg(pid int, addr uintptr, n int) (string, error) {
	data := make([]byte, n)
	localIov := unix.Iovec{
		Base: &data[0],
		Len:  getNativeUint(n),
	}

	removeIov := unix.RemoteIovec{
		Base: addr,
		Len:  n,
	}

	// ProcessVMReadv is much faster than PtracePeekData since it doesn't route the data through kernel space,
	// but there may be times where this doesn't work.  We may want to fall back to PtracePeekData if this fails
	numBytes, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{removeIov}, 0)
	if err != nil {
		return "", err
	}

	if numBytes == 0 {
		return "", nil
	}

	// don't want to use cgo... look for the first 0 byte for the end of the c string
	size := bytes.IndexByte(data, 0)
	if size < 0 {
		// No null terminator found; use the full buffer.
		size = numBytes
	}
	// sanitizePath ensures the returned string round-trips losslessly
	// through JSON even when the kernel handed us non-UTF-8 path bytes.
	// Valid-UTF-8 paths (the 99.99% case) are returned unchanged, so the
	// wire format is unchanged for normal builds. See path_encoding.go
	// and issue #164.
	return sanitizePath(data[:size]), nil
}

func cleanString(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\x00", " "))
}

func (p *ptraceContext) markReaped(tid int) {
	if p.reaped == nil {
		p.reaped = make(map[int]bool)
	}
	p.reaped[tid] = true
}

// ptraceLoopFault, when set, runs after every wait in runTrace's loop with the
// pid that wait reported and the pids the trace has recorded, and an error it
// returns ends the trace there, leaving the reported pid in its stop. It is nil
// in production; tests use it to fail a trace after its options are installed
// and its tracees are running.
var ptraceLoopFault func(reported int, known []int) error

// tracedPids returns the root and every pid the trace has a record for.
func (p *ptraceContext) tracedPids() []int {
	pids := []int{p.parentPid}
	for pid := range p.processes {
		if pid != p.parentPid {
			pids = append(pids, pid)
		}
	}
	return pids
}

// killTracees SIGKILLs everything the trace still holds, so no tracee is left
// in ptrace-stop when runTrace fails: the root's process group (runCmd makes
// the root a group leader), the root itself, and every tid the trace recorded
// and has not reaped. An unreaped tracee's id cannot have been reused, so this
// never signals a stranger. Kill errors are ignored: ESRCH means the target is
// already gone.
//
// Killing is not the end of it. With PTRACE_O_TRACEEXIT a killed tracee stops
// at PTRACE_EVENT_EXIT, which do_exit reaches BEFORE it closes the task's
// files, so it keeps the command's stdout pipe open until the tracer resumes
// it; and a dead tracee that is not cilock's own child stays a zombie until the
// tracer reaps it. So the kill is followed by a drain (drainTracees).
func (p *ptraceContext) killTracees() {
	_ = unix.Kill(-p.parentPid, unix.SIGKILL)
	_ = unix.Kill(p.parentPid, unix.SIGKILL)
	// Recorded tids, and every tid the loop saw even if it never recorded
	// it: a descendant in another session escapes the group kill, and one
	// left at a consumed stop is never reported again.
	for _, tids := range []map[int]bool{p.seen, p.processTids()} {
		for tid := range tids {
			if !p.reaped[tid] {
				_ = unix.Kill(tid, unix.SIGKILL)
			}
		}
	}
	p.drainTracees(time.Now().Add(tracerDrainBound))
}

func (p *ptraceContext) markSeen(tid int) {
	if p.seen == nil {
		p.seen = make(map[int]bool)
	}
	p.seen[tid] = true
}

func (p *ptraceContext) processTids() map[int]bool {
	tids := make(map[int]bool, len(p.processes))
	for tid := range p.processes {
		tids[tid] = true
	}
	return tids
}

// tracerDrainBound caps drainTracees. A killed tracee reports within
// milliseconds; the bound exists so the cleanup of a failed trace can never
// itself become a hang.
const tracerDrainBound = 5 * time.Second

// drainTracees reaps the tracees killTracees killed, resuming any that reports
// a stop (its PTRACE_EVENT_EXIT stop, or the first stop of a tid forked during
// the kill, which is killed too) so it can finish dying. It runs until there
// is nothing left to wait for (ECHILD) or the deadline, never merely until the
// tids it knows are gone: a tid forked while the kill was in flight is known
// to no one until it reports. Reaping the root here leaves runCmd's c.Wait()
// to find it gone, exactly as after a normal trace, whose loop reaps the root
// too. Like that loop it waits on any child: the only children cilock has
// during a trace are the command and, through ptrace, its descendants.
func (p *ptraceContext) drainTracees(deadline time.Time) {
	for time.Now().Before(deadline) {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOHANG, nil)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return // ECHILD: nothing traced or unreaped remains
		case pid == 0:
			time.Sleep(time.Millisecond)
			continue
		}
		if status.Stopped() {
			// A stop reported after the kill: EVENT_EXIT, or a tid that
			// was forked while the kill was in flight. Kill it (a no-op
			// for one already dying) and let it run to its death.
			_ = unix.Kill(pid, unix.SIGKILL)
			_ = unix.PtraceCont(pid, 0)
			continue
		}
		// Exited or signalled: reaped.
		p.markReaped(pid)
	}
}

// tracerPidOf returns the TracerPid in /proc/<pid>/status, or -1 when it
// cannot be read, which never equals a tid.
func tracerPidOf(pid int) int {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)) //nolint:gosec // G304: reading /proc/<pid>/status
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
	}
	return -1
}

func getPPIDFromStatus(status []byte) (int, error) {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "PPid:") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}
			ppid := strings.TrimSpace(parts[1])
			return strconv.Atoi(ppid)
		}
	}

	return 0, fmt.Errorf("PPid not found in status")
}

func getSpecBypassIsVulnFromStatus(status []byte) bool {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Speculation_Store_Bypass:") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}
			isVuln := strings.TrimSpace(parts[1])
			if strings.Contains(isVuln, "vulnerable") {
				return true
			}
		}
	}

	return false
}

// extractTLSSNI reads the write buffer from the traced process and parses
// the TLS ClientHello to extract the Server Name Indication (SNI) hostname.
// The SNI is plaintext in the ClientHello — no decryption needed.
//
// TLS record layout:
//
//	[0]     ContentType (0x16 = Handshake)
//	[1:3]   Version
//	[3:5]   Length
//	[5]     HandshakeType (0x01 = ClientHello)
//	[6:9]   Handshake length
//	[9:11]  ClientHello version
//	[11:43] Random (32 bytes)
//	[43]    SessionID length → skip SessionID
//	...     CipherSuites length → skip
//	...     Compression length → skip
//	...     Extensions length
//	...     Extensions: look for type 0x0000 (SNI)
//
//nolint:gocognit,gocyclo,funlen // byte-level TLS ClientHello parse with bounds checks at every step
func (p *ptraceContext) extractTLSSNI(pid int, bufPtr uintptr, bufLen int) string {
	// Read up to 512 bytes — SNI is always in the first few hundred bytes
	readLen := bufLen
	if readLen > 512 {
		readLen = 512
	}
	if readLen < 43 {
		return "" // too short for a ClientHello
	}

	data := make([]byte, readLen)
	localIov := unix.Iovec{Base: &data[0], Len: getNativeUint(readLen)}
	remoteIov := unix.RemoteIovec{Base: bufPtr, Len: readLen}

	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil {
		return ""
	}

	// Verify TLS record header
	if data[0] != 0x16 { // not a Handshake record
		return ""
	}
	// recordLen := int(binary.BigEndian.Uint16(data[3:5]))

	// Verify ClientHello
	if len(data) < 6 || data[5] != 0x01 {
		return ""
	}

	// Skip: handshake header (4 bytes) + client version (2) + random (32) = offset 43
	pos := 43
	if pos >= readLen {
		return ""
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > readLen {
		return ""
	}

	// Cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > readLen {
		return ""
	}

	// Compression methods
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 > readLen {
		return ""
	}

	// Extensions
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > readLen {
		extensionsEnd = readLen
	}

	// Walk extensions looking for SNI (type 0x0000)
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		//nolint:nestif // SNI-in-extensions parse — bounds checks dominate nesting
		if extType == 0x0000 && extLen > 5 && pos+extLen <= extensionsEnd {
			// SNI extension: list length (2) + type (1) + name length (2) + name
			sniListLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			if sniListLen > extLen-2 {
				break
			}
			nameType := data[pos+2]
			if nameType != 0 { // 0 = host_name
				break
			}
			nameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
			nameStart := pos + 5
			nameEnd := nameStart + nameLen
			if nameEnd > extensionsEnd || nameLen == 0 || nameLen > 255 {
				break
			}
			hostname := string(data[nameStart:nameEnd])
			// Basic validation: hostname should be printable ASCII
			for _, c := range hostname {
				if c < 0x20 || c > 0x7e {
					return ""
				}
			}
			return hostname
		}

		pos += extLen
	}

	return ""
}
