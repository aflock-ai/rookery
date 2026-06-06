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

package commandrun

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	Name = "command-run"
	// Type is the predicate URI the producer emits. v0.2 is the current
	// producer (the interned, _meta-first wire shape — see v2_marshal.go).
	// v0.1 attestations remain *verifiable* via the LegacyDecoder in
	// legacy.go, which registers under a distinct name + the v0.1 URI so
	// `cilock run --attestations command-run` always selects this producer.
	Type    = V02PredicateType
	RunType = attestation.ExecuteRunType

	// EnvVarTraceMode selects the tracing backend. Hoisted to the
	// cross-platform file so commandrun.go can read it for trace-mode
	// detail on non-Linux builds without forcing platform-specific
	// imports.
	//
	//	(unset) | "ebpf" — eBPF (default on Linux). Hard-fail if not available.
	//	"ptrace"        — ptrace+seccomp. Explicit opt-in; no fallback errors.
	EnvVarTraceMode = "CILOCK_TRACE_MODE"
)

// commandWaitDelay bounds how long c.Wait() waits for the exec I/O copy
// goroutines AFTER the wrapped process has already exited. See the large
// comment in runCmd for why this is the anti-hang guarantee. Sized
// generously so a legitimately slow final flush from the real command is
// never clipped; it only ever fires when a lingering descendant is
// holding the inherited stdout/stderr pipe write-end open past process
// exit (in which case the alternative is hanging forever).
//
// A var (not a const) solely so the hang regression test can shorten it
// to keep the suite fast while still exercising the real force-close
// path; production never reassigns it.
var commandWaitDelay = 30 * time.Second

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &CommandRun{}
	_ CommandRunAttestor   = &CommandRun{}
)

type CommandRunAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *CommandRun
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Option func(*CommandRun)

func WithCommand(cmd []string) Option {
	return func(cr *CommandRun) {
		cr.Cmd = cmd
	}
}

func WithMaterials(materials map[string]cryptoutil.DigestSet) Option {
	return func(cr *CommandRun) {
		cr.materials = materials
	}
}

func WithTracing(enabled bool) Option {
	return func(cr *CommandRun) {
		cr.enableTracing = enabled
	}
}

func WithSilent(silent bool) Option {
	return func(cr *CommandRun) {
		cr.silent = silent
	}
}

// WithIgnoreExitCode tells the attestor to record the wrapped command's
// exit code in the predicate but NOT propagate the exit-error up to the
// cilock run pipeline. Use when the wrapped tool exits non-zero on
// findings (semgrep, gosec, hadolint, checkov, trivy --exit-code, prowler
// v3, govulncheck) — without this option, the postproduct stage skips
// every downstream attestor (sarif/sbom/vex/etc.) and the tool's output
// never gets parsed into the envelope.
//
// Policy Rego still has access to the real exit code via
// `input.attestation.exitcode` and can deny on it.
func WithIgnoreExitCode(ignore bool) Option {
	return func(cr *CommandRun) {
		cr.ignoreExitCode = ignore
	}
}

// WithPrewalkSkipDirs adds directory base names to the pre-trace
// workspace walk's skip list. Directories with these basenames are
// not descended into during the snapshot used to distinguish
// overwrites from clean creations. Additive on top of the built-in
// defaults (.git, node_modules, vendor, .cache).
//
// Each entry should be a single directory NAME (basename), not a
// path. Empty entries are silently ignored.
func WithPrewalkSkipDirs(names []string) Option {
	return func(cr *CommandRun) {
		for _, n := range names {
			if n == "" {
				continue
			}
			cr.prewalkSkipDirs = append(cr.prewalkSkipDirs, n)
		}
	}
}

// WithPrewalkIncludeDirs marks directory base names that must NOT
// be skipped during the pre-trace walk, even if those names appear
// in the built-in default skip set or in the operator's
// --prewalk-skip-dir list. Most-specific wins: include beats skip.
//
// Useful when a build legitimately writes into one of the
// default-skipped trees (e.g. a vendoring step that produces files
// under vendor/, or a tool that emits artefacts into .cache/).
func WithPrewalkIncludeDirs(names []string) Option {
	return func(cr *CommandRun) {
		for _, n := range names {
			if n == "" {
				continue
			}
			cr.prewalkIncludeDirs = append(cr.prewalkIncludeDirs, n)
		}
	}
}

// WithRequireZeroDrops enables the fail-closed attestation gate. If
// the trace observed ANY BPF ringbuf drops, fanotify handler
// timeouts, or other data-loss signals at the end of the trace, the
// attestor returns an error instead of emitting a known-incomplete
// attestation. For high-stakes release builds where "we missed some
// events" is unacceptable.
//
// Default off — most builds tolerate the few-percent drop rate on
// JVM-class workloads in exchange for not interrupting CI. Opt in
// via --require-zero-drops or the API.
func WithRequireZeroDrops(require bool) Option {
	return func(cr *CommandRun) {
		cr.requireZeroDrops = require
	}
}

// ZeroDropsError signals that --require-zero-drops was set and the
// trace observed loss. Wraps a structured breakdown so the operator
// (and any tooling parsing stderr) can see WHICH counters were
// non-zero.
type ZeroDropsError struct {
	RingbufOpenatDrops     uint64
	RingbufReadTapDrops    uint64
	FanotifyTimeouts       uint64
	FanotifyQueueOverflows uint64
	FanotifyDigestsCapHit  uint64
	UnhashedOpensTotal     uint64
	FallbackHashFailures   uint64
	FsVeritySealFailures   uint64
}

func (e *ZeroDropsError) Error() string {
	return fmt.Sprintf(
		"attestation rejected (--require-zero-drops): "+
			"bpf-openat-drops=%d bpf-readtap-drops=%d "+
			"fanotify-timeouts=%d fanotify-queue-overflows=%d fanotify-cap-hit=%d "+
			"unhashed-opens=%d fallback-hash-failures=%d fsverity-failures=%d",
		e.RingbufOpenatDrops, e.RingbufReadTapDrops,
		e.FanotifyTimeouts, e.FanotifyQueueOverflows, e.FanotifyDigestsCapHit,
		e.UnhashedOpensTotal, e.FallbackHashFailures, e.FsVeritySealFailures,
	)
}

// zeroDropsGate inspects the trace diagnostics and returns a
// ZeroDropsError when ANY data-loss counter is non-zero. Called
// from runCmd when WithRequireZeroDrops is set.
//
// What counts as a drop:
//   - RingbufOpenatDrops > 0: openat events the BPF kernel side lost
//   - RingbufReadTapDrops > 0: content chunks lost
//   - FanotifyTimeouts > 0: handler too slow → kernel default-allow
//   - UnhashedOpensTotal > 0: files we observed opening but couldn't hash
//   - FallbackHashFailures > 0: aggregate hash failures (silent + recorded)
//   - FsVeritySealFailures > 0: kernel sealing returned an error
//
// Note: PartialReadFallbacks is NOT a drop — partial reads are a
// CORRECT behavior (we fall back to the openat-time digest which
// is still authoritative). Don't fail on those.
func (r *CommandRun) zeroDropsGate() error {
	if r.Summary == nil {
		// Trace produced no summary — that's itself a degradation
		// signal, but for now we don't treat it as a drop.
		return nil
	}
	d := r.Summary.Diagnostics
	// "Drop" means LOST data — we can't even surface evidence that an
	// open happened. There are two distinct failure modes:
	//
	//   HARD DROPS (this gate fails on these):
	//     - RingbufOpenatDrops: kernel-side BPF ringbuf overflow.
	//       The open event itself is gone; we don't know it happened.
	//     - RingbufReadTapDrops: same, for content chunks.
	//     - FanotifyTimeouts / QueueOverflows / DigestsCapHit:
	//       fanotify lost the event OR the kernel default-allowed
	//       a syscall we couldn't process in time.
	//     - FsVeritySealFailures: kernel sealing rejected.
	//
	//   SOFT DROPS (recorded, NOT gated):
	//     - UnhashedOpens entries: we observed the open and recorded
	//       its path, syscall, pid, and reason. We just don't have a
	//       content hash. The verifier sees per-file evidence and
	//       decides what to do with it. This is strictly more
	//       transparent than the "vanishing into a counter" prior
	//       behavior — every UnhashedOpen is a documented gap, not
	//       a blind spot.
	//     - FallbackHashFailures: secondary capture-path failures
	//       on files fanotify may or may not have rescued; either
	//       way the attestation has per-file evidence.
	//
	// The model: HARD drops fail the build (blindspot, no recovery).
	// SOFT drops downgrade the per-file digest to "open recorded
	// without content" — surfaceable in attestation, queryable by
	// the verifier. Hosted-GHA workloads with toolchain reads under
	// /opt/hostedtoolcache always have a few of these from
	// startup-race / fast-fork-exec patterns; making them fail-closed
	// turns require-zero-drops into a permanent red light.
	if d.RingbufOpenatDrops > 0 || d.RingbufReadTapDrops > 0 ||
		d.FanotifyTimeouts > 0 || d.FanotifyQueueOverflows > 0 ||
		d.FanotifyDigestsCapHit > 0 ||
		d.FsVeritySealFailures > 0 {
		return &ZeroDropsError{
			RingbufOpenatDrops:     d.RingbufOpenatDrops,
			RingbufReadTapDrops:    d.RingbufReadTapDrops,
			FanotifyTimeouts:       d.FanotifyTimeouts,
			FanotifyQueueOverflows: d.FanotifyQueueOverflows,
			FanotifyDigestsCapHit:  d.FanotifyDigestsCapHit,
			UnhashedOpensTotal:     d.UnhashedOpensTotal,
			FallbackHashFailures:   d.FallbackHashFailures,
			FsVeritySealFailures:   d.FsVeritySealFailures,
		}
	}
	return nil
}

func New(opts ...Option) *CommandRun {
	cr := &CommandRun{}

	for _, opt := range opts {
		opt(cr)
	}

	return cr
}

// SocketInfo records a socket creation syscall.
type SocketInfo struct {
	Family   string `json:"family"`   // AF_INET, AF_INET6, AF_UNIX, etc.
	Type     string `json:"type"`     // SOCK_STREAM, SOCK_DGRAM, etc.
	Protocol int    `json:"protocol"` // 0 = default, 6 = TCP, 17 = UDP
	FD       int    `json:"fd"`       // file descriptor returned
}

// NetworkConnection records a connect or bind syscall.
type NetworkConnection struct {
	Syscall   string `json:"syscall"`             // "connect" or "bind"
	Family    string `json:"family"`              // AF_INET, AF_INET6, AF_UNIX
	Address   string `json:"address"`             // IP address or Unix socket path
	Port      int    `json:"port,omitempty"`      // TCP/UDP port (0 for AF_UNIX)
	FD        int    `json:"fd"`                  // socket file descriptor
	Timestamp string `json:"timestamp,omitempty"` // when the syscall was observed
	Hostname  string `json:"hostname,omitempty"`  // TLS SNI hostname (extracted from ClientHello)
}

// DNSLookup records a detected DNS resolution (heuristic: connect to port 53).
type DNSLookup struct {
	ServerAddress string `json:"serverAddress"`
	ServerPort    int    `json:"serverPort"`
}

// NetworkActivity aggregates all network operations for a process.
type NetworkActivity struct {
	Sockets     []SocketInfo        `json:"sockets,omitempty"`
	Connections []NetworkConnection `json:"connections,omitempty"`
	DNSLookups  []DNSLookup         `json:"dnsLookups,omitempty"`
}

// FileWrite records a write to a file descriptor. We track the path
// (resolved from the fd via /proc/pid/fd/N) and bytes written.
type FileWrite struct {
	Path      string `json:"path"`
	Bytes     int    `json:"bytes"`
	Timestamp string `json:"timestamp,omitempty"`
}

// FileRename records a rename/move operation.
type FileRename struct {
	OldPath   string `json:"oldPath"`
	NewPath   string `json:"newPath"`
	Timestamp string `json:"timestamp,omitempty"`
}

// FileDelete records an unlink operation.
type FileDelete struct {
	Path      string `json:"path"`
	Timestamp string `json:"timestamp,omitempty"`
}

// FilePermChange records a chmod operation.
type FilePermChange struct {
	Path      string `json:"path"`
	Mode      uint32 `json:"mode"`    // new permission bits
	SetExec   bool   `json:"setExec"` // true if executable bit was set
	Timestamp string `json:"timestamp,omitempty"`
}

// SyscallEvent records a notable syscall that doesn't fit other categories.
type SyscallEvent struct {
	Syscall   string `json:"syscall"`          // "memfd_create", "ptrace", "mount", "clone"
	Detail    string `json:"detail,omitempty"` // human-readable detail
	Args      []int  `json:"args,omitempty"`   // raw syscall arguments
	Timestamp string `json:"timestamp,omitempty"`
	// Path is the resolved path the syscall acted on, when known.
	// For mmap, this is the mapped file. For two-fd transfers
	// (copy_file_range, splice, sendfile) this is the SOURCE.
	// Empty when fd → path resolution failed (open event missed,
	// fd inherited from before trace start, etc.).
	Path string `json:"path,omitempty"`
	// TargetPath is the destination side for two-fd transfers
	// (copy_file_range, splice, sendfile). Unused for single-fd
	// syscalls.
	TargetPath string `json:"targetPath,omitempty"`
	// DigestSource tells the verifier where the digest for Path
	// came from, when one exists in OpenedFiles. Possible values:
	//   - "fanotify-open-time" — kernel-synchronous hash at open;
	//     TRUSTED at open time, may differ from bytes-the-tracee-
	//     actually-read for mmap-read files mutated post-open.
	//   - "bpf-streaming"      — accumulated via read-tap kretprobe;
	//     IS what the tracee saw.
	//   - "openat-path-hash"   — hashed via /proc/<pid>/fd/<fd> at
	//     openat time; race window between openat and our hasher.
	//   - "" (empty)           — no digest captured (mmap-read with
	//     no prior fanotify hash; zero-copy syscall).
	// Verifiers use this to set their trust threshold per syscall.
	DigestSource string `json:"digestSource,omitempty"`
}

// FileActivity aggregates all file mutation operations for a process.
type FileActivity struct {
	Writes      []FileWrite      `json:"writes,omitempty"`
	Renames     []FileRename     `json:"renames,omitempty"`
	Deletes     []FileDelete     `json:"deletes,omitempty"`
	PermChanges []FilePermChange `json:"permChanges,omitempty"`
}

type ProcessInfo struct {
	Program       string                          `json:"program,omitempty"`
	ProcessID     int                             `json:"processid"`
	ParentPID     int                             `json:"parentpid"`
	ProgramDigest cryptoutil.DigestSet            `json:"programdigest,omitempty"`
	Comm          string                          `json:"comm,omitempty"`
	Cmdline       string                          `json:"cmdline,omitempty"`
	ExeDigest     cryptoutil.DigestSet            `json:"exedigest,omitempty"`
	OpenedFiles   map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`
	// WrittenDigests carries content digests for files the tracee
	// WROTE during the trace, captured via the BPF write-tap (kretprobe
	// on sys_write / pwrite64 returns the bytes the kernel actually
	// transferred). Keyed by absolute path, value is a digest of the
	// bytes the tracee emitted — independent of any other writer or
	// post-close mutation. Distinct from OpenedFiles (which tracks
	// READ digests). A path may appear in both if the tracee wrote
	// AND read it; classification rules use this split to put outputs
	// in products and inputs in materials without conflation.
	WrittenDigests map[string]cryptoutil.DigestSet `json:"writtenDigests,omitempty"`
	// FsVerityDigests holds kernel-rooted Merkle root digests for
	// product files where the kernel computed and stored a
	// fs-verity hash. Keyed by absolute path, value is the
	// algorithm + hex digest (e.g. "sha256:abc...def"). The kernel
	// REFUSES to read corrupted blocks on these files, so a
	// verifier can re-read the file with fs-verity enabled and
	// trust the kernel's bit-exact verification.
	// Distinct from WrittenDigests because the Merkle root is NOT
	// the same as a plain SHA-256 over the file content (it's a
	// hash of a Merkle tree over fixed-size blocks).
	FsVerityDigests map[string]string `json:"fsverityDigests,omitempty"`
	// UnhashedOpens carries opens we saw the kernel event for but
	// could NOT hash — typically because the file was unlinked or
	// the process exited between the kernel event and our hash
	// attempt. For each entry the attestation records WHAT path
	// was opened and WHY we couldn't hash it.
	//
	// SECURITY: these entries ARE suspicious. An attacker could race
	// to delete a file after a tracee reads it, leaving an
	// "unhashable" hole the attestation can't audit. Verifiers
	// MUST decide policy on these — they're not silently dropped.
	// Common benign cases:
	//  - gcc unlinking /tmp/cc*.s temp files after use
	//  - Short-lived helper processes that exit before our hasher
	//    pool reaches the event
	// Common adversarial cases:
	//  - Tracee deliberately racing to delete sensitive files
	//  - A read-then-unlink that "launders" content from view
	UnhashedOpens    []UnhashedOpen   `json:"unhashedOpens,omitempty"`
	Environ          string           `json:"environ,omitempty"`
	SpecBypassIsVuln bool             `json:"specbypassisvuln,omitempty"`
	Network          *NetworkActivity `json:"network,omitempty"`
	FileOps          *FileActivity    `json:"fileOps,omitempty"`
	SyscallEvents    []SyscallEvent   `json:"syscallEvents,omitempty"`

	// ExitCode is the wait status of the traced process. For cleanly-
	// exited processes it is the literal exit status. For signal-
	// terminated processes it follows shell convention: 128 + signal
	// number. Zero (omitted from JSON) means "still running when trace
	// ended" or "exit code unknown" — verifiers must not infer
	// successful exit from a missing/zero value.
	ExitCode int `json:"exitcode,omitempty"`
}

// UnhashedOpen records an openat where we observed the kernel event
// but could not produce a digest. Always paired with a Reason so a
// verifier can judge whether the gap is benign or suspicious.
type UnhashedOpen struct {
	Path   string `json:"path"`
	Reason string `json:"reason"` // e.g. "file removed before hash", "process exited"
}

// TraceSummary is the AI-agent and operator-friendly index of a
// trace. Designed so a reader scanning the first ~5 KB of the
// attestation has enough info to decide what to drill into.
//
// All fields are best-effort and omitempty — a non-traced run
// or a trace that produced no events still serializes cleanly
// (Summary itself is omitempty on CommandRun).
type TraceSummary struct {
	// CaptureMode records which data source produced the trace —
	// "ebpf-readtap", "ptrace", or unset for non-traced runs.
	// Verifiers + agents use this to understand trust level.
	CaptureMode string `json:"captureMode,omitempty"`

	// TraceModeDetail is a human-readable hint for the operator,
	// e.g. "eBPF kprobes + read-tap" or "ptrace+seccomp". Optional.
	TraceModeDetail string `json:"traceModeDetail,omitempty"`

	// DurationNs is how long the tracee ran, end-to-end, in
	// nanoseconds. Lets agents triage by elapsed time without
	// computing it from start/end fields elsewhere.
	DurationNs int64 `json:"durationNs,omitempty"`

	// Totals are scalar counts useful for at-a-glance triage.
	Totals TraceTotals `json:"totals"`

	// Outliers flags interesting events worth investigating — the
	// largest file read, the most-frequently-opened path, any
	// security-sensitive syscalls (ptrace, mount, memfd_create).
	// A clean build has all-zero counts here.
	Outliers TraceOutliers `json:"outliers,omitempty"`

	// Diagnostics records data-quality info the operator needs to
	// see immediately — ringbuf drops, partial reads that triggered
	// path-hash fallback, etc. Non-zero values mean the attestation
	// may be incomplete.
	Diagnostics TraceDiagnostics `json:"diagnostics,omitempty"`

	// FanotifyOnlyDigests holds paths fanotify hashed but no process
	// recorded an open for. This happens when BPF dropped the openat
	// event OR the open occurred outside the watched_pids set OR a
	// process that opened the file exited before BPF could record it.
	// The kernel-rooted digest is still authoritative even though we
	// can't attribute it to a specific tracee process. Verifiers
	// SHOULD treat these as "observed in the workspace" without
	// process-tree provenance. Hex-encoded SHA-256.
	FanotifyOnlyDigests map[string]string `json:"fanotifyOnlyDigests,omitempty"`

	// InterestingPaths is a short list of paths an agent should
	// look at first — anything outside the "normal" build paths
	// (/etc/passwd, /proc/self/environ, etc.) or anything in the
	// security-events list. Capped to ~32 entries.
	InterestingPaths []string `json:"interestingPaths,omitempty"`
}

// TraceTotals is the scalar count summary.
type TraceTotals struct {
	Processes   int `json:"processes,omitempty"`
	UniquePaths int `json:"uniquePaths,omitempty"`
	Reads       int `json:"reads,omitempty"`
	Writes      int `json:"writes,omitempty"`
	Renames     int `json:"renames,omitempty"`
	Deletes     int `json:"deletes,omitempty"`
	Execs       int `json:"execs,omitempty"`
	NetEvents   int `json:"netEvents,omitempty"`
	// Classification breakdown — populated when CaptureProbe path
	// runs (capture-mode=trace). Lets the AI agent see at-a-glance
	// what kind of files the tracee touched without loading the
	// per-process arrays.
	Materials      int `json:"materials,omitempty"`      // distinct files read
	Intermediates  int `json:"intermediates,omitempty"`  // files both written + read
	Products       int `json:"products,omitempty"`       // user-facing outputs
	CacheArtifacts int `json:"cacheArtifacts,omitempty"` // written into cache/temp
}

// TraceOutliers flags noteworthy artifacts. Most are file-event
// outliers; SuspiciousOps is a tally of security-sensitive syscalls
// (ptrace, mount, etc.) that any reader should examine.
type TraceOutliers struct {
	LargestRead   *TraceFileRef  `json:"largestRead,omitempty"`
	MostOpened    *TraceFileRef  `json:"mostOpened,omitempty"`
	SuspiciousOps map[string]int `json:"suspiciousOps,omitempty"`
}

// TraceFileRef points at a specific file mentioned in the trace,
// with the metric that made it interesting.
type TraceFileRef struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes,omitempty"`
	Count int    `json:"count,omitempty"`
}

// TraceDiagnostics records data-quality info. Non-zero values mean
// the attestation has known gaps.
type TraceDiagnostics struct {
	// RingbufOpenatDrops is the count of openat events the BPF
	// ringbuf dropped under pressure. Non-zero means the
	// attestation is missing some opens.
	RingbufOpenatDrops uint64 `json:"ringbufOpenatDrops,omitempty"`

	// RingbufReadTapDrops is the same for read-tap content events.
	RingbufReadTapDrops uint64 `json:"ringbufReadTapDrops,omitempty"`

	// PartialReadFallbacks is the count of files where the tracee
	// did a partial read (closed before reading the full file) and
	// the framework fell back to path-hash. Informational only.
	PartialReadFallbacks uint64 `json:"partialReadFallbacks,omitempty"`

	// FallbackHashFailures is the count of INDIVIDUAL openat events
	// where hashing failed (TOCTOUError / TOCTOUMissing). Each such
	// failure is dispatched by recordEBPFOpenat to one of two places:
	//
	//   - If the same path was already cleanly hashed in the same
	//     process: silent drop. The successful capture stands, the
	//     failure is invisible to the verifier. See HashFailureSilentDrops.
	//
	//   - Else: an UnhashedOpens entry with a Reason on the process.
	//     Visible to verifiers — explicit gap with explanation. See
	//     UnhashedOpensTotal.
	//
	// FallbackHashFailures = HashFailureSilentDrops + UnhashedOpensTotal
	// (approximately; the sets aren't perfectly disjoint across procs).
	FallbackHashFailures uint64 `json:"fallbackHashFailures,omitempty"`

	// UnhashedOpensTotal is the total count of UnhashedOpens entries
	// across all per-process records. Each entry has an explicit
	// Reason so verifiers can judge whether a gap is benign (e.g.
	// "file removed before hash" on a temp file) or worth investigating.
	UnhashedOpensTotal uint64 `json:"unhashedOpensTotal,omitempty"`

	// HashFailureSilentDrops counts hash failures that did NOT
	// produce an UnhashedOpens entry. Two sub-cases (both counted):
	//   - same path was already cleanly hashed in the same process
	//     (the "caught it elsewhere" case — failure is harmless)
	//   - same path already had an UnhashedOpens entry (the dedup
	//     case — the gap is already recorded; this failure adds no
	//     new information)
	// A high silent-drop count alongside a high FallbackHashFailures
	// total means most failures were retries of paths we already
	// know about. Near-zero silent drops with non-zero
	// FallbackHashFailures means each failure became a verifiable gap.
	HashFailureSilentDrops uint64 `json:"hashFailureSilentDrops,omitempty"`

	// FanotifyAvailable reports whether the fanotify integrity gate
	// was active for this trace. true = every open under the workspace
	// mount was synchronously hashed by the kernel-blocking handler;
	// false = BPF-only with potential drops.
	FanotifyAvailable bool `json:"fanotifyAvailable,omitempty"`

	// FanotifyEventsHashed is the count of synchronous open events
	// the fanotify handler hashed during this trace. A non-zero
	// value alongside zero RingbufReadTapDrops means content capture
	// was strictly zero-loss.
	FanotifyEventsHashed uint64 `json:"fanotifyEventsHashed,omitempty"`

	// FanotifyDigestsMerged is the count of OpenedFiles entries
	// upgraded from BPF-sourced digests to fanotify-sourced ones.
	// Verifiers can use this as a confidence indicator: high merged
	// count = most digests are kernel-synchronous.
	FanotifyDigestsMerged uint64 `json:"fanotifyDigestsMerged,omitempty"`

	// FanotifyTimeouts is the count of fanotify events where the
	// userspace handler took longer than its budget. Each timeout
	// means the kernel defaulted to FAN_ALLOW (no hash captured);
	// non-zero is a degradation signal.
	FanotifyTimeouts uint64 `json:"fanotifyTimeouts,omitempty"`

	// FanotifyQueueOverflows counts FAN_Q_OVERFLOW events the kernel
	// emitted to signal it dropped fanotify events because our
	// handler fell behind. NON-ZERO = the synchronous-zero-drop
	// promise was violated; the attestation has unknown gaps.
	FanotifyQueueOverflows uint64 `json:"fanotifyQueueOverflows,omitempty"`

	// FanotifyDigestsCapHit counts paths the fanotify handler
	// hashed but couldn't store because the per-trace cap was
	// reached (default 200_000 paths). The hash WAS computed and
	// the tracee was allowed, but the path isn't in the attestation.
	// Non-zero means a pathological workload outran our memory
	// budget; verifiers should treat such attestations as
	// incomplete (the cap-hit count documents how many entries
	// are missing).
	FanotifyDigestsCapHit uint64 `json:"fanotifyDigestsCapHit,omitempty"`

	// CacheReadsSkipped is the count of read opens the eBPF hasher
	// released WITHOUT hashing because the path classified as
	// build-internal cache/temp (Go module cache, GOCACHE, /tmp). These
	// are content-addressed storage pinned by lockfiles, not products
	// and not meaningful materials. Skipping them removes the dominant
	// hash load on cold builds and avoids churning-cache TOCTOU
	// failures that would otherwise inflate FallbackHashFailures /
	// HashFailureSilentDrops. High here + low drops = the optimization
	// is working as intended, not a sign of lost data.
	CacheReadsSkipped uint64 `json:"cacheReadsSkipped,omitempty"`

	// FanotifyCacheSkips is the same idea for the fanotify gate: opens
	// the synchronous handler released without hashing because the path
	// classified as cache/temp. Reduces handler latency → fewer
	// timeouts / queue overflows.
	FanotifyCacheSkips uint64 `json:"fanotifyCacheSkips,omitempty"`

	// FanotifyIgnoreMarksAdded / FanotifyIgnoreMarkErrors report the
	// "hash once" EXPERIMENT (CILOCK_FANO_IGNORE_ONCE): how many inode
	// FAN_MARK_IGNORE marks were added (each suppresses repeat
	// FAN_OPEN_PERM for one inode until it's modified) and how many such
	// marks failed. High added-count + low EventsHashed on a repeat-heavy
	// build = the in-kernel open-storm collapse is working.
	FanotifyIgnoreMarksAdded uint64 `json:"fanotifyIgnoreMarksAdded,omitempty"`
	FanotifyIgnoreMarkErrors uint64 `json:"fanotifyIgnoreMarkErrors,omitempty"`

	// FsVerityAvailable reports whether fs-verity sealing was active
	// for this trace's workspace FS. true = the kernel computed and
	// stored Merkle roots over product files; false = streaming
	// SHA-256 only.
	FsVerityAvailable bool `json:"fsVerityAvailable,omitempty"`

	// FsVerityFilesSealed counts files where fs-verity sealing
	// succeeded. Each represents a product whose digest is now
	// Merkle-rooted and the kernel will refuse to read corrupted
	// blocks downstream — tamper-evident.
	FsVerityFilesSealed uint64 `json:"fsVerityFilesSealed,omitempty"`

	// FsVeritySealFailures counts attempted seals that failed for
	// reasons other than "FS doesn't support" (which is the probe
	// path). Non-zero suggests a real issue worth investigating.
	FsVeritySealFailures uint64 `json:"fsVeritySealFailures,omitempty"`
}

type CommandRun struct {
	Cmd      []string `json:"cmd"`
	ExitCode int      `json:"exitcode"`

	// Summary is a top-level scannable view of the trace. Designed
	// for AI agents and operators who need to triage a build without
	// loading the full processes[] array (which can be 20+ MB on a
	// large parallel build). Populated by the trace path; empty in
	// non-traced runs. Serialized BEFORE the heavy fields so a
	// streaming JSON reader hits the summary in the first few KB.
	Summary *TraceSummary `json:"summary,omitempty"`

	Stdout    string        `json:"stdout,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	Processes []ProcessInfo `json:"processes,omitempty"`

	// keyGuard is the signer's anti-tamper state read back at Attest time
	// (see readHardening). It is copied into the v0.2 `_meta.keyGuard` block
	// by ToV02 and restored by FromV02, so it travels INSIDE the signed
	// predicate as non-forgeability evidence. Never marshaled directly (it is
	// unexported); the v0.1 wire shape never carried it.
	keyGuard *V02KeyGuard

	silent        bool
	materials     map[string]cryptoutil.DigestSet
	enableTracing bool

	// traceeWorkdir is the working directory the tracee actually ran
	// with — populated by runCmd just before exec.Command starts.
	// TraceOutputs uses it to resolve relative paths in fileOps.Writes /
	// Renames (e.g. atomic-rename target "bin/gh") to absolute paths
	// the verifier can match. os.Getwd() at attestation time isn't
	// reliable: cilock may chdir between runCmd and the post-trace
	// summary build, and ctx.WorkingDir() may be empty when the
	// caller didn't pass one explicitly.
	traceeWorkdir string

	// traceStartTime is the wall-clock time captured just before
	// exec.Command starts. The stat-fallback in TraceOutputs uses it
	// to distinguish pre-existing files (mtime < traceStartTime) from
	// files actually modified during the trace (mtime >= traceStartTime).
	// Critical when write-tap misses an overwrite — without this we'd
	// hash a pre-build file and falsely emit it as a product.
	traceStartTime time.Time

	// prePaths is the set of absolute file paths under traceeWorkdir
	// that existed BEFORE the trace started. Populated by runCmd's
	// pre-exec walk. Used by the stat-fallback in TraceOutputs to
	// distinguish (a) overwrites of pre-existing files (Source:
	// trace-pathhash-overwrite — content lost unless verifier has a
	// prior attestation) from (b) clean creations during the trace
	// (Source: trace-pathhash). The mtime check handles the
	// untouched-skip case; this set handles the overwrite tag.
	prePaths         map[string]struct{}
	ignoreExitCode   bool
	requireZeroDrops bool

	// prewalkSkipDirs lists directory base names to skip when
	// snapshotting pre-trace workspace state. Populated by
	// WithPrewalkSkipDirs from the operator's --prewalk-skip-dir
	// flags. Additive on top of the built-in default set.
	prewalkSkipDirs []string

	// prewalkIncludeDirs lists directory base names that must NOT
	// be skipped even if they appear in the built-in default set or
	// the user's --prewalk-skip-dir list. Populated by
	// WithPrewalkIncludeDirs from --prewalk-include-dir. The
	// include set is the most-specific override and wins over both
	// defaults and user-supplied skips.
	prewalkIncludeDirs []string

	// cacheMatcher classifies tracee-written paths as cache/temp
	// (excluded from products) vs user-facing outputs. Installed by
	// the product attestor at Attest time via SetCacheMatcher; nil
	// in walk-mode runs (where TraceOutputs isn't called).
	cacheMatcher *attestation.CachePathMatcher

	// ringbufDropOpenat / ringbufDropReadTap stash the BPF ringbuf
	// drop counters read at trace teardown. buildTraceSummary reads
	// these into Summary.Diagnostics when it builds the summary
	// AFTER trace() returns. Set unconditionally on the eBPF path;
	// zero on the ptrace path (no ringbuf).
	ringbufDropOpenat  uint64
	ringbufDropReadTap uint64

	// fanotifySession holds the active fanotify integrity-gate
	// handler when CILOCK_FANOTIFY enables it. nil on the BPF-only
	// path. Started before c.Start(); stopped + merged at trace end.
	fanotifySession *fanotifySession
	// fanotifyDigestsMerged is the count of OpenedFiles entries
	// updated with fanotify-sourced digests. Surfaced in Diagnostics
	// so verifiers know how much of the attestation is
	// kernel-synchronous vs path-hash-based.
	fanotifyDigestsMerged uint64
	// fanotifyEventsHashed / fanotifyTimeouts / fanotifyQueueOverflows
	// / fanotifyDigestsCapHit surface per-trace fanotify operational
	// stats.
	fanotifyEventsHashed   uint64
	fanotifyTimeouts       uint64
	fanotifyQueueOverflows uint64
	fanotifyDigestsCapHit  uint64
	// fanotifyCacheSkips stashes the count of opens the fanotify gate
	// released without hashing because the path classified as cache/temp.
	fanotifyCacheSkips uint64
	// fanotifyIgnoreMarksAdded / fanotifyIgnoreMarkErrors stash the
	// "hash once" experiment's inode-ignore-mark counters.
	fanotifyIgnoreMarksAdded uint64
	fanotifyIgnoreMarkErrors uint64
	// fanotifyOnlyDigests holds paths fanotify hashed that no
	// process recorded an open for. Surfaced at end-of-trace to
	// Summary.FanotifyOnlyDigests so no kernel-observed open is lost.
	fanotifyOnlyDigests map[string]string
	// fanotifyWriteOpenClaimed holds paths whose OpenedFiles entry was a
	// WRITE-open (nil-digest) that fanotify upgraded with an open-time
	// hash. That hash is NOT read-evidence, so TraceOutputs excludes
	// these from readPaths — otherwise a written product fanotify hashed
	// gets demoted to an "intermediate" and dropped from the product tree.
	fanotifyWriteOpenClaimed map[string]bool
	// fanotifyProductDigests holds path → SHA-256 of FINAL written content
	// captured at FAN_CLOSE_WRITE — authoritative product content the kernel
	// hashed at close, independent of the lossy eBPF write-tap. TraceOutputs
	// emits these as products with zero-drop content.
	fanotifyProductDigests map[string][32]byte
	// fsVerityState holds opportunistic fs-verity sealing state.
	// Probed at trace start; per-product seal calls during finalize
	// consult Available to skip the ioctl on unsupported FS.
	fsVerityState *fsVerityState

	// partialReadFallbacks / fallbackHashFailures stash the dispatcher's
	// per-trace counters: how many openat events fell back to path-hash
	// because read-tap saw only a prefix, and how many of those
	// path-hashes themselves errored. Surface into Summary.Diagnostics
	// so an attestation alone tells you whether read-tap was effective.
	partialReadFallbacks uint64
	fallbackHashFailures uint64
	// hashSilentByDigest / hashSilentByDedup decompose fallbackHashFailures
	// into "we already had a clean digest for this path" vs "we already
	// recorded this gap." Together they tell verifiers whether the
	// failure count masks real holes or harmless retries.
	hashSilentByDigest uint64
	hashSilentByDedup  uint64
	// cacheReadsSkipped stashes the eBPF hasher's count of read opens
	// released without hashing because the path classified as
	// build-internal cache/temp (cacheMatcher). Surfaced into
	// Summary.Diagnostics so the skip is transparent.
	cacheReadsSkipped uint64

	// resolvedCaptureMode records which capture-mode the framework
	// selected for this run ("trace", "walk", "ima"). Populated by
	// the framework at Attest time so buildTraceSummary can surface
	// it; otherwise blank.
	resolvedCaptureMode string

	// resolvedTraceBackend records the concrete tracing backend that
	// actually ran ("ebpf", "ptrace+seccomp"), captured at dispatch in
	// trace(). It is the HONEST source for Summary.TraceModeDetail — the
	// env var CILOCK_TRACE_MODE only reflects a user *request*, which is
	// empty in the common auto-select case, leaving a traced attestation
	// unable to say which backend produced it. Downstream hermeticity
	// derivation needs to know the backend (and that a trace actually ran),
	// so this is set from the resolved mode, not the request.
	resolvedTraceBackend string

	// ebpfConsumer holds an open eBPF consumer when the eBPF tracing
	// path is active. Opened BEFORE the child process starts so
	// kprobes are attached when the child fires its first openat.
	// The trace path picks it up and closes it on completion.
	//
	// Typed as interface{} here to avoid pulling the ebpf submodule
	// into the public type surface; the linux build tags use the
	// real *ebpf.Consumer.
	ebpfConsumer ebpfConsumerIface
}

// ebpfConsumerIface is the subset of *ebpf.Consumer that CommandRun
// needs to hold a reference to. Defined here so the windows/macOS
// builds don't have to import the ebpf submodule.
type ebpfConsumerIface interface {
	Close() error
	// RootGlobalTgid returns cilock's kernel-global tgid as recorded by the
	// BPF sentinel, for seeding the userspace watched-set's rootParent so
	// the trace is namespace-correct. 0 when unset (host-namespace path).
	RootGlobalTgid() uint32
}

func (a *CommandRun) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

func (rc *CommandRun) Attest(ctx *attestation.AttestationContext) error {
	// Snapshot the AttestationContext's workdir before any early
	// return so that downstream consumers (TraceOutputs's relative-
	// path resolution, the stat-fallback's pre-existence checks) have
	// a usable base path even when runCmd doesn't execute — e.g.
	// tests that synthesize a CommandRun with pre-populated Processes
	// and no Cmd, or callers that want to introspect a partial state.
	if rc.traceeWorkdir == "" {
		rc.traceeWorkdir = ctx.WorkingDir()
	}

	if len(rc.Cmd) == 0 {
		return attestation.ErrAttestor{
			Name:    rc.Name(),
			RunType: rc.RunType(),
			Reason:  "CommandRun attestation requires a command to run",
		}
	}

	if err := rc.runCmd(ctx); err != nil {
		return err
	}

	// Record the signer's anti-tamper state (read back from the kernel, never
	// asserted) so the non-forgeability evidence travels inside the signed
	// v0.2 predicate's _meta.keyGuard.
	rc.keyGuard = readHardening()

	return nil
}

func (rc *CommandRun) Data() *CommandRun {
	return rc
}

func (rc *CommandRun) Name() string {
	return Name
}

func (rc *CommandRun) Type() string {
	return Type
}

func (rc *CommandRun) RunType() attestation.RunType {
	return RunType
}

// commandRunWire is a method-less view of CommandRun used to (de)serialize the
// historical v0.1 wire shape via struct tags. Casting to it strips
// CommandRun's custom v0.2 MarshalJSON/UnmarshalJSON, so the legacy decoder and
// the v0.1-baseline tests can still round-trip the original inline format.
type commandRunWire CommandRun

// MarshalJSON emits the v0.2 predicate body: the interned, _meta-first wire
// shape (see v2_marshal.go), with the signer's anti-tamper state in
// _meta.keyGuard. This is what the producer publishes under command-run/v0.2.
func (rc *CommandRun) MarshalJSON() ([]byte, error) {
	out, _, err := MarshalV02WithSections(rc.ToV02())
	if err != nil {
		return nil, fmt.Errorf("command-run v0.2 marshal: %w", err)
	}
	return out, nil
}

// UnmarshalJSON decodes a v0.2 predicate body and de-interns it back into this
// CommandRun, so verify-time consumers reading Data() (link, slsa, rego) see
// the same trace the producer recorded.
func (rc *CommandRun) UnmarshalJSON(data []byte) error {
	var p V02Predicate
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("command-run v0.2 unmarshal: %w", err)
	}
	decoded := FromV02(&p)
	if decoded == nil {
		return fmt.Errorf("command-run v0.2 unmarshal: nil predicate")
	}
	rc.Cmd = decoded.Cmd
	rc.ExitCode = decoded.ExitCode
	rc.Stdout = decoded.Stdout
	rc.Stderr = decoded.Stderr
	rc.Summary = decoded.Summary
	rc.Processes = decoded.Processes
	rc.keyGuard = decoded.keyGuard
	return nil
}

// CanProvide implements attestation.CaptureProbe. Returns true when
// the command-run attestor INTENDS to provide trace data — tracing
// is enabled in the config. The actual data may not be available
// yet (this method is called by material attestor BEFORE the trace
// runs), but the intent is enough for capture-mode resolution.
//
// At call time TraceInputs/TraceOutputs returns whatever's actually
// captured — empty if the tracee crashed before producing records,
// or if this is called before command-run's Attest finishes. Material
// attestor accepts this contract: it short-circuits its walk and
// trusts the trace to populate later. If the trace fails entirely
// the materials map is empty by design (the "fail loudly" contract).
//
// IMA support arrives in a follow-up; for now CaptureIMA always
// returns false here even when an IMA log is available, until the
// IMA reader plugin is wired through this same probe interface.
func (rc *CommandRun) CanProvide(mode attestation.CaptureMode) bool {
	if mode != attestation.CaptureTrace {
		return false
	}
	if rc == nil {
		return false
	}
	return rc.enableTracing
}

// TraceInputs implements attestation.CaptureProbe. Returns one entry
// per unique file path the tracee opened with read intent, keyed by
// absolute path. The digest comes from the read-tap streaming hash
// (or the path-hash fallback when the tracee did a partial read).
// Entries with nil digests are omitted — caller already knows the
// path was touched via the process records; materials should only
// list files the framework can attest with a content hash.
//
// When the same path is opened by N processes, the last non-nil
// digest wins. They should all match for stable files; verifiers
// who care about per-process granularity walk Processes[].OpenedFiles
// directly.
func (rc *CommandRun) TraceInputs() map[string]attestation.CaptureEntry {
	if rc == nil {
		return nil
	}
	out := make(map[string]attestation.CaptureEntry, 1024)
	for i := range rc.Processes {
		for path, ds := range rc.Processes[i].OpenedFiles {
			if ds == nil {
				// Skip nil-digest entries — the path was opened but
				// the trace didn't capture content (write-only,
				// O_PATH, etc.). Material attestor needs digests.
				continue
			}
			digest, err := ds.ToNameMap()
			if err != nil {
				continue
			}
			out[path] = attestation.CaptureEntry{
				Digest: digest,
				Source: "trace-readtap",
			}
		}
	}
	return out
}

// SetCacheMatcher installs a compiled cache classifier on the
// command-run attestor. Called by the product attestor (via
// ConfigureFromCtx) before invoking TraceOutputs / TraceCacheArtifacts
// so the classifier reflects the context's CachePatternOptions.
func (rc *CommandRun) SetCacheMatcher(m *attestation.CachePathMatcher) {
	if rc != nil {
		rc.cacheMatcher = m
	}
}

// Finalize implements attestation.Finalizer. Runs after every other
// attestor has completed — at that point the product attestor has
// installed the cache matcher on this CommandRun and the trace's
// per-process data is stable. We populate the Summary's classification
// counters (materials / intermediates / products / cacheArtifacts)
// so AI agents reading the summary block see the breakdown without
// loading per-attestation merkle trees.
//
// Tiny cost: O(N) over the captured paths once, where N is the total
// unique paths (a few × 10K on a Go build). Sub-millisecond.
func (rc *CommandRun) Finalize(ctx *attestation.AttestationContext) error {
	if rc == nil || rc.Summary == nil {
		return nil
	}
	// Materials = unique paths from reads (deduped across processes).
	mats := rc.TraceInputs()
	inters := rc.TraceIntermediates()
	prods := rc.TraceOutputs()
	cache := rc.TraceCacheArtifacts()
	rc.Summary.Totals.Materials = len(mats)
	rc.Summary.Totals.Intermediates = len(inters)
	rc.Summary.Totals.Products = len(prods)
	rc.Summary.Totals.CacheArtifacts = len(cache)
	return nil
}

// TraceOutputs implements attestation.CaptureProbe. Returns ONE entry
// per file path the tracee wrote and then NEVER read back. The map is
// the unfiltered write set — cache/temp classification is the
// product attestor's job (and lives in product.Attest's precedence
// table). Returning everything here lets the operator's
// --attestor-product-include-glob rescue paths a default cache pattern
// would otherwise drop.
//
// Files the tracee wrote AND later read are intermediates (e.g.,
// Go's _pkg_.a build cache entries that compile workers produce and
// the linker consumes); those flow into TraceInputs() instead, since
// semantically they're inputs the linker stage consumed.
//
// Callers that want the cache-only bucket (for inventory) use
// TraceCacheArtifacts(); both methods now see the same superset of
// writes, and downstream classification picks the bucket per the
// product-attestor precedence rules.
//
// Path-hashing happens here lazily: outputs aren't streamed during the
// trace (the tracee owns those bytes and writes them; the read-tap
// only sees content for files the tracee READ). At this point the
// tracee has exited, files are stable on disk, and a path-hash is
// race-free.
func (rc *CommandRun) TraceOutputs() map[string]attestation.CaptureEntry {
	if rc == nil {
		return nil
	}
	// Collect every path the tracee actually CONSUMED content from.
	// OpenedFiles is a superset — it includes O_WRONLY/O_CREAT opens
	// recorded with nil digests for inventory purposes. Those aren't
	// "reads" semantically; the tracee opened them to write. Filter
	// to entries that have a real digest, which proves content was
	// read (or path-hashed) for this path.
	readPaths := make(map[string]bool, 4096)
	for i := range rc.Processes {
		for path, ds := range rc.Processes[i].OpenedFiles {
			if path == "" || ds == nil {
				continue
			}
			// A digest that came from fanotify upgrading a WRITE-open is
			// NOT read-evidence (fanotify hashes every open, including the
			// build's output files; for an O_CREAT output it's the empty
			// pre-write content). Counting it as a read would demote the
			// written product to an "intermediate" and drop it from the
			// product tree — the empty-product-tree failure on GitHub's
			// Azure runner when fanotify is on and the eBPF write-tap
			// fails. Genuine reads still appear via their BPF read-tap
			// digest (not in fanotifyWriteOpenClaimed).
			if rc.fanotifyWriteOpenClaimed[path] {
				continue
			}
			readPaths[path] = true
		}
	}

	// Atomic-rename builds (Go, Cargo, GCC -o) write to an absolute
	// temp path then RENAME(2) to a relative target (e.g. "bin/gh"
	// when the tracee's cwd is the workspace). The kernel records
	// the rename target as-given — relative. Resolve against the
	// tracee's working dir (snapshotted in runCmd) so verifier-side
	// paths are absolute. Falls back to current cilock cwd if the
	// tracee was created outside runCmd (unit tests, library use).
	base := rc.traceeWorkdir
	if base == "" {
		if cwd, err := os.Getwd(); err == nil {
			base = cwd
		}
	}
	resolvePath := func(p string) string {
		if p == "" || filepath.IsAbs(p) || base == "" {
			return p
		}
		return filepath.Join(base, p)
	}

	// Build a global "path → bytes-as-written digest" map from every
	// process's WrittenDigests. The kernel write-tap streams the SHA
	// over each write at the moment bytes leave the tracee, so this
	// digest is race-free against post-build deletes, renames, and
	// cwd changes — UNLIKE post-hoc os.Stat + pathHashIfExists.
	writtenDigests := make(map[string]cryptoutil.DigestSet, 256)
	writePaths := make(map[string]bool, 256)
	for i := range rc.Processes {
		for path, ds := range rc.Processes[i].WrittenDigests {
			if path == "" {
				continue
			}
			p := resolvePath(path)
			writtenDigests[p] = ds
			writePaths[p] = true
		}
		fo := rc.Processes[i].FileOps
		if fo == nil {
			continue
		}
		for _, w := range fo.Writes {
			if w.Path != "" {
				writePaths[resolvePath(w.Path)] = true
			}
		}
		// Renames: the new path's content IS the old path's last-write
		// digest (rename moves bytes unchanged). Carry the in-kernel
		// digest across the rename so atomic-rename builds (Go, Cargo,
		// GCC -o) get a real digest on the final product path instead
		// of a witness-only entry.
		for _, r := range fo.Renames {
			if r.NewPath == "" {
				continue
			}
			newP := resolvePath(r.NewPath)
			writePaths[newP] = true
			if r.OldPath != "" {
				oldP := resolvePath(r.OldPath)
				if ds, ok := writtenDigests[oldP]; ok {
					writtenDigests[newP] = ds
				}
			}
		}
	}

	out := make(map[string]attestation.CaptureEntry, len(writePaths))
	for p := range writePaths {
		if readPaths[p] {
			continue // intermediate — belongs to materials, not products
		}
		// Cache classification deliberately does NOT happen here.
		// Returning the unfiltered write set lets the product attestor
		// apply user-facing precedence (--attestor-product-include-glob
		// can rescue a path the cache pattern would otherwise drop).
		// commandrun.TraceCacheArtifacts() applies the cache matcher
		// for callers that specifically want the cache-only bucket.
		// (Fixes blind Linux UX test Bug 1: silent empty product set
		// when build output lands under /tmp/**.)

		// Primary path: in-kernel write-tap digest. Race-free.
		if ds, ok := writtenDigests[p]; ok {
			if dm, err := ds.ToNameMap(); err == nil && dm != nil {
				out[p] = attestation.CaptureEntry{
					Digest: dm,
					Source: "trace-write-tap",
				}
				continue
			}
		}

		// Fallback: the trace observed a write but no write-tap digest
		// (kernel buffer overflow, syscall pattern we don't tap like
		// mmap+msync, or the write-tap simply didn't run). Stat +
		// pathhash for forensic completeness; produces witness-only
		// entries when the file is gone.
		info, statErr := os.Stat(p)
		if statErr != nil {
			out[p] = attestation.CaptureEntry{
				Digest: nil,
				Source: "trace-write-only",
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		// Pre-existence + overwrite detection. Without this, a file
		// that was already on disk before the trace started and was
		// never touched would silently get hashed and emitted as a
		// product — wrong. mtime is the cheapest reliable signal:
		// every write path (sys_write, mmap+msync, writev,
		// copy_file_range, rename) updates mtime. Compare against
		// the snapshot captured in runCmd just before exec.
		if !rc.traceStartTime.IsZero() && info.ModTime().Before(rc.traceStartTime) {
			// Pre-existing AND untouched during the trace. Skip:
			// it's not a product, regardless of what the trace
			// thought it saw. Don't emit a witness-only entry —
			// that would still surface this file in the attestation.
			continue
		}
		digest := pathHashIfExists(p, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
		if digest == nil {
			out[p] = attestation.CaptureEntry{
				Digest: nil,
				Source: "trace-write-only",
			}
			continue
		}
		// Source tag: distinguish overwrite of pre-existing content
		// from clean creation. Verifiers can use this to spot
		// supply-chain swaps (attacker pre-stages a file, build
		// overwrites it but the trace can't tell what was there
		// before). For overwrites we only know the POST-write
		// digest; pre-content is lost unless the verifier has it
		// from a prior attestation.
		source := "trace-pathhash"
		if _, preExisted := rc.prePaths[p]; preExisted {
			source = "trace-pathhash-overwrite"
		}
		out[p] = attestation.CaptureEntry{
			Digest: digest,
			Source: source,
		}
	}

	// Authoritative product signal: exists-at-exit + modified-in-window.
	// Any regular file under the tracee's workspace whose mtime is at/after
	// the command-start instant and that survives at exit is a product the
	// command produced — even when the (lossy) eBPF write-tap captured NO
	// write event for it (GitHub's Azure 6.17 kernel dropped entire write
	// events, e.g. syft's SBOM output) and even when the file was also read
	// in this step (a one-step build+scan legitimately yields multiple
	// products — the binary AND its SBOM). This anchors products on
	// filesystem reality rather than on lossy syscall events. Pure inputs
	// are excluded for free: a read does not update mtime, so only
	// written/created files match. Cache classification still runs in the
	// product attestor (classifyTracePath), so workspace files under cache
	// patterns are filtered there. Digest comes from the write-tap when we
	// captured it; otherwise nil and the product attestor hashes the
	// surviving file at attest time.
	// CILOCK_DEV_DISABLE_SURVIVOR_WALK is an ablation knob (dev/experiments
	// only) to isolate the survivor-walk's contribution vs the write-tap /
	// FAN_CLOSE_WRITE paths. Unset in normal operation.
	if base != "" && !rc.traceStartTime.IsZero() && os.Getenv("CILOCK_DEV_DISABLE_SURVIVOR_WALK") == "" {
		_ = filepath.Walk(base, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil //nolint:nilerr // best-effort; a stat error on one entry must not abort product capture
			}
			if info.IsDir() {
				// Never descend into VCS metadata — it's never a product
				// and is expensive to walk.
				if info.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if _, seen := out[path]; seen {
				return nil
			}
			if info.ModTime().Before(rc.traceStartTime) {
				return nil
			}
			var dm map[string]string
			if ds, ok := writtenDigests[path]; ok {
				if m, e := ds.ToNameMap(); e == nil {
					dm = m
				}
			}
			out[path] = attestation.CaptureEntry{Digest: dm, Source: "trace-mtime-survivor"}
			return nil
		})
	}

	// FAN_CLOSE_WRITE products: the kernel hashed each written file's FINAL
	// content at close. This is authoritative, zero-drop product content
	// (modulo fanotify queue overflow, which is counted) captured WITHOUT
	// the lossy eBPF write-tap — so it overrides any prior entry (write-tap
	// digest, witness-only nil, or survivor-walk placeholder) for the path.
	for path, raw := range rc.fanotifyProductDigests {
		out[path] = attestation.CaptureEntry{
			Digest: map[string]string{"sha256": fmt.Sprintf("%x", raw[:])},
			Source: "fanotify-close-write",
		}
	}

	return out
}

// TraceCacheArtifacts returns the files the tracee wrote into
// well-known cache or temp paths (matched by the installed
// CachePathMatcher). Semantically these are build-internal storage,
// not user-facing products. Surfaced separately so downstream
// auditors can inventory them without conflating them with products.
//
// Same filtering as TraceOutputs: excludes intermediates (write+read)
// so each path lands in at most ONE bucket:
//   - read-only path     → material
//   - written+read path  → intermediate (within materials)
//   - written + matches  → cache artifact (this method)
//   - written, not read,
//     no cache match     → product (TraceOutputs)
func (rc *CommandRun) TraceCacheArtifacts() map[string]attestation.CaptureEntry {
	if rc == nil || rc.cacheMatcher == nil {
		return nil
	}
	readPaths := make(map[string]bool, 4096)
	for i := range rc.Processes {
		for path, ds := range rc.Processes[i].OpenedFiles {
			if path == "" || ds == nil {
				continue
			}
			// A digest that came from fanotify upgrading a WRITE-open is
			// NOT read-evidence (fanotify hashes every open, including the
			// build's output files; for an O_CREAT output it's the empty
			// pre-write content). Counting it as a read would demote the
			// written product to an "intermediate" and drop it from the
			// product tree — the empty-product-tree failure on GitHub's
			// Azure runner when fanotify is on and the eBPF write-tap
			// fails. Genuine reads still appear via their BPF read-tap
			// digest (not in fanotifyWriteOpenClaimed).
			if rc.fanotifyWriteOpenClaimed[path] {
				continue
			}
			readPaths[path] = true
		}
	}
	out := make(map[string]attestation.CaptureEntry, 256)
	add := func(path string) {
		if path == "" || readPaths[path] {
			return
		}
		if !rc.cacheMatcher.Matches(path) {
			return
		}
		if _, dup := out[path]; dup {
			return
		}
		digest := pathHashIfExists(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
		out[path] = attestation.CaptureEntry{
			Digest: digest,
			Source: "trace-pathhash",
		}
	}
	for i := range rc.Processes {
		fo := rc.Processes[i].FileOps
		if fo == nil {
			continue
		}
		for _, w := range fo.Writes {
			add(w.Path)
		}
		for _, r := range fo.Renames {
			add(r.NewPath)
		}
	}
	return out
}

// TraceIntermediates returns the files the tracee wrote AND read —
// build-cache entries, compile worker outputs the linker consumes,
// generated source code that gets compiled in the same run, etc.
// Semantically these are *intermediate materials*: produced and
// consumed within the same build. They're already covered by
// TraceInputs (as reads); this method exists so callers can
// explicitly surface the "produced-then-consumed" subset for
// auditing or for a separate intermediate/v0.1 attestation type.
func (rc *CommandRun) TraceIntermediates() map[string]attestation.CaptureEntry {
	if rc == nil {
		return nil
	}
	readPaths := make(map[string]bool, 4096)
	for i := range rc.Processes {
		for path, ds := range rc.Processes[i].OpenedFiles {
			if path == "" || ds == nil {
				continue
			}
			// A digest that came from fanotify upgrading a WRITE-open is
			// NOT read-evidence (fanotify hashes every open, including the
			// build's output files; for an O_CREAT output it's the empty
			// pre-write content). Counting it as a read would demote the
			// written product to an "intermediate" and drop it from the
			// product tree — the empty-product-tree failure on GitHub's
			// Azure runner when fanotify is on and the eBPF write-tap
			// fails. Genuine reads still appear via their BPF read-tap
			// digest (not in fanotifyWriteOpenClaimed).
			if rc.fanotifyWriteOpenClaimed[path] {
				continue
			}
			readPaths[path] = true
		}
	}

	out := make(map[string]attestation.CaptureEntry, 256)
	for i := range rc.Processes {
		fo := rc.Processes[i].FileOps
		if fo == nil {
			continue
		}
		add := func(path string) {
			if path == "" || !readPaths[path] {
				return
			}
			if _, dup := out[path]; dup {
				return
			}
			// Prefer the read-tap digest already in OpenedFiles —
			// it's what the linker actually consumed. Fall back to
			// path-hash if read-tap captured nil (partial read).
			for j := range rc.Processes {
				if ds, ok := rc.Processes[j].OpenedFiles[path]; ok && ds != nil {
					if nm, err := ds.ToNameMap(); err == nil {
						out[path] = attestation.CaptureEntry{
							Digest: nm,
							Source: "trace-readtap",
						}
						return
					}
				}
			}
			digest := pathHashIfExists(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
			out[path] = attestation.CaptureEntry{
				Digest: digest,
				Source: "trace-pathhash",
			}
		}
		for _, w := range fo.Writes {
			add(w.Path)
		}
		for _, r := range fo.Renames {
			add(r.NewPath)
		}
	}
	return out
}

// annotateDigestSources walks all SyscallEvents in the trace's
// processes and tags each one's DigestSource based on what's known
// about how its Path's digest was captured. Runs ONCE post-trace
// so the per-event source is correct without per-event bookkeeping
// during the hot path.
//
// fanotifyOnlyDigests is the set of paths fanotify hashed but no
// process opened — used to disambiguate the "fanotify-on-time"
// label from the openat-time path-hash case.
func annotateDigestSources(processes []ProcessInfo, fanotifyAvailable bool, fanotifyOnly map[string]string) {
	if !fanotifyAvailable && len(fanotifyOnly) == 0 {
		// No fanotify ran; every digest is BPF-sourced.
		for i := range processes {
			for j := range processes[i].SyscallEvents {
				ev := &processes[i].SyscallEvents[j]
				if ev.Path == "" {
					continue
				}
				if _, has := processes[i].OpenedFiles[ev.Path]; has {
					ev.DigestSource = "openat-path-hash"
				}
			}
		}
		return
	}
	for i := range processes {
		for j := range processes[i].SyscallEvents {
			ev := &processes[i].SyscallEvents[j]
			if ev.Path == "" {
				continue
			}
			_, hasOpened := processes[i].OpenedFiles[ev.Path]
			_, hasFanOnly := fanotifyOnly[ev.Path]
			switch {
			case hasOpened && fanotifyAvailable:
				// Fanotify was active; mergeFanotifyDigests overwrote
				// OpenedFiles[Path] with the kernel-synchronous hash.
				ev.DigestSource = "fanotify-open-time"
			case hasOpened:
				// BPF-only path captured this.
				ev.DigestSource = "openat-path-hash"
			case hasFanOnly:
				// Fanotify caught it but BPF didn't — verifier should
				// look in Summary.FanotifyOnlyDigests.
				ev.DigestSource = "fanotify-only"
			default:
				// No digest available. Common for mmap-read where the
				// tracee opened a file that fanotify wasn't watching
				// (off-mount), or zero-copy syscalls.
				ev.DigestSource = ""
			}
		}
	}
}

// buildTraceSummary produces the AI-agent / operator scannable view
// of a finished trace. Computed in a single pass over Processes.
// Cost is O(N) over the captured opens + file-ops, which is tiny
// compared to the trace itself.
func buildTraceSummary(processes []ProcessInfo, duration time.Duration) *TraceSummary {
	s := &TraceSummary{
		DurationNs: duration.Nanoseconds(),
	}

	pathOpens := make(map[string]int, 4096)
	uniquePaths := make(map[string]bool, 4096)
	interesting := make(map[string]bool, 16)

	for i := range processes {
		p := &processes[i]
		s.Totals.Processes++

		for path := range p.OpenedFiles {
			if path == "" {
				continue // defensive: shouldn't happen, but skip if it does
			}
			uniquePaths[path] = true
			pathOpens[path]++
			s.Totals.Reads++
			if isInterestingPath(path) {
				interesting[path] = true
			}
		}

		if p.FileOps != nil {
			s.Totals.Writes += len(p.FileOps.Writes)
			s.Totals.Renames += len(p.FileOps.Renames)
			s.Totals.Deletes += len(p.FileOps.Deletes)
		}

		if p.Program != "" {
			s.Totals.Execs++
		}
		if p.Network != nil {
			s.Totals.NetEvents++
		}

		for _, ev := range p.SyscallEvents {
			if !isSecuritySensitiveSyscall(ev.Syscall) {
				continue // TOCTOU markers etc. aren't security signals
			}
			if s.Outliers.SuspiciousOps == nil {
				s.Outliers.SuspiciousOps = make(map[string]int, 8)
			}
			s.Outliers.SuspiciousOps[ev.Syscall]++
		}
	}
	s.Totals.UniquePaths = len(uniquePaths)

	// Most-opened path: pick the highest count.
	var mostPath string
	var mostCount int
	for path, count := range pathOpens {
		if count > mostCount {
			mostCount = count
			mostPath = path
		}
	}
	if mostCount > 1 {
		s.Outliers.MostOpened = &TraceFileRef{Path: mostPath, Count: mostCount}
	}

	// InterestingPaths: sort + cap at 32 entries so an agent can
	// scan them quickly.
	if len(interesting) > 0 {
		paths := make([]string, 0, len(interesting))
		for p := range interesting {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		if len(paths) > 32 {
			paths = paths[:32]
		}
		s.InterestingPaths = paths
	}

	return s
}

// isSecuritySensitiveSyscall identifies syscalls that, on their own,
// warrant an agent's attention regardless of count. Excludes
// high-frequency normal ops (dup2 fires constantly during shell
// pipelines and isn't itself a red flag) and operational markers
// the trace records into SyscallEvents (TOCTOU-suspect openats are
// data-quality signals, not security ones).
func isSecuritySensitiveSyscall(name string) bool {
	switch name {
	case "ptrace", "mount", "memfd_create", "prctl",
		"setsid", "setns", "init_module", "finit_module",
		"clone", "clone3", "mprotect", "kexec_load":
		return true
	}
	return false
}

// isInterestingPath returns true for paths an AI agent or operator
// auditor should look at first — anything outside the normal build
// + system path tree. Conservative: errs on the side of inclusion.
func isInterestingPath(p string) bool {
	// Paths that commonly carry secrets or environment state.
	suspect := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/ssh/",
		"/etc/kubernetes/",
		"/.ssh/",
		"/.aws/",
		"/.docker/",
		"/.kube/",
		"/.gnupg/",
		"/proc/self/environ",
		"/proc/self/maps",
		"/proc/self/mem",
		"/proc/1/",
		"/dev/kvm",
		"/dev/mem",
		"/dev/kmsg",
		"/sys/kernel/security/",
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/secrets/",
	}
	for _, s := range suspect {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

// snapshotPrePaths walks root and returns the set of absolute file
// paths that exist on disk RIGHT NOW. Called by runCmd immediately
// before c.Start() so the stat-fallback in TraceOutputs can later
// distinguish overwrites (path was in prePaths) from clean creations
// (path was NOT in prePaths). Skips:
//   - non-regular files (devices, sockets, pipes — not products)
//   - directories the user can't read (best-effort, log + continue)
//   - well-known build-cache trees that produce useless noise
//     (.git/, node_modules/, vendor/) since the verifier already
//     classifies these via CachePathMatcher.
//
// Bounded by maxPrePathEntries to prevent OOM on monster workdirs;
// when the limit is hit, we return what we have and the overwrite
// tag will be missing for any paths beyond it (degraded honesty,
// not silent corruption).
// DefaultPrewalkSkipDirs lists the built-in directory basenames the
// pre-trace walk skips by default. Operators extend or override
// this set via --prewalk-skip-dir and --prewalk-include-dir.
//
// Exported so the override-audit regression test can find a
// matching CLI flag by string-grep without false negatives.
var DefaultPrewalkSkipDirs = []string{".git", "node_modules", "vendor", ".cache"}

func snapshotPrePaths(root string, extraSkip, includeOverride []string) map[string]struct{} {
	if root == "" {
		return nil
	}
	const maxPrePathEntries = 1_000_000
	out := make(map[string]struct{}, 4096)
	skipDirs := make(map[string]struct{}, len(DefaultPrewalkSkipDirs)+len(extraSkip))
	for _, n := range DefaultPrewalkSkipDirs {
		skipDirs[n] = struct{}{}
	}
	for _, n := range extraSkip {
		if n == "" {
			continue
		}
		skipDirs[n] = struct{}{}
	}
	// Most-specific wins: includes override both defaults and user skips.
	for _, n := range includeOverride {
		delete(skipDirs, n)
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort; skip unreadable subtrees
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(out) >= maxPrePathEntries {
			return filepath.SkipAll
		}
		out[path] = struct{}{}
		return nil
	})
	return out
}

// pathHashIfExists returns a name-map digest for the file at path, or
// nil if the file doesn't exist / can't be read. Errors are swallowed
// here because outputs may legitimately disappear (the tracee writes
// then deletes a temp file). The caller decides whether nil should
// land in the attestation.
func pathHashIfExists(path string, hashes []cryptoutil.DigestValue) map[string]string {
	ds, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	if err != nil {
		return nil
	}
	nameMap, err := ds.ToNameMap()
	if err != nil {
		return nil
	}
	return nameMap
}

func (rc *CommandRun) TracingEnabled() bool {
	return rc.enableTracing
}

// StartedAt returns the wall-clock instant captured immediately before the
// command's exec.Start, on every run (traced or not). The product attestor's
// walk path uses it to decide whether a same-digest file was rewritten during
// the command window (mtime >= StartedAt → product). Zero if the command never
// started.
func (rc *CommandRun) StartedAt() time.Time {
	return rc.traceStartTime
}

func (r *CommandRun) runCmd(ctx *attestation.AttestationContext) error {
	// CommandContext (not Command) so configureProcessReaping can wire a
	// non-nil c.Cancel — os/exec REQUIRES the command be created with a
	// context before Cancel may be set, else Start() fails. ctx.Context()
	// defaults to context.Background() (never nil), so when no cancellable
	// context is plumbed the command simply never cancels and Cancel never
	// fires; WaitDelay remains the sole anti-hang guarantee on that path.
	c := exec.CommandContext(ctx.Context(), r.Cmd[0], r.Cmd[1:]...) //nolint:gosec // G204: command is user-specified by design
	c.Dir = ctx.WorkingDir()
	// Snapshot the dir the tracee will actually run in, before any
	// post-exec cwd changes happen on the parent. Used by TraceOutputs
	// to resolve relative paths in fileOps.Writes / Renames.
	if c.Dir != "" {
		r.traceeWorkdir = c.Dir
	} else if cwd, cwdErr := os.Getwd(); cwdErr == nil {
		// exec.Command inherits parent cwd when Dir is empty.
		r.traceeWorkdir = cwd
	}
	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	stdoutWriters := []io.Writer{&stdoutBuffer}
	stderrWriters := []io.Writer{&stderrBuffer}
	if ctx.OutputWriters() != nil {
		stdoutWriters = append(stdoutWriters, ctx.OutputWriters()...)
		stderrWriters = append(stderrWriters, ctx.OutputWriters()...)
	}

	if !r.silent {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}

	stdoutWriter := io.MultiWriter(stdoutWriters...)
	stderrWriter := io.MultiWriter(stderrWriters...)
	c.Stdout = stdoutWriter
	c.Stderr = stderrWriter

	// Anti-hang guarantee. Because c.Stdout/c.Stderr are io.Writers
	// (not *os.File), os/exec wires the child's stdout/stderr through
	// INTERNAL os.Pipes and spawns copy goroutines; c.Wait() blocks
	// until those pipes hit EOF — which requires EVERY descendant that
	// inherited the write end to close it (i.e. exit). A wrapped build
	// that backgrounds a child outliving the main process (or a traced
	// grandchild stranded by ptrace/eBPF under concurrent cold builds)
	// keeps the write end open, so c.Wait() hangs FOREVER and the CI
	// step never returns. WaitDelay bounds the wait that happens AFTER
	// the wrapped process itself exits: its timer starts only on
	// process exit and force-closes the pipes (Wait returns
	// exec.ErrWaitDelay) if the I/O goroutines haven't finished by then.
	//
	// For a normal fast command no descendant holds the write end, the
	// goroutines hit EOF in microseconds, and WaitDelay never fires —
	// zero truncation of legitimate output. It fires ONLY in the
	// pathological lingering-descendant case, where the alternative is
	// hanging forever and capturing nothing. The window is generous so
	// a legitimately slow final flush from the real command is never
	// clipped. configureProcessReaping additionally puts the child in
	// its own process group and wires c.Cancel so the descendant GROUP
	// is killed, letting the pipes reach EOF naturally in the common
	// slow case and reserving the force-close strictly for truly stuck
	// descendants.
	c.WaitDelay = commandWaitDelay
	configureProcessReaping(c)

	if r.enableTracing {
		enableTracing(c)
		// For the eBPF mode we MUST attach kprobes before the child
		// runs, otherwise we race the child's first openat. This
		// helper opens the consumer (attaching kprobes) when eBPF
		// mode is selected, or returns the trace-mode error with
		// remediation instructions when eBPF was requested but
		// unavailable. ptrace mode is a no-op.
		if err := r.preStartTracingSetup(); err != nil {
			return err
		}
		// Build the cache classifier up front so the trace can consult
		// it DURING capture (the product attestor's SetCacheMatcher runs
		// later, after the trace). Same patterns the product attestor
		// uses, so capture-time skips and product-time classification
		// agree. fanotify + the eBPF hasher skip these paths to avoid
		// hashing build-internal cache (Go module cache, GOCACHE, /tmp)
		// — the dominant open volume on cold builds and the main drop /
		// overhead source.
		if r.cacheMatcher == nil {
			if m, _ := attestation.NewCachePathMatcher(attestation.ResolveCachePatterns(ctx.CachePatterns())); m != nil {
				r.cacheMatcher = m
			}
		}
		var cacheSkip func(string) bool
		if r.cacheMatcher != nil {
			cacheSkip = r.cacheMatcher.Matches
		}
		// Optional fanotify integrity gate. When enabled, EVERY
		// open() of a file under the workspace mount is synchronously
		// hashed by the kernel-blocking fanotify handler — zero drops
		// by construction. Falls back to BPF-only if the env var
		// requests auto-mode and fanotify is unavailable.
		fanSession, err := maybeStartFanotify(c.Dir, cacheSkip)
		if err != nil {
			return err
		}
		r.fanotifySession = fanSession
		// Optional fs-verity sealing of products. When the FS
		// supports it, every write-only file gets Merkle-rooted at
		// close time and the kernel refuses to read corrupted blocks
		// downstream. Auto mode silently skips on unsupported FS.
		fsvState, err := probeFsVerity(c.Dir)
		if err != nil {
			return err
		}
		r.fsVerityState = fsvState
	}
	// Downgrade the tracee's uid/gid back to the invoker when cilock
	// is running under sudo (for BPF / fanotify caps). Otherwise the
	// build inherits root + caps and can escalate trivially. No-op
	// when not running as root or SUDO_UID isn't set.
	applyTraceePrivilegeDrop(c)

	// Snapshot the workspace pre-state so TraceOutputs can later
	// distinguish (a) pre-existing files we never touched (skip),
	// (b) overwrites of pre-existing files (tag), and (c) clean
	// creations. Done immediately before c.Start() so the time
	// boundary is tight. snapshotPrePaths is best-effort: walk
	// errors are logged but don't abort the trace.
	r.traceStartTime = time.Now()
	r.prePaths = snapshotPrePaths(r.traceeWorkdir, r.prewalkSkipDirs, r.prewalkIncludeDirs)

	if err := c.Start(); err != nil {
		// If eBPF was pre-opened but Start failed, release the consumer.
		if r.ebpfConsumer != nil {
			_ = r.ebpfConsumer.Close()
			r.ebpfConsumer = nil
		}
		if r.fanotifySession != nil {
			_, _, _ = r.fanotifySession.stop()
			r.fanotifySession = nil
		}
		return err
	}

	// Scope the fanotify hash to the build's own process group now that the
	// child exists. configureProcessReaping set Setpgid, so the child is a
	// group leader whose pgid == its pid and its descendants inherit it. After
	// this, the handler releases every FOREIGN opener (the CI runner that
	// launched cilock, sibling build containers, host daemons) immediately
	// instead of blocking it on a hash — a foreign stall can make the runner
	// miss this step shell's exit and hang the job to its timeout. Nil-safe;
	// a no-op on non-Linux.
	if r.fanotifySession != nil && c.Process != nil {
		r.fanotifySession.setBuildPgid(c.Process.Pid)
	}

	var err error
	if r.enableTracing { //nolint:nestif // sequential exit-handling: trace vs Wait, ExitError type assert, ignore-exit-code branch — each shallow check, refactor would obscure ordering
		traceStart := time.Now()
		r.Processes, err = r.trace(c, ctx)
		traceDuration := time.Since(traceStart)
		// Wait for I/O copying goroutines to complete before reading buffers.
		// trace() uses ptrace to detect process exit, but exec's I/O goroutines
		// may still be flushing pipe data into stdoutBuffer/stderrBuffer.
		// c.WaitDelay (set in runCmd before Start) bounds this so a lingering
		// grandchild holding the pipe write-end can never hang us forever; on
		// expiry Wait returns exec.ErrWaitDelay, which we ignore here because
		// the trace already captured the authoritative exit status.
		_ = c.Wait() // exit status already captured by trace

		// Drain + merge fanotify digests (if enabled). Done BEFORE
		// summary build so Diagnostics see the merged count.
		if r.fanotifySession != nil {
			fanDigests, fanCloseWrite, fanStats := r.fanotifySession.stop()
			r.fanotifySession = nil
			merged, only, writeOpenClaimed := mergeFanotifyDigests(r.Processes, fanDigests)
			r.fanotifyDigestsMerged = uint64(merged)
			r.fanotifyOnlyDigests = only
			r.fanotifyWriteOpenClaimed = writeOpenClaimed
			// FAN_CLOSE_WRITE digests are the kernel-hashed FINAL content of
			// files the tracee wrote+closed — authoritative product content,
			// captured without the lossy eBPF write-tap. TraceOutputs emits
			// these as products.
			r.fanotifyProductDigests = fanCloseWrite
			r.fanotifyEventsHashed = fanStats.EventsHashed
			r.fanotifyTimeouts = fanStats.HandlerTimeouts
			r.fanotifyQueueOverflows = fanStats.QueueOverflows
			r.fanotifyDigestsCapHit = fanStats.DigestsCapHit
			r.fanotifyCacheSkips = fanStats.CacheSkips
			r.fanotifyIgnoreMarksAdded = fanStats.IgnoreMarksAdded
			r.fanotifyIgnoreMarkErrors = fanStats.IgnoreMarkErrors
		}

		// Build the AI-agent-friendly summary from the captured
		// Processes data. Runs once, after the trace completes.
		// Tiny CPU cost (one pass over the slice) for a big UX win
		// — readers can triage the build in <5 KB instead of 20 MB.
		r.Summary = buildTraceSummary(r.Processes, traceDuration)
		// V2 Phase 5: surface the diagnostics that were stashed
		// during the trace into the Summary so they survive in the
		// signed attestation. Without this, operators can only see
		// ringbuf drops in the log output at trace time — they're
		// invisible to anyone verifying the stored attestation later.
		if r.Summary != nil {
			r.Summary.Diagnostics.RingbufOpenatDrops = r.ringbufDropOpenat
			r.Summary.Diagnostics.RingbufReadTapDrops = r.ringbufDropReadTap
			r.Summary.Diagnostics.PartialReadFallbacks = r.partialReadFallbacks
			r.Summary.Diagnostics.FallbackHashFailures = r.fallbackHashFailures
			// Walk processes to count UnhashedOpens entries — explicit
			// per-process gaps with reasons, visible to verifiers.
			// HashFailureSilentDrops counts at the dispatch source:
			// the failure was dropped because the same path was
			// already cleanly hashed in the same process. Sum of
			// (silentByDigest + silentByDedup) is the residual after
			// counting newly-added UnhashedOpens entries.
			var unhashedTotal uint64
			for i := range r.Processes {
				unhashedTotal += uint64(len(r.Processes[i].UnhashedOpens))
			}
			r.Summary.Diagnostics.UnhashedOpensTotal = unhashedTotal
			r.Summary.Diagnostics.HashFailureSilentDrops = r.hashSilentByDigest + r.hashSilentByDedup
			r.Summary.Diagnostics.CacheReadsSkipped = r.cacheReadsSkipped
			// Fanotify integrity-gate stats. FanotifyAvailable is
			// true iff any events were hashed (the handler was active);
			// merged-count tells verifiers how many BPF digests got
			// upgraded to kernel-synchronous fanotify digests.
			if r.fanotifyEventsHashed > 0 || r.fanotifyDigestsMerged > 0 {
				r.Summary.Diagnostics.FanotifyAvailable = true
				r.Summary.Diagnostics.FanotifyEventsHashed = r.fanotifyEventsHashed
				r.Summary.Diagnostics.FanotifyDigestsMerged = r.fanotifyDigestsMerged
				r.Summary.Diagnostics.FanotifyTimeouts = r.fanotifyTimeouts
				r.Summary.Diagnostics.FanotifyQueueOverflows = r.fanotifyQueueOverflows
				r.Summary.Diagnostics.FanotifyDigestsCapHit = r.fanotifyDigestsCapHit
				r.Summary.Diagnostics.FanotifyCacheSkips = r.fanotifyCacheSkips
				r.Summary.Diagnostics.FanotifyIgnoreMarksAdded = r.fanotifyIgnoreMarksAdded
				r.Summary.Diagnostics.FanotifyIgnoreMarkErrors = r.fanotifyIgnoreMarkErrors
			}
			if len(r.fanotifyOnlyDigests) > 0 {
				r.Summary.FanotifyOnlyDigests = r.fanotifyOnlyDigests
			}
			// Annotate mmap / zero-copy syscall events with their
			// digest source so verifiers can trust-tier per event.
			// fanotify-on-time digest is strongest (kernel-synchronous);
			// openat-path-hash is weaker (race window between openat
			// and our hash). Empty source means no digest captured
			// (e.g., mmap without prior fanotify, or zero-copy syscall).
			annotateDigestSources(r.Processes, r.Summary.Diagnostics.FanotifyAvailable, r.fanotifyOnlyDigests)
			// fs-verity sealing stats. Surfaced even when count is 0
			// so the JSON can convey "this trace had fs-verity active
			// but no products were sealed" (e.g. read-only workload).
			if r.fsVerityState != nil {
				r.Summary.Diagnostics.FsVerityAvailable = r.fsVerityState.Available
				r.Summary.Diagnostics.FsVerityFilesSealed = r.fsVerityState.Sealed.Load()
				r.Summary.Diagnostics.FsVeritySealFailures = r.fsVerityState.SealFailures.Load()
			}
			if r.resolvedCaptureMode != "" {
				r.Summary.CaptureMode = r.resolvedCaptureMode
				// TraceModeDetail differentiates the backend within
				// a mode — "ebpf" vs "ptrace" for trace, "fs-verity"
				// vs "streaming-hash" for walk, etc. For now we map
				// trace → backend; future phases (IMA, fentry) will
				// expand this.
				switch r.resolvedCaptureMode {
				case "trace":
					// Prefer the concrete backend resolved at dispatch ("ebpf" /
					// "ptrace+seccomp") so auto-select runs name their backend;
					// fall back to the env *request* only when no backend was
					// recorded (e.g. a non-Linux build that never dispatched a trace).
					if r.resolvedTraceBackend != "" {
						r.Summary.TraceModeDetail = r.resolvedTraceBackend
					} else if traceMode := os.Getenv(EnvVarTraceMode); traceMode != "" {
						r.Summary.TraceModeDetail = traceMode
					}
				}
			}
		}
		// Fail-closed gate. If the operator requested strict
		// attestation honesty, reject the attestation when any
		// drop / loss / timeout occurred. Surfaces a verifier-
		// actionable error rather than a silently-incomplete record.
		if r.requireZeroDrops {
			if gateErr := r.zeroDropsGate(); gateErr != nil {
				return gateErr
			}
		}
	} else {
		err = c.Wait()
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
			if r.ignoreExitCode {
				// Record the exit code in the predicate but don't propagate
				// the error. This lets postproduct attestors (sarif/sbom/vex/
				// etc.) still fire for tools that exit non-zero on findings.
				err = nil
			}
		} else if errors.Is(err, exec.ErrWaitDelay) {
			// The wrapped command itself exited cleanly; WaitDelay only fired
			// because a lingering descendant kept the inherited stdout/stderr
			// pipe write-end open past process exit. We force-closed the pipes
			// and captured the output we had — far better than hanging the CI
			// step forever. Don't propagate this as a command failure.
			err = nil
		}
	}

	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()
	return err
}
