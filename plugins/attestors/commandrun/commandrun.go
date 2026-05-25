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
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "command-run"
	Type    = "https://aflock.ai/attestations/command-run/v0.1"
	RunType = attestation.ExecuteRunType
)

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
}

// FileActivity aggregates all file mutation operations for a process.
type FileActivity struct {
	Writes      []FileWrite      `json:"writes,omitempty"`
	Renames     []FileRename     `json:"renames,omitempty"`
	Deletes     []FileDelete     `json:"deletes,omitempty"`
	PermChanges []FilePermChange `json:"permChanges,omitempty"`
}

type ProcessInfo struct {
	Program          string                          `json:"program,omitempty"`
	ProcessID        int                             `json:"processid"`
	ParentPID        int                             `json:"parentpid"`
	ProgramDigest    cryptoutil.DigestSet            `json:"programdigest,omitempty"`
	Comm             string                          `json:"comm,omitempty"`
	Cmdline          string                          `json:"cmdline,omitempty"`
	ExeDigest        cryptoutil.DigestSet            `json:"exedigest,omitempty"`
	OpenedFiles      map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`
	// WrittenDigests carries content digests for files the tracee
	// WROTE during the trace, captured via the BPF write-tap (kretprobe
	// on sys_write / pwrite64 returns the bytes the kernel actually
	// transferred). Keyed by absolute path, value is a digest of the
	// bytes the tracee emitted — independent of any other writer or
	// post-close mutation. Distinct from OpenedFiles (which tracks
	// READ digests). A path may appear in both if the tracee wrote
	// AND read it; classification rules use this split to put outputs
	// in products and inputs in materials without conflation.
	WrittenDigests   map[string]cryptoutil.DigestSet `json:"writtenDigests,omitempty"`
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
	UnhashedOpens    []UnhashedOpen                  `json:"unhashedOpens,omitempty"`
	Environ          string                          `json:"environ,omitempty"`
	SpecBypassIsVuln bool                            `json:"specbypassisvuln,omitempty"`
	Network          *NetworkActivity                `json:"network,omitempty"`
	FileOps          *FileActivity                   `json:"fileOps,omitempty"`
	SyscallEvents    []SyscallEvent                  `json:"syscallEvents,omitempty"`

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

	// InterestingPaths is a short list of paths an agent should
	// look at first — anything outside the "normal" build paths
	// (/etc/passwd, /proc/self/environ, etc.) or anything in the
	// security-events list. Capped to ~32 entries.
	InterestingPaths []string `json:"interestingPaths,omitempty"`
}

// TraceTotals is the scalar count summary.
type TraceTotals struct {
	Processes        int `json:"processes,omitempty"`
	UniquePaths      int `json:"uniquePaths,omitempty"`
	Reads            int `json:"reads,omitempty"`
	Writes           int `json:"writes,omitempty"`
	Renames          int `json:"renames,omitempty"`
	Deletes          int `json:"deletes,omitempty"`
	Execs            int `json:"execs,omitempty"`
	NetEvents        int `json:"netEvents,omitempty"`
	// Classification breakdown — populated when CaptureProbe path
	// runs (capture-mode=trace). Lets the AI agent see at-a-glance
	// what kind of files the tracee touched without loading the
	// per-process arrays.
	Materials      int `json:"materials,omitempty"`     // distinct files read
	Intermediates  int `json:"intermediates,omitempty"` // files both written + read
	Products       int `json:"products,omitempty"`      // user-facing outputs
	CacheArtifacts int `json:"cacheArtifacts,omitempty"`// written into cache/temp
}

// TraceOutliers flags noteworthy artifacts. Most are file-event
// outliers; SuspiciousOps is a tally of security-sensitive syscalls
// (ptrace, mount, etc.) that any reader should examine.
type TraceOutliers struct {
	LargestRead   *TraceFileRef     `json:"largestRead,omitempty"`
	MostOpened    *TraceFileRef     `json:"mostOpened,omitempty"`
	SuspiciousOps map[string]int    `json:"suspiciousOps,omitempty"`
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

	silent         bool
	materials      map[string]cryptoutil.DigestSet
	enableTracing  bool
	ignoreExitCode bool

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


	// resolvedCaptureMode records which capture-mode the framework
	// selected for this run ("trace", "walk", "ima"). Populated by
	// the framework at Attest time so buildTraceSummary can surface
	// it; otherwise blank.
	resolvedCaptureMode string

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
}

func (a *CommandRun) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

func (rc *CommandRun) Attest(ctx *attestation.AttestationContext) error {
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
// per file path the tracee wrote and then NEVER read back, EXCLUDING
// build-internal storage (caches, temp dirs). These are the true
// user-facing "products" of the build — the final compiled binary,
// generated source files in the working directory, etc.
//
// Files the tracee wrote AND later read are intermediates (e.g.,
// Go's _pkg_.a build cache entries that compile workers produce and
// the linker consumes); those flow into TraceInputs() instead, since
// semantically they're inputs the linker stage consumed.
//
// Files written to /tmp, ~/.cache, /var/tmp etc. are cache/temp
// artifacts — surfaced via TraceCacheArtifacts() for inventory but
// not counted as products.
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
			readPaths[path] = true
		}
	}

	writePaths := make(map[string]bool, 256)
	for i := range rc.Processes {
		fo := rc.Processes[i].FileOps
		if fo == nil {
			continue
		}
		for _, w := range fo.Writes {
			if w.Path != "" {
				writePaths[w.Path] = true
			}
		}
		for _, r := range fo.Renames {
			if r.NewPath != "" {
				writePaths[r.NewPath] = true
			}
		}
	}

	out := make(map[string]attestation.CaptureEntry, len(writePaths))
	for p := range writePaths {
		if readPaths[p] {
			continue // intermediate — belongs to materials, not products
		}
		if rc.cacheMatcher != nil && rc.cacheMatcher.Matches(p) {
			continue // cache/temp — surfaced via TraceCacheArtifacts
		}
		info, statErr := os.Stat(p)
		switch {
		case statErr != nil:
			// File is gone (unlinked between trace and attest) or
			// path is relative-to-a-different-cwd. We KNOW the trace
			// observed a write to this path — emit a witness entry
			// without a digest. Downstream consumers (policies,
			// inclusion-proof) skip entries lacking a digest, but
			// the path survives in the products list for inventory.
			// Without this, V2 phase 2's atomic-rename + fast-exit
			// pattern produces silent product drops (issue #152).
			out[p] = attestation.CaptureEntry{
				Digest: nil,
				Source: "trace-write-only",
			}
			continue
		case !info.Mode().IsRegular():
			// Directories, sockets, pipes — can't be path-hashed,
			// not products. Drop silently.
			continue
		}
		digest := pathHashIfExists(p, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
		if digest == nil {
			// File existed at stat time but disappeared (or was
			// unreadable) at hash time. Same handling as missing.
			out[p] = attestation.CaptureEntry{
				Digest: nil,
				Source: "trace-write-only",
			}
			continue
		}
		out[p] = attestation.CaptureEntry{
			Digest: digest,
			Source: "trace-pathhash",
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

func (r *CommandRun) runCmd(ctx *attestation.AttestationContext) error {
	c := exec.Command(r.Cmd[0], r.Cmd[1:]...) //nolint:gosec // G204: command is user-specified by design
	c.Dir = ctx.WorkingDir()
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
	}
	// Downgrade the tracee's uid/gid back to the invoker when cilock
	// is running under sudo (for BPF / fanotify caps). Otherwise the
	// build inherits root + caps and can escalate trivially. No-op
	// when not running as root or SUDO_UID isn't set.
	applyTraceePrivilegeDrop(c)

	if err := c.Start(); err != nil {
		// If eBPF was pre-opened but Start failed, release the consumer.
		if r.ebpfConsumer != nil {
			_ = r.ebpfConsumer.Close()
			r.ebpfConsumer = nil
		}
		return err
	}

	var err error
	if r.enableTracing { //nolint:nestif // sequential exit-handling: trace vs Wait, ExitError type assert, ignore-exit-code branch — each shallow check, refactor would obscure ordering
		traceStart := time.Now()
		r.Processes, err = r.trace(c, ctx)
		traceDuration := time.Since(traceStart)
		// Wait for I/O copying goroutines to complete before reading buffers.
		// trace() uses ptrace to detect process exit, but exec's I/O goroutines
		// may still be flushing pipe data into stdoutBuffer/stderrBuffer.
		_ = c.Wait() //nolint:errcheck // exit status already captured by trace

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
			if r.resolvedCaptureMode != "" {
				r.Summary.CaptureMode = r.resolvedCaptureMode
				// TraceModeDetail differentiates the backend within
				// a mode — "ebpf" vs "ptrace" for trace, "fs-verity"
				// vs "streaming-hash" for walk, etc. For now we map
				// trace → backend; future phases (IMA, fentry) will
				// expand this.
				switch r.resolvedCaptureMode {
				case "trace":
					if traceMode := os.Getenv(EnvVarTraceMode); traceMode != "" {
						r.Summary.TraceModeDetail = traceMode
					}
				}
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
		}
	}

	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()
	return err
}
