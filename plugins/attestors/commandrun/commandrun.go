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
	Processes   int `json:"processes,omitempty"`
	UniquePaths int `json:"uniquePaths,omitempty"`
	Reads       int `json:"reads,omitempty"`
	Writes      int `json:"writes,omitempty"`
	Renames     int `json:"renames,omitempty"`
	Deletes     int `json:"deletes,omitempty"`
	Execs       int `json:"execs,omitempty"`
	NetEvents   int `json:"netEvents,omitempty"`
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

	// FallbackHashFailures is the count of partial-read fallbacks
	// where the path-hash itself couldn't read the file (e.g.,
	// file was deleted before fallback ran). Non-zero means some
	// paths in the attestation have nil digests by design.
	FallbackHashFailures uint64 `json:"fallbackHashFailures,omitempty"`
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

// CanProvide implements attestation.CaptureProbe. The command-run
// attestor can supply trace-derived materials + products whenever
// tracing was enabled AND it actually captured process data. When
// the tracee crashed before producing any process records, callers
// should NOT use trace data — fall back to walk for correctness.
//
// IMA support arrives in a follow-up; for now CaptureIMA always
// returns false here even when an IMA log is available, until the
// IMA reader plugin is wired through this same probe interface.
func (rc *CommandRun) CanProvide(mode attestation.CaptureMode) bool {
	if mode != attestation.CaptureTrace {
		return false
	}
	if rc == nil || !rc.enableTracing {
		return false
	}
	return len(rc.Processes) > 0
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

// TraceOutputs implements attestation.CaptureProbe. Returns one entry
// per unique file path the tracee WROTE during execution — the union
// of FileOps.Writes paths and FileOps.Renames new-paths across all
// captured processes.
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
	paths := make(map[string]bool, 256)
	for i := range rc.Processes {
		fo := rc.Processes[i].FileOps
		if fo == nil {
			continue
		}
		for _, w := range fo.Writes {
			if w.Path != "" {
				paths[w.Path] = true
			}
		}
		for _, r := range fo.Renames {
			if r.NewPath != "" {
				paths[r.NewPath] = true
			}
		}
	}
	out := make(map[string]attestation.CaptureEntry, len(paths))
	for p := range paths {
		// Hashing outputs synchronously here is fine — the tracee has
		// exited, files are stable, and there are typically far fewer
		// outputs than inputs on a build. For a Go build of cilock
		// this is the final binary + a handful of intermediates.
		digest := pathHashIfExists(p, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
		out[p] = attestation.CaptureEntry{
			Digest: digest,
			Source: "trace-pathhash",
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
