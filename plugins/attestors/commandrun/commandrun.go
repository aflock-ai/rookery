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

type CommandRun struct {
	Cmd       []string      `json:"cmd"`
	Stdout    string        `json:"stdout,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	ExitCode  int           `json:"exitcode"`
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
		r.Processes, err = r.trace(c, ctx)
		// Wait for I/O copying goroutines to complete before reading buffers.
		// trace() uses ptrace to detect process exit, but exec's I/O goroutines
		// may still be flushing pipe data into stdoutBuffer/stderrBuffer.
		_ = c.Wait() //nolint:errcheck // exit status already captured by trace
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
