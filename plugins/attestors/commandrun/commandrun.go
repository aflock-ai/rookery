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
	"encoding/json"
	"io"
	"os"
	"os/exec"
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
//
// Timestamp is held as a time.Time so the hot path (event capture) avoids
// the ~500ns/~42-byte allocation of formatting a string. The wire format
// is preserved by a custom MarshalJSON below that emits RFC3339Nano (or
// omits the field entirely when zero).
type NetworkConnection struct {
	Syscall   string    `json:"syscall"`             // "connect" or "bind"
	Family    string    `json:"family"`              // AF_INET, AF_INET6, AF_UNIX
	Address   string    `json:"address"`             // IP address or Unix socket path
	Port      int       `json:"port,omitempty"`      // TCP/UDP port (0 for AF_UNIX)
	FD        int       `json:"fd"`                  // socket file descriptor
	Timestamp time.Time `json:"timestamp,omitempty"` // when the syscall was observed
	Hostname  string    `json:"hostname,omitempty"`  // TLS SNI hostname (extracted from ClientHello)
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
	Path      string    `json:"path"`
	Bytes     int       `json:"bytes"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// FileRename records a rename/move operation.
type FileRename struct {
	OldPath   string    `json:"oldPath"`
	NewPath   string    `json:"newPath"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// FileDelete records an unlink operation.
type FileDelete struct {
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// FilePermChange records a chmod operation.
type FilePermChange struct {
	Path      string    `json:"path"`
	Mode      uint32    `json:"mode"`    // new permission bits
	SetExec   bool      `json:"setExec"` // true if executable bit was set
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// SyscallEvent records a notable syscall that doesn't fit other categories.
type SyscallEvent struct {
	Syscall   string    `json:"syscall"`          // "memfd_create", "ptrace", "mount", "clone"
	Detail    string    `json:"detail,omitempty"` // human-readable detail
	Args      []int     `json:"args,omitempty"`   // raw syscall arguments
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// FileLink records a hardlink or symlink creation. A build that swaps a
// file via link() never calls write() — so without capturing link ops,
// content substitution is invisible to the attestor.
type FileLink struct {
	SourcePath string    `json:"sourcePath"`
	LinkPath   string    `json:"linkPath"`
	IsSymlink  bool      `json:"isSymlink"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
}

// FileTruncate records a truncate/ftruncate operation. Truncate can clear
// a file's contents without ever calling write — same invisibility risk
// as link().
type FileTruncate struct {
	Path      string    `json:"path"`
	NewSize   int64     `json:"newSize"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// DirOp records a directory creation or removal.
type DirOp struct {
	Path      string    `json:"path"`
	Op        string    `json:"op"` // "mkdir" or "rmdir"
	Mode      uint32    `json:"mode,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// --- JSON wire-format preservation --------------------------------------
//
// Default time.Time MarshalJSON emits RFC3339Nano — which matches the prior
// string-based wire format exactly. The reason these per-struct MarshalJSON
// methods exist is omitempty: encoding/json's omitempty does NOT consider
// time.Time{} (the zero value) empty, so without an override an unset
// Timestamp would serialize as "0001-01-01T00:00:00Z" — breaking the
// existing contract that an unset timestamp is dropped from the JSON.
//
// We use shadow types (separate struct definitions to avoid recursing into
// MarshalJSON) so the custom marshalers only intercept the omit-on-zero
// behavior; field order, names, and value formatting are otherwise the
// default encoding/json output.

type fileWriteJSON struct {
	Path      string     `json:"path"`
	Bytes     int        `json:"bytes"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func (f FileWrite) MarshalJSON() ([]byte, error) {
	out := fileWriteJSON{Path: f.Path, Bytes: f.Bytes}
	if !f.Timestamp.IsZero() {
		out.Timestamp = &f.Timestamp
	}
	return json.Marshal(out)
}

type fileRenameJSON struct {
	OldPath   string     `json:"oldPath"`
	NewPath   string     `json:"newPath"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func (f FileRename) MarshalJSON() ([]byte, error) {
	out := fileRenameJSON{OldPath: f.OldPath, NewPath: f.NewPath}
	if !f.Timestamp.IsZero() {
		out.Timestamp = &f.Timestamp
	}
	return json.Marshal(out)
}

type fileDeleteJSON struct {
	Path      string     `json:"path"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func (f FileDelete) MarshalJSON() ([]byte, error) {
	out := fileDeleteJSON{Path: f.Path}
	if !f.Timestamp.IsZero() {
		out.Timestamp = &f.Timestamp
	}
	return json.Marshal(out)
}

type filePermChangeJSON struct {
	Path      string     `json:"path"`
	Mode      uint32     `json:"mode"`
	SetExec   bool       `json:"setExec"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func (f FilePermChange) MarshalJSON() ([]byte, error) {
	out := filePermChangeJSON{Path: f.Path, Mode: f.Mode, SetExec: f.SetExec}
	if !f.Timestamp.IsZero() {
		out.Timestamp = &f.Timestamp
	}
	return json.Marshal(out)
}

type syscallEventJSON struct {
	Syscall   string     `json:"syscall"`
	Detail    string     `json:"detail,omitempty"`
	Args      []int      `json:"args,omitempty"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func (s SyscallEvent) MarshalJSON() ([]byte, error) {
	out := syscallEventJSON{Syscall: s.Syscall, Detail: s.Detail, Args: s.Args}
	if !s.Timestamp.IsZero() {
		out.Timestamp = &s.Timestamp
	}
	return json.Marshal(out)
}

type fileLinkJSON struct {
	SourcePath string     `json:"sourcePath"`
	LinkPath   string     `json:"linkPath"`
	IsSymlink  bool       `json:"isSymlink"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

func (f FileLink) MarshalJSON() ([]byte, error) {
	out := fileLinkJSON{SourcePath: f.SourcePath, LinkPath: f.LinkPath, IsSymlink: f.IsSymlink}
	if !f.Timestamp.IsZero() {
		out.Timestamp = &f.Timestamp
	}
	return json.Marshal(out)
}

type fileTruncateJSON struct {
	Path      string     `json:"path"`
	NewSize   int64      `json:"newSize"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func (f FileTruncate) MarshalJSON() ([]byte, error) {
	out := fileTruncateJSON{Path: f.Path, NewSize: f.NewSize}
	if !f.Timestamp.IsZero() {
		out.Timestamp = &f.Timestamp
	}
	return json.Marshal(out)
}

type dirOpJSON struct {
	Path      string     `json:"path"`
	Op        string     `json:"op"`
	Mode      uint32     `json:"mode,omitempty"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func (d DirOp) MarshalJSON() ([]byte, error) {
	out := dirOpJSON{Path: d.Path, Op: d.Op, Mode: d.Mode}
	if !d.Timestamp.IsZero() {
		out.Timestamp = &d.Timestamp
	}
	return json.Marshal(out)
}

type networkConnectionJSON struct {
	Syscall   string     `json:"syscall"`
	Family    string     `json:"family"`
	Address   string     `json:"address"`
	Port      int        `json:"port,omitempty"`
	FD        int        `json:"fd"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
}

func (n NetworkConnection) MarshalJSON() ([]byte, error) {
	out := networkConnectionJSON{
		Syscall:  n.Syscall,
		Family:   n.Family,
		Address:  n.Address,
		Port:     n.Port,
		FD:       n.FD,
		Hostname: n.Hostname,
	}
	if !n.Timestamp.IsZero() {
		out.Timestamp = &n.Timestamp
	}
	return json.Marshal(out)
}

// FileActivity aggregates all file mutation operations for a process.
type FileActivity struct {
	Writes      []FileWrite      `json:"writes,omitempty"`
	Renames     []FileRename     `json:"renames,omitempty"`
	Deletes     []FileDelete     `json:"deletes,omitempty"`
	PermChanges []FilePermChange `json:"permChanges,omitempty"`
	Links       []FileLink       `json:"links,omitempty"`
	Truncates   []FileTruncate   `json:"truncates,omitempty"`
	DirOps      []DirOp          `json:"dirOps,omitempty"`
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
	}

	if err := c.Start(); err != nil {
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
