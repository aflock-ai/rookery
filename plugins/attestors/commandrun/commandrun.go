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
	"maps"
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

// WithScriptCapture selects how much of an executed script or makefile is
// recorded. Defaults to ScriptCaptureIdentity (path + digest, no bytes).
//
// ScriptCaptureContent embeds the script body and is opt-in per step: scripts
// routinely inline credentials, and an attestation is signed, immutable and
// broadly readable.
func WithScriptCapture(mode ScriptCaptureMode) Option {
	return func(cr *CommandRun) {
		cr.scriptCapture = mode
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

// The socket-family vocabulary carried in SocketInfo.Family and
// NetworkConnection.Family. These names are part of the WIRE CONTRACT — they
// travel inside the signed predicate and a verifier reads them — so the whole
// vocabulary lives here beside the structs that carry it rather than inside one
// backend.
const (
	// FamilyIPv4 and FamilyIPv6 are IP sockets whose version the observer read
	// from the kernel.
	FamilyIPv4 = "AF_INET"
	FamilyIPv6 = "AF_INET6"

	// FamilyUnix is a local socket named by filesystem path.
	FamilyUnix = "AF_UNIX"

	// FamilyNetlink is a Linux kernel-configuration socket. It reaches the
	// local kernel and cannot name a remote host.
	FamilyNetlink = "AF_NETLINK"

	// FamilyInetUnspecified means "an IP socket, but the observer could not
	// tell IPv4 from IPv6". It is NOT a guess at AF_INET: it classifies as IP
	// networking, so an un-versioned observation still breaks hermeticity.
	FamilyInetUnspecified = "AF_INET_UNSPECIFIED"

	// FamilyUnspecified is a sockaddr the observer READ and whose sa_family
	// was AF_UNSPEC. On connect() that is the DISCONNECT idiom: it dissolves a
	// connected UDP socket's association, and glibc's resolver issues one on
	// every hostname lookup. The operation is fully described and what it
	// describes reaches nothing, so it is non-remote.
	//
	// It carries no claim about operations the observer could NOT describe.
	// That is FamilyNotObservable, which is a different fact with a different
	// class, because "this reached nothing" and "I could not see what this
	// reached" must never collapse into one value.
	FamilyUnspecified = "AF_UNSPEC"

	// FamilyVSock is a VM socket. It is REMOTE-CAPABLE and it is NOT IP: a
	// guest reaches its hypervisor host through one, and the host reaches the
	// guest, so a build can pull an undeclared input over AF_VSOCK exactly as
	// it can over TCP. Naming it here is what stops it arriving at a consumer
	// as the Linux tracer's numeric "AF_40" fallback, which no table
	// classifies and which cilock's egress filter therefore dropped — signing
	// a hermetic claim over a build that talked to its host.
	FamilyVSock = "AF_VSOCK"
)

// Values a tracer records when it observed a network operation but the
// observation channel did not name part of it.
//
// The distinction they preserve is the one this attestor exists to keep: an
// endpoint we could not name is NOT an endpoint that was not there. A backend
// that dropped such a connection would hand cilock an empty egress list, and
// `Hermetic = len(NetworkEgress) == 0` would turn "we did not look" into "there
// was none" — the exact projection of absence as an authoritative value that
// SLSA L3's hermeticity claim must never rest on.
const (
	// HostNotObservable is the Address of an endpoint whose PORT was observed
	// and whose HOST the platform cannot report. The parentheses are the
	// point: they are legal in neither a DNS name nor an IP literal, so this
	// value cannot be misread as a resolved host, cannot parse as a loopback
	// address, and cannot be dialled. An operator reading
	// "(host-not-observable):443" learns both facts at once — something was
	// fetched over 443, and this platform cannot say from where.
	HostNotObservable = "(host-not-observable)"

	// FDNotObservable is the FD of a connection observed through a channel
	// that does not report file descriptors. Zero would be a real fd (stdin),
	// so an out-of-range value is used to mean "unknown" instead.
	FDNotObservable = -1

	// FamilyNotObservable is the Family of an outbound operation the observer
	// SAW and could not describe: the sockaddr could not be read, or the
	// channel reported the syscall without its arguments. It is a synthetic
	// name, not a kernel domain, and it is deliberately distinct from
	// FamilyUnspecified — AF_UNSPEC is a family that WAS read and reaches
	// nothing, this is a family that was never read at all.
	//
	// It classifies as FamilyClassUnobservable, which a consumer counts as
	// egress. That is the conservative reading and the only honest one: a
	// channel nobody could look at cannot be certified as one that reached
	// nothing, and `Hermetic = len(NetworkEgress) == 0` would otherwise turn
	// "we did not look" into "there was none".
	FamilyNotObservable = "AF_UNOBSERVED"
)

// UnobservedConnection describes an outbound operation a backend SAW and could
// not read the arguments of, so the operation lands in the predicate instead of
// vanishing from it.
//
// Dropping such an event is the fail-open this vocabulary exists to prevent:
// the syscall happened, the attestor is the only witness, and an empty
// Connections list is what `Hermetic = len(NetworkEgress) == 0` reads as proof
// that nothing was reached. Recorded through here it reaches a consumer as
// egress that nobody can name, which is a verdict a policy can waive with its
// eyes open.
func UnobservedConnection(syscall string, fd int) NetworkConnection {
	return NetworkConnection{
		Syscall:   syscall,
		Family:    FamilyNotObservable,
		Address:   HostNotObservable,
		FD:        fd,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// SocketFamilyClass is what a Family value denotes to a consumer deciding
// whether a connection is a channel through which a build can pull undeclared
// inputs.
type SocketFamilyClass int

const (
	// FamilyClassUndefined is the class of a Family value this vocabulary does
	// not define: the numeric "AF_<n>" a Linux tracer writes for a domain it
	// has no name for, or an empty string from an observer that recorded no
	// family at all.
	//
	// It means "I do not know what this reaches", and the ONLY safe reading of
	// that is that it MIGHT reach a remote host — so a consumer must count it
	// as egress, never drop it. AF_VSOCK is why: it is remote-capable, and
	// before this vocabulary named it, it arrived here as "AF_40", fell into
	// this class, and cilock's filter dropped it. `Hermetic =
	// len(NetworkEgress) == 0` then signed "reached nothing" over a build that
	// reached its hypervisor host.
	//
	// It is the zero value on purpose: a family the vocabulary has not learned
	// yet lands in the conservative class rather than in a permissive one.
	// TestUnclassifiedRuntimeFamilyBreaksHermeticity in cilock pins the
	// consumer half.
	FamilyClassUndefined SocketFamilyClass = iota

	// FamilyClassIP is IP networking: the family through which a build reaches
	// a remote host, and the class that breaks hermeticity. It includes
	// FamilyInetUnspecified, because an IP socket whose version the observer
	// could not read is an OBSERVATION of IP egress, not the absence of one.
	FamilyClassIP

	// FamilyClassUnix is a local socket named by filesystem path, judged by
	// the path rather than by the family.
	FamilyClassUnix

	// FamilyClassNonRemote is a family in this vocabulary that cannot name a
	// remote host, so it is never egress.
	FamilyClassNonRemote

	// FamilyClassRemoteNonIP is a family that reaches a host OUTSIDE this
	// kernel without being IP — AF_VSOCK's guest<->host channel. It is egress:
	// a build can pull an undeclared input through it. It is a separate class
	// from FamilyClassIP rather than a member of it because the Family names
	// travel in the signed predicate, and calling a VM socket "IP" on the wire
	// would be false.
	FamilyClassRemoteNonIP

	// FamilyClassUnobservable is an outbound operation the observer SAW and
	// could not describe — FamilyNotObservable. A consumer counts it as
	// egress.
	//
	// It is separate from FamilyClassNonRemote because those two answer
	// different questions. Non-remote answers "what does this channel reach?"
	// with "nothing outside this kernel". Unobservable answers it with "I
	// cannot say", and the only safe reading of "I cannot say" is that it
	// might have reached anything. Collapsing the second into the first is how
	// a build that fetched over a channel nobody could see gets signed
	// hermetic.
	//
	// It is also separate from FamilyClassUndefined, which is about the
	// VOCABULARY not defining a string. This one is a defined member of the
	// vocabulary whose meaning IS "unobservable", so a backend has a name to
	// report the fact with instead of a blank field or a silent drop. Both
	// classes count as egress; they differ in what a reader is being told.
	FamilyClassUnobservable
)

// socketFamilyClasses is the ONE place that decides what each family name in
// this vocabulary denotes. Consumers — cilock's hermeticity filter above all —
// ask ClassifySocketFamily rather than comparing Family against a hand-written
// list of strings, so a family added to the vocabulary is classified once here
// instead of once in every reader that happens to get updated. A reader that
// silently fails to recognise an IP family drops that connection from the
// egress list, and `Hermetic = len(NetworkEgress) == 0` then publishes "there
// was no egress" for a build that fetched over the network.
//
// TestEverySocketFamilyConstantIsClassified fails the build when a family
// constant in this package is missing from this table.
var socketFamilyClasses = map[string]SocketFamilyClass{
	FamilyIPv4:            FamilyClassIP,
	FamilyIPv6:            FamilyClassIP,
	FamilyInetUnspecified: FamilyClassIP,
	FamilyUnix:            FamilyClassUnix,
	FamilyNetlink:         FamilyClassNonRemote,
	FamilyUnspecified:     FamilyClassNonRemote,
	FamilyNotObservable:   FamilyClassUnobservable,
	FamilyVSock:           FamilyClassRemoteNonIP,
}

// ClassifySocketFamily reports what a SocketInfo.Family or
// NetworkConnection.Family value denotes.
//
// It is TOTAL over its runtime input, not just over the constants declared
// here: any string a tracer can put in Family — "AF_42", "" — gets a class,
// and a value outside the vocabulary gets FamilyClassUndefined, which a
// consumer must treat as possible egress. That distinction is the whole point.
// A compile-time gate over the declared constants (see
// TestEverySocketFamilyConstantIsClassified) cannot see "AF_42", because no
// constant declares it; only the runtime default can.
func ClassifySocketFamily(family string) SocketFamilyClass {
	return socketFamilyClasses[family]
}

// FamilyIsIP reports whether a Family value denotes IP networking — the single
// question cilock's egress filter asks of a family.
func FamilyIsIP(family string) bool {
	return ClassifySocketFamily(family) == FamilyClassIP
}

// FamilyIsUnix reports whether a Family value denotes a path-named local socket.
func FamilyIsUnix(family string) bool {
	return ClassifySocketFamily(family) == FamilyClassUnix
}

// SocketFamilyClassifications returns a copy of the classification table, so a
// consumer in another module can assert its own filter handles every family
// this attestor can emit rather than the subset its author had in mind.
func SocketFamilyClassifications() map[string]SocketFamilyClass {
	return maps.Clone(socketFamilyClasses)
}

// NetworkConnection records a connect or bind syscall.
//
// Syscall names the operation the observer saw — "connect" (the only value
// cilock counts against hermeticity), "bind", "accept" from the macOS
// sandbox-report backend, "sendto" or "dns_query" from the Linux backends.
// Family/Address/Port are the
// destination as the observer saw it; where an observer could not see part of
// it, the constants above say so explicitly rather than leaving a zero value to
// be read as fact. A report-based observer that is told a port and never a host
// therefore records HostNotObservable with a real port, and a consumer reads
// that as egress it cannot name — never as egress that did not happen.
type NetworkConnection struct {
	Syscall   string `json:"syscall"`             // "connect", "bind", "accept", "sendto", "dns_query"
	Family    string `json:"family"`              // AF_INET, AF_INET6, AF_UNIX, AF_INET_UNSPECIFIED, AF_UNSPEC
	Address   string `json:"address"`             // IP address, Unix socket path, or HostNotObservable
	Port      int    `json:"port,omitempty"`      // TCP/UDP port (0 for AF_UNIX or when unobserved)
	FD        int    `json:"fd"`                  // socket file descriptor; FDNotObservable when unknown
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
	// Outcome says whether the backend OBSERVED THIS SYSCALL SUCCEED, or only
	// observed it being ATTEMPTED. Empty means the backend does not
	// distinguish (the Linux backends observe the call itself, so an event
	// there is an event that happened).
	//
	// It exists because `Syscall: "execve"` and a populated Program read as
	// "this image ran" to every consumer, and on the macOS sandbox-report
	// backend that is a claim the channel cannot support: an ALLOW report
	// proves the sandbox PERMITTED the exec, not that execve then returned.
	// A permitted exec can still fail with ENOENT or ENOEXEC after the report,
	// and the return value is not observable. Saying so only in a free-text
	// limitations note leaves a policy no MACHINE-READABLE way to tell the
	// weaker semantics from the stronger, which is the same failure that left
	// ProgramDigest, ExeDigest and OpenedFiles empty on that backend.
	//
	// The field is additive and omitempty, so an older consumer sees exactly
	// the document it saw before; a consumer that needs "did it run" checks
	// this before treating an execve event as an execution.
	Outcome string `json:"outcome,omitempty"`

	// PathDigestAtCollectorOpen is the bytes found AT THE REPORTED PATH WHEN
	// THE COLLECTOR OPENED IT. It is NOT proof of what executed, and the name
	// says so because a shorter one would not.
	//
	// A field called "Digest" beside an exec event reads as "the bytes that
	// ran" to every consumer — which is precisely why this backend leaves
	// ProgramDigest and ExeDigest EMPTY. The same reasoning applies here, so
	// the claim is narrowed in the NAME rather than in a note a policy author
	// may never read: an image-deny policy matching on this is matching an
	// observation of a path, not of an execution.
	//
	// What defeats it, stated rather than implied: the collector opens the
	// path AFTER report delivery, and it follows symlinks. A tracee can exec
	// image A through a symlink, retarget that symlink to a PRE-EXISTING image
	// B before the open, and B is measured for A's event — B's ctime predates
	// the report, so the replacement check passes, and B is unchanged
	// afterwards, so the end-of-run content check passes too. Binding the
	// vnode the kernel actually loaded needs Endpoint Security, which the
	// install-nothing constraint rules out. DigestSource carries the same
	// statement in machine-readable form ("collector-open-path-hash").
	//
	// It is published at all because the per-process fields cannot carry it:
	// ProgramDigest keeps the first exec and ExeDigest the last, and
	// OpenedFiles is path-keyed, so a path exec'd repeatedly over different
	// bytes retains only its final measurement and every intermediate image
	// (A→B→C hides B) is unmeasured anywhere else. Empty when nothing was
	// captured; DigestSource is then "" as well, so an absent measurement
	// reads as a stated gap rather than a borrowed one.
	PathDigestAtCollectorOpen cryptoutil.DigestSet `json:"pathDigestAtCollectorOpen,omitempty"`
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

	// Darwin carries the macOS sandbox-report backend's data-quality
	// counters. Nil on every other platform (and on darwin runs that were
	// not traced), so it costs a Linux attestation nothing.
	Darwin *DarwinTraceDiagnostics `json:"darwin,omitempty"`
}

// UnprovenExec is one observed exec whose process could not be tied to the
// traced root: see DarwinTraceDiagnostics.UnprovenExecs.
//
// It is a GAP — a pid and a time — and carries NO image identity of any
// kind. The report stream is machine-wide and an unproven pid's owner is
// unknown by construction (unproven means "we could not read whose it is"),
// so publishing the image's path hash or its content digest would disclose
// that another user of this machine ran something. Being able to read a
// world-readable binary is not permission to say who executed it. A policy
// that forbids an image fails closed on a non-empty list instead.
type UnprovenExec struct {
	PID       int    `json:"pid"`
	Timestamp string `json:"timestamp,omitempty"`
}

// DarwinTraceDiagnostics reports what the macOS sandbox-report tracer saw and,
// more importantly, what it could NOT prove. The backend observes a
// machine-wide report stream and admits a process only on kernel-read
// evidence, so a verifier needs the size of the discard pile to judge whether
// a small tree means "little work" or "little attribution".
type DarwinTraceDiagnostics struct {
	// ExecReports / ForkReports are the reports attributed to this build.
	ExecReports uint64 `json:"execReports,omitempty"`
	ForkReports uint64 `json:"forkReports,omitempty"`

	// UnattributedReports counts exec/fork reports DROPPED because this
	// build's ownership of the process could not be proven — most often
	// another sandbox user on the same machine. Dropping is deliberate:
	// counting a stranger's work as this build's is the failure that would
	// let an agent pass a gate by starting a decoy build.
	UnattributedReports uint64 `json:"unattributedReports,omitempty"`

	// UnprovenPIDs counts processes whose kernel facts could not be read
	// before they disappeared. Each one is a process this attestation does
	// NOT describe in the tree; what it was seen to exec is in UnprovenExecs.
	UnprovenPIDs uint64 `json:"unprovenPids,omitempty"`

	// UnprovenExecs lists the exec reports of those unproven pids: the image
	// the kernel says was loaded, the digest pinned at report time when the
	// image could be pinned, and the pid — but NO parent edge, because none
	// was read. This is the third bucket between "this build's" and
	// "dropped". A child that execs and exits inside the report channel's
	// delivery latency loses the kernel-fact poll — measured 2026-08-27 on
	// macOS 15/arm64 under load at 25–38% of the children of a 1,500-way
	// fork storm — and dropping those reports would let exactly such a child
	// make its exec vanish from the evidence. Listing them without
	// attribution states what was observed and what was not: the exec
	// happened under this machine's sandbox report channel, and it MAY be
	// another sandbox user's. A policy that forbids an image anywhere in the
	// tree must fail closed on this list too; a policy that needs a complete
	// tree requires unprovenPids == 0. Capped at maxUnprovenExecs, with the
	// overflow counted in UnprovenExecsOmitted.
	UnprovenExecs []UnprovenExec `json:"unprovenExecs,omitempty"`

	// UnprovenExecsOmitted counts unproven exec reports past the cap, so a
	// bounded list cannot read as a complete one.
	UnprovenExecsOmitted uint64 `json:"unprovenExecsOmitted,omitempty"`

	// ExecDigestBinding states what an exec digest on this backend is bound
	// to: "path-at-collector-open-time" — the bytes at the reported path when the
	// report arrived, verified unchanged at the end of the run — and never
	// the vnode the kernel loaded. A verifier that needs the executed bytes
	// proven must not read programDigest here as that proof.
	ExecDigestBinding string `json:"execDigestBinding,omitempty"`

	// CollectorRecordsUnreadable counts NDJSON records from `log stream` that
	// could not be decoded AT ALL — the line was not valid JSON, so neither
	// its pid nor whether it was even a sandbox report could be read.
	//
	// It is kept separate from UnparsedRecords, which means "unreadable and
	// PROVABLY a stranger's". Ownership here is not proven foreign; it is
	// UNKNOWN, and unknown fails toward ours everywhere else in this backend.
	// A malformed record also usually means the stream was truncated, which
	// is a data-loss event whoever it belonged to. Non-zero refuses the
	// trace: this build's exec or connection may be inside the record nobody
	// could read.
	CollectorRecordsUnreadable uint64 `json:"collectorRecordsUnreadable,omitempty"`

	// UnparseableOwnReports counts kernel sandbox reports the parser could
	// not read whose pid is this build's or undecidable. Non-zero refuses
	// the trace: an exec or a connection may be missing from the evidence.
	// (A stranger's unreadable report is counted in UnparsedRecords.)
	UnparseableOwnReports uint64 `json:"unparseableOwnReports,omitempty"`

	// UnresolvedAncestry counts processes whose own facts were read but
	// whose parent chain runs into a process nothing could be read about —
	// an intermediate that exited before its poll, or an unseen ancestor
	// that appeared after the root started. Readable facts prove one edge,
	// not non-descent, so these are UNPROVEN rather than foreign: network
	// fails toward non-hermetic, execs are listed in unprovenExecs.
	UnresolvedAncestry uint64 `json:"unresolvedAncestry,omitempty"`

	// UnobservedDescendants counts processes the kernel process table showed
	// attached to this build at exit — started after the root, parented by
	// a tree member or in the root's process group — that never produced a
	// report: a forked child that neither exec'd nor touched the network.
	// They are not in the tree (nothing was observed of them) and one still
	// running when the command exits refuses the attestation. A detached
	// child whose parent already exited hangs off launchd and cannot be told
	// from an app launched mid-build; that residual is stated in the note.
	UnobservedDescendants uint64 `json:"unobservedDescendants,omitempty"`

	// ReparentedAfterRoot counts processes that appeared after the root
	// started and hang off launchd: a descendant whose intermediate parent
	// exited before its facts were read (double-fork, setsid), or an app the
	// user launched mid-build. A readable ppid of 1 does not prove
	// non-descent, so these are classified UNPROVEN rather than foreign —
	// their network fails toward non-hermetic and their execs are listed in
	// unprovenExecs — and one still running when the command exits refuses
	// the attestation outright.
	ReparentedAfterRoot uint64 `json:"reparentedAfterRoot,omitempty"`

	// GroupOnlyPIDs counts processes that shared the traced root's process
	// group while their kernel-read parent chain never reached the root, and
	// were therefore EXCLUDED from the tree.
	//
	// Process-group membership is not proof of descent: POSIX setpgid lets any
	// process in the same session join an existing group, so admitting a pid on
	// group equality alone would let a helper an agent controls put its execs
	// and its network connections into a signed tree with one syscall and no
	// parent edge. Excluding them makes the tree smaller than reality in one
	// legitimate case — a process whose parent exited before the poll, leaving
	// it reparented to launchd — so the number is published rather than
	// dropped: it is the size of what this attestation declines to claim.
	GroupOnlyPIDs uint64 `json:"groupOnlyPids,omitempty"`

	// CoalescedDuplicates counts repeats the kernel folded into a single
	// report ("N duplicate reports for ..."). The events happened; only the
	// per-occurrence detail was collapsed by the logging layer.
	CoalescedDuplicates uint64 `json:"coalescedDuplicates,omitempty"`

	// ImagesUnhashed counts exec'd images whose bytes could not be pinned or
	// digested, so their Program/Exe digests are absent rather than guessed.
	ImagesUnhashed uint64 `json:"imagesUnhashed,omitempty"`

	// Argv0Normalized is true when the sandbox wrapper handed the traced
	// command its RESOLVED PATH as argv[0] where the caller had asked for a
	// bare name — the ordinary shape of exec.Command, and not refusable
	// without refusing nearly every invocation, but visible because a
	// program can read argv[0] to choose behaviour or find its resources.
	// An argv[0] naming a different executable, or an empty one, is refused
	// outright rather than recorded here.
	Argv0Normalized bool `json:"argv0Normalized,omitempty"`

	// ObservedChildren counts the distinct non-root pids this build was seen
	// to have: members, pids whose facts could not be read, and the ones the
	// exit sweep found. It is published BESIDE ForkReports, never subtracted
	// from it — a posix_spawn child emits no fork report and would cancel a
	// genuinely missing one, so the difference is not exact. A policy that
	// needs a complete tree compares the two itself: disagreement proves
	// incompleteness, agreement proves nothing.
	ObservedChildren uint64 `json:"observedChildren,omitempty"`

	// AttributedExecsUndigested counts execs INSIDE the tree that carry no
	// image digest: the image was gone before its report arrived, exceeded
	// the pin bound, or was rewritten in place after it ran. Non-zero refuses
	// the attestation — an exec that is signed without a digest is a hole an
	// image-deny policy walks straight through — so a verifier only ever
	// sees zero here; the field documents the rule.
	AttributedExecsUndigested uint64 `json:"attributedExecsUndigested,omitempty"`

	// UnparsedRecords counts log records that did not decode. Non-zero means
	// the report format moved under us and this backend needs revisiting.
	UnparsedRecords uint64 `json:"unparsedRecords,omitempty"`

	// NetworkObserved states that the network report channel was ASKED FOR and
	// PROVEN TO DELIVER, for both operation classes a verdict keys on. cilock
	// refuses to derive hermeticity from a backend that answers false, because
	// an empty egress list from an observer that never watched is not evidence
	// of anything.
	//
	// BOTH HALVES ARE REQUIRED, and each answers a different way of being
	// wrong:
	//
	//  1. The profile THIS RUN applied asked the kernel to narrate network
	//     operations. Computed from the applied profile at run time, never
	//     asserted, so deleting the report rule flips this to false and the
	//     claim is withheld rather than silently inherited.
	//  2. A live probe pair actually got reports back — an ACCEPTED INBOUND
	//     connection from a listener probe and an OUTBOUND connect from a
	//     connector probe, both registered so neither one's traffic is ever
	//     booked as the build's. The profile text proves intent, not delivery:
	//     a backend that accepted the profile and then emitted no network
	//     events would otherwise hand back an empty egress list for a build
	//     that fetched the world.
	//
	// Proving ONE class is not enough and that was a live gap until the pair
	// existed: cilock counts an outbound connect as a fetch AND an accepted
	// inbound connection as an undeclared input channel, so an outbound-only
	// proof let this field be true while inbound reports never arrived at all.
	//
	// Emitted even when false: a missing field must not be readable as "true".
	NetworkObserved bool `json:"networkObserved"`

	// NetworkHostsObservable is FALSE on this backend, always, and says the
	// single most important thing a verifier needs in order to read the
	// endpoint list correctly: IT IS PORT-ONLY BY CONSTRUCTION.
	//
	// The Seatbelt report names the filter that matched, not the destination.
	// Measured on macOS 15.7.7/arm64: a connection to the literal IP
	// 93.184.215.14 with no DNS in the path still reports `remote:*:443`, an
	// IPv6 connection reports the same shape as IPv4, and a loopback
	// connection is indistinguishable from an external one. Every IP endpoint
	// in processes[].network.connections therefore carries the address
	// "(host-not-observable)" with a real port. A verifier must not read that
	// as a resolved name, and must not read a short endpoint list as a
	// narrowly-scoped build. Emitted even when false.
	NetworkHostsObservable bool `json:"networkHostsObservable"`

	// NetworkReports counts network operations attributed to this build.
	NetworkReports uint64 `json:"networkReports,omitempty"`

	// NetworkReportsUnattributed counts network reports DROPPED because the
	// reporting process was PROVEN foreign: its kernel facts were read and
	// its parent chain does not reach this build's root. The stream is
	// machine-wide and every other sandboxed process on the Mac narrates its
	// own traffic, so this pile is normally large and is normally other
	// people's connections — which is exactly why they must not be counted as
	// this build's egress.
	NetworkReportsUnattributed uint64 `json:"networkReportsUnattributed,omitempty"`

	// NetworkReportsUnprovenOwnership counts network reports whose OWNERSHIP
	// COULD NOT BE DECIDED: the reporting pid's kernel facts were gone before
	// the poll (a child that connected and exited inside the delivery
	// window), or the pid was a recycled canary pid. These are the opposite
	// of the pile above and get the opposite treatment: "might be ours" must
	// not become "was not ours", so each OUTBOUND one is also recorded on the
	// root as a FamilyNotObservable connection — egress nobody could describe
	// — which cilock's filter counts against hermeticity. A verifier reading
	// a non-zero value here knows the verdict failed closed on attribution,
	// not that a destination was seen.
	NetworkReportsUnprovenOwnership uint64 `json:"networkReportsUnprovenOwnership,omitempty"`

	// NetworkReportsWithoutDestination counts IN-TREE outbound reports for
	// which the kernel named no destination at all — a bare `network-outbound`
	// line. Measured: a process that called getaddrinfo() and never connected
	// produced exactly this line plus the mDNSResponder socket connect, so in
	// the benign case the shape is the name-RESOLUTION path.
	//
	// These COUNT as egress, recorded under FamilyNotObservable: the kernel
	// proved an outbound operation happened and named nothing about it, and an
	// operation nobody could describe cannot be certified as one that reached
	// nothing. The benign reading does not rescue it either — name resolution
	// is a two-way remote channel (queried names leave the machine, answers
	// arrive as undeclared inputs). The consequence is that a macOS build
	// which resolves a hostname is non-hermetic HERE, exactly as a Linux
	// build whose resolver traffic is observed as real sockets is; a policy
	// that accepts resolution can waive the labelled entry with its eyes
	// open. The counter sizes this pile separately so a verifier can tell
	// resolver-shaped noise from format drift (the counter below).
	NetworkReportsWithoutDestination uint64 `json:"networkReportsWithoutDestination,omitempty"`

	// NetworkReportsUnrecognizedDestination counts in-tree reports whose
	// destination field this parser did not understand. Unlike the bare shape
	// above these DO count as egress, with an unnameable host: an unrecognized
	// shape is precisely the case where absence of understanding must not
	// become absence of egress. Non-zero means the report format moved and
	// this backend needs revisiting.
	NetworkReportsUnrecognizedDestination uint64 `json:"networkReportsUnrecognizedDestination,omitempty"`

	// PidReuseDetected counts pids observed to change INCARNATION (kernel
	// start time) mid-session. A recycled pid's cached ancestry belongs to a
	// dead process, so its facts are poisoned to unproven the moment the new
	// incarnation is seen: the new process cannot inherit the old chain (that
	// would let a pid-wrapping build put a stranger's work in the signed
	// tree), and events under that pid thereafter fail toward non-hermetic
	// (network) or toward a smaller tree (exec). Non-zero means the pid space
	// wrapped while the build ran — rare, and worth a verifier's attention.
	PidReuseDetected uint64 `json:"pidReuseDetected,omitempty"`

	// DeniedReports counts in-tree operations the sandbox REFUSED — deny(N)
	// reports. A denied exec loaded no bytes and a denied connect reached
	// nothing, so these enter no tree node and no egress list; recording a
	// refused attempt as an executed image would let a no-op build imitate an
	// expected process tree by running its "work" under a deny-everything
	// nested profile. The count is published so a verifier can see that
	// something tried. The observation profile itself allows everything, so
	// denies here come from a nested sandbox a descendant applied.
	DeniedReports uint64 `json:"deniedReports,omitempty"`

	// ForgedRecords counts log records that PARSED as sandbox reports but did
	// not come from the kernel, and were therefore refused.
	//
	// os_log is an ordinary API: any process can emit a line whose text reads
	// like a sandbox report. Provenance — processID 0, userID 0, /kernel, the
	// Sandbox kext as sender — is what separates a real report from an imitation,
	// and a user process cannot forge processID 0 because the logging system
	// stamps it from the emitter's real identity.
	//
	// Surfaced in the SIGNED predicate rather than merely logged, because a
	// non-zero value means something was writing sandbox-shaped messages while
	// this build ran. That is a bug or an attack, and a verifier should be able
	// to see it without access to the machine.
	ForgedRecords uint64 `json:"forgedRecords,omitempty"`

	// Note states the backend's blind spots inside the signed predicate, so
	// a verifier reading a stored attestation does not have to consult our
	// source to know what an absent field means here.
	Note string `json:"note,omitempty"`
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

	// Scripts are the interpreted scripts and makefiles this command executes,
	// resolved from argv and hashed BEFORE the command runs. Independent of
	// tracing: it works on every platform, including those where no kernel
	// tracing backend exists, and it survives the caller deleting a temp
	// wrapper script once the step completes.
	Scripts []ScriptRef `json:"scripts,omitempty"`

	// keyGuard is the signer's anti-tamper state read back at Attest time
	// (see readHardening). It is copied into the v0.2 `_meta.keyGuard` block
	// by ToV02 and restored by FromV02, so it travels INSIDE the signed
	// predicate as non-forgeability evidence. Never marshaled directly (it is
	// unexported); the v0.1 wire shape never carried it.
	keyGuard *V02KeyGuard

	silent        bool
	materials     map[string]cryptoutil.DigestSet
	enableTracing bool

	// scriptCapture selects script/makefile capture depth. The zero value is
	// the empty string rather than a valid mode, so scriptCaptureMode()
	// resolves it to the identity default instead of silently disabling
	// capture for every caller that predates this option.
	scriptCapture ScriptCaptureMode

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

	// darwinTraceDiag is stashed by the macOS sandbox-report tracer during
	// trace() and folded into the Summary afterwards. It cannot be written
	// to r.Summary directly because Summary is (re)built AFTER trace()
	// returns, which would clobber anything set here. Nil on other platforms.
	darwinTraceDiag *DarwinTraceDiagnostics

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

	// Capture script identity BEFORE running: wrapper scripts written to a
	// temp dir are commonly removed by the caller once the step finishes, and
	// a post-run capture would report every one of them as non-existent.
	//
	// SCOPE OF THE CLAIM. Scripts records the identity of the file the argv
	// NAMED, measured at capture time. It does not, and cannot here, assert
	// that those exact bytes are the bytes the kernel executed: the path can
	// be rewritten or the symlink re-pointed between this measurement and
	// exec. Binding the two would mean executing from a captured snapshot
	// (which changes the command's semantics) or taking the digest from
	// execution tracing of the opened inode.
	//
	// This is the measurement model the whole attestor family already uses,
	// not a gap introduced here: the material attestor walks the working
	// directory and publishes a path -> DigestSet map before the command
	// runs, with the same time-of-measurement property. For an in-workdir
	// script the digest published here matches material's pre-run entry for
	// the same path; what this field adds is WHICH of those files was the one
	// invoked. Consumers must read it as "the identity of the named script",
	// and a policy needing execution-bound bytes wants tracing, not this
	// field.
	//
	// The other half of the same limit: the INTERPRETER is identified by the
	// basename of argv[0] alone, never by inspecting the binary. See
	// resolveScriptOperands for the full statement of what a ScriptRef does
	// and does not assert.
	rc.Scripts = captureScriptRefs(ctx.Context(), rc.Cmd, rc.scriptWorkdir(ctx), rc.scriptCaptureMode())

	if err := rc.runCmd(ctx); err != nil {
		return err
	}

	// Now that the command has run, the trace can say which of those captured
	// files were actually opened, and with what bytes. Anything it cannot speak
	// to stays unverified — including everything on this path when runCmd
	// returned an error above, which is the safe direction.
	rc.bindScriptsToTrace()

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
	rc.Scripts = decoded.Scripts
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
			// macOS sandbox-report counters, including the size of the
			// discard pile. Nil (and absent from the wire) everywhere else.
			r.Summary.Diagnostics.Darwin = r.darwinTraceDiag
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

	r.Stdout = redactSensitiveEnvValues(stdoutBuffer.String())
	r.Stderr = redactSensitiveEnvValues(stderrBuffer.String())
	// Same leak via sibling SIGNED sinks. Two more env-derived string fields
	// reach the v0.2 predicate (signed + uploaded to Archivista) verbatim:
	//
	//  - r.Cmd: the operator's command argv. The shell expands a secret env var
	//    into it BEFORE cilock starts (`cilock run -- mytool --token=$MY_API_TOKEN`
	//    arrives as `["mytool","--token=<secret>"]`), and ToV02 signs it as the
	//    top-level `cmd`. Redact here — AFTER exec at line 1773, so execution is
	//    unaffected; the only remaining reader is the marshal.
	//  - each traced process's Cmdline: read verbatim from /proc/<pid>/cmdline
	//    and interned into the signed Cmdlines[] table (every process, not just
	//    the top one).
	//
	// Both expand the secret into argv, so they would leak even with
	// stdout/stderr scrubbed. (Environ is the other env-derived field, but ToV02
	// deliberately DROPS it, so it never reaches the signed bytes — see
	// v2_marshal.go.)
	redactArgv(r.Cmd)
	redactProcessCmdlines(r.Processes)
	return err
}

// redactedOutputValue replaces a sensitive value found in captured output.
const redactedOutputValue = "[REDACTED]"

// minRedactableValueLen guards against pathological over-redaction: replacing a
// very short env value (e.g. "1" or "ci") would scrub unrelated text from the
// logs. Real credentials are long, so we only redact values at least this long.
const minRedactableValueLen = 8

// sensitiveEnvKeySubstrings identifies environment variables whose VALUE is a
// credential. Unlike the environment attestor's DefaultSensitiveEnvList — which
// is deliberately broad (`*KEY*`, `*PAT*`) because obfuscating a captured var is
// harmless — output redaction must be CONSERVATIVE: a false positive scrubs
// innocent text from the signed logs (e.g. a broad `KEY`/`PAT` would mangle
// `MONKEY`/`PATH` values). These substrings appear only in real secret vars.
var sensitiveEnvKeySubstrings = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL",
	"PRIVATE_KEY", "ACCESS_KEY", "APIKEY", "API_KEY", "SIGNING_KEY", "SSH_KEY",
}

func isSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, s := range sensitiveEnvKeySubstrings {
		if strings.Contains(upper, s) {
			return true
		}
	}
	return false
}

// redactSensitiveEnvValues masks the values of sensitive environment variables
// wherever they appear in captured command output, before that output is signed
// into evidence shipped to Archivista + CI artifacts. command-run is always-run
// and captures stdout/stderr verbatim, so a secret echoed into the logs (the
// common leak) would otherwise be re-published. This closes that case; it cannot
// catch a secret that was never in the environment (e.g. typed inline).
func redactSensitiveEnvValues(s string) string {
	if s == "" {
		return s
	}
	for _, kv := range os.Environ() {
		key, val, found := strings.Cut(kv, "=")
		if !found || len(val) < minRedactableValueLen || !isSensitiveEnvKey(key) {
			continue
		}
		s = strings.ReplaceAll(s, val, redactedOutputValue)
	}
	return s
}

// redactArgv masks sensitive env-var values out of an argv slice in place. Used
// for the top-level r.Cmd, which the shell expands a secret into before cilock
// starts and which ToV02 signs as the predicate's `cmd`. Element 0 is a program
// path; the conservative helper leaves it untouched (a path won't equal a >=8
// char secret value), so passing the whole slice is safe.
func redactArgv(argv []string) {
	for i := range argv {
		argv[i] = redactSensitiveEnvValues(argv[i])
	}
}

// redactProcessCmdlines masks sensitive env-var values out of every traced
// process's Cmdline before that slice is interned into the v0.2 predicate's
// signed Cmdlines[] table (and uploaded to Archivista). Each Cmdline is read
// verbatim from /proc/<pid>/cmdline, so an env secret expanded into argv (e.g.
// `mytool --token=$MY_API_TOKEN`) would otherwise be re-published in the signed
// evidence — the same leak the stdout/stderr redaction closes, via a sibling
// sink. Applied to ALL processes, not just the top one. Uses the same
// conservative helper for consistency.
func redactProcessCmdlines(processes []ProcessInfo) {
	for i := range processes {
		processes[i].Cmdline = redactSensitiveEnvValues(processes[i].Cmdline)
	}
}

// scriptWorkdir resolves the directory relative script operands are read
// against, mirroring what runCmd will set c.Dir to.
//
// It must return an ABSOLUTE directory. Leaving it empty still resolves to the
// same place (Go resolves a relative path against the process CWD, which is
// exactly runCmd's own fallback), but it records a bare relative path such as
// "scan.sh" into signed evidence — a claim a verifier cannot resolve later
// without guessing which directory it meant.
func (rc *CommandRun) scriptWorkdir(ctx *attestation.AttestationContext) string {
	if dir := ctx.WorkingDir(); dir != "" {
		// NOT filepath.Abs. Abs calls Clean, and Clean removes `..` LEXICALLY —
		// it deletes the preceding component from the string without knowing
		// what that component was. runCmd hands this same value to exec.Cmd.Dir
		// verbatim, and the kernel does the opposite: it follows the component
		// first and applies `..` to wherever it landed. With `work/link/..`
		// where link is a symlink, those are two different directories, and
		// capture then hashed a real file with a real digest that the command
		// never opened.
		//
		// Making it absolute WITHOUT cleaning keeps the `..` intact all the way
		// into hydrateScriptRef, which already hands such paths to EvalSymlinks
		// — the one place in this attestor that resolves `..`, and the same fix
		// an earlier round applied to operands. This is that fix applied to the
		// class rather than to the instance.
		if abs, ok := absoluteAttemptedPath(dir, ""); ok {
			return abs
		}
		return dir
	}
	if cwd, err := getwd(); err == nil {
		return cwd
	}
	return rc.traceeWorkdir
}

// scriptCaptureMode resolves the configured capture mode, defaulting to
// identity. An unset field means "caller predates this option", not "caller
// asked for nothing" — defaulting to off would leave every existing caller
// with no script evidence and no indication that any was available.
func (rc *CommandRun) scriptCaptureMode() ScriptCaptureMode {
	switch rc.scriptCapture {
	case ScriptCaptureOff, ScriptCaptureIdentity, ScriptCaptureContent:
		return rc.scriptCapture
	default:
		return ScriptCaptureIdentity
	}
}
