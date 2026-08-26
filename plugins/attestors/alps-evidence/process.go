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

package alpsevidence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrProcessNotFound is returned by a ProcessSource when the requested PID does
// not exist or is not inspectable by the current user.
var ErrProcessNotFound = errors.New("alps-evidence: process not found")

// ErrEnvironmentUnreadable is returned by a ProcessSource when a process's
// environment cannot be read at all — macOS withholds it for SIP-protected and
// hardened-runtime binaries, /proc/<pid>/environ is unreadable across users.
//
// The distinction from an empty result is load-bearing: an environment that
// was READ and did not contain a key proves the key was unset, while an
// environment that could not be read proves nothing. A caller that collapses
// the two will promote a lower-precedence config value to "effective" when a
// higher-precedence environment override cannot be ruled out.
var ErrEnvironmentUnreadable = errors.New("alps-evidence: process environment unreadable")

// ErrUnsupportedPlatform is returned by the process source on platforms where
// no ancestry reader is implemented.
var ErrUnsupportedPlatform = errors.New("alps-evidence: process inspection not implemented on this platform")

// ProcessInfo is the raw, unredacted kernel view of one process. Values here
// flow into detection and provider inspection; only a redacted subset ever
// reaches the predicate.
type ProcessInfo struct {
	PID       int
	PPID      int
	StartTime string

	// Executable is the image path as recorded at exec time. On macOS this is
	// the path handed to execve, which may be a symlink.
	Executable string

	// Comm is the kernel's short name for the process, truncated by the kernel
	// (16 bytes on both Linux and macOS).
	Comm string

	// Argv is the full argument vector. It is deliberately NOT serialized; see
	// ProcessRef. Providers read it, redaction decides what escapes.
	Argv []string

	// Env holds environment variables the source was able to read. It is only
	// populated for keys a caller asked for. Empty is normal and not an error:
	// macOS refuses environment reads for SIP-protected binaries even when the
	// caller owns the process.
	Env map[string]string

	// coverage records which identity sources were actually READ. It is
	// unexported and written in exactly one place — processInfoBuilder.build —
	// so a ProcessInfo cannot claim to have been examined unless a source
	// vouched for each read. Its zero value claims nothing; see
	// identityCoverage for why that polarity is the fix.
	coverage identityCoverage

	// execGeneration is an opaque token naming which EXECUTION of this process
	// the read observed — a value that changes on every execve, including one
	// that re-executes the same pathname. Platform sources fill it in
	// ReadProcess (Linux: a digest of /proc/<pid>/auxv, which the kernel
	// rewrites at every exec; macOS: a digest over the exec-time regions of
	// the KERN_PROCARGS2 snapshot). Empty means the platform could not
	// produce a signal, and processInstance.validate FAILS on empty rather
	// than treating "no evidence of an exec" as evidence of none — the same
	// polarity identityCoverage uses. It is unexported and never serialized:
	// it exists only so a follow-up read can prove it landed on the same
	// execution, never as published evidence.
	execGeneration string
}

// ProcessSource reads process state. Split out as an interface so detection is
// testable against fixture process trees that model real installations.
type ProcessSource interface {
	// ReadProcess returns the process's kernel state without environment.
	ReadProcess(pid int) (ProcessInfo, error)

	// ReadEnvironment returns the values of the requested keys for the given
	// process. An empty map with a nil error is a valid, common outcome and
	// means the environment WAS read and the keys were not set. When the
	// environment itself cannot be read, the source returns an error
	// (conventionally wrapping ErrEnvironmentUnreadable) so callers can tell
	// "unset" from "unknown" — the two carry opposite evidentiary weight.
	//
	// It takes the process INSTANCE rather than a bare pid, for the same
	// reason OpenProcessImage does: a pid is a reusable number, and an
	// environment read addressed by number alone can land on a different
	// process — a recycled pid, or the same pid after an execve replaced the
	// image and environment together — and hand back values that would be
	// published beside an executable, argv and ancestry describing the
	// original. An implementation validates the instance after reading and
	// reports a mismatch as an unreadable environment, never as values.
	ReadEnvironment(instance processInstance, keys []string) (map[string]string, error)
}

// processImageOpener is optionally implemented by a ProcessSource that can
// open the running process IMAGE, rather than the path the kernel recorded
// for it. On Linux, /proc/<pid>/exe is such a handle: it stays bound to the
// binary the process actually exec'd even after the path on disk has been
// replaced by an update. Sources without such a facility (macOS has none)
// simply do not implement this, and executable evidence falls back to a
// single path-based open with the binding recorded as path-based.
//
// It takes the process INSTANCE rather than a bare pid. A pid is a reusable
// number, so an open addressed by number alone can land on a different process
// after wraparound and hand back an image that would be published beside a
// start time, argv and ancestry describing the original. The instance carries
// the start time that tells the two apart, and an implementation validates
// before returning a handle.
type processImageOpener interface {
	OpenProcessImage(instance processInstance) (*os.File, error)
}

// executableBase is the lowercased basename of the process image path.
//
// It intentionally does not fall back to argv[0]: on macOS the Claude Code
// binary lives at .../claude/versions/2.1.234 and its argv[0] is the rewritten
// process title "claude bg-spare". Conflating the two produced a matcher that
// silently compared the wrong string. Callers that want the argv view ask for
// argvProgram explicitly.
func executableBase(p ProcessInfo) string {
	return lowerBase(p.Executable)
}

// lowerBase is the lowercased basename of a path, or "" for the empty path.
// Shared with the match-time fingerprint helpers so both compare the same
// normalization of a name.
func lowerBase(path string) string {
	if path == "" {
		return ""
	}
	return strings.ToLower(filepath.Base(path))
}

// commBase is the lowercased kernel short name.
func commBase(p ProcessInfo) string {
	return strings.ToLower(strings.TrimSpace(p.Comm))
}

// argvProgram is the basename of the first whitespace-delimited token of
// argv[0], lowercased.
//
// Agents that rewrite their process title publish argv[0] values such as
// "claude bg-spare" or "codex tui". Taking the whole string as a path yields a
// basename of "claude bg-spare", which matches nothing. Taking the first token
// yields "claude", which is the identity the product intended to publish.
//
// This value is fully attacker-controlled — any process can set its own title —
// so a match resting on it is recorded with a fingerprint name that says so.
func argvProgram(p ProcessInfo) string {
	if len(p.Argv) == 0 {
		return ""
	}
	// Fields rather than a manual index scan: an argv[0] that begins with
	// whitespace made an index-based split return the untrimmed string, so a
	// title of " claude" yielded the program name " claude".
	fields := strings.Fields(p.Argv[0])
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(filepath.Base(fields[0]))
}

// pathElements splits a path into its lowercased components, dropping empties.
// Used for exact directory-name fingerprints such as "the parent directory is
// literally named versions". Never used for substring containment.
func pathElements(p string) []string {
	cleaned := filepath.ToSlash(filepath.Clean(p))
	parts := strings.Split(cleaned, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		out = append(out, strings.ToLower(part))
	}
	return out
}

// looksLikeVersion reports whether s is a bare dotted numeric version such as
// "2.1.234" or "0.143.0", optionally with a pre-release suffix.
//
// The check is strict on the numeric head so that an ordinary basename never
// gets promoted to a version claim.
func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	head := s
	if i := strings.IndexAny(s, "-+"); i > 0 {
		head = s[:i]
	}
	parts := strings.Split(head, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

// splitNULTerminated splits a NUL-terminated kernel buffer — the layout of
// /proc/<pid>/cmdline — into its entries, preserving empty ones.
//
// Empty Unix arguments are valid (execve passes "" like any other string) and
// each occupies one NUL-terminated slot in the buffer. An earlier shape of
// this function dropped every empty entry, which shifted all later arguments
// one slot left: `codex --model "" --sandbox read-only` read as
// [codex --model --sandbox read-only], and the flag scanner attested
// "--sandbox" as the model inside signed evidence. Only the single trailing
// terminator is removed; internal and trailing empty ARGUMENTS survive. The
// darwin source never had this bug — KERN_PROCARGS2 decoding keeps all argc
// entries — so this is the Linux twin of that behavior.
func splitNULTerminated(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
}

// optionTerminator is the POSIX bare "--": everything after it is an operand,
// never a flag.
const optionTerminator = "--"

// optionArgv returns argv truncated at the first bare "--" option terminator.
//
// Every flag scanner in this package must consume options through this cut.
// Both priority CLIs follow the POSIX convention: everything after a lone "--"
// is positional — prompt text or tool arguments, chosen freely by whoever
// typed the prompt. A scanner that reads past the terminator lets a prompt
// like `codex exec -- --sandbox read-only` override the run's REAL sandbox
// posture inside signed evidence. For an unmeasured CLI that turned out not to
// honor "--", stopping early costs at most an unrecorded flag — an observation
// gap — never a wrong claim, which is the direction this attestor fails in.
//
// Deliberately NOT applied to the non-flag argv scans: the npm-shim matcher
// (node may be invoked as `node -- script.js`) and the vendor-chain version
// harvest (Claude Code's pty host carries its spawn target's versioned path
// after a "--"). Those read paths, not options, and their measured layouts
// place the evidence after a terminator.
func optionArgv(argv []string) []string {
	for i, arg := range argv {
		if arg == optionTerminator {
			return argv[:i]
		}
	}
	return argv
}

// argvValue extracts the value of a flag from argv, handling both "--flag value"
// and "--flag=value", and returns the LAST occurrence before the "--"
// terminator.
//
// Last-wins is what the CLIs being observed actually do, and it is the same
// rule argvKeyValue follows. Codex is clap v4, where a value argument's
// default ArgAction::Set OVERWRITES on a repeat; Claude Code is commander.js,
// which likewise overwrites an option's value each time it is seen. A
// first-wins scan attested "gpt-old" for `codex --model gpt-old --model
// gpt-new`, naming a model that never served the run.
//
// A separate-token value that is itself flag-shaped is refused rather than
// consumed. Neither CLI allows hyphen-leading values for these flags (clap's
// allow_hyphen_values is off by default, so it errors instead), and consuming
// one produced signed evidence claiming "--sandbox" was the model. Refusing
// costs at most an unrecorded flag — an observation gap — which is the
// direction this attestor fails in. A lone "-" stays a legal value.
func argvValue(argv []string, names ...string) (string, bool) {
	argv = optionArgv(argv)
	value, found := "", false
	for i := 0; i < len(argv); i++ {
		for _, name := range names {
			if argv[i] == name {
				if i+1 < len(argv) && !flagShaped(argv[i+1]) {
					value, found = argv[i+1], true
				}
				break
			}
			if prefix := name + "="; strings.HasPrefix(argv[i], prefix) {
				value, found = strings.TrimPrefix(argv[i], prefix), true
				break
			}
			// clap accepts a short option's value in the same argv slot:
			// `-punsafe`, `-mgpt-5`, `-sread-only`, and `-auntrusted` are
			// live Codex spellings. Missing this form is not merely an absent
			// observation: ignoring -punsafe and then resolving top-level
			// config can publish a safer posture than the selected profile.
			if len(name) == 2 && strings.HasPrefix(name, "-") && strings.HasPrefix(argv[i], name) && len(argv[i]) > len(name) {
				value, found = strings.TrimPrefix(argv[i], name), true
				break
			}
		}
	}
	return value, found
}

// flagShaped reports whether an argument reads as an option rather than a
// value. A lone "-" is excluded: it is the conventional stdin placeholder and
// a legal value.
func flagShaped(arg string) bool {
	return len(arg) > 1 && strings.HasPrefix(arg, "-")
}

// argvKeyValue extracts a "key=value" pair passed through a repeatable override
// flag such as Codex's "-c model=gpt-5", returning the LAST assignment to the
// requested key before the "--" terminator.
//
// The flag is repeatable by design and Codex applies the overrides in order,
// so a later assignment replaces an earlier one. Returning the first match
// attested "gpt-old" for `codex -c model=gpt-old -c model=gpt-new` — a model
// the run explicitly overrode — inside signed evidence. The key comparison
// stays an exact "key=" prefix so "model_reasoning_effort=..." is never read
// as the model.
func argvKeyValue(argv []string, flagNames []string, key string) (string, bool) {
	want := key + "="
	argv = optionArgv(argv)
	value, found := "", false
	for i, arg := range argv {
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}
		for _, flag := range flagNames {
			var payload string
			switch {
			case arg == flag:
				payload = next
			case strings.HasPrefix(arg, flag+"="):
				payload = strings.TrimPrefix(arg, flag+"=")
			case len(flag) == 2 && strings.HasPrefix(flag, "-") && strings.HasPrefix(arg, flag) && len(arg) > len(flag):
				// clap also accepts `-cmodel=gpt-5`; the long
				// `--config=model=gpt-5` form is handled above.
				payload = strings.TrimPrefix(arg, flag)
			default:
				continue
			}
			if strings.HasPrefix(payload, want) {
				value, found = strings.TrimPrefix(payload, want), true
			}
		}
	}
	return value, found
}

// ---------------------------------------------------------------------------
// Identity coverage — what was actually READ about a process
// ---------------------------------------------------------------------------

// identitySource names one of the process facts a provider is allowed to match
// on. These are exactly the three inputs to matchByName, which is why they are
// the three whose absence can invalidate a not-detected verdict.
type identitySource string

const (
	identityExecutable identitySource = "executable"
	identityComm       identitySource = "comm"
	identityArgv       identitySource = "argv"
)

// identityCoverage is the positive record of which identity sources a
// ProcessSource actually managed to read for one process.
//
// ITS ZERO VALUE CLAIMS NOTHING, and that is the entire design.
//
// The defect this replaces: a ProcessInfo assembled from FAILED reads was
// indistinguishable from one assembled from successful reads. A process that
// exited between enumeration and read — measured, a real zombie — came back
// with err == nil, an empty Executable and no Argv, which is precisely what a
// live process legitimately lacking an executable path looks like. The walk
// read the empty one as "examined, not an agent" and signed not-detected: a
// positive claim that EVERY ancestor was examined, made about a process whose
// identity was never read.
//
// A bool meaning "this was fine" would not fix that, because the next source to
// forget it would default into the confident answer. Coverage is the other
// polarity: nothing is claimed unless a constructor recorded it, so a site that
// forgets degrades the verdict to incomplete rather than silently strengthening
// it. Forgetting costs a refusal, never a false claim.
type identityCoverage struct {
	// vouched is set only by processInfoBuilder.build, so a ProcessInfo that
	// nobody constructed through the builder is treated as unexamined.
	vouched bool

	// gaps names the sources whose read failed. Empty on a vouched value means
	// every source was read.
	gaps []identitySource
}

// fullyExamined reports whether every identity source a provider can match on
// was actually read for this process.
//
// Only a fully examined ancestor can support a not-detected verdict: a provider
// might have matched on exactly the source that was missing, so an unread
// source is an unanswered question, not a negative answer.
func (p ProcessInfo) fullyExamined() bool {
	return p.coverage.vouched && len(p.coverage.gaps) == 0
}

// identityGaps names the identity sources that could not be read. A ProcessInfo
// that never went through the builder reports every source as a gap, because
// nothing is known about how it was assembled.
func (p ProcessInfo) identityGaps() []identitySource {
	if !p.coverage.vouched {
		return []identitySource{identityExecutable, identityComm, identityArgv}
	}
	return p.coverage.gaps
}

// processInfoBuilder is the only way to obtain a ProcessInfo that claims to
// have been examined.
//
// Each setter takes the (value, error) pair STRAIGHT FROM THE READ rather than
// a value the caller already inspected. That shape is the point: a Go call can
// forward a two-result read directly — b.executable(os.Readlink(path)) — so the
// error has nowhere to be dropped. The shape this replaces was
// `exe, _ := os.Readlink(path)`, where discarding the error took one character
// and left no trace.
type processInfoBuilder struct {
	info ProcessInfo
	gaps []identitySource
}

// newProcessInfo starts a build from the facts that identify the process slot
// itself. These come from the enumeration read, which has already succeeded by
// the time a builder exists — a failure there is a missing process, reported as
// an error instead.
func newProcessInfo(pid, ppid int, startTime string) *processInfoBuilder {
	return &processInfoBuilder{info: ProcessInfo{PID: pid, PPID: ppid, StartTime: startTime}}
}

// executable records the image path read, or the failure to read it.
func (b *processInfoBuilder) executable(path string, err error) *processInfoBuilder {
	if err != nil {
		b.gaps = append(b.gaps, identityExecutable)
		return b
	}
	b.info.Executable = path
	return b
}

// comm records the kernel short name read, or the failure to read it.
func (b *processInfoBuilder) comm(name string, err error) *processInfoBuilder {
	if err != nil {
		b.gaps = append(b.gaps, identityComm)
		return b
	}
	b.info.Comm = name
	return b
}

// argv records the argument vector read, or the failure to read it.
func (b *processInfoBuilder) argv(argv []string, err error) *processInfoBuilder {
	if err != nil {
		b.gaps = append(b.gaps, identityArgv)
		return b
	}
	b.info.Argv = argv
	return b
}

// execGeneration records the per-execution token read for this process, or the
// failure to read one. A failed read is NOT an identity gap — the token is
// never matched on and never published — but it is not forgiven either: the
// token stays empty, and processInstance.validate fails on an empty side, so
// an unreadable generation degrades every follow-up read to "unreadable"
// rather than silently weakening the instance bind.
func (b *processInfoBuilder) execGeneration(token string, err error) *processInfoBuilder {
	if err != nil {
		return b
	}
	b.info.execGeneration = token
	return b
}

// build stamps the coverage record and yields the ProcessInfo. This is the only
// place vouched is ever set.
func (b *processInfoBuilder) build() ProcessInfo {
	b.info.coverage = identityCoverage{vouched: true, gaps: b.gaps}
	return b.info
}

// ---------------------------------------------------------------------------
// Instance binding — which RUN of a pid a follow-up read is allowed to describe
// ---------------------------------------------------------------------------

// processInstance identifies one RUN of a process, not merely a slot in the
// process table.
//
// A pid is a reusable number. Any read addressed by number ALONE — opening the
// image, re-reading a stat file — can therefore land on a different process
// than the one being described, and the evidence it returns would be published
// beside a pid, start time, argv and ancestry that describe the original. The
// start time is what separates one run of a pid from the next, so it travels
// with the number and is checked before anything derived from a second read is
// accepted.
//
// This is the same rule openAgentPath applies to paths, one layer over: a read
// must be bound to the thing it claims to describe.
type processInstance struct {
	pid       int
	startTime string

	// executable is the image path recorded when this process was captured.
	//
	// It is here because pid and start time BOTH SURVIVE execve. An agent that
	// execs a different binary between the walk reading it and a follow-up read
	// keeps its number and its start time, so those two alone would wave the
	// new image through to be digested and published beside the OLD path, argv,
	// fingerprint and ancestry. The path catches the DIFFERENT-image exec and
	// carries a readable name into the error; it cannot catch a re-exec of the
	// SAME pathname, which is what execGeneration is for.
	executable string

	// execGeneration is the per-execution token captured with the process; see
	// ProcessInfo.execGeneration. It is here because pid, start time AND image
	// path all survive an execve that re-executes the same pathname — a
	// self-update re-exec, `exec "$0"` in a wrapper — so the three fields
	// above together still accept a post-exec process image and would pair its
	// environment or image handle with the argv, fingerprint and ancestry
	// captured from the previous execution. The generation is the field a
	// same-path execve changes.
	execGeneration string
}

// instance is how a captured ProcessInfo names the run it describes.
func (p ProcessInfo) instance() processInstance {
	return processInstance{pid: p.PID, startTime: p.StartTime, executable: p.Executable, execGeneration: p.execGeneration}
}

// validate reports whether a freshly read process is still the instance that
// was captured.
//
// An ABSENT start time fails. A platform that cannot report one cannot vouch
// that this is the same run, and "no evidence of a change" is not evidence of
// no change — the same polarity identityCoverage uses.
func (i processInstance) validate(got ProcessInfo) error {
	if i.startTime == "" || got.StartTime == "" {
		return fmt.Errorf("alps-evidence: pid %d has no start time, so a follow-up read cannot be bound to the captured process", i.pid)
	}
	if got.PID != i.pid || got.StartTime != i.startTime {
		return fmt.Errorf("alps-evidence: pid %d is no longer the process that was captured (start time %q, now %q)",
			i.pid, i.startTime, got.StartTime)
	}
	// An exec keeps the number and the start time and changes the image, so
	// this is the comparison that sees it. An image path that could not be read
	// on either side proves nothing and must not pass as agreement.
	if i.executable == "" || got.Executable == "" {
		return fmt.Errorf("alps-evidence: pid %d has no readable image path, so a follow-up read cannot be bound to the captured process", i.pid)
	}
	if got.Executable != i.executable {
		return fmt.Errorf("alps-evidence: pid %d exec'd a different image since it was captured", i.pid)
	}
	// A same-path execve keeps the pid, the start time AND the image path, so
	// none of the checks above sees it. Only the per-execution generation
	// distinguishes one execution of a pathname from the next, and a side that
	// has none cannot rule the re-exec out — so an ABSENT generation fails,
	// exactly like the absent start time above. Refusing costs a degraded read
	// (the caller reports unreadable); accepting would pair one execution's
	// values with another execution's identity inside signed evidence.
	if i.execGeneration == "" || got.execGeneration == "" {
		return fmt.Errorf("alps-evidence: pid %d has no execution-generation signal, so a same-path re-exec between capture and read cannot be ruled out", i.pid)
	}
	if got.execGeneration != i.execGeneration {
		return fmt.Errorf("alps-evidence: pid %d exec'd since it was captured (execution generation changed; the image path %q is unchanged, so this was a same-path re-exec or an unreadable transition)", i.pid, i.executable)
	}
	return nil
}
