// Copyright 2026 The Rookery Contributors
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
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// ScriptCaptureMode selects how much of an interpreted script or makefile the
// attestor records.
type ScriptCaptureMode string

const (
	// ScriptCaptureOff records nothing.
	ScriptCaptureOff ScriptCaptureMode = "off"

	// ScriptCaptureIdentity records the resolved path, size and content digest
	// but NOT the bytes. This is the default: hashing a file the command is
	// about to execute exposes nothing the argv did not already expose, and it
	// makes the step verifiable and drift-detectable.
	ScriptCaptureIdentity ScriptCaptureMode = "identity"

	// ScriptCaptureContent additionally embeds the script body. Opt-in only.
	// Build scripts routinely inline credentials (`curl -H "Authorization:
	// ..."`, `export TOKEN=...`), and an attestation is signed, immutable and
	// broadly readable — a secret captured here cannot be withdrawn. Operators
	// who need the body must ask for it per step.
	ScriptCaptureContent ScriptCaptureMode = "content"
)

// ParseScriptCaptureMode converts an operator-supplied string to a mode,
// rejecting anything it does not recognise.
//
// The zero value resolving to identity is right for a CALLER that predates the
// option, but wrong for a human who typed something. Casting a flag string
// straight to ScriptCaptureMode would turn "contnet" into identity silently,
// and the operator would believe content capture was on. A typo must fail
// loudly; only an ABSENT value defaults.
func ParseScriptCaptureMode(s string) (ScriptCaptureMode, error) {
	switch ScriptCaptureMode(s) {
	case "":
		return ScriptCaptureIdentity, nil
	case ScriptCaptureOff:
		return ScriptCaptureOff, nil
	case ScriptCaptureIdentity:
		return ScriptCaptureIdentity, nil
	case ScriptCaptureContent:
		return ScriptCaptureContent, nil
	default:
		return "", fmt.Errorf(
			"unrecognised script capture mode %q; valid values are %q, %q, %q",
			s, ScriptCaptureOff, ScriptCaptureIdentity, ScriptCaptureContent)
	}
}

// maxScriptContentBytes caps embedded content. Exceeding it truncates and sets
// ContentTruncated — never silently shortens.
const maxScriptContentBytes = 256 * 1024

// maxScriptDigestBytes bounds how much of an operand will be hashed.
//
// Cancellation only bounds the work if somebody cancels, and the attestation
// context may carry no deadline at all. A file that grows as fast as it is read
// would then hold a worker forever, before the command has even started. This
// ceiling is the unconditional bound; exceeding it ABSTAINS, because a digest
// over the first N bytes would describe a prefix while claiming to identify the
// file.
//
// A var, not a const, solely so tests can exercise the boundary without writing
// the real ceiling to disk. Nothing in production assigns to it.
var maxScriptDigestBytes int64 = 64 << 20

// maxCaptureTotalBytes bounds ONE capture pass across every operand in it.
//
// The per-operand ceiling above bounds a single file and nothing more, which
// leaves the argv itself as the amplifier: `make -f big.mk` repeated a thousand
// times is a small command line and a thousand full rehashes, all before the
// command starts. Deduplication removes the repeated case entirely; this bounds
// what is left — many DISTINCT large operands — so a short argv can no longer
// buy unbounded I/O.
//
// A var for the same reason as maxScriptDigestBytes.
var maxCaptureTotalBytes int64 = 256 << 20

// windowsExecutableNames reports whether program names carry Windows
// executable-suffix and case-folding rules.
//
// A var, not a direct runtime.GOOS test, so the Windows branch is exercised by
// tests on every platform. A branch that only runs on the one OS nobody
// develops on is exactly where a silent evidence gap ships.
var windowsExecutableNames = runtime.GOOS == "windows"

// getwd is os.Getwd, indirected so a test can exercise the one branch where an
// operand cannot be made absolute at all. Nothing in production assigns to it.
// Same reason as maxScriptDigestBytes above: the branch is unreachable from the
// outside otherwise, and an untested branch in failure-reporting code is where
// a wrong record gets written.
var getwd = os.Getwd

// ScriptRole describes why a path was collected.
type ScriptRole string

const (
	// RoleInterpreterOperand is the script argument to sh/bash/python/node/...
	RoleInterpreterOperand ScriptRole = "interpreter-operand"
	// RoleMakefile is an explicit `make -f X` or the implicit makefile that
	// GNU make would select in the working directory.
	RoleMakefile ScriptRole = "makefile"
)

// ScriptRef is one resolved script or makefile.
//
// MEASUREMENT SEMANTIC — read this before relying on Digest. The digest is
// taken at attest time, BEFORE the command executes. It is a statement about
// what was on disk when the attestor looked, not proof of the bytes the kernel
// subsequently executed: a rewrite or path swap in the window between capture
// and exec would not be visible here. Capturing after execution would be
// strictly worse (wrapper scripts are routinely deleted by then, and the file
// could equally have changed), so the ordering is deliberate.
//
// When execution-time bytes are what matters, the authoritative source is the
// process trace: ProcessInfo.OpenedFiles records digests for the files the
// tracee actually opened, measured from kernel events rather than from a
// separate look at the path. A verifier that needs "what really ran" should
// prefer that and treat ScriptRef.Digest as the pre-execution snapshot it is.
//
// Every field that can be missing has an explicit companion explaining WHY it
// is missing. A ScriptRef with no Digest and no Unresolved reason would be
// indistinguishable from a file we hashed to nothing, and "we did not look" and
// "we looked and it was empty" are different claims about the build.
type ScriptRef struct {
	// Path is the operand as resolved against the tracee's working directory.
	//
	// It is ABSOLUTE on every outcome, success or failure, unless
	// PathUnresolvable says otherwise. A failure record whose Path is the bare
	// argv token cannot do the one job it exists for — naming which file could
	// not be measured — because a bare token is indistinguishable from a
	// successfully resolved relative path.
	Path string `json:"path"`

	// PathUnresolvable reports that Path could NOT be made absolute and is
	// therefore the operand as it appeared in argv, not a location.
	//
	// Without it the two states share one representation, and a reader would
	// have to guess whether "build.sh" is a resolution this attestor performed
	// or one it failed to perform. It requires the process working directory to
	// be unavailable, so it is false in ordinary operation and omitted from the
	// JSON — but a record that cannot express its own degradation is how a
	// failure gets read as a fact.
	PathUnresolvable bool `json:"pathUnresolvable,omitempty"`

	// Role is why this path was collected.
	Role ScriptRole `json:"role"`

	// Digest is the content digest. Absent when Unresolved is set.
	Digest cryptoutil.DigestSet `json:"digest,omitempty"`

	// SizeBytes is the on-disk size. Absent when Unresolved is set.
	SizeBytes int64 `json:"sizeBytes,omitempty"`

	// Content is the script body, present ONLY under ScriptCaptureContent.
	Content string `json:"content,omitempty"`

	// ContentTruncated reports that Content holds only the first
	// maxScriptContentBytes bytes. The Digest always covers the WHOLE file, so
	// a truncated Content plus a full-file Digest is not a contradiction — but
	// a verifier must not hash Content and expect Digest to match.
	ContentTruncated bool `json:"contentTruncated,omitempty"`

	// ContentOmittedBinary reports that the file is not valid UTF-8 and its
	// body was withheld even though content capture was requested. Digest and
	// SizeBytes remain populated.
	ContentOmittedBinary bool `json:"contentOmittedBinary,omitempty"`

	// Unresolved explains why no digest was recorded — the file did not exist,
	// was not a regular file, or could not be read. Mutually exclusive with
	// Digest.
	Unresolved string `json:"unresolved,omitempty"`

	// ExecutionBinding states whether Digest was PROVEN to be the bytes the
	// kernel executed, rather than merely the bytes on disk when the attestor
	// looked. It is ALWAYS emitted — deliberately not omitempty.
	//
	// The omitempty is the whole point. A binding status that disappears when
	// it is "unverified" makes absence ambiguous: a consumer cannot tell an
	// unbound digest from a producer that predates this field, and the safe
	// reading of an ambiguous claim is never the one people take. Emitting it
	// unconditionally means every ScriptRef this attestor writes states its own
	// epistemic status, and a policy can require the value rather than infer it
	// from the field being there.
	ExecutionBinding ScriptExecutionBinding `json:"executionBinding"`
}

// ScriptExecutionBinding is the answer to "were these the bytes that RAN?".
//
// The distinction is the reason this type exists. A pre-execution digest and an
// execution-bound digest are different claims about the build, and they were
// previously indistinguishable in the signed output: both appeared as a bare
// `digest`, and a verifier had no way to tell proof from snapshot. In a
// supply-chain predicate that gap is the whole attack — a rename between capture
// and exec attests file A while file B runs, and the signature covers it either
// way.
type ScriptExecutionBinding string

const (
	// ScriptBindingUnverified: the digest is a capture-time measurement and
	// NOTHING MORE. It is not proof the file executed.
	//
	// This is the default and, in practice, the common case. Execution binding
	// needs the process trace, which is opt-in and Linux-only, and the trace
	// deliberately skips reads under temp and cache directories — precisely
	// where wrapper scripts live. A skipped read produces this value, never a
	// match: a blind spot must not be able to manufacture a positive.
	ScriptBindingUnverified ScriptExecutionBinding = "unverified"

	// ScriptBindingVerified: the process trace observed this exact path being
	// opened during the run, and the digest the kernel's read-tap produced
	// agrees with the digest captured before exec.
	//
	// This is the only value that licenses "these bytes ran".
	ScriptBindingVerified ScriptExecutionBinding = "verified"

	// ScriptBindingMismatch: the trace observed this path and the bytes DIFFER
	// from what was captured. The file changed between measurement and
	// execution.
	//
	// The captured digest is dropped when this is set. It is known to describe
	// something other than what ran, and a digest known to be wrong is worse
	// than no digest at all — the signature would make it authoritative.
	ScriptBindingMismatch ScriptExecutionBinding = "mismatch"
)

// optionGrammar models ONE program's option grammar.
//
// A single global table cannot work: bash's `-e` is errexit and takes no
// operand, while perl's `-e` introduces inline code. Sharing one table means
// `bash -e deploy.sh` records no script, or an operand-taking option's VALUE is
// mistaken for the executed script. Both produce wrong signed evidence.
//
// Membership is the ONLY thing that makes a token safe to walk past. A token
// the grammar does not name is not "probably harmless": it may consume the
// token that follows it, and then whatever the resolver names next is not the
// operand the program actually received. So a scan abstains on the first token
// it cannot account for, and the tables below stay small on purpose — every
// entry is a claim about another program's argument parsing, and a wrong claim
// is how a real file with a real digest gets signed as the thing that ran.
type optionGrammar struct {
	// switches take no value.
	switches map[string]bool

	// valueOptions take a value: the attached tail (`-fci.mk`, `--file=ci.mk`)
	// when there is one, otherwise the following token.
	//
	// Membership here asserts the value is OPAQUE — that no value can stop the
	// operand running. `perl -I /nonexistent` still runs the script, so -I
	// belongs here. An option the interpreter validates does NOT, however
	// ordinary its values look, because the argv then names an operand that
	// never executed. The probe harness enforces the distinction by running
	// each of these with a deliberately bogus value.
	valueOptions map[string]bool

	// enumeratedValueOptions take a value the interpreter VALIDATES, mapped to
	// the values verified to still run the operand. Anything else abstains.
	//
	// `dash -o pipefail build.sh` is the case that forced this: dash has no
	// pipefail, exits before build.sh, and the resolver used to consume the
	// value and sign build.sh as executed. The sets are derived from the probe
	// rather than from a specification — POSIX lists `noexec` as a valid `set
	// -o` name and it runs nothing on any shell, so reading the spec would have
	// produced exactly the wrong answer.
	enumeratedValueOptions map[string]map[string]bool

	// attachedValueOptions take a value ONLY as the attached tail. Perl's
	// `-Mstrict` and `-F,` are the examples: `perl -M strict build.pl` is not a
	// spelling variant, it is an error perl exits on without ever running
	// build.pl. Modelling those as ordinary valueOptions let the scan swallow
	// the next token and then record the operand behind it as an executed
	// script — the same false claim as a mis-modelled switch, reached through
	// the value grammar instead.
	//
	// Without an attached value the invocation is malformed for the program, so
	// the scan abstains.
	attachedValueOptions map[string]bool

	// unresolvable names options that are modelled, and modelled as "no
	// answer". Four reasons, all reaching the same behaviour: the program runs
	// code given on the command line or read from stdin; it resolves paths
	// against a directory this resolver does not follow; its own value grammar
	// is ambiguous; or THE OPERAND IS NEVER EXECUTED under it.
	//
	// That last group is the subtle one. `python3 -h decoy.py` exits 0 having
	// never opened decoy.py, and `make --version -f decoy.mk` never reads
	// decoy.mk. Classifying those as ordinary switches is not a parse error —
	// the token is understood — it is a false CLAIM, because the recorded
	// operand is a real file with a real digest that this command demonstrably
	// did not run, attached to a command that succeeded.
	//
	// Listing an option here rather than leaving it unknown changes nothing
	// about the behaviour — both abstain — but it records that the refusal is
	// deliberate.
	unresolvable map[string]bool

	// plusToggles marks the shells, where `+x` is the disable form of `-x` and
	// `+o` takes a value exactly as `-o` does. Elsewhere `+` introduces no
	// option at all, so a `+` token is a shape the grammar cannot account for.
	plusToggles bool

	// longOptionsFirst marks programs that only recognise long options BEFORE
	// any short one. Bash is the case: `bash --norc -e s.sh` runs s.sh, while
	// `bash -e --norc s.sh` makes bash report "--: invalid option" and run
	// nothing. The scanner is otherwise order-independent, which is a claim
	// about ordering that bash does not honour — so it signed a script bash had
	// refused to start. make, python and node accept either order, verified.
	longOptionsFirst bool
}

// programName reduces argv[0] to the key the grammar tables above are written
// in.
//
// filepath.Base alone is right on POSIX and wrong on Windows, where every
// interpreter is invoked as `python.exe`, `bash.exe`, `make.exe` and the
// filesystem is case-insensitive, so `Make.EXE` names the same program as
// `make`. cilock ships a windows/amd64 binary and this file carries no build
// tag, so a raw-basename match silently produced NO script evidence for every
// interpreted step on that platform.
//
// Only `.exe` is stripped. `.bat` and `.cmd` are batch scripts run by cmd.exe,
// not the program they are named after: a `make.cmd` wrapper has its own
// argument handling, and borrowing make's grammar for it would sign whatever
// the wrapper's arguments happen to name as the makefile that was read. That is
// the wrapper hazard this resolver already documents and declines to guess at,
// so those keep abstaining.
//
// Nothing is stripped off Windows. A POSIX file named "python.exe" is a file
// named "python.exe" — claiming python's grammar for it would be inventing a
// program, and inventing one is how the wrong file gets signed as executed.
func programName(arg0 string) string {
	base := filepath.Base(arg0)
	if !windowsExecutableNames {
		return base
	}
	base = strings.ToLower(base)
	// On Windows filepath.Base already cuts at `\`. Doing it explicitly costs
	// nothing there and is what keeps this branch exercisable from a POSIX test
	// host, where Base treats a backslash as an ordinary filename character.
	if i := strings.LastIndexByte(base, '\\'); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, ".exe")
}

func flagSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// unionFlags merges flag sets into a fresh map, so a grammar built from a
// shared base cannot mutate that base.
func unionFlags(sets ...map[string]bool) map[string]bool {
	m := map[string]bool{}
	for _, s := range sets {
		for k := range s {
			m[k] = true
		}
	}
	return m
}

// verifiedShellSwitches is the set of options that were confirmed, BY RUNNING
// THE REAL BINARY, to still execute the operand on every shell this repo can
// probe: sh, bash, zsh, dash and ksh.
//
// One shared shellGrammar used to serve all six shells, which meant bash's own
// options were asserted for all of them. `dash --norc decoy.sh` exits on the
// unsupported option without opening decoy.sh, and the resolver hashed it
// anyway — signed evidence that a script ran when it provably did not. The
// probe found more than the review did: dash also rejects -h, -k, -p and -t.
//
// TestGrammarSwitchClaimsHoldAgainstRealInterpreters re-derives this from the
// live tables on every run, so an entry cannot be added back without proof.
var verifiedShellSwitches = flagSet("-e", "-x", "-u", "-v", "-l", "-i", "-a", "-b", "-m", "-E")

// shellUnresolvable is shared by every shell: these mean the same thing in all
// of them, and listing an option here is inert anyway (an unlisted option
// abstains too), so a wrong entry here cannot produce a wrong claim.
var shellUnresolvable = flagSet(
	"-c", // the program is the next token, not a path
	// -s makes the shell read its program from STDIN. Every remaining
	// operand is then a positional PARAMETER: `bash -s deploy.sh` passes
	// deploy.sh to the stdin script as $1 and executes nothing of that
	// name from disk.
	"-s",
	// -n is noexec: the shell reads and parses the script and never runs
	// it. The file is genuinely opened, so this is milder than the help
	// options below — but the field claims the script the command
	// EXECUTES, and under -n nothing was executed.
	"-n",
	// Exit before reading the operand at all.
	"--help", "--version",
)

// posixShellGrammar serves the shells that share only the verified core.
//
// `sh` gets this one for a reason worth stating: sh is not a program, it is a
// NAME. It is bash on macOS and dash on Debian, so a claim under that name is
// only safe if it holds for both — which is exactly what the verified set is.
// verifiedSetOptions are `set -o` names confirmed to still run the operand on
// every shell posixShellGrammar serves: sh, zsh, dash and ksh.
//
// pipefail is absent on purpose — dash has no such option and exits before the
// script runs, and `sh` may BE dash. noexec is absent for a different reason:
// POSIX names it, every shell accepts it, and it runs nothing. A specification
// would have admitted both.
var verifiedSetOptions = flagSet("errexit", "nounset", "xtrace", "verbose", "noglob", "allexport")

var posixShellGrammar = optionGrammar{
	switches: verifiedShellSwitches,
	enumeratedValueOptions: map[string]map[string]bool{
		"-o": verifiedSetOptions,
	},
	unresolvable:     shellUnresolvable,
	plusToggles:      true,
	longOptionsFirst: true,
}

// bashGrammar adds the options verified against bash specifically.
//
// -h is a SWITCH deliberately: POSIX specifies sh -h as hashall ("locate and
// remember utilities invoked by functions"), not help, and `bash -h build.sh`
// really does run build.sh — confirmed by the probe, not by reading. -v is
// likewise verbose, not version.
var bashGrammar = optionGrammar{
	switches: unionFlags(verifiedShellSwitches,
		flagSet("-h", "-k", "-p", "-t", "--posix", "--norc", "--noprofile")),
	// bash adds pipefail to the verified core; `bash -euo pipefail build.sh`
	// is the canonical CI idiom and it does run build.sh.
	enumeratedValueOptions: map[string]map[string]bool{
		"-o": unionFlags(verifiedSetOptions, flagSet("pipefail")),
	},
	unresolvable:     shellUnresolvable,
	plusToggles:      true,
	longOptionsFirst: true,
}

// unverifiedShellGrammar claims NO options at all.
//
// It is used for shells the probe harness could not run anywhere, so every
// option claim for them would rest on documentation — which is what produced
// this round's findings. The PROGRAM is still recognised, so `ash build.sh`
// resolves normally; only option-bearing invocations abstain. Missing evidence,
// which is the safe direction, instead of a guess that can be wrong.
var unverifiedShellGrammar = optionGrammar{
	unresolvable:     shellUnresolvable,
	plusToggles:      true,
	longOptionsFirst: true,
}

// interpreters maps an argv[0] basename to its argument grammar.
var interpreters = map[string]optionGrammar{
	"bash": bashGrammar,

	// Verified core only. zsh and ksh do accept a few of bash's extras, but
	// not the same few, and the difference is not worth a table each for
	// options this rare — the core is what every one of them ran.
	"sh": posixShellGrammar, "zsh": posixShellGrammar,
	"dash": posixShellGrammar, "ksh": posixShellGrammar,

	// Not installed anywhere the harness runs, so nothing about its options
	// has ever been checked.
	"ash": unverifiedShellGrammar,

	// One table per NAME, not one table for the language. pythonGrammar was
	// probed against python3 and nothing else; sharing it with the other two
	// spellings asserted python3's option set for interpreters that reject it.
	// See python2Grammar and pythonAmbiguousGrammar.
	"python": pythonAmbiguousGrammar, "python2": python2Grammar, "python3": pythonGrammar,

	"node":   nodeGrammar,
	"nodejs": nodeGrammar,

	"perl": {
		// -n and -p wrap the script in a read loop; it still executes. This is
		// the opposite of the shell's -n, which is noexec — the same letter
		// meaning "still runs" here and "never runs" there is exactly why the
		// grammar is per-interpreter.
		switches: flagSet("-w", "-W", "-n", "-p", "-l", "-a", "-T", "-U", "-s"),
		// -I takes a separate token; the probe confirms `perl -I . x.pl` runs.
		valueOptions: flagSet("-I"),
		// Attached only. `perl -M strict x.pl` and `perl -F , x.pl` are errors
		// perl exits on without running x.pl — verified, not assumed.
		attachedValueOptions: flagSet("-M", "-m", "-F"),
		unresolvable: flagSet(
			"-e", "-E", // inline code for perl, the opposite of bash
			"-x", // takes an OPTIONAL attached directory; see the -j note below
			"-c", // compile and exit: the script is parsed, never run
			// Print usage or version and exit without running the operand.
			"-h", "-v", "-V",
		),
	},
	"ruby": {
		switches: flagSet("-w", "-n", "-p", "-l", "-a", "-d"),
		// -I only. Its value is opaque — `ruby -I /nonexistent x.rb` still runs
		// x.rb, so no value can make the record wrong.
		valueOptions: flagSet("-I"),
		// Attached only: `ruby -F , x.rb` does not run x.rb.
		attachedValueOptions: flagSet("-F"),
		unresolvable: flagSet(
			"-e", // inline code
			// -C chdirs BEFORE resolving the script, so `ruby -C sub build.rb`
			// runs sub/build.rb. Resolving against the original workdir is not
			// a near miss: where both exist it hashes a real, wrong file.
			"-C",
			"-W", // optional attached level (-W2)
			"-c", // syntax check only: the script is parsed, never run
			// -r NAMES A LIBRARY and -E an encoding. Ruby resolves both before
			// running anything and exits when it cannot, so the value decides
			// whether the operand executes — and the valid values are every
			// installed library and every encoding name, which nothing here can
			// enumerate or verify.
			"-r", "-E",
			// -v prints the version and, with no script, exits. With a script
			// it also runs it — a split this resolver declines to model.
			"-v", "--version", "-h", "--help",
		),
	},
}

// pythonUnresolvable is shared by all three python spellings: these mean the
// same thing in 2.x and 3.x, and listing an option here is inert anyway (an
// unlisted option abstains too), so a wrong entry cannot produce a wrong claim.
var pythonUnresolvable = flagSet(
	"-c", // inline program text
	"-m", // names a MODULE, not a path on disk
	// Print usage or version and exit. `python3 -h decoy.py` never opens
	// decoy.py. The --help-* variants (3.11+) are unknown to this table and
	// therefore already abstain.
	"-h", "--help", "-V", "--version",
)

// pythonGrammar is PYTHON 3's grammar and is claimed for `python3` ALONE.
//
// Every entry below was probed against a real python3. Several of them do not
// exist in python 2.x at all — -I (3.4+), -q, -b, -X (3.2+) and
// --check-hash-based-pycs (3.7+) — and python 2 exits with an option error
// without ever opening the operand. `python2 --check-hash-based-pycs=default
// build.py` is the shape that made this concrete: the scan consumed the option
// and its value, recorded build.py, and hashed a file that never ran.
//
// The probe harness cannot catch that on its own. It SKIPS an interpreter the
// machine does not carry, and no machine this suite runs on carries python2 —
// so a table shared across the spellings ships its python3 claims unverified
// for the other two. One table per NAME is what keeps a claim attached to the
// binary it was actually checked against.
var pythonGrammar = optionGrammar{
	// -i inspects interactively AFTER running the script, and -v is verbose
	// import tracing: both still execute the operand.
	switches: flagSet("-B", "-E", "-i", "-I", "-O", "-q", "-s",
		"-S", "-u", "-v", "-x", "-d", "-b"),
	// -W and -X are opaque: python accepts an unrecognised value for either and
	// still runs the script, verified with deliberate garbage.
	valueOptions: flagSet("-W", "-X"),
	// --check-hash-based-pycs is validated by python, which exits on anything
	// outside this set.
	enumeratedValueOptions: map[string]map[string]bool{
		"--check-hash-based-pycs": flagSet("always", "default", "never"),
	},
	unresolvable: pythonUnresolvable,
}

// python2Grammar claims NO options, for the same reason unverifiedShellGrammar
// does: nothing about python 2's argument parsing has ever been checked by the
// probe, because python2 is absent from every machine this suite runs on.
//
// Documentation would let it claim more. Documentation is what produced the
// finding this grammar exists to answer, and the direction of the error is not
// symmetric: an option wrongly believed harmless makes the scan walk past a
// token python2 rejects, and the attestor then signs a script that provably
// never ran. Missing evidence is recoverable; false signed evidence is not.
//
// The PROGRAM is still recognised, so `python2 build.py` — the overwhelmingly
// common form — resolves exactly as before. Only option-bearing invocations
// abstain.
var python2Grammar = optionGrammar{unresolvable: pythonUnresolvable}

// pythonAmbiguousGrammar serves BARE `python`, which is a NAME rather than a
// program — the same problem `sh` has, and it takes the same answer.
//
// `python` is python 2.7 on RHEL 7/8, CentOS, Amazon Linux 1 and older Debian,
// and python 3 on everything current. A claim made under that name is only safe
// if it holds for BOTH, and the intersection cannot be established here: the
// probe can only ever run whichever one this machine installs, so verifying
// against a python3 named `python` says nothing about the python2 named
// `python` on the build host that actually matters.
//
// So it claims no options either. `python build.py` still resolves; `python -I
// build.py` no longer records a script that a python2 host would have refused
// to run.
var pythonAmbiguousGrammar = optionGrammar{unresolvable: pythonUnresolvable}

var nodeGrammar = optionGrammar{
	switches: flagSet("--no-warnings", "--trace-warnings",
		"--enable-source-maps", "--experimental-modules"),
	// No value options at all. Every one node has names a MODULE, which node
	// resolves before running the script and exits when it cannot — so the
	// value decides whether the operand executes, and the valid values are
	// every module specifier that could exist.
	unresolvable: flagSet(
		"-e", "--eval", "-p", "--print", // inline program text
		// Module-valued: see above. --loader and --import are here for the
		// same reason, and additionally could not be probed at all.
		"-r", "--require", "--loader", "--import",
		// Print usage or version and exit.
		"-h", "--help", "-v", "--version", "--v8-options",
		// -i forces the REPL open. Whether a file operand still runs alongside
		// it is not something this resolver can assert, so it declines.
		"-i", "--interactive",
	),
}

// makeGrammar is GNU make's option grammar, used by the SAME scanner as the
// interpreters. make had its own hand-rolled scan until `make -sfCustom.mk`
// showed what that costs: the cluster hid the -f, the scan found no explicit
// makefile, and implicit lookup signed a Makefile that make never opened.
var makeGrammar = optionGrammar{
	// RoleMakefile claims the file make READS, not a file it executes, so the
	// cut falls in a different place than for an interpreter. -n/--dry-run, -q
	// and -p all decline to run the recipes but still open and parse the
	// makefile, so they remain plain switches; the shell's -n, which never runs
	// the script it was handed, does not.
	switches: flagSet(
		"-b", "-B", "-d", "-e", "-i", "-k", "-L", "-m", "-n", "-p",
		"-q", "-r", "-R", "-s", "-S", "-t", "-w",
		"--always-make", "--check-symlink-times", "--dry-run",
		"--environment-overrides", "--ignore-errors", "--just-print",
		"--keep-going", "--no-builtin-rules", "--no-builtin-variables",
		"--no-keep-going", "--no-print-directory", "--print-data-base",
		"--print-directory", "--question", "--quiet", "--recon", "--silent",
		"--stop", "--touch", "--warn-undefined-variables",
	),
	valueOptions: flagSet(
		"-f", "--file", "--makefile",
		"-C", "--directory",
		"-I", "--include-dir",
		"-o", "--old-file", "--assume-old",
		"-W", "--what-if", "--new-file", "--assume-new",
	),
	unresolvable: flagSet(
		// Optional-argument options. GNU make takes the value from the
		// attached tail, or from the FOLLOWING token when that token looks
		// numeric — a peek this resolver deliberately does not model. Treating
		// one as a switch would misread `-j 4`'s operand as a goal; treating it
		// as a value option would let `-j -f ci.mk` swallow the -f and then
		// sign the implicit makefile. Refusing the invocation costs a record;
		// guessing costs correctness.
		"-j", "--jobs",
		"-l", "--load-average", "--max-load",
		"-O", "--output-sync",
		// Print usage or version and exit WITHOUT reading any makefile.
		// `make --version -f decoy.mk` never opens decoy.mk, so recording it
		// as an input of a successful command is false evidence.
		"-h", "--help", "-v", "--version",
		"--debug",
		// --eval arrived in GNU make 3.82 and the probe machine ships 3.81,
		// where it is an unknown option and make reads no makefile at all.
		// Unverifiable here, so it abstains rather than being taken on trust.
		"-E", "--eval",
	),
}

// implicitMakefiles is GNU make's search order for a makefile when no -f is
// given. Order is significant: make stops at the first that exists.
var implicitMakefiles = []string{"GNUmakefile", "makefile", "Makefile"}

// resolveScriptOperands inspects argv and returns the scripts and makefiles the
// command will execute, relative to workdir.
//
// WHAT A RESOLVED ScriptRef ASSERTS, AND WHAT IT DOES NOT.
//
// The claim is exactly: "this argv named this path as the program operand of a
// command whose argv[0] basename is <interpreter>". Two things it is NOT.
//
// It is not proof of what executed. The digest is taken before exec (see
// ScriptRef), and the path could be rewritten in between.
//
// It is not proof that the interpreter was the interpreter. The program is
// identified by the BASENAME of argv[0] and nothing here opens that binary or
// checks what it is. A wrapper installed as `bash`, or any executable of that
// name with different argument handling, is indistinguishable at this layer: it
// may ignore the operand entirely while this resolver records that operand as
// the executed script. That gap is not closable from inside this function —
// deciding whether an arbitrary executable on PATH "really is bash" has no
// bounded answer, and a heuristic (an expected path, a hash of the binary)
// would replace an honest limitation with a false assurance. The material for
// a verifier that cares is already in the signed predicate: argv[0] travels in
// CommandRun.Cmd, so a policy can require an expected absolute interpreter
// path, and where execution-time truth is needed ProcessInfo.OpenedFiles
// reports the inodes the tracee actually opened.
//
// Within that claim it is deliberately conservative: it reports a path only
// when EVERY token before the operand was positively classified against the
// program's own grammar, and reports nothing otherwise.
func resolveScriptOperands(argv []string, workdir string) []ScriptRef {
	return resolveScriptPlan(argv, workdir).refs
}

// scriptPlan is what an argv NAMED, together with the filesystem precondition
// that must hold for any of it to have been read.
//
// The two are separate because they are answered by different kinds of
// evidence. Which paths the argv named is a pure function of the argv and the
// grammar, and the tests that pin it must be able to ask it about trees that do
// not exist. Whether the command could have reached those paths is a fact about
// the disk, and it belongs where the evidence is MEASURED — a path that make
// never chdir'd to must not be hashed, however correctly it was composed.
type scriptPlan struct {
	refs []ScriptRef

	// requireDir is the effective `make -C` directory, empty when no -C was
	// given. GNU make chdirs into it BEFORE opening any makefile and exits 2
	// when it cannot, so if this directory is not there, nothing in refs was
	// read — including an ABSOLUTE -f, which composes to a real file that make
	// never opened.
	requireDir string
}

func resolveScriptPlan(argv []string, workdir string) scriptPlan {
	argv = stripEnvPrefix(argv)
	if len(argv) == 0 {
		return scriptPlan{}
	}

	prog := programName(argv[0])

	if grammar, ok := interpreters[prog]; ok {
		if op, ok := firstScriptOperand(argv[1:], grammar); ok {
			return scriptPlan{refs: []ScriptRef{{Path: op, Role: RoleInterpreterOperand}}}
		}
		return scriptPlan{}
	}
	if prog == "make" || prog == "gmake" {
		refs, requireDir := makefileOperands(argv[1:], workdir)
		return scriptPlan{refs: refs, requireDir: requireDir}
	}
	return scriptPlan{}
}

// stripEnvPrefix removes a leading `env` and any VAR=value assignments so that
// `env GOOS=linux bash build.sh` resolves the same as `bash build.sh`.
//
// This is not hypothetical: production command-run argv in this shape is how
// the wrapper scripts are invoked, and without it every one of them resolves to
// the program `env` and yields nothing.
func stripEnvPrefix(argv []string) []string {
	// An assignment is only skipped while parsing a CONFIRMED `env`. There is no
	// shell in a captured argv: `["FOO=bar","bash","decoy.sh"]` asks the kernel
	// to exec a program literally named "FOO=bar", which does not exist, so
	// nothing runs. Skipping it unconditionally invented an `env` that was never
	// there and then recorded decoy.sh as the executed script of a command that
	// could not even start.
	for len(argv) > 0 && programName(argv[0]) == "env" {
		argv = argv[1:]
		// Drop `env`'s own flags that take no operand. `-i`/`--ignore-
		// environment` is the common one; anything else with an operand we
		// bail on rather than mis-parse.
		for len(argv) > 0 && (argv[0] == "-i" || argv[0] == "--ignore-environment") {
			argv = argv[1:]
		}
		// Assignments belong to THIS env invocation. The loop repeats so
		// `env A=1 env B=2 bash x.sh` still reaches bash.
		for len(argv) > 0 && isEnvAssignment(argv[0]) {
			argv = argv[1:]
		}
	}
	return argv
}

// isEnvAssignment reports whether a token is a shell VAR=value assignment.
//
// The test is on the NAME, not the whole token: assignment values routinely
// contain slashes (`BIN=/tmp/tmp.Zt2PWVy655/cilock` is a verbatim production
// example), so rejecting anything path-shaped drops the very assignments this
// function exists to skip.
func isEnvAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range tok[:eq] {
		isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
		isDigit := r >= '0' && r <= '9'
		if !isAlpha && !(isDigit && i > 0) {
			return false
		}
	}
	return true
}

// argToken is one POSITIVELY CLASSIFIED argv token: an option, with its value
// when it has one, or an operand.
type argToken struct {
	// option is the canonical option name ("-f", "--file"), empty for an
	// operand.
	option string
	// value is the option's value, or the operand itself.
	value string
}

func (t argToken) isOperand() bool { return t.option == "" }

// scanArgs classifies every token in args against one program's grammar.
//
// ok=false means ABSTAIN, and it is returned for the first token the grammar
// cannot account for: an unknown option, an unknown member of a cluster, a `+`
// token where `+` introduces no option, an attached value on an option that
// takes none, an option the grammar marks unresolvable, or an option promising
// a value the argv does not carry.
//
// There is deliberately no partial result. An unclassified token may itself
// consume the token after it, so everything beyond it is unanchored and naming
// any of it is a guess — which is precisely how this resolver signed files that
// the command never opened. Callers must treat !ok as "record nothing", never
// as "fall back to a default".
//
// stopAtFirstOperand ends the scan at the first operand. Interpreters need it:
// everything after the script belongs to the script, and those arguments follow
// a grammar this resolver has no knowledge of. make does not: its options,
// goals and variable assignments are interleaved.
func scanArgs(args []string, g optionGrammar, stopAtFirstOperand bool) ([]argToken, bool) {
	var out []argToken
	endOfOptions := false
	sawShortOption := false

	for i := 0; i < len(args); i++ {
		tok := args[i]

		// `--` ends option parsing for every program modelled here. After it
		// `make -- -f Custom.mk` treats both tokens as goals and reads the
		// implicit makefile, while `bash -- build.sh` runs build.sh.
		if !endOfOptions && tok == "--" {
			endOfOptions = true
			continue
		}

		if endOfOptions || isOperandToken(tok) {
			out = append(out, argToken{value: tok})
			if stopAtFirstOperand {
				return out, true
			}
			continue
		}

		var consumesNext, ok bool
		if strings.HasPrefix(tok, "--") {
			if g.longOptionsFirst && sawShortOption {
				// Bash only recognises long options ahead of every short one;
				// here it reports "--: invalid option" and never runs the
				// operand, so nothing beyond this token is a script it ran.
				return nil, false
			}
			out, consumesNext, ok = appendLongOption(out, tok, g)
		} else {
			sawShortOption = true
			out, consumesNext, ok = appendShortCluster(out, tok, g)
		}
		if !ok {
			return nil, false
		}
		if consumesNext {
			if i+1 >= len(args) {
				// The option promised a value the argv does not have. The
				// invocation is malformed for the program too; guessing what
				// it meant is not this resolver's job.
				return nil, false
			}
			i++
			out[len(out)-1].value = args[i]
		}

		// Enumerated values are checked HERE rather than inside the classifiers
		// so the attached and separate spellings get the same treatment: by
		// this point the value is known whichever way it was written.
		last := out[len(out)-1]
		if values, enumerated := g.enumeratedValueOptions[last.option]; enumerated && !values[last.value] {
			return nil, false
		}
	}
	return out, true
}

// isOperandToken reports whether a token is a plain operand rather than
// something that must be classified against a grammar.
//
// A bare "-" is the conventional stdin operand and never an option. Everything
// else beginning with "-" OR "+" is option-shaped. The `+` half is not
// theoretical: testing only for a leading "-" is what made `bash +o errexit
// build.sh` record "+o" — an option the grammar already listed — as the
// executed script.
func isOperandToken(tok string) bool {
	if tok == "-" {
		return true
	}
	return !strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "+")
}

// appendLongOption classifies a `--name` or `--name=value` token.
func appendLongOption(out []argToken, tok string, g optionGrammar) ([]argToken, bool, bool) {
	name, value := tok, ""
	attached := false
	if eq := strings.IndexByte(tok, '='); eq > 0 {
		name, value, attached = tok[:eq], tok[eq+1:], true
	}

	switch {
	case g.unresolvable[name]:
		return nil, false, false
	case g.valueOptions[name], g.enumeratedValueOptions[name] != nil:
		// scanArgs checks an enumerated value once it is known, so both take
		// the same path here.
		return append(out, argToken{option: name, value: value}), !attached, true
	case g.attachedValueOptions[name]:
		if !attached {
			// The program requires the value attached and errors out without
			// it; nothing after this token is the operand it ran.
			return nil, false, false
		}
		return append(out, argToken{option: name, value: value}), false, true
	case g.switches[name] && !attached:
		return append(out, argToken{option: name}), false, true
	default:
		// An unknown option, or an attached value on an option that takes
		// none: either way a form this grammar does not model.
		return nil, false, false
	}
}

// appendShortCluster classifies a single-dash — or, for a shell, single-plus —
// token as a cluster of one-letter options.
//
// `-e` and `-euo` are the same shape, so they take the same path: treating a
// short token as one opaque flag is what let a clustered value-taking option
// swallow the script (`-euo pipefail build.sh` recorded "pipefail") and what
// hid the -f inside `make -sfCustom.mk`.
func appendShortCluster(out []argToken, tok string, g optionGrammar) ([]argToken, bool, bool) {
	if tok[0] == '+' && !g.plusToggles {
		return nil, false, false // `+` introduces no option for this program
	}
	letters := tok[1:]
	if letters == "" {
		return nil, false, false // a bare introducer names no option
	}

	for i := 0; i < len(letters); i++ {
		// A shell's `+x` is the disable form of `-x` and `+o` takes a value
		// exactly as `-o` does, so the introducer is normalised away and one
		// table serves both.
		name := "-" + string(letters[i])
		tail := letters[i+1:]

		switch {
		case g.unresolvable[name]:
			return nil, false, false
		case g.valueOptions[name], g.enumeratedValueOptions[name] != nil:
			// GNU style: the value is the rest of the cluster when there is
			// one (`-fCustom.mk`, `-opipefail`), otherwise the next token
			// (`-euo pipefail`, `-sf Custom.mk`). scanArgs validates an
			// enumerated value after either spelling has produced one.
			return append(out, argToken{option: name, value: tail}), tail == "", true
		case g.attachedValueOptions[name]:
			// Attached only. `perl -Mstrict build.pl` runs build.pl; `perl -M
			// strict build.pl` is an error perl exits on, so consuming the next
			// token and naming what follows would record a script that never
			// ran.
			if tail == "" {
				return nil, false, false
			}
			return append(out, argToken{option: name, value: tail}), false, true
		case g.switches[name]:
			out = append(out, argToken{option: name})
		default:
			return nil, false, false // unknown member: abstain
		}
	}
	return out, false, true
}

// firstScriptOperand finds the script path among an interpreter's arguments.
//
// ok=false — abstain — covers three cases that must not be distinguishable in
// the output: the scan met something it could not account for, the argv named
// no operand at all, or the operand is the stdin marker.
func firstScriptOperand(args []string, g optionGrammar) (string, bool) {
	toks, ok := scanArgs(args, g, true)
	if !ok || len(toks) == 0 {
		return "", false
	}

	last := toks[len(toks)-1]
	if !last.isOperand() {
		return "", false // options only: nothing was named to run
	}
	if last.value == "-" {
		// A bare "-" is the stdin program for every interpreter modelled here.
		// It is not a file: recording it invents a path that never existed.
		return "", false
	}
	return last.value, true
}

// makefileOperands resolves `make -f X` or make's implicit makefile search.
//
// A failed scan returns NOTHING and must never fall through to implicit
// lookup. That fall-through is the dangerous half: an option the scan could not
// account for may have been an -f, and implicit lookup would then hash whatever
// default makefile happens to be on disk and sign it as the one make read.
// The second return value is the effective -C directory that must exist for any
// returned path to have been read; see scriptPlan.requireDir.
func makefileOperands(args []string, workdir string) ([]ScriptRef, string) {
	toks, ok := scanArgs(args, makeGrammar, false)
	if !ok {
		return nil, ""
	}

	// `make -C dir` changes directory before reading a makefile. Ignoring it
	// hashes the caller's Makefile while make actually reads dir/Makefile —
	// signed evidence pointing at a file the build never read. Later -C
	// options are relative to earlier ones, matching GNU make, and -f paths
	// resolve against the directory they all compose to.
	dir := workdir
	// sawChdir, not `dir != workdir`: `make -C .` composes back to the same
	// directory but is still a chdir make performs and can still fail.
	sawChdir := false
	var explicit []string
	for _, t := range toks {
		switch t.option {
		case "-C", "--directory":
			if t.value == "" {
				// `make --directory=` / `make -C ""` is not a no-op: make
				// refuses it ("the `-C' option requires a non-empty string
				// argument"), exits 2, and reads no makefile at all. Treating
				// it as "stay put" and carrying on named a makefile the build
				// never opened — including via implicit lookup, which is why
				// this abstains for the whole invocation rather than skipping
				// the option.
				return nil, ""
			}
			dir = joinUnderBase(dir, t.value)
			sawChdir = true
		case "-f", "--file", "--makefile":
			// GNU make reads EVERY -f it is given, in order. Overwriting here
			// signed only the last one and silently omitted the rest.
			if t.value == "" {
				return nil, "" // `--file=` names nothing; there is no honest answer
			}
			explicit = append(explicit, t.value)
		}
	}

	// The chdir is a precondition on EVERY path below, so it travels with them
	// rather than being checked here: this function stays a pure composition of
	// argv and grammar, and the tests that pin that composition go on asking it
	// about directory trees that do not exist.
	requireDir := ""
	if sawChdir {
		requireDir = dir
	}

	if len(explicit) > 0 {
		// -f paths resolve relative to the -C directory, as make does.
		refs := make([]ScriptRef, 0, len(explicit))
		for _, e := range explicit {
			if e == "-" {
				// `make -f -` reads the makefile from stdin. There is no file
				// to hash, and an explicit -f means implicit lookup must NOT
				// run either — falling through would sign a default Makefile
				// make never read.
				continue
			}
			refs = append(refs, ScriptRef{Path: joinUnderBase(dir, e), Role: RoleMakefile})
		}
		return refs, requireDir
	}

	// Implicit lookup. Report a makefile only where one exists: naming
	// "Makefile" when none is present fabricates a path the build never read.
	for _, name := range implicitMakefiles {
		candidate := name
		if dir != "" {
			// rawJoin, not Join: dir may carry a `..` that only the kernel can
			// resolve correctly (see joinUnderBase).
			candidate = rawJoin(dir, name)
		}
		if fi, err := os.Stat(candidate); err == nil && fi.Mode().IsRegular() {
			return []ScriptRef{{Path: candidate, Role: RoleMakefile}}, requireDir
		}
	}
	return nil, ""
}

// joinUnderBase resolves rel against base, leaving an absolute rel untouched.
//
// It deliberately does NOT use filepath.Join. Join calls Clean, and Clean
// removes `..` LEXICALLY — it deletes the preceding component from the string
// without knowing what that component is. The kernel does the opposite: it
// follows the component first and applies `..` to wherever it landed. With
// `link -> /other/sub`, `link/../x.mk` is /other/x.mk to the kernel and
// /work/x.mk after Clean. Collapsing here would destroy the information before
// anything can resolve it correctly, so the raw form is carried through and
// hydrateScriptRef hands it to the OS intact.
func joinUnderBase(base, rel string) string {
	if rel == "" {
		return base
	}
	if filepath.IsAbs(rel) || base == "" {
		return rel
	}
	return rawJoin(base, rel)
}

// rawJoin concatenates two path segments WITHOUT cleaning them.
//
// The separator handling is the only normalisation performed: no `..` removal,
// no `.` removal. See joinUnderBase for why.
func rawJoin(base, rel string) string {
	sep := string(filepath.Separator)
	if strings.HasSuffix(base, sep) {
		return base + rel
	}
	return base + sep + rel
}

// hasParentTraversal reports whether any component of p is "..".
//
// This is the ONLY construct filepath.Clean handles differently from the
// kernel. Clean also drops "." components and duplicate separators, and neither
// changes which file is opened — so paths without `..` can still be cleaned
// safely, and only these need the OS asked.
func hasParentTraversal(p string) bool {
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	return false
}

// captureScriptRefs resolves argv operands and populates digests, and content
// when the mode asks for it.
//
// Call this BEFORE running the command: wrapper scripts written to a temp
// directory are frequently deleted by the caller once the step finishes, and a
// post-run capture would find nothing and report every one of them unresolved.
func captureScriptRefs(ctx context.Context, argv []string, workdir string, mode ScriptCaptureMode) []ScriptRef {
	refs, _ := captureScriptRefsWithBudget(ctx, argv, workdir, mode)
	return refs
}

// captureScriptRefsWithBudget is captureScriptRefs plus the spent budget, so a
// test can assert what was actually READ rather than only what was recorded.
// Those differ precisely when dedupe is broken, and the recorded output looks
// identical either way.
func captureScriptRefsWithBudget(ctx context.Context, argv []string, workdir string, mode ScriptCaptureMode) ([]ScriptRef, *captureBudget) {
	budget := newCaptureBudget()
	if mode == ScriptCaptureOff {
		return nil, budget
	}
	plan := resolveScriptPlan(argv, workdir)

	// Every ref leaves this function UNVERIFIED. Binding is something only the
	// post-execution trace can grant, so capture-time code must never be able
	// to emit anything stronger — a default of "verified" that a later step
	// forgets to downgrade is the exact failure this field exists to prevent,
	// and it would fail in the unsafe direction.
	for i := range plan.refs {
		plan.refs[i].ExecutionBinding = ScriptBindingUnverified
	}

	// The chdir make performs BEFORE it opens anything is a precondition on
	// every path this argv named. When it cannot succeed make exits 2 having
	// read nothing, so measuring any of those paths would attach a real digest
	// to a file this command demonstrably never opened.
	//
	// The relative--f case degraded correctly by accident — the composed path
	// does not resolve either — which is what made the ABSOLUTE case easy to
	// miss: `make -C missing -f /etc/real.mk` composes to a file that very much
	// exists, and hashing it produced exactly the false signed evidence this
	// resolver exists to prevent.
	if reason, blocked := chdirBlocksRead(plan.requireDir); blocked {
		for i := range plan.refs {
			attempted, absolute := absoluteAttemptedPath(plan.refs[i].Path, workdir)
			plan.refs[i].Path = attempted
			plan.refs[i].PathUnresolvable = !absolute
			plan.refs[i].Unresolved = reason
		}
		return plan.refs, budget
	}

	for i := range plan.refs {
		hydrateScriptRef(ctx, &plan.refs[i], workdir, mode, budget)
	}
	return plan.refs, budget
}

// chdirBlocksRead reports whether make's effective -C directory is one make
// could not have entered, and the reason to record when it is not.
//
// This is a filesystem fact rather than an argv fact, which is why it lives here
// and not in the grammar: `-o pipefail` is decidable from the argv alone, so the
// resolver is obliged to know it, while whether a directory exists can only be
// answered by looking. Looking is cheap, it happens once per capture, and the
// alternative is signing a makefile that was never opened.
func chdirBlocksRead(requireDir string) (string, bool) {
	if requireDir == "" {
		return "", false
	}

	// requireDir is already composed against the caller's workdir inside
	// makefileOperands, so anything still relative here is relative to this
	// process — the same base the kernel would use for the command itself.
	abs, _ := absoluteAttemptedPath(requireDir, "")

	fi, err := os.Stat(abs)
	switch {
	case err == nil && fi.IsDir():
		return "", false
	case err != nil && errors.Is(err, os.ErrNotExist):
		return fmt.Sprintf(
			"not measured: make changes directory to %q before opening any "+
				"makefile and that directory does not exist, so make exits "+
				"without reading this file", abs), true
	case err != nil:
		return fmt.Sprintf(
			"not measured: make changes directory to %q before opening any "+
				"makefile and that directory could not be examined: %v", abs, err), true
	default:
		return fmt.Sprintf(
			"not measured: make changes directory to %q before opening any "+
				"makefile and that path is not a directory (mode %s), so make "+
				"exits without reading this file", abs, fi.Mode()), true
	}
}

// captureBudget is the whole capture pass's allowance, shared by every operand
// in one argv.
//
// A per-operand ceiling bounds one file and nothing else: `make -f big.mk`
// repeated a thousand times is a thousand argv tokens and a thousand full
// rehashes, all before runCmd, where no command timeout applies. That is the
// same wedge as the FIFO open and the unbounded read, reached a third way — by
// VOLUME rather than by any single item — so the bound belongs to the pass, not
// to the item.
//
// measured also makes the pass idempotent per file: a path already hydrated is
// copied, not re-read, which is what collapses the repeated-operand case from
// N reads to one.
type captureBudget struct {
	// remaining is the aggregate byte allowance left for this pass.
	remaining int64
	// measured maps a RESOLVED absolute path to its finished ref. Failures are
	// cached too — re-stat'ing a missing file a thousand times is the same
	// amplification in miniature.
	measured map[string]ScriptRef
	// hydrations counts operands whose bytes were actually read. Repeats of an
	// already-measured path do not increment it.
	hydrations int
	// bytesRead totals the bytes read across the pass.
	bytesRead int64
}

func newCaptureBudget() *captureBudget {
	return &captureBudget{
		remaining: maxCaptureTotalBytes,
		measured:  make(map[string]ScriptRef),
	}
}

// spend charges n bytes to the pass allowance.
//
// remaining saturates at zero. A plain subtraction let it go negative, and a
// negative allowance is not merely untidy: it is what the NEXT operand's read
// ceiling is computed from, so the overdraft compounded silently instead of
// stopping the pass.
func (b *captureBudget) spend(n int64) {
	b.bytesRead += n
	if n >= b.remaining {
		b.remaining = 0
		return
	}
	b.remaining -= n
}

// budgetExhaustedReason is the single wording for an operand the pass-wide
// allowance cannot pay for, whether that was discovered before opening the file
// or part-way through reading it. One message, because the operator's response
// is the same either way: this argv asked for too much in total.
func budgetExhaustedReason() string {
	return fmt.Sprintf(
		"capture budget exhausted: this argv may read at most %d bytes in "+
			"total across all operands; nothing was measured for this one",
		maxCaptureTotalBytes)
}

// hydrateScriptRef fills in size, digest and optional content for one ref.
//
// Everything is read through a SINGLE open file handle. Taking size from a
// Stat, the digest from a second open, and the bytes from a third lets a
// concurrent rewrite or a symlink swap produce a ScriptRef whose fields come
// from different files — a self-consistent-looking record describing something
// that never existed. One descriptor pins one inode for all three reads.
func hydrateScriptRef(ctx context.Context, ref *ScriptRef, workdir string, mode ScriptCaptureMode, budget *captureBudget) {
	abs, ok := resolveCapturePath(ctx, ref, workdir)
	if !ok {
		return // resolveCapturePath recorded why
	}

	// Same file, named twice in one argv: copy the measurement instead of
	// re-reading it. `make -f big.mk` repeated a thousand times must cost one
	// read, not a thousand. Keyed on the RESOLVED path, so `-f a.mk -f ./a.mk`
	// collapses too.
	if done, seen := budget.measured[abs]; seen {
		role := ref.Role // this occurrence's role, not the first one's
		*ref = done
		ref.Role = role
		return
	}

	measureScriptRef(ctx, ref, abs, mode, budget)

	// Cached on EVERY outcome, including failures: re-stat'ing a missing file
	// once per occurrence is the same amplification in miniature.
	budget.measured[abs] = *ref
}

// absoluteAttemptedPath turns an operand into the absolute path the attestor is
// about to look for. It deliberately does NOT resolve `..` — that is the OS's
// job, a few lines further on — and so it cannot be used as the final path.
//
// ok=false means there is no absolute form to be had: nothing supplied a
// working directory and the process cannot report its own. The best-known form
// comes back anyway, because "this token was attempted" is still information —
// but the caller must MARK it rather than let it pass as a location.
func absoluteAttemptedPath(operand, workdir string) (string, bool) {
	p := operand
	if !filepath.IsAbs(p) && workdir != "" {
		p = rawJoin(workdir, p)
	}
	if filepath.IsAbs(p) {
		return p, true
	}

	// Either no workdir at all, or one that is itself relative. Both resolve
	// against THIS process's working directory: that is where runCmd runs a
	// command it was given no directory for, so it is the base the kernel would
	// use, not a guess this function is making.
	cwd, err := getwd()
	if err != nil {
		return p, false
	}
	return rawJoin(cwd, p), true
}

// resolveCapturePath turns a ref's operand into the absolute path to measure,
// or records why it cannot and returns false. Either way it leaves ref.Path
// holding the best absolute form known at that point.
func resolveCapturePath(ctx context.Context, ref *ScriptRef, workdir string) (string, bool) {
	// Record WHAT WAS ATTEMPTED before anything that can fail.
	//
	// Every exit below emits a ScriptRef whose entire content is "this file
	// could not be measured", and a Path still holding the argv token cannot
	// carry that claim: "build.sh" is indistinguishable from a successfully
	// resolved relative path, so the record names an operand where a verifier
	// needs a file. Assigning only after a successful open — which is what this
	// used to do — left every failing path reporting the unresolved token.
	attempted, absolute := absoluteAttemptedPath(ref.Path, workdir)
	ref.Path = attempted
	ref.PathUnresolvable = !absolute
	if !absolute {
		ref.Unresolved = fmt.Sprintf(
			"cannot locate operand %q: no working directory was supplied and the "+
				"process cannot report its own, so there is no absolute path to "+
				"record; the path above is the argv operand, not a location", attempted)
		return "", false
	}

	if err := ctx.Err(); err != nil {
		ref.Unresolved = fmt.Sprintf("capture aborted before reading: %v", err)
		return "", false
	}

	abs := attempted

	// `..` is resolved by the OS, never by this package.
	//
	// filepath.Clean would remove it lexically, which names a different file
	// than the kernel opens whenever a symlinked directory precedes it — an
	// ordinary shape in build scripts, needing no attacker and no race. Rather
	// than reimplement kernel path resolution (symlink chains, ELOOP limits,
	// relative targets, mount points — a resolver of its own, wrong in its own
	// ways), the work is DELEGATED: EvalSymlinks walks the path component by
	// component the way the kernel does. Where the OS cannot answer, this
	// abstains rather than emit a path it cannot stand behind.
	//
	// Paths without `..` keep the old lexical Clean, which only drops "." and
	// duplicate separators — neither changes which file is opened.
	if hasParentTraversal(abs) {
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			ref.Unresolved = fmt.Sprintf(
				"cannot resolve %q through its parent traversal: %v", abs, err)
			return "", false
		}
		abs = resolved
	} else {
		abs = filepath.Clean(abs)
	}

	// The resolved form supersedes the attempted one now that the OS has
	// answered. Everything downstream fails against THIS path, so this is the
	// path those failures must report.
	ref.Path = abs
	return abs, true
}

// measureScriptRef opens abs and fills in size, digest and optional content,
// spending the pass's shared budget.
//
// ref.Path already holds abs: resolveCapturePath establishes it before anything
// that can fail, so every abstain below reports the file it was about and this
// function never has to assign it.
func measureScriptRef(ctx context.Context, ref *ScriptRef, abs string, mode ScriptCaptureMode, budget *captureBudget) {
	// Stop the pass BEFORE the I/O, not after it. Discovering exhaustion from
	// the result of a read means the read was already paid for, and with the
	// allowance at zero every further distinct operand still opened its file and
	// pulled one full hash buffer — so an argv naming enough operands read far
	// past the ceiling the ceiling exists to enforce. Once there is nothing left
	// to spend there is nothing to learn from opening anything.
	if budget.remaining <= 0 {
		ref.Unresolved = budgetExhaustedReason()
		return
	}

	// Look BEFORE opening. Opening a FIFO for reading blocks until a writer
	// appears, and this runs before the command starts — outside the command's
	// own timeout, outside context cancellation — so an argv naming a FIFO
	// wedges the attestor, and the build, with no signal about why. A blocking
	// open also disturbs an existing writer, which is a side effect an attestor
	// has no business having on the thing it is measuring. This check keeps the
	// ordinary case from touching a pipe at all.
	fi, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ref.Unresolved = "file does not exist at attest time"
		} else {
			ref.Unresolved = fmt.Sprintf("stat failed: %v", err)
		}
		return
	}
	if !fi.Mode().IsRegular() {
		ref.Unresolved = fmt.Sprintf("not a regular file (mode %s)", fi.Mode())
		return
	}

	// That stat is advisory ONLY. The path can be swapped between the stat and
	// the open, so stat-then-open is its own time-of-check/time-of-use gap —
	// and here the consequence of losing that race is a hang, not just a wrong
	// answer. O_NONBLOCK removes the hang outright: it makes the open itself
	// incapable of blocking on a pipe that arrived in the window, and it is a
	// no-op for the regular files this is meant to read.
	f, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: path came from the argv of the command being attested
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ref.Unresolved = "file does not exist at attest time"
		} else {
			ref.Unresolved = fmt.Sprintf("open failed: %v", err)
		}
		return
	}
	defer func() { _ = f.Close() }()

	// The AUTHORITATIVE check, on the DESCRIPTOR rather than the path: a
	// path-based stat can describe a different file than the one now held open,
	// so whatever the pre-check said, what matters is what we actually have.
	fi, err = f.Stat()
	if err != nil {
		ref.Unresolved = fmt.Sprintf("stat failed: %v", err)
		return
	}
	if !fi.Mode().IsRegular() {
		ref.Unresolved = fmt.Sprintf("not a regular file (mode %s)", fi.Mode())
		return
	}

	// ONE streaming pass produces digest, size and content together.
	//
	// Holding a descriptor pins the inode, not its contents: a hash-then-seek-
	// then-reread sequence can still be overtaken by an in-place rewrite, and
	// a stat-derived size can describe bytes neither the digest nor the
	// content saw. Teeing the hash input is the only arrangement where all
	// three provably describe the same bytes.
	counter := &byteCounter{}
	sink := io.Writer(counter)
	var body *cappedBuffer
	var text *utf8Validator
	if mode == ScriptCaptureContent {
		body = &cappedBuffer{limit: maxScriptContentBytes}
		// ContentOmittedBinary claims something about the FILE, so it is
		// computed from the file. Deriving it from body's retained prefix made
		// a whole-file claim out of a 256 KiB sample. Only content mode pays
		// for this; identity mode's sink is unchanged.
		text = &utf8Validator{valid: true}
		sink = io.MultiWriter(counter, body, text)
	}

	// The read is bounded and interruptible. Both matter here and nowhere else
	// in the attestor: this runs BEFORE the command starts, so neither the
	// command timeout nor its cancellation can reach it.
	//
	// Two ceilings apply, and the tighter one wins. Which one it was has to be
	// recorded, because "this file is too big" and "this argv asked for too
	// much in total" call for different operator responses.
	limit, hitAggregate := maxScriptDigestBytes, false
	if budget.remaining < limit {
		limit, hitAggregate = budget.remaining, true
	}

	guarded := &boundedReader{r: f, ctx: ctx, limit: limit}
	digest, err := cryptoutil.CalculateDigestSet(io.TeeReader(guarded, sink), defaultScriptDigests())

	// Spend what was read whether or not it produced a digest: an abandoned
	// read still cost the I/O this budget exists to bound.
	budget.spend(guarded.read)
	budget.hydrations++

	if err != nil {
		// Nothing measured is trustworthy if the stream failed part-way, so
		// report the failure rather than a size from a partial read. Every
		// branch below returns WITHOUT setting Digest, SizeBytes or Content: a
		// digest over the bytes read before giving up would describe a prefix
		// while claiming to identify the file.
		switch {
		case errors.Is(err, errScriptTooLarge) && hitAggregate:
			ref.Unresolved = budgetExhaustedReason()
		case errors.Is(err, errScriptTooLarge):
			ref.Unresolved = fmt.Sprintf(
				"exceeds the %d-byte per-operand capture ceiling; nothing was measured "+
					"rather than a digest over a prefix", maxScriptDigestBytes)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			ref.Unresolved = fmt.Sprintf("capture aborted mid-read: %v", err)
		default:
			ref.Unresolved = fmt.Sprintf("digest failed: %v", err)
		}
		return
	}
	ref.Digest = digest
	ref.SizeBytes = counter.n

	if body == nil {
		return
	}
	if !text.complete() {
		// A binary "script" is not something an operator asked to read, and
		// embedding raw bytes in JSON helps nobody. Judged over the WHOLE file,
		// so a file whose first 256 KiB happen to be text is not recorded as a
		// truncated text script.
		ref.ContentOmittedBinary = true
		return
	}
	// Trim a rune the cap sliced in half.
	//
	// The buffer stops at exactly maxScriptContentBytes, which can land inside
	// a multibyte character. Emitting that byte string would put a broken rune
	// at the end of the embedded body even though the file itself is fine.
	captured := body.buf.Bytes()
	if counter.n > int64(maxScriptContentBytes) {
		captured = trimPartialRune(captured)
	}
	ref.Content = string(captured)
	ref.ContentTruncated = counter.n > int64(maxScriptContentBytes)
}

// classifyBinding compares the digest captured before exec against a digest the
// process trace observed for the same path, and returns what may honestly be
// claimed.
//
// The three-way answer is the point. cryptoutil's DigestSet.Equal is a two-way
// predicate and returns FALSE for "no shared algorithm to compare on" as well as
// for "the bytes differ" — collapsing a blind spot into a positive accusation.
// Using it alone would report MISMATCH whenever the trace happened to record a
// different algorithm than the capture did, dropping a perfectly good digest and
// crying tamper at a build that did nothing wrong. Comparability has to be
// established before disagreement can mean anything.
//
// The downgrade rule is still cryptoutil's. Once a shared algorithm agrees, this
// defers to Equal for the verdict, so a match on a weak algorithm cannot stand
// in for a strong one that only one side carries (GHSA-pgpm-j729-qcvh). Where
// Equal declines on those grounds the answer is UNVERIFIED, not VERIFIED — a
// binding this function cannot fully stand behind is not a binding.
func classifyBinding(captured, observed cryptoutil.DigestSet) ScriptExecutionBinding {
	shared, disagreed := 0, false
	for alg, capturedHex := range captured {
		observedHex, ok := observed[alg]
		if !ok {
			continue
		}
		shared++
		if capturedHex != observedHex {
			disagreed = true
		}
	}

	switch {
	case shared == 0:
		// Nothing in common to compare. That is ignorance, not evidence of
		// tampering, and it must not read as either a match or an accusation.
		return ScriptBindingUnverified
	case disagreed:
		return ScriptBindingMismatch
	case captured.Equal(observed):
		return ScriptBindingVerified
	default:
		// Shared algorithms agreed, but Equal withheld the verdict — the
		// strongest algorithm present is carried by only one side. Claiming a
		// binding here is the downgrade this defends against.
		return ScriptBindingUnverified
	}
}

// bindScriptsToTrace upgrades or retracts each script's binding using what the
// process trace actually observed. It runs AFTER the command, because that is
// the only moment execution-time evidence exists.
//
// Absence is never a match. A path the trace did not record — tracing off, a
// non-Linux host, a read the tracer skips, or a key recorded in a different form
// than the capture resolved — leaves the ref UNVERIFIED. The lookup is an exact
// key match on purpose: the backends key OpenedFiles differently (ptrace records
// the raw relative token, fanotify a fully symlink-resolved path), and inventing
// a fuzzy match across those forms to win more "verified" answers would let one
// file's digest be credited to another file's path.
//
// There is deliberately NO re-measurement fallback. Re-opening the path after
// the run and comparing is not a weaker binding, it is an unsound one: a file
// swapped and swapped back matches, and the wrapper scripts this attestor most
// wants to bind are routinely deleted by then. It would manufacture assurance
// rather than provide it.
func (rc *CommandRun) bindScriptsToTrace() {
	if len(rc.Scripts) == 0 || !rc.enableTracing {
		return
	}

	for i := range rc.Scripts {
		ref := &rc.Scripts[i]
		if len(ref.Digest) == 0 {
			continue // nothing was measured, so there is nothing to bind
		}

		observed, seen := rc.tracedReadDigest(ref.Path)
		if !seen {
			continue // stays unverified
		}

		switch classifyBinding(ref.Digest, observed) {
		case ScriptBindingVerified:
			ref.ExecutionBinding = ScriptBindingVerified
		case ScriptBindingMismatch:
			// FAIL CLOSED. The bytes that ran are not the bytes measured, so
			// every field derived from that measurement is retracted rather
			// than published alongside a warning: a signed digest travels
			// further than the caveat next to it.
			ref.ExecutionBinding = ScriptBindingMismatch
			ref.Digest = nil
			ref.SizeBytes = 0
			ref.Content = ""
			ref.ContentTruncated = false
			ref.ContentOmittedBinary = false
			ref.Unresolved = "not measured: the process trace observed this path " +
				"being read with different bytes than were captured before exec, so " +
				"the captured digest describes a file this command did not run and " +
				"has been withheld"
		case ScriptBindingUnverified:
			// Comparability failed, not the comparison. Leave the capture-time
			// measurement standing, still labelled unverified.
		}
	}
}

// tracedReadDigest returns the digest the trace recorded for a path being read
// during the run.
//
// It searches every traced process: a script handed to a shell is frequently
// opened by a CHILD of the process the attestor launched, so scoping this to the
// top-level process would report "not seen" for the ordinary case.
func (rc *CommandRun) tracedReadDigest(path string) (cryptoutil.DigestSet, bool) {
	if path == "" {
		return nil, false
	}
	for i := range rc.Processes {
		if ds, ok := rc.Processes[i].OpenedFiles[path]; ok && len(ds) > 0 {
			return ds, true
		}
	}
	return nil, false
}

// utf8Validator reports whether EVERYTHING written to it is valid UTF-8.
//
// It exists because ContentOmittedBinary names a property of the file while the
// only bytes retained anywhere are the first maxScriptContentBytes. Judging the
// file by that prefix made the flag's name overstate its evidence: a file that
// is text for 256 KiB and binary afterwards came back flagged as valid text.
//
// The bytes already stream past for the digest, so validating them costs CPU
// and no additional I/O.
type utf8Validator struct {
	valid bool
	// pending holds the 1-3 leading bytes of a rune that a chunk boundary cut
	// in half. Without it every multibyte rune landing on a ~32 KiB io.Copy
	// boundary would read as invalid, and large UTF-8 scripts would stop being
	// embedded for a reason that has nothing to do with their contents.
	pending []byte
}

// complete reports whether the whole stream was valid UTF-8. Bytes still held
// back as an incomplete rune mean the file ENDED mid-character, which is not
// valid UTF-8 either — so a truncated-rune tail is binary, not text.
func (v *utf8Validator) complete() bool { return v.valid && len(v.pending) == 0 }

func (v *utf8Validator) Write(p []byte) (int, error) {
	if !v.valid {
		return len(p), nil // already decided; keep the digest streaming
	}

	buf := p
	if len(v.pending) > 0 {
		buf = append(append(make([]byte, 0, len(v.pending)+len(p)), v.pending...), p...)
		v.pending = nil
	}

	// Hold back a trailing partial rune for the next chunk. At end of stream
	// nothing more arrives, so anything still held back is a truncated rune —
	// which valid() treats as invalid.
	if keep := trailingPartialRune(buf); keep > 0 {
		v.pending = append(make([]byte, 0, keep), buf[len(buf)-keep:]...)
		buf = buf[:len(buf)-keep]
	}
	if !utf8.Valid(buf) {
		v.valid = false
		v.pending = nil
	}
	return len(p), nil
}

// trailingPartialRune reports how many bytes at the end of b begin a rune that
// is not complete yet. At most 3: a UTF-8 rune is at most 4 bytes.
//
// A trailing sequence that is INVALID rather than incomplete returns 0, so the
// caller's utf8.Valid sees it and rejects it rather than carrying it forward
// forever.
func trailingPartialRune(b []byte) int {
	for i := 1; i <= utf8.UTFMax-1 && i <= len(b); i++ {
		tail := b[len(b)-i:]
		if !utf8.RuneStart(tail[0]) {
			continue // a continuation byte; the rune starts further back
		}
		if utf8.FullRune(tail) {
			return 0 // complete, or definitively invalid — not a truncation
		}
		return i
	}
	return 0
}

// trimPartialRune drops a trailing byte sequence that a hard byte cap split
// mid-character. A UTF-8 rune is at most 4 bytes, so at most 3 can be dangling.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < 3 && len(b) > 0; i++ {
		if utf8.Valid(b) {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

// errScriptTooLarge reports that an operand ran past the capture ceiling.
var errScriptTooLarge = errors.New("operand exceeds the script capture ceiling")

// boundedReader makes a read both interruptible and finite.
//
// It is the read-side counterpart to opening with O_NONBLOCK: that stopped a
// special file from blocking the OPEN, this stops an ordinary regular file from
// consuming a worker on the READ. A file being appended to as fast as it is
// consumed has no end, and this capture happens before the command starts,
// where nothing else would ever stop it.
//
// The context is checked between reads rather than during one. A read already
// blocked in the kernel — a hung network filesystem — cannot be interrupted
// this way; that case is out of reach from inside the process and is not
// claimed to be handled.
type boundedReader struct {
	r     io.Reader
	ctx   context.Context
	limit int64
	read  int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}

	// Clamp the UNDERLYING read, do not merely judge it afterwards.
	//
	// Comparing the running total to the limit after handing the caller's whole
	// buffer to the kernel is a bound that does not bound: by the time it fires,
	// the I/O it exists to prevent has already happened, once per call. That is
	// the difference between overshooting by one buffer per operand and not
	// overshooting at all.
	//
	// The allowance is limit+1, not limit. "The file ends exactly at the
	// ceiling" and "the file runs past it" are only distinguishable by reading
	// one byte more than the ceiling permits — the first must be measured, the
	// second must abstain, and a reader that stops at exactly limit cannot tell
	// which one it is holding. That single probe byte is the entire overshoot,
	// and it is paid at most once per operand.
	room := b.limit - b.read + 1
	if room <= 0 {
		// Already past the ceiling: nothing further may be read, and returning
		// (0, nil) here would spin io.Copy forever.
		return 0, errScriptTooLarge
	}
	if int64(len(p)) > room {
		p = p[:room]
	}

	n, err := b.r.Read(p)
	b.read += int64(n)
	// Strictly greater: a file of exactly limit bytes is within the ceiling.
	if b.read > b.limit {
		return n, errScriptTooLarge
	}
	return n, err
}

// byteCounter totals everything written to it, giving the true file size from
// the same pass that produced the digest.
type byteCounter struct{ n int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// cappedBuffer retains the first limit bytes and discards the rest, never
// erroring — the hash must keep streaming to the end of the file even once
// the content cap is reached.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		c.buf.Write(p[:room])
	}
	return len(p), nil
}

// defaultScriptDigests is the hash set applied to scripts and makefiles. It
// matches what the rest of the attestor records for file materials so a
// verifier can compare a script digest against a material digest directly.
func defaultScriptDigests() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}
