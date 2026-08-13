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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The grammar tables in script_operands.go are claims about OTHER PROGRAMS'
// argument parsing. Written from documentation and memory, they were wrong
// repeatedly and in the dangerous direction: a wrong `switches` entry makes the
// scanner walk past an option the interpreter actually rejects, and the
// attestor then signs a script the command provably never ran.
//
// This file removes documentation from the loop. It enumerates the LIVE tables
// and, for every switch and value-option they claim, runs the real binary
// against a decoy that records a sentinel when it is executed. A claim the
// binary contradicts fails the build.
//
// What this does and does not guarantee, stated plainly:
//
//   - It cannot ADD entries. It is a ratchet against wrong claims, not a
//     generator of right ones. The tables were narrowed by hand to what these
//     probes confirmed on a machine carrying sh, bash, zsh, dash, ksh, python3,
//     perl, ruby, node and GNU make; anything that could not be confirmed there
//     was removed rather than kept on trust.
//   - An interpreter absent from the machine running the suite is SKIPPED, and
//     its claims go unverified on that run. That is why the tables are narrow:
//     the entries that survive are the ones that held everywhere they could be
//     tried, so a skip costs coverage rather than correctness.
//   - It verifies three things: which options EXIST, which VALUES they accept,
//     and what ORDER they may appear in. An earlier version verified only the
//     first and documented the other two as known gaps. That was not enough —
//     the code went on asserting through them, and a stated limitation that
//     still emits a positive claim is a bug with a comment. Both are now
//     probed: valueOptions must survive a deliberately bogus value (proving no
//     value can change the outcome), enumeratedValueOptions must accept every
//     listed value and reject the bogus one, and a long option after a short
//     one must match what longOptionsFirst claims.
//
// The surface that remains unverified is therefore ENUMERATED rather than
// unknown, and it is exactly three things:
//
//  1. Interpreters not installed on the machine running the suite.
//  2. make's -f/--file/--makefile, which is this probe's own mechanism for
//     pointing make at the decoy.
//  3. make's -C/--directory, whose value make validates against the FILESYSTEM
//     rather than against the argv. The resolver stays pure and does not check
//     it; see TestMakeMissingChdirDirectoryRecordsNoDigest for what that does
//     and does not cost.

// interpreterProbe knows how to ask one real interpreter, empirically, whether
// it used the operand it was handed as its program.
type interpreterProbe struct {
	// ext is the decoy file's extension.
	ext string

	// decoy returns a program that records sentinel at the moment the
	// interpreter commits to running this file. Where that moment is differs by
	// language and getting it wrong makes the whole harness lie:
	//
	//   - shells and python execute top level, so a top-level write is right.
	//   - perl and ruby wrap the body in a read loop under -n/-p, which never
	//     iterates on empty stdin. A BEGIN block fires regardless.
	//   - make's -n/-q/-p decline to run RECIPES but still read and parse the
	//     makefile, and RoleMakefile claims the file make READS. A $(shell)
	//     at top level fires during parsing.
	decoy func(sentinel string) string

	// valueFor gives a value known to be accepted, for options that take one.
	// An option missing from here cannot be probed and is reported as such.
	valueFor map[string]string
}

func shellDecoy(sentinel string) string {
	return fmt.Sprintf("echo ran > %q\n", sentinel)
}

var shellProbe = interpreterProbe{
	ext:      "sh",
	decoy:    shellDecoy,
	valueFor: map[string]string{"-o": "errexit"}, // POSIX; `pipefail` is not
}

// interpreterProbes must cover every interpreter whose grammar claims anything.
// A grammar with no probe is a claim nothing can check, which is the state this
// file exists to make impossible.
var interpreterProbes = map[string]interpreterProbe{
	"sh": shellProbe, "bash": shellProbe, "zsh": shellProbe,
	"dash": shellProbe, "ksh": shellProbe, "ash": shellProbe,

	"python": pythonProbe, "python2": pythonProbe, "python3": pythonProbe,

	"node": nodeProbe, "nodejs": nodeProbe,

	"perl": {
		ext: "pl",
		// BEGIN, not top level: perl -n/-p wrap the body in `while(<>){...}`,
		// which never runs on empty stdin even though the file IS the program.
		decoy: func(s string) string {
			return fmt.Sprintf("BEGIN{open(F,'>',%q);print F 'ran';close F}\n1;\n", s)
		},
		valueFor: map[string]string{"-I": ".", "-M": "strict", "-m": "strict", "-F": ","},
	},
	"ruby": {
		ext: "rb",
		decoy: func(s string) string {
			return fmt.Sprintf("BEGIN{File.write(%q,'ran')}\n", s)
		},
		valueFor: map[string]string{"-I": ".", "-r": "date", "-F": ",", "-E": "UTF-8"},
	},
}

var pythonProbe = interpreterProbe{
	ext: "py",
	// The first line is a comment on purpose: python -x SKIPS line one.
	decoy: func(s string) string {
		return fmt.Sprintf("# -x skips this line\nopen(%q,'w').write('ran')\n", s)
	},
	valueFor: map[string]string{
		"-W": "ignore", "-X": "faulthandler", "--check-hash-based-pycs": "default",
	},
}

var nodeProbe = interpreterProbe{
	ext: "js",
	decoy: func(s string) string {
		return fmt.Sprintf("require('fs').writeFileSync(%q,'ran')\n", s)
	},
	// `fs` is a builtin, so it needs no fixture on disk to require.
	valueFor: map[string]string{"-r": "fs", "--require": "fs"},
}

// operandExecuted runs bin with args plus a decoy operand and reports whether
// the decoy actually ran.
//
// Exit status is deliberately ignored. A shell may exit non-zero for reasons
// having nothing to do with whether it opened the operand, and `-n`-style
// options exit zero without running anything. The sentinel is the only signal
// that answers the question the grammar table is making a claim about.
func (p interpreterProbe) operandExecuted(t *testing.T, bin string, opts ...string) bool {
	t.Helper()

	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	operand := filepath.Join(dir, "decoy."+p.ext)
	if err := os.WriteFile(operand, []byte(p.decoy(sentinel)), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := append(append([]string{}, opts...), operand)
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: the whole point is running these binaries
	cmd.Dir = dir
	// Stdin nil is the null device, so an interactive or stdin-reading option
	// hits EOF and exits instead of hanging the suite.
	_ = cmd.Run()

	_, err := os.Stat(sentinel)
	return err == nil
}

// TestGrammarSwitchClaimsHoldAgainstRealInterpreters is the ratchet.
//
// It walks the LIVE interpreters map, so a table entry added later is verified
// automatically — there is no separate list to forget to update. That is the
// property that matters: the claim cannot be widened without proof on any
// machine where the binary exists.
func TestGrammarSwitchClaimsHoldAgainstRealInterpreters(t *testing.T) {
	var verified, skipped []string

	for _, prog := range sortedKeys(interpreters) {
		g := interpreters[prog]

		probe, ok := interpreterProbes[prog]
		if !ok {
			t.Errorf("%q has a grammar but no probe recipe: nothing can check what "+
				"it claims about that program's argument parsing, which is exactly "+
				"how the wrong file gets signed as the executed script", prog)
			continue
		}
		if len(g.switches) == 0 && len(g.valueOptions) == 0 &&
			len(g.attachedValueOptions) == 0 && len(g.enumeratedValueOptions) == 0 {
			continue // claims nothing, so there is nothing to prove
		}

		bin, err := exec.LookPath(prog)
		if err != nil {
			skipped = append(skipped, prog)
			continue
		}

		// Verify the PROBE before trusting any negative from it. If the decoy
		// does not run with no options at all, every "did not execute" below
		// would be an artefact of the harness rather than a fact about the
		// table.
		if !probe.operandExecuted(t, bin) {
			t.Errorf("%s: the probe does not execute its own decoy with no options — "+
				"the harness is broken here, not the table; treating its results as "+
				"evidence would be worse than having no harness", prog)
			continue
		}

		for _, opt := range sortedKeys(g.switches) {
			if !probe.operandExecuted(t, bin, opt) {
				t.Errorf("%s: the table lists %q as a SWITCH, meaning the scanner walks "+
					"past it and records the operand as the executed script — but %s did "+
					"not execute the operand. This argv would sign a script the command "+
					"provably never ran.", prog, opt, prog)
				continue
			}
			verified = append(verified, prog+" "+opt)
		}

		for _, opt := range sortedKeys(g.valueOptions) {
			value, ok := probe.valueFor[opt]
			if !ok {
				t.Errorf("%s: %q takes a value but the harness has no known-good value "+
					"for it, so the claim is unverified — supply one or drop the entry",
					prog, opt)
				continue
			}
			if !probe.operandExecuted(t, bin, opt, value) {
				t.Errorf("%s: the table lists %q as a value option taking the FOLLOWING "+
					"token, but `%s %s %s` did not execute the operand — the scan would "+
					"swallow the value and record whatever came next as an executed "+
					"script", prog, opt, prog, opt, value)
				continue
			}
			// Membership in valueOptions asserts the value is OPAQUE: that no
			// value can stop the operand running. Garbage proves it. An option
			// that fails here is validated by the interpreter and belongs in
			// enumeratedValueOptions or unresolvable — this is the check that
			// `dash -o pipefail` slipped through for a whole round.
			if !probe.operandExecuted(t, bin, opt, bogusOptionValue) {
				t.Errorf("%s: %q is in valueOptions, which asserts its value cannot "+
					"change whether the operand runs — but `%s %s %s` did not execute "+
					"it. The interpreter validates this value, so an unverified one "+
					"would be signed as an execution that never happened.",
					prog, opt, prog, opt, bogusOptionValue)
				continue
			}
			verified = append(verified, fmt.Sprintf("%s %s <opaque>", prog, opt))
		}

		for _, opt := range sortedKeys(g.enumeratedValueOptions) {
			// Every enumerated value must actually run the operand...
			bad := 0
			for _, value := range sortedKeys(g.enumeratedValueOptions[opt]) {
				if !probe.operandExecuted(t, bin, opt, value) {
					t.Errorf("%s: %q lists %q among its verified values, but `%s %s %s` "+
						"did not execute the operand", prog, opt, value, prog, opt, value)
					bad++
					continue
				}
				verified = append(verified, fmt.Sprintf("%s %s %s", prog, opt, value))
			}
			// ...and an unlisted value must NOT, or the enumeration is
			// pointless and is costing evidence for no reason.
			if bad == 0 && probe.operandExecuted(t, bin, opt, bogusOptionValue) {
				t.Errorf("%s: %q is enumerated, but `%s %s %s` runs the operand too — "+
					"the interpreter does not validate this value, so the enumeration "+
					"only rejects invocations that would have been fine",
					prog, opt, prog, opt, bogusOptionValue)
			}
		}

		// Ordering. The tables had only ever recorded which options EXIST, not
		// where they may appear, and the scanner assumed order-independence
		// that bash does not honour.
		if long := firstLongSwitch(g); long != "" {
			short := firstShortSwitch(g)
			if short != "" {
				runs := probe.operandExecuted(t, bin, short, long)
				switch {
				case runs && g.longOptionsFirst:
					t.Errorf("%s: longOptionsFirst rejects `%s %s %s`, but it runs the "+
						"operand — the restriction is costing evidence", prog, prog, short, long)
				case !runs && !g.longOptionsFirst:
					t.Errorf("%s: `%s %s %s` does NOT run the operand, but the grammar "+
						"accepts a long option after a short one and would record it as "+
						"an executed script — set longOptionsFirst", prog, prog, short, long)
				default:
					verified = append(verified,
						fmt.Sprintf("%s ordering %s then %s", prog, short, long))
				}
			}
		}

		for _, opt := range sortedKeys(g.attachedValueOptions) {
			value, ok := probe.valueFor[opt]
			if !ok {
				t.Errorf("%s: %q is claimed attached-value but the harness has no "+
					"known-good value for it", prog, opt)
				continue
			}
			// The attached form must work...
			if !probe.operandExecuted(t, bin, opt+value) {
				t.Errorf("%s: the table claims `%s%s` runs the operand, but it did not",
					prog, opt, value)
				continue
			}
			// ...and the separate form must NOT, or the option belongs in
			// valueOptions and this classification is silently costing evidence.
			if probe.operandExecuted(t, bin, opt, value) {
				t.Errorf("%s: %q is classified attached-only, but `%s %s %s` runs the "+
					"operand too — that is a valueOption, and abstaining on it drops "+
					"evidence we could have recorded", prog, opt, prog, opt, value)
				continue
			}
			verified = append(verified, fmt.Sprintf("%s %s%s (attached-only)", prog, opt, value))
		}
	}

	// A run that verified nothing is not a passing run, it is an absent one.
	if len(verified) == 0 {
		t.Fatal("no grammar claim could be verified on this machine — the suite is " +
			"reporting success for checks that never ran")
	}
	t.Logf("verified %d grammar claims against real binaries", len(verified))
	if len(skipped) > 0 {
		t.Logf("UNVERIFIED on this machine (interpreter not installed): %v — their "+
			"claims are narrow precisely because a skip proves nothing", skipped)
	}
}

// TestMakeGrammarSwitchClaimsHoldAgainstRealMake is the same ratchet for make,
// which does not live in the interpreters map.
//
// The claim differs: RoleMakefile names the file make READS, not one it
// executes, so -n/-q/-p stay switches. The probe matches that claim by using a
// $(shell) that fires while the makefile is being PARSED.
func TestMakeGrammarSwitchClaimsHoldAgainstRealMake(t *testing.T) {
	bin := ""
	for _, name := range []string{"make", "gmake"} {
		if p, err := exec.LookPath(name); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		t.Skip("no make on this machine; the makeGrammar claims go unverified here")
	}

	read := func(opts ...string) bool {
		dir := t.TempDir()
		sentinel := filepath.Join(dir, "sentinel")
		mk := filepath.Join(dir, "decoy.mk")
		body := fmt.Sprintf("$(shell echo ran > %q)\nall:\n\t@true\n", sentinel)
		if err := os.WriteFile(mk, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		args := append(append([]string{}, opts...), "-f", mk)
		cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: the whole point is running this binary
		cmd.Dir = dir
		_ = cmd.Run()
		_, err := os.Stat(sentinel)
		return err == nil
	}

	if !read() {
		t.Fatal("make does not read the decoy makefile with no options — the probe " +
			"is broken, not the table")
	}

	// Value options. Two are exempt, each for a stated reason rather than a
	// bare comment:
	//   -f/--file/--makefile IS the mechanism this probe uses to point make at
	//     the decoy, so probing it with a bogus value would only prove that a
	//     missing makefile is missing.
	//   -C/--directory is validated by make AND by the resolver; its abstain is
	//     asserted by TestMakeNonexistentDirectoryAbstains instead.
	exempt := map[string]string{
		"-f": "the probe mechanism", "--file": "the probe mechanism",
		"--makefile": "the probe mechanism",
		"-C":         "resolver-validated", "--directory": "resolver-validated",
	}
	makeValues := map[string]string{
		"-I": ".", "--include-dir": ".",
		"-o": "afile", "--old-file": "afile", "--assume-old": "afile",
		"-W": "afile", "--what-if": "afile", "--new-file": "afile", "--assume-new": "afile",
	}
	for _, opt := range sortedKeys(makeGrammar.valueOptions) {
		if _, ok := exempt[opt]; ok {
			continue
		}
		value, ok := makeValues[opt]
		if !ok {
			t.Errorf("makeGrammar lists %q as a value option but the probe has no "+
				"known-good value for it, so the claim is unverified", opt)
			continue
		}
		if !read(opt, value) {
			t.Errorf("makeGrammar lists %q as a value option, but `make %s %s` did not "+
				"read the makefile", opt, opt, value)
			continue
		}
		// Same opacity requirement as the interpreters: if a bogus value stops
		// make reading the makefile, the value is load-bearing and cannot be
		// trusted unverified.
		if !read(opt, bogusOptionValue) {
			t.Errorf("makeGrammar lists %q in valueOptions, which asserts the value "+
				"cannot change whether the makefile is read — but a bogus value "+
				"stopped it", opt)
		}
	}

	for _, opt := range sortedKeys(makeGrammar.switches) {
		if !read(opt) {
			t.Errorf("makeGrammar lists %q as a switch, but make did not read the "+
				"makefile with it — the resolver would record a makefile make never "+
				"opened", opt)
		}
	}

	// The empty -C that this round fixes: make refuses it outright, so the
	// resolver must not carry on and name a makefile.
	if read("--directory=") {
		t.Error("make read a makefile despite an empty --directory=; the abstain " +
			"added for it is guarding a case that does not occur, which means the " +
			"guard or this probe is wrong")
	}
}

// bogusOptionValue is a value no interpreter recognises for anything. It is the
// control: an option that still runs the operand with this is one whose value
// cannot make the record wrong.
const bogusOptionValue = "zzz-not-a-real-value"

// firstLongSwitch and firstShortSwitch pick a representative of each shape so
// the ordering probe has something concrete to combine. Deterministic by
// sorting, so a failure is reproducible.
func firstLongSwitch(g optionGrammar) string {
	for _, s := range sortedKeys(g.switches) {
		if strings.HasPrefix(s, "--") {
			return s
		}
	}
	return ""
}

func firstShortSwitch(g optionGrammar) string {
	for _, s := range sortedKeys(g.switches) {
		if !strings.HasPrefix(s, "--") {
			return s
		}
	}
	return ""
}

// sortedKeys keeps the probe order deterministic, so a failure names the same
// option every run rather than whichever one the map happened to yield first.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
