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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// shCTexts are `sh -c` texts that sh runs as one simple command whose words are
// exactly the blank-separated words of the text. Each must resolve the way its
// words resolve as a direct argv.
var shCTexts = []string{
	"bash scripts/build.sh",
	"./build.sh",
	"  bash   scripts/build.sh  ",
	"bash\tscripts/build.sh",
	"python3 -u tool.py --flag=x",
	"env A=1 bash scripts/build.sh",
	"make -f ci.mk all",
	"node a.js é",
	"tool a!b a%b a@b:c,d",
}

// A text sh would read as anything more than blank-separated words, and any
// shape other than exactly `sh -c <text>`, records nothing.
func TestShCTextAbstainsUnlessItIsOneSimpleCommand(t *testing.T) {
	workdir := t.TempDir()
	writeExecFixture(t, workdir, "build.sh", "#!/bin/sh\ntrue\n")
	writeExecFixture(t, workdir, "a.sh", "#!/bin/sh\ntrue\n")

	texts := []string{
		"bash a.sh; true", "true && bash a.sh", "bash a.sh | cat", "bash a.sh &",
		"bash a.sh > out", "bash a.sh < in", "(bash a.sh)", "{ bash a.sh; }",
		"bash $X", "bash `echo a.sh`", "bash 'a.sh'", `bash "a.sh"`, `bash a\ b.sh`,
		"bash ~/a.sh", "bash a*.sh", "bash a?.sh", "bash [a].sh", "bash {a,b}.sh",
		"bash a.sh # comment", "bash a.sh\n", "true\nbash a.sh",
		// A leading assignment is not a program name. With a slash in the value
		// it would otherwise pass for a path to an executable.
		"FOO=/x ./build.sh", "FOO=1 bash a.sh",
		// A builtin or reserved word first runs no program of that name.
		"exec ./build.sh", "command bash a.sh", "! ./build.sh", "time bash a.sh",
		"", "   ",
	}
	for _, text := range texts {
		if refs := resolveScriptOperands([]string{"sh", "-c", text}, workdir); len(refs) != 0 {
			t.Errorf("sh -c %q: want no refs, got %+v", text, refs)
		}
	}

	for _, argv := range [][]string{
		{"sh", "-c", "bash a.sh", "name", "arg"}, // extra operands become $0 and $1
		{"sh", "-e", "-c", "bash a.sh"},
		{"sh", "-c"},
		// bash reads BASH_ENV and zsh reads .zshenv before -c text runs, and
		// either can define a function that shadows the program named.
		{"bash", "-c", "bash a.sh"},
		{"zsh", "-c", "bash a.sh"},
		{"dash", "-c", "bash a.sh"},
	} {
		if refs := resolveScriptOperands(argv, workdir); len(refs) != 0 {
			t.Errorf("%q: want no refs, got %+v", argv, refs)
		}
	}
}

// bash, including bash running as sh, imports functions from the environment,
// so an inherited BASH_FUNC_bash%% runs in place of the bash on PATH.
func TestShCTextAbstainsWhenTheEnvironmentDefinesFunctions(t *testing.T) {
	workdir := t.TempDir()
	writeExecFixture(t, workdir, "a.sh", "#!/bin/sh\ntrue\n")
	argv := []string{"sh", "-c", "bash a.sh"}
	if refs := resolveScriptOperands(argv, workdir); len(refs) != 1 {
		t.Fatalf("control: want one ref without function definitions, got %+v", refs)
	}

	for _, kv := range [][2]string{
		{"BASH_FUNC_bash%%", "() { :; }"},
		{"BASH_FUNC_bash()", "() { :; }"},
		{"bash", "() { :; }"}, // the pre-2014 import format
	} {
		t.Run(kv[0], func(t *testing.T) {
			t.Setenv(kv[0], kv[1])
			if refs := resolveScriptOperands(argv, workdir); len(refs) != 0 {
				t.Errorf("%s set: want no refs, got %+v", kv[0], refs)
			}
		})
	}
}

// A simple `sh -c` text resolves exactly as its words would as an argv, and
// the env prefix and path spelling of the outer sh are handled as for any argv.
func TestShCTextResolvesLikeItsWords(t *testing.T) {
	workdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workdir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecFixture(t, workdir, "scripts/build.sh", "#!/bin/sh\ntrue\n")
	writeExecFixture(t, workdir, "build.sh", "#!/bin/sh\ntrue\n")
	writeExecFixture(t, workdir, "ci.mk", "all:\n")

	for _, text := range shCTexts {
		want := resolveScriptOperands(strings.FieldsFunc(text, isShBlank), workdir)
		for _, argv := range [][]string{
			{"sh", "-c", text},
			{"/bin/sh", "-c", text},
			{"env", "X=1", "sh", "-c", text},
		} {
			if got := resolveScriptOperands(argv, workdir); !reflect.DeepEqual(got, want) {
				t.Errorf("%q: got %+v, want %+v", argv, got, want)
			}
		}
	}

	got := resolveScriptOperands([]string{"sh", "-c", "bash scripts/build.sh"}, workdir)
	if len(got) != 1 || got[0].Role != RoleInterpreterOperand || got[0].Path != "scripts/build.sh" {
		t.Errorf("bash scripts/build.sh: got %+v", got)
	}
	got = resolveScriptOperands([]string{"sh", "-c", "./build.sh"}, workdir)
	if len(got) != 1 || got[0].Role != RoleExecutable {
		t.Errorf("./build.sh: got %+v", got)
	}
}

// The claim above is only as good as "sh hands the program exactly these
// words". Run every text under a real sh whose PATH and working directory hold
// an argv-dumping stand-in for the first word, and compare.
func TestShCTextWordsAreTheArgvShPasses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("compares against a POSIX sh")
	}
	fake := t.TempDir()
	cwd := t.TempDir()
	out := filepath.Join(t.TempDir(), "argv")
	// A loop, not printf "$@": printf with no arguments still prints one empty
	// field, which would read as a one-element argv.
	dumper := "#!/bin/sh\n: > \"$ARGV_OUT\"\nfor a in \"$@\"; do printf '%s\\000' \"$a\" >> \"$ARGV_OUT\"; done\n"

	for _, text := range shCTexts {
		words, ok := shCommandWords([]string{"sh", "-c", text}, nil)
		if !ok {
			t.Fatalf("%q: shCommandWords declined a simple command", text)
		}
		dir := fake
		if strings.Contains(words[0], "/") {
			dir = cwd
		}
		writeExecFixture(t, dir, words[0], dumper)

		cmd := exec.Command("/bin/sh", "-c", text)
		cmd.Dir = cwd
		cmd.Env = []string{"PATH=" + fake, "ARGV_OUT=" + out}
		if res, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%q under sh: %v: %s", text, err, res)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		if len(raw) > 0 {
			for _, a := range bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0}) {
				got = append(got, string(a))
			}
		}
		want := words[1:]
		if len(want) == 0 {
			want = nil
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: sh passed %q, the resolver read %q", text, got, want)
		}
	}
}

// The resolver never asks sh what a first word means; it relies on every name
// it gives a role to being a program sh looks up, never a builtin or reserved
// word. Pin that for every name the tables hold.
func TestNoResolvedProgramIsAShellBuiltin(t *testing.T) {
	builtins := strings.Fields(`! { } case do done elif else esac fi for function if in select then
		time until while [[ ]] . : break continue eval exec exit export readonly return set
		shift times trap unset alias bg cd command declare echo false fc fg getopts hash jobs
		kill let local printf pwd read source test true type typeset ulimit umask unalias wait
		builtin caller compgen complete dirs disown enable help history logout mapfile popd
		print pushd readarray shopt suspend autoload bindkey emulate whence where which`)
	for _, b := range builtins {
		if _, ok := interpreters[b]; ok || b == "make" || b == "gmake" {
			t.Errorf("%q is a shell builtin or reserved word and a resolved program", b)
		}
	}
}

// End to end: the command really runs under sh, and the script is recorded.
// A file with no #! still runs (sh interprets it after execve refuses it) and
// is not recorded as an executable.
func TestAttestRecordsTheScriptAnShCTextRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	workdir := t.TempDir()
	body := "#!/bin/sh\necho build-ran\n"
	path := writeExecFixture(t, workdir, "build.sh", body)
	writeExecFixture(t, workdir, "plain", "exit 0\n")

	rc, err := attestExecIn(t, workdir, WithCommand([]string{"sh", "-c", "sh build.sh"}), WithScriptCapture(ScriptCaptureContent))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if rc.ExitCode != 0 || len(rc.Scripts) != 1 || rc.Scripts[0].Path != path || rc.Scripts[0].Content != body {
		t.Fatalf("exit %d, scripts %+v", rc.ExitCode, rc.Scripts)
	}

	rc, err = attestExecIn(t, workdir, WithCommand([]string{"sh", "-c", "./plain"}), WithScriptCapture(ScriptCaptureContent))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if rc.ExitCode != 0 || len(rc.Scripts) != 0 {
		t.Fatalf("no-#! file: exit %d, scripts %+v", rc.ExitCode, rc.Scripts)
	}
}
