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

// jade:ring local

package commandrun

import (
	"testing"
)

// Codex on #10139: the function check read only this process's environment,
// but an `env ... sh -c` prefix hands sh an environment of its own. The
// mechanism is that the words of the -c text are only the program sh runs
// when the shell sh STARTS WITH defines no function and splits on blanks, so
// every variable the prefix sets is part of that decision. env accepts any
// NAME=value, including names a shell identifier cannot spell
// (BASH_FUNC_bash%%), so the prefix must not be parsed by the shell's rules.
func TestShCTextAbstainsWhenTheEnvPrefixChangesTheShell(t *testing.T) {
	workdir := t.TempDir()
	writeExecFixture(t, workdir, "a.sh", "#!/bin/sh\ntrue\n")
	if refs := resolveScriptOperands([]string{"env", "X=1", "sh", "-c", "bash a.sh"}, workdir); len(refs) != 1 {
		t.Fatalf("control: an ordinary assignment changes nothing, want one ref, got %+v", refs)
	}

	for _, argv := range [][]string{
		{"env", "BASH_FUNC_bash%%=() { :; }", "sh", "-c", "bash a.sh"},
		{"env", "BASH_FUNC_bash()=() { :; }", "sh", "-c", "bash a.sh"},
		{"env", "bash=() { :; }", "sh", "-c", "bash a.sh"},
		{"env", "X=1", "env", "BASH_FUNC_bash%%=() { :; }", "sh", "-c", "bash a.sh"},
		// A field separator other than the default changes the words.
		{"env", "IFS=/", "sh", "-c", "bash a.sh"},
		// A name env accepts but sh would not treat as an assignment.
		{"env", "A-B=1", "sh", "-c", "bash a.sh"},
	} {
		if refs := resolveScriptOperands(argv, workdir); len(refs) != 0 {
			t.Errorf("%q: want no refs, got %+v", argv, refs)
		}
	}

	// The same holds for an IFS the process itself inherits.
	t.Setenv("IFS", "/")
	if refs := resolveScriptOperands([]string{"sh", "-c", "bash a.sh"}, workdir); len(refs) != 0 {
		t.Errorf("IFS=/ inherited: want no refs, got %+v", refs)
	}
}

// `env -i` starts sh with an empty environment, so an inherited function
// definition does not reach it; the prefix's own assignments still do.
func TestShCTextEnvIgnoreEnvironmentStillChecksItsAssignments(t *testing.T) {
	workdir := t.TempDir()
	writeExecFixture(t, workdir, "a.sh", "#!/bin/sh\ntrue\n")
	if refs := resolveScriptOperands([]string{"env", "-i", "BASH_FUNC_bash%%=() { :; }", "sh", "-c", "bash a.sh"}, workdir); len(refs) != 0 {
		t.Errorf("env -i with a function assignment: want no refs, got %+v", refs)
	}
	if refs := resolveScriptOperands([]string{"env", "-i", "X=1", "sh", "-c", "bash a.sh"}, workdir); len(refs) != 1 {
		t.Errorf("env -i with an ordinary assignment: want one ref, got %+v", refs)
	}
}
