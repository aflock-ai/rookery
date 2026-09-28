// jade:ring local
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

//go:build linux

package commandrun

import (
	"os"
	"path/filepath"
	"testing"
)

// A process that execs a second time must keep its first image in the record.
// The ptrace backend used to keep ONE record per pid and reset it on every
// exec, so `sh -c '...; exec cat'` was signed as a run in which sh never
// executed, with sh's own opens filed under cat. BusyBox sh (and dash) exec
// the LAST simple command of a -c string in place without being asked, which
// is how the Wolfi runner found this: TestAutoFallbackToPtraceTracesTheTree
// saw no process for sh. `exec` is spelled out here so every shell takes the
// same path and the test does not depend on that optimisation.
func TestReExecKeepsTheReplacedImage(t *testing.T) {
	forceEBPFUnavailable(t)
	t.Setenv(EnvVarTraceMode, "")
	t.Setenv(EnvVarFanotify, "off")

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	sh := copyExecutable(t, "sh", bin)
	cat := copyExecutable(t, "cat", bin)
	shHex, catHex := fileSHA256(t, sh), fileSHA256(t, cat)
	if shHex == catHex {
		t.Skipf("sh and cat are the same bytes here (%s); the records could not be told apart", shHex)
	}
	input := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(input, []byte("re-exec\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The shell opens the redirect target itself, before it execs cat; cat
	// opens the input. Each open belongs to the image that made it.
	shOpened := filepath.Join(dir, "sh-opened.txt")

	rc, err := runAutoTraced(t, dir, []string{sh, "-c", "exec " + cat + " " + input + " >" + shOpened})
	if err != nil {
		t.Fatalf("traced run failed: %v", err)
	}

	var shRec, catRec *ProcessInfo
	programs := make([]string, 0, len(rc.Processes))
	for i := range rc.Processes {
		programs = append(programs, rc.Processes[i].Program)
		switch rc.Processes[i].Program {
		case sh:
			shRec = &rc.Processes[i]
		case cat:
			catRec = &rc.Processes[i]
		}
	}
	if shRec == nil || catRec == nil {
		t.Fatalf("both images ran on one pid and both must be recorded: sh=%v cat=%v programs=%v",
			shRec != nil, catRec != nil, programs)
	}
	if shRec.ProcessID != catRec.ProcessID {
		t.Errorf("sh pid %d, cat pid %d: exec replaces the image, not the process", shRec.ProcessID, catRec.ProcessID)
	}
	if got := firstHex(shRec.ExeDigest); got != shHex {
		t.Errorf("sh exedigest %s (source %q), want the digest of sh's bytes %s", got, shRec.ExeDigestSource, shHex)
	}
	if got := firstHex(catRec.ExeDigest); got != catHex {
		t.Errorf("cat exedigest %s (source %q), want the digest of cat's bytes %s", got, catRec.ExeDigestSource, catHex)
	}
	if catRec.Comm != "cat" {
		t.Errorf("cat comm = %q", catRec.Comm)
	}
	if _, ok := catRec.OpenedFiles[input]; !ok {
		t.Errorf("cat's open of %s is not on cat's record", input)
	}
	if _, ok := shRec.OpenedFiles[input]; ok {
		t.Errorf("cat's open of %s was filed under sh", input)
	}
	if _, ok := shRec.OpenedFiles[shOpened]; !ok {
		t.Errorf("sh's open of its redirect target %s is not on sh's record", shOpened)
	}
	if _, ok := catRec.OpenedFiles[shOpened]; ok {
		t.Errorf("sh's open of %s was filed under cat", shOpened)
	}
}
