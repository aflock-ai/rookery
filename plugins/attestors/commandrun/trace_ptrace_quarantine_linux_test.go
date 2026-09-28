// jade:ring nightly
//
// QUARANTINED from the local and merge-queue rings: every commandrun test that
// drives the ptrace backend (forces it, then runs a traced command) hits the
// KNOWN PRODUCT BUG #10481, not a flaky test. The ptrace tracer can leave a
// tracee in ptrace-stop, so c.Wait() never returns; runAutoTraced's 3-minute
// bound turns that into a red test, which ejects a queue group. 9863 was
// ejected that way on 2026-09-28 (merge_group run 36434227303) by
// TestReExecKeepsTheReplacedImage and TestAutoFallbackToPtraceTracesTheTree.
// They still run every night in nightly.yml's tracer-exec-attribution job, so
// the tracer is not unwatched, and TestEveryPtraceTraceTestIsQuarantined
// (jade/cmd) keeps this list complete. The #10481 fix PR moves them back to
// their original files under `// jade:ring local` and deletes this file.
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
	"os/exec"
	"path/filepath"
	"testing"
	"time"
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

// A command that never exits must come back as a timeout within the bound,
// not hold the test binary to go test's 30-minute alarm.
func TestAutoTracedDeadlineKillsAHungCommand(t *testing.T) {
	forceEBPFUnavailable(t)
	t.Setenv(EnvVarTraceMode, "")
	t.Setenv(EnvVarFanotify, "off")
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	start := time.Now()
	_, _, timedOut := runAutoTracedWithin(t, t.TempDir(), []string{sleep, "3600"}, 2*time.Second)
	if !timedOut {
		t.Fatal("a command that never exits was not reported as timed out")
	}
	if took := time.Since(start); took > 45*time.Second {
		t.Fatalf("the deadline fired after %s; the kill did not unblock the wait", took)
	}
}

// TestAutoFallbackToPtraceTracesTheTree is the customer shape: default
// CILOCK_TRACE_MODE (auto), no eBPF, fanotify off. Before the fix the child
// was never put under ptrace and the attestor failed with ESRCH.
func TestAutoFallbackToPtraceTracesTheTree(t *testing.T) {
	forceEBPFUnavailable(t)
	t.Setenv(EnvVarTraceMode, "")
	t.Setenv(EnvVarFanotify, "off")

	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(input, []byte("unprivileged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Copy the images we exec into the test dir so their bytes are known and
	// DISTINCT: a digest of one program recorded against another is the
	// failure the exec-stop fix exists to prevent.
	sh := copyExecutable(t, "sh", filepath.Join(dir, "bin"))
	// sh, cat and ls run from COPIES in the test dir. When that dir is on a
	// filesystem the kernel owns (tmpfs, ext4), the ptrace backend can claim
	// a mapped-image digest; measured at execve ENTRY, /proc/<pid>/exe is
	// still the shell, so the shell's digest would be signed as cat's.
	catPath := copyExecutable(t, "cat", filepath.Join(dir, "bin"))
	lsPath := copyExecutable(t, "ls", filepath.Join(dir, "bin"))
	script := catPath + " " + input + " >/dev/null; " + lsPath + " >/dev/null"
	rc, err := runAutoTraced(t, dir, []string{sh, "-c", script})
	if err != nil {
		t.Fatalf("auto-mode ptrace fallback must trace, not fail: %v", err)
	}
	if rc.resolvedTraceBackend != traceModePtrace.String() {
		t.Fatalf("backend = %q, want %q", rc.resolvedTraceBackend, traceModePtrace.String())
	}

	for _, want := range []struct {
		base, path string
	}{{filepath.Base(sh), sh}, {"cat", catPath}, {"ls", lsPath}} {
		p := findProgram(rc, want.base)
		if p == nil {
			got := make([]string, 0, len(rc.Processes))
			for i := range rc.Processes {
				got = append(got, rc.Processes[i].Program)
			}
			t.Fatalf("no process for %s; programs=%v", want.base, got)
		}
		if len(p.OpenedFiles) == 0 {
			t.Errorf("%s: no openedfiles recorded", want.base)
		}
		if len(p.ExeDigest) == 0 {
			t.Errorf("%s: no exedigest recorded", want.base)
			continue
		}
		// The recorded image digest must be the digest of THIS program's
		// bytes (resolved through symlinks, as execve does).
		real, rerr := filepath.EvalSymlinks(want.path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		wantHex := fileSHA256(t, real)
		if got := firstHex(p.ExeDigest); got != wantHex {
			t.Errorf("%s: exedigest %s (source %q) is not the digest of %s (%s)",
				want.base, got, p.ExeDigestSource, real, wantHex)
		}
		// comm is read from the tracee: it must name the new image, not the
		// shell that forked it.
		if want.base != filepath.Base(sh) && p.Comm != want.base {
			t.Errorf("%s: comm = %q, want the post-exec name", want.base, p.Comm)
		}
	}
	if _, ok := findProgram(rc, "cat").OpenedFiles[input]; !ok {
		t.Errorf("cat's open of %s was not recorded", input)
	}

	// Coverage states the tracer and that ptrace + fanotify-off is partial.
	if rc.Summary == nil || rc.Summary.Coverage == nil {
		t.Fatal("traced run carries no summary.coverage")
	}
	cov := rc.Summary.Coverage
	if cov.Tracer != traceModePtrace.String() || cov.Complete {
		t.Errorf("coverage = %+v, want tracer ptrace+seccomp, complete=false", cov)
	}
	kinds := map[string]bool{}
	for _, g := range cov.Gaps {
		kinds[g.Kind] = true
	}
	for _, k := range []string{GapFanotifyDisabled, GapSyscallsUntraced} {
		if !kinds[k] {
			t.Errorf("coverage gaps %v missing %q", cov.Gaps, k)
		}
	}
}

// TestPtrace_E2E_StillWorksAfterRefactor verifies the ptrace path
// still captures openat events after the eBPF refactor. Ensures the
// preStartTracingSetup() change didn't regress the ptrace flow.
func TestPtrace_E2E_StillWorksAfterRefactor(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("ptrace e2e test requires root (PTRACE_TRACEME on a child)")
	}
	t.Setenv(EnvVarTraceMode, "ptrace")

	dir := t.TempDir()
	target := filepath.Join(dir, "ptrace-sentinel.txt")
	content := []byte("ptrace-path-still-works\n")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}

	procs := runUnderEBPF(t, []string{"/bin/cat", target}) // helper name is misleading; runs whatever mode is set

	// Find ProcessInfo with our path in OpenedFiles
	found := false
	for _, p := range procs {
		if _, ok := p.OpenedFiles[target]; ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ptrace mode did not capture sentinel openat. procs=%d files:\n%s",
			len(procs), summarizeOpenedFiles(procs))
	}
}
