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
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The ptrace backend reads an exec's path at syscall ENTRY and binds it to the
// image at the PTRACE_EVENT_EXEC stop. A path kept from one exec attempt must
// never name a different exec. The sequence that did exactly that: a failed
// execve (no exec stop, so its path was never consumed), then a successful
// execveat on the same thread (no entry handler, so nothing replaced it). The
// signed record then paired the failed path with the image that actually ran.

const (
	envExecAttributionTarget = "CILOCK_TEST_EXEC_ATTRIBUTION_TARGET"
	envExecAttributionForm   = "CILOCK_TEST_EXEC_ATTRIBUTION_FORM"
	bogusExecPath            = "/nonexistent/cilock-failed-execve-target"
)

// TestHelperFailedExecveThenExecveat is the traced child's body, not a test.
// It skips unless TestFailedExecveDoesNotNameTheNextExec launched it. Exit 0
// is reachable ONLY through the execveat'd `true`, so a clean exit proves the
// sequence ran as designed.
func TestHelperFailedExecveThenExecveat(t *testing.T) {
	target := os.Getenv(envExecAttributionTarget)
	if target == "" {
		t.Skip("helper: runs only as the traced child of TestFailedExecveDoesNotNameTheNextExec")
	}
	// Both calls must come from ONE thread: the entry-time path is keyed by tid.
	runtime.LockOSThread()

	// 1. execve that fails (ENOENT). The kernel never reaches the exec stop.
	if err := unix.Exec(bogusExecPath, []string{"bogus"}, os.Environ()); err == nil {
		os.Exit(97)
	}

	// 2. execveat of the target: by absolute path, or through a descriptor
	// (fexecve: AT_EMPTY_PATH with an empty path).
	dirfd, path, flags := unix.AT_FDCWD, target, 0
	if os.Getenv(envExecAttributionForm) == "fd" {
		fd, err := unix.Open(target, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			os.Exit(96)
		}
		dirfd, path, flags = fd, "", unix.AT_EMPTY_PATH
	}
	pathp, _ := unix.BytePtrFromString(path)
	argv0, _ := unix.BytePtrFromString(filepath.Base(target))
	argv := []*byte{argv0, nil}
	envv := []*byte{nil}
	_, _, _ = unix.RawSyscall6(unix.SYS_EXECVEAT,
		uintptr(dirfd), //nolint:gosec // G115: AT_FDCWD is a negative fd by definition
		uintptr(unsafe.Pointer(pathp)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envv[0])),
		uintptr(flags), 0)
	os.Exit(98) // reached only if execveat failed
}

func TestFailedExecveDoesNotNameTheNextExec(t *testing.T) {
	for _, form := range []string{"path", "fd"} {
		t.Run(form, func(t *testing.T) {
			forceEBPFUnavailable(t)
			t.Setenv(EnvVarTraceMode, "")
			t.Setenv(EnvVarFanotify, "off")

			dir := t.TempDir()
			target := copyExecutable(t, "true", filepath.Join(dir, "bin"))
			t.Setenv(envExecAttributionTarget, target)
			t.Setenv(envExecAttributionForm, form)
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}

			rc, err := runAutoTraced(t, dir, []string{self, "-test.run=^TestHelperFailedExecveThenExecveat$"})
			if err != nil {
				t.Fatalf("traced helper failed (exit 96/97/98 = the exec sequence did not run as designed): %v", err)
			}

			var named *ProcessInfo
			for i := range rc.Processes {
				p := &rc.Processes[i]
				if p.Program == bogusExecPath {
					t.Errorf("pid %d: the FAILED execve's path %q is recorded as a program (exedigest %s)",
						p.ProcessID, p.Program, firstHex(p.ExeDigest))
				}
				if p.Program == target {
					named = p
				}
			}
			switch form {
			case "path":
				// An absolute execveat path names the program exactly as an
				// execve path does, and the record binds it to those bytes.
				if named == nil {
					t.Fatalf("execveat of %s is not recorded under its path", target)
				}
				if got, want := firstHex(named.ProgramDigest), fileSHA256(t, target); got != want {
					t.Errorf("programDigest %s is not the digest of %s (%s)", got, target, want)
				}
			case "fd":
				// A descriptor names no path: the record must say "unknown"
				// (empty), never borrow one.
				if named != nil {
					t.Errorf("fd-based execveat recorded under path %q it never named", named.Program)
				}
			}
		})
	}
}

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
