// jade:ring nightly
//
// QUARANTINED from the local and merge-queue rings: a KNOWN PRODUCT BUG, not a
// flaky test. The ptrace tracer can leave a tracee stopped after the traced
// root exits (likely unhandled attach-SIGSTOP re-injection and no detach on
// root exit), so c.Wait() never returns: #10481. On the loaded buildbox this
// test hung in 4 of 40 runs, and once held #10011's offload ring for 30
// minutes. It still runs every night in nightly.yml's tracer-exec-attribution
// job, so the tracer is not unwatched; runAutoTraced's 3-minute bound turns a
// hang there into a red subtest.
// EXPIRES 2026-10-12. The #10481 fix PR must move this test back to
// trace_exec_attribution_linux_test.go under `// jade:ring local` and delete
// this file.
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
