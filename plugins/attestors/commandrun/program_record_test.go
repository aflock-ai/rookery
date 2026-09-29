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

// Program-record tests that need a seam inside the measurement. The wire-level
// tests are in program_record_wire_test.go.

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestProgramRealPathComesFromTheHashedDescriptor: the symlink argv[0] names
// is re-pointed after cilock opened the program and before it reads anything
// back. realPath must still name the file whose bytes were hashed. A second
// walk of the name (EvalSymlinks(path)) would name the new target beside the
// old target's digest: a path and a digest describing two different files.
func TestProgramRealPathComesFromTheHashedDescriptor(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("descriptor path readback is Linux and macOS in this build (Windows is lane P1b)")
	}
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	other := filepath.Join(dir, "other")
	writeProgramScript(t, original, programTestScript)
	writeProgramScript(t, other, "#!/bin/sh\n# a different program\nexit 0\n")
	link := filepath.Join(dir, "tool")
	if err := os.Symlink(original, link); err != nil {
		t.Fatal(err)
	}

	swapped := false
	testAfterProgramOpen = func() {
		if swapped {
			return
		}
		swapped = true
		tmp := link + ".new"
		if err := os.Symlink(other, tmp); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(tmp, link); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testAfterProgramOpen = nil })

	m := measureProgramFile(link, programHashes(nil))
	if !swapped {
		t.Fatal("the seam never ran: nothing was swapped")
	}
	if m.realPath != realPathOf(t, original) {
		t.Fatalf("realPath = %q, want the file the descriptor holds, %q", m.realPath, realPathOf(t, original))
	}
	if m.realPathSource == RealPathEvalSymlinksConfirmed || m.realPathSource == RealPathFromName {
		t.Fatalf("realPathSource = %q: the path must come from the descriptor", m.realPathSource)
	}
	body, err := os.ReadFile(original) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if got := digestSHA256(t, m.digest); got != programSHA256Hex(body) {
		t.Fatalf("digest = %q, want the original file's %q", got, programSHA256Hex(body))
	}
}

// TestRealPathFailureKeepsTheDigest: when the descriptor cannot report its
// path (no /proc, for example), the bytes were still read through it, so the
// digest stays. Only the name is lost, and the record says so.
func TestRealPathFailureKeepsTheDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX script fixture")
	}
	dir := t.TempDir()
	prog := filepath.Join(dir, "tool")
	writeProgramScript(t, prog, programTestScript)
	decoy := filepath.Join(dir, "decoy")
	writeProgramScript(t, decoy, programTestScript)

	fdRealPath = func(*os.File) (string, string, error) {
		return "", "", errors.New("no /proc in this test")
	}
	t.Cleanup(func() { fdRealPath = platformFDRealPath; evalSymlinks = filepath.EvalSymlinks })

	t.Run("the name, confirmed against the descriptor, is kept", func(t *testing.T) {
		evalSymlinks = filepath.EvalSymlinks
		m := measureProgramFile(prog, programHashes(nil))
		if m.realPath != realPathOf(t, prog) || m.realPathSource != RealPathEvalSymlinksConfirmed {
			t.Fatalf("realPath = %q (%s), want %q (%s)", m.realPath, m.realPathSource, realPathOf(t, prog), RealPathEvalSymlinksConfirmed)
		}
		if m.digest == nil {
			t.Fatal("digest withdrawn although the bytes were read")
		}
	})

	t.Run("a name that is another file is refused, and the digest stays", func(t *testing.T) {
		evalSymlinks = func(string) (string, error) { return decoy, nil }
		m := measureProgramFile(prog, programHashes(nil))
		if m.realPath != "" {
			t.Fatalf("realPath = %q: a name that is not the hashed file must not be recorded", m.realPath)
		}
		if m.realPathSource != RealPathUnresolved || m.realPathReason == "" {
			t.Fatalf("realPathSource = %q, realPathReason = %q: want unresolved with a reason", m.realPathSource, m.realPathReason)
		}
		if got := digestSHA256(t, m.digest); got != programSHA256Hex([]byte(programTestScript)) {
			t.Fatalf("digest = %q: the digest must be kept when only the real path fails", got)
		}
		if m.unresolved != "" {
			t.Fatalf("unresolved = %q, want empty: the program was hashed", m.unresolved)
		}
	})
}

// TestExecTargetChangedAfterRecordIsNotVerified: the guard before Start. Any
// rewrite of c.Path or c.Args that cilock does not name as its own wrapper
// leaves the record saying so. The positive control is a relative argv[0],
// whose c.Path stays relative while the recorded path is absolute; comparing
// the guard with the recorded path would flag every ./gradlew.
func TestExecTargetChangedAfterRecordIsNotVerified(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX script fixtures")
	}
	t.Cleanup(func() { testBeforeExecGuard = nil })

	t.Run("a rewritten exec target is reported", func(t *testing.T) {
		workdir := t.TempDir()
		recorded := filepath.Join(workdir, "recorded")
		substitute := filepath.Join(workdir, "substitute")
		writeProgramScript(t, recorded, programTestScript)
		writeProgramScript(t, substitute, "#!/bin/sh\necho substituted\n")
		testBeforeExecGuard = func(c *exec.Cmd) {
			c.Path = substitute
			c.Args = []string{substitute}
		}
		rc, p := runForProgram(t, []string{recorded}, workdir)
		if rc.Stdout != "substituted\n" {
			t.Fatalf("precondition: the substitute did not run (stdout %q)", rc.Stdout)
		}
		if got := wireStr(p, "bindingReason"); got != programReasonExecTargetChanged {
			t.Fatalf("bindingReason = %q, want %q", got, programReasonExecTargetChanged)
		}
		requireUnverifiedBinding(t, p)
	})

	for _, argv0 := range []string{"./t", "bin/tool"} {
		t.Run("positive control: relative "+argv0+" is not a change", func(t *testing.T) {
			testBeforeExecGuard = nil
			workdir := t.TempDir()
			writeProgramScript(t, filepath.Join(workdir, argv0), programTestScript)
			_, p := runForProgram(t, []string{argv0}, workdir)
			if got := wireStr(p, "bindingReason"); got != programReasonNotBound {
				t.Fatalf("bindingReason = %q, want %q: an untouched relative argv[0] must stay bindable", got, programReasonNotBound)
			}
			if p["wrapper"] != nil {
				t.Fatalf("wrapper = %v on an untraced run", p["wrapper"])
			}
		})
	}
}

func TestSniffProgramFormat(t *testing.T) {
	cases := []struct {
		head []byte
		want string
	}{
		{[]byte("#!/bin/sh\n"), "script"},
		{[]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, "elf"},
		{[]byte{0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1}, "mach-o"},
		{[]byte{0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 7}, "mach-o"},
		{[]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}, "mach-o-universal"},
		{[]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61}, "other"}, // a Java class file
		{[]byte("MZ\x90\x00"), "pe"},
		{[]byte("hello"), "other"},
		{nil, "other"},
	}
	for _, tc := range cases {
		if got := sniffProgramFormat(tc.head); got != tc.want {
			t.Errorf("sniffProgramFormat(%x) = %q, want %q", tc.head, got, tc.want)
		}
	}
}

func digestSHA256(t *testing.T, ds cryptoutil.DigestSet) string {
	t.Helper()
	nm, err := ds.ToNameMap()
	if err != nil {
		t.Fatal(err)
	}
	return nm["sha256"]
}

// TestUnknownSetIDIsNotFalseOnTheWire: a ProgramFile nobody established the
// set-id facts for must not sign "setId": false. The zero value is "unknown",
// emitted as null, so a rule reading setId == false refuses it.
func TestUnknownSetIDIsNotFalseOnTheWire(t *testing.T) {
	raw, err := json.Marshal(ProgramFile{Device: 1, Inode: 2, Links: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"setId":false`) {
		t.Fatalf("file = %s: the zero value claims the program verified free of set-id bits and capabilities", raw)
	}
	if !strings.Contains(string(raw), `"setId":null`) {
		t.Fatalf("file = %s: setId must be emitted, as null, when it is unknown", raw)
	}
}
