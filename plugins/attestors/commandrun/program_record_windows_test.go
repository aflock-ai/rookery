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

//go:build windows

package commandrun

import (
	"os"
	"path/filepath"
	"testing"
)

// windowsExecutableFixture copies a system executable next to an
// extensionless decoy of the same name, so a record that hashed the name as
// typed would hash the decoy while Start ran name.exe.
func windowsExecutableFixture(t *testing.T) (dir, exe string, exeBody []byte) {
	t.Helper()
	src := filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe")
	body, err := os.ReadFile(src) //nolint:gosec // a system executable, read as a fixture
	if err != nil {
		t.Skipf("precondition: no %s to copy: %v", src, err)
	}
	dir = t.TempDir()
	exe = filepath.Join(dir, "tool.exe")
	if err := os.WriteFile(exe, body, 0o755); err != nil { //nolint:gosec // an executable fixture must be executable
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("a decoy that is not the program\r\n"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return dir, exe, body
}

// TestWindowsProgramRecordIsTheExtensionStartRuns: on Windows, Start adds the
// PATHEXT extension to a relative or absolute argv[0] that has none. The
// record must describe tool.exe, the file that runs, never the extensionless
// name the caller typed.
func TestWindowsProgramRecordIsTheExtensionStartRuns(t *testing.T) {
	t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")

	t.Run(`relative .\tool`, func(t *testing.T) {
		dir, _, body := windowsExecutableFixture(t)
		rc, p := runForProgram(t, []string{`.\tool`}, dir)
		if rc.ExitCode != 0 {
			t.Fatalf("precondition: tool.exe did not run cleanly: exit %d", rc.ExitCode)
		}
		if p == nil {
			t.Fatal("no program record")
		}
		if got, want := wireStr(p, "path"), wireStr(p, "workdir")+`\.\tool.exe`; got != want {
			t.Fatalf("path = %q, want %q: the record must name the file Start runs", got, want)
		}
		if got := wireSHA256(p); got != programSHA256Hex(body) {
			t.Fatalf("digest = %q, want tool.exe's %q", got, programSHA256Hex(body))
		}
		if got := wireStr(p, "bindingReason"); got != programReasonNotBound {
			t.Fatalf("bindingReason = %q, want %q", got, programReasonNotBound)
		}
	})

	t.Run(`absolute dir\tool`, func(t *testing.T) {
		dir, exe, body := windowsExecutableFixture(t)
		rc, p := runForProgram(t, []string{filepath.Join(dir, "tool")}, dir)
		if rc.ExitCode != 0 {
			t.Fatalf("precondition: tool.exe did not run cleanly: exit %d", rc.ExitCode)
		}
		if p == nil {
			t.Fatal("no program record")
		}
		if got := wireStr(p, "path"); got != exe {
			t.Fatalf("path = %q, want %q", got, exe)
		}
		if got := wireSHA256(p); got != programSHA256Hex(body) {
			t.Fatalf("digest = %q, want tool.exe's %q", got, programSHA256Hex(body))
		}
	})
}
