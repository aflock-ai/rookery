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

package commandrun

// The program record must describe the file Start executes. On Windows Start
// resolves the PATHEXT extension of a relative or absolute argv[0] itself,
// after exec.Command returned, so the record resolves it first and hands Start
// the resolved name. These tests run on every platform: the Windows lookup is
// a pure function over a stat callback, and the seam lets a POSIX run prove
// the record and the exec target are one string.

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// fakeStat answers like exec's chkStat over a fixed set of regular files.
func fakeStat(files ...string) func(string) error {
	return func(p string) error {
		if slices.Contains(files, p) {
			return nil
		}
		return fs.ErrNotExist
	}
}

func TestWindowsExecExtensionMirrorsStart(t *testing.T) {
	sep := string(filepath.Separator)
	w := filepath.Join(string(filepath.Separator), "w")
	exts := []string{".com", ".exe", ".bat", ".cmd"}
	cases := []struct {
		name, path, dir string
		files           []string
		want            string
		wantErr         bool
	}{
		{
			name: "relative name gains the extension, and stays relative to Dir",
			path: "." + sep + "tool", dir: w,
			files: []string{filepath.Join(w, "tool"), filepath.Join(w, "tool.exe")},
			want:  "." + sep + "tool.exe",
		},
		{
			name: "a bare name is looked up as .\\name, never on PATH",
			path: "tool", dir: w,
			files: []string{filepath.Join(w, "tool.exe")},
			want:  "." + sep + "tool.exe",
		},
		{
			name: "PATHEXT order decides: .com before .exe",
			path: "." + sep + "tool", dir: w,
			files: []string{filepath.Join(w, "tool.exe"), filepath.Join(w, "tool.com")},
			want:  "." + sep + "tool.com",
		},
		{
			name: "absolute name gains the extension",
			path: filepath.Join(w, "tool"), dir: "",
			files: []string{filepath.Join(w, "tool"), filepath.Join(w, "tool.exe")},
			want:  filepath.Join(w, "tool.exe"),
		},
		{
			name: "absolute name ignores Dir",
			path: filepath.Join(w, "tool"), dir: filepath.Join(sep, "elsewhere"),
			files: []string{filepath.Join(w, "tool.exe")},
			want:  filepath.Join(w, "tool.exe"),
		},
		{
			name: "an extension PATHEXT lists is taken as resolved, without a stat",
			path: "." + sep + "tool.EXE", dir: w,
			want: "." + sep + "tool.EXE",
		},
		{
			name: "an extension PATHEXT does not list is kept when that file exists",
			path: "." + sep + "tool.sh", dir: w,
			files: []string{filepath.Join(w, "tool.sh"), filepath.Join(w, "tool.sh.exe")},
			want:  "." + sep + "tool.sh",
		},
		{
			name: "an unlisted extension that does not exist gains one that does",
			path: "." + sep + "tool.sh", dir: w,
			files: []string{filepath.Join(w, "tool.sh.exe")},
			want:  "." + sep + "tool.sh.exe",
		},
		{
			name: "no candidate exists", path: "." + sep + "tool", dir: w,
			files:   []string{filepath.Join(w, "tool")},
			wantErr: true,
		},
		{name: "empty", path: "", dir: w, wantErr: true},
		{name: "dot", path: ".", dir: w, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := windowsExecExtension(tc.path, tc.dir, exts, fakeStat(tc.files...))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("windowsExecExtension(%q, %q) = %q, want an error", tc.path, tc.dir, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("windowsExecExtension(%q, %q) = %q, %v; want %q", tc.path, tc.dir, got, err, tc.want)
			}
		})
	}
}

func TestWindowsPathExt(t *testing.T) {
	if got, want := windowsPathExt(""), []string{".com", ".exe", ".bat", ".cmd"}; !slices.Equal(got, want) {
		t.Fatalf("windowsPathExt(\"\") = %q, want the default %q", got, want)
	}
	if got, want := windowsPathExt(".EXE;;cmd"), []string{".exe", ".cmd"}; !slices.Equal(got, want) {
		t.Fatalf("windowsPathExt = %q, want %q", got, want)
	}
}

// TestRecordedProgramIsTheExecTarget simulates the Windows lookup on this host:
// "./tool" resolves to "./tool.exe" while an extensionless decoy "tool" sits
// beside it. The record must hash tool.exe and name it, and Start must run
// exactly the string the record names.
func TestRecordedProgramIsTheExecTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX script fixtures; program_record_windows_test.go covers Windows natively")
	}
	workdir := t.TempDir()
	real := "#!/bin/sh\necho real\n"
	writeProgramScript(t, filepath.Join(workdir, "tool.exe"), real)
	writeProgramScript(t, filepath.Join(workdir, "tool"), "#!/bin/sh\necho decoy\n")

	resolveExecTarget = func(c *exec.Cmd) (string, error) {
		return windowsExecExtension(c.Path, c.Dir, []string{".exe"}, statRegularFile)
	}
	var started string
	testBeforeExecGuard = func(c *exec.Cmd) { started = c.Path }
	t.Cleanup(func() { resolveExecTarget = platformExecTarget; testBeforeExecGuard = nil })

	rc, p := runForProgram(t, []string{"./tool"}, workdir)
	if rc.Stdout != "real\n" {
		t.Fatalf("stdout = %q: Start did not run tool.exe", rc.Stdout)
	}
	if p == nil {
		t.Fatal("no program record")
	}
	if started != "./tool.exe" {
		t.Fatalf("exec target = %q, want the resolved ./tool.exe", started)
	}
	if got, want := wireStr(p, "path"), wireStr(p, "workdir")+"/"+started; got != want {
		t.Fatalf("path = %q, want %q: the record and the exec target must be one string", got, want)
	}
	if got := wireSHA256(p); got != programSHA256Hex([]byte(real)) {
		t.Fatalf("digest = %q, want tool.exe's %q", got, programSHA256Hex([]byte(real)))
	}
	if got := wireStr(p, "bindingReason"); got != programReasonNotBound {
		t.Fatalf("bindingReason = %q, want %q: resolving the extension is not a change of target", got, programReasonNotBound)
	}
}

// TestUnresolvableExecTargetDoesNotRun: when the lookup Start would make
// fails, nothing runs. The record never stands beside a program it could not
// name, and Start is not left to resolve a different one.
func TestUnresolvableExecTargetDoesNotRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX script fixtures")
	}
	workdir := t.TempDir()
	marker := filepath.Join(workdir, "ran")
	writeProgramScript(t, filepath.Join(workdir, "tool"), "#!/bin/sh\ntouch "+marker+"\n")
	refusal := errors.New("no PATHEXT candidate")
	resolveExecTarget = func(*exec.Cmd) (string, error) { return "", refusal }
	t.Cleanup(func() { resolveExecTarget = platformExecTarget })

	_, err := attestForProgram(t, []string{"./tool"}, workdir)
	if !errors.Is(err, refusal) {
		t.Fatalf("Attest error = %v, want the lookup refusal", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the program ran although its exec target could not be resolved")
	}
}

// TestUnreadableWorkdirIsNotInventedAsRoot: with no Dir and no readable
// working directory, a relative argv[0] resolves against the process's
// directory, the one exec uses. Prefixing the empty workdir would hash /./t.
func TestUnreadableWorkdirIsNotInventedAsRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX script fixtures")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	writeProgramScript(t, filepath.Join(dir, "t"), programTestScript)
	getwd = func() (string, error) { return "", errors.New("getcwd: permission denied") }
	t.Cleanup(func() { getwd = os.Getwd })

	c := exec.Command("./t") //nolint:gosec // test fixture
	r := &CommandRun{Cmd: []string{"./t"}}
	r.recordProgram(c, nil)
	if r.Program == nil {
		t.Fatal("no program record")
	}
	if r.Program.Path != "./t" {
		t.Fatalf("path = %q, want the name exec resolves against the process directory, %q", r.Program.Path, "./t")
	}
	if got := digestSHA256(t, r.Program.Digest); got != programSHA256Hex([]byte(programTestScript)) {
		t.Fatalf("digest = %q (unresolved %q), want the program's", got, r.Program.Unresolved)
	}
}

// TestFormatIsNotClaimedFromAFailedRead: a failed read of the first bytes is
// not a program whose bytes match no format.
func TestFormatIsNotClaimedFromAFailedRead(t *testing.T) {
	if got := formatFromHead([]byte("#!"), 2, errors.New("EIO")); got != "" {
		t.Fatalf("format = %q after a failed read, want none", got)
	}
	if got := formatFromHead([]byte("#!/bin/sh"), 2, nil); got != "script" {
		t.Fatalf("format = %q, want script", got)
	}
	if got := formatFromHead([]byte("#!\x00\x00"), 2, io.EOF); got != "script" {
		t.Fatalf("format = %q for a short file, want script", got)
	}
}
