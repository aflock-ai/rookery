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

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// Codex on #9683: on Windows the record composed a non-absolute c.Path with
// the working directory by concatenation, but filepath.IsAbs is false for a
// ROOTED path (\tools\tool.exe) and a DRIVE-RELATIVE one (D:tool.exe), and
// Windows resolves neither against the working directory. With Dir C:\work,
// \tools\tool.exe runs C:\tools\tool.exe, so the record hashed a decoy at
// C:\work\tools\tool.exe. The mechanism is that the record must compose the
// path the way the process launch does: syscall's joinExeDirAndFName
// (syscall/exec_windows.go), which StartProcess applies whenever Dir is set.

// fakeFullPath stands in for GetFullPathName on any host: it cleans an
// absolute drive path, and resolves a drive-relative path on drive D against
// D's current directory, D:\dcwd.
func fakeFullPath(p string) (string, error) {
	p = strings.ReplaceAll(p, "/", `\`)
	switch {
	case len(p) >= 3 && p[1] == ':' && p[2] == '\\':
		return cleanWindows(p), nil
	case len(p) >= 2 && (p[0] == 'D' || p[0] == 'd') && p[1] == ':':
		return cleanWindows(`D:\dcwd\` + p[2:]), nil
	}
	return "", errors.New("fakeFullPath: unsupported " + p)
}

func cleanWindows(p string) string {
	vol, rest := p[:2], p[2:]
	var out []string
	for _, part := range strings.Split(rest, `\`) {
		switch part {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, part)
		}
	}
	return vol + `\` + strings.Join(out, `\`)
}

func TestWindowsProgramPathIsWhatStartProcessRuns(t *testing.T) {
	const dir = `C:\work`
	for _, tc := range []struct {
		path, want string
	}{
		// Relative: joined with the directory, spelled as the kernel walks it.
		{`tool.exe`, `C:\work\tool.exe`},
		{`.\tool.exe`, `C:\work\.\tool.exe`},
		{`bin\tool.exe`, `C:\work\bin\tool.exe`},
		// Rooted: the directory's drive, never the directory.
		{`\tools\tool.exe`, `C:\tools\tool.exe`},
		{`/tools/tool.exe`, `C:/tools/tool.exe`},
		// Drive-relative on the directory's drive: joined with the directory.
		{`C:tool.exe`, `C:\work\tool.exe`},
		{`c:bin\tool.exe`, `C:\work\bin\tool.exe`},
		// Drive-relative on another drive: that drive's current directory.
		{`D:tool.exe`, `D:\dcwd\tool.exe`},
		// Absolute and UNC: as given.
		{`C:\x\tool.exe`, `C:\x\tool.exe`},
		{`E:/x/tool.exe`, `E:/x/tool.exe`},
		{`\\server\share\tool.exe`, `\\server\share\tool.exe`},
	} {
		got, err := windowsProgramPath(dir, tc.path, fakeFullPath)
		if err != nil {
			t.Errorf("%q: %v", tc.path, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.path, got, tc.want)
		}
	}

	// What StartProcess refuses, the record refuses: a bare drive, and any
	// non-absolute path against a UNC directory.
	for _, tc := range []struct{ dir, path string }{
		{dir, `C:`},
		{`\\server\share\work`, `tool.exe`},
		{`\\server\share\work`, `\tools\tool.exe`},
		{dir, ``},
	} {
		if got, err := windowsProgramPath(tc.dir, tc.path, fakeFullPath); err == nil {
			t.Errorf("dir %q path %q: got %q, want a refusal", tc.dir, tc.path, got)
		}
	}
}

// The record uses that composition: with the Windows rule substituted, a
// rooted argv[0] is recorded at the directory's drive root, not under it.
func TestRecordedProgramPathUsesTheLaunchComposition(t *testing.T) {
	composeProgramPath = func(workdir, path string) (string, error) {
		return windowsProgramPath(`C:\work`, path, fakeFullPath)
	}
	resolveExecTarget = func(c *exec.Cmd) (string, error) { return c.Path, nil }
	t.Cleanup(func() { composeProgramPath = platformProgramPath; resolveExecTarget = platformExecTarget })

	c := &exec.Cmd{Path: `\tools\tool.exe`, Args: []string{`\tools\tool.exe`}, Dir: `C:\work`}
	r := &CommandRun{Cmd: []string{`\tools\tool.exe`}}
	r.recordProgram(c, nil)
	if r.Program == nil {
		t.Fatal("no program record")
	}
	if r.Program.Path != `C:\tools\tool.exe` {
		t.Fatalf("path = %q, want the file StartProcess runs, %q", r.Program.Path, `C:\tools\tool.exe`)
	}

	// A path StartProcess would refuse is refused before anything runs.
	composeProgramPath = func(string, string) (string, error) { return "", errors.New("EINVAL") }
	c = &exec.Cmd{Path: `C:`, Args: []string{`C:`}, Dir: `C:\work`}
	r = &CommandRun{Cmd: []string{`C:`}}
	r.recordProgram(c, nil)
	if c.Err == nil || r.Program != nil {
		t.Fatalf("an uncomposable path was recorded (%+v) or left to run (err %v)", r.Program, c.Err)
	}
}
