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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// composeProgramPath is the path the record measures for c.Path run from
// workdir. Seam: tests substitute the Windows rule on any host.
var composeProgramPath = platformProgramPath

func platformProgramPath(workdir, path string) (string, error) {
	if runtime.GOOS == "windows" && workdir != "" {
		return windowsProgramPath(workdir, path, windowsFullPath)
	}
	return posixProgramPath(workdir, path), nil
}

// posixProgramPath: exec evaluates a relative Path against Dir. Concatenate
// rather than Join: Join cleans, and the record keeps the path as the kernel
// will walk it. With no workdir to name, the path stays relative and is
// opened against the process's directory, the one exec uses; prefixing ""
// would measure a file under the root.
func posixProgramPath(workdir, path string) string {
	if filepath.IsAbs(path) || workdir == "" {
		return path
	}
	return workdir + string(os.PathSeparator) + path
}

// windowsProgramPath is syscall's joinExeDirAndFName (go1.26
// syscall/exec_windows.go), which StartProcess applies to argv0 whenever Dir
// is set because CreateProcess would otherwise resolve it against the
// parent's directory. With no Dir, CreateProcess resolves against the current
// directory, which is what recordProgram passes as dir then, so the one rule
// covers both. fullPath is GetFullPathName, passed in so every host can test
// the rule.
//
// Windows resolves neither a ROOTED path (\tools\x.exe: the directory's drive)
// nor a DRIVE-RELATIVE one on another drive (D:x.exe: that drive's current
// directory) against the directory, and filepath.IsAbs is false for both, so
// joining them with it would measure a file the launch never runs. The
// relative and same-drive cases are concatenated as posixProgramPath does,
// which names the same file GetFullPathName would.
func windowsProgramPath(dir, p string, fullPath func(string) (string, error)) (string, error) {
	isSlash := func(c byte) bool { return c == '\\' || c == '/' }
	if p == "" {
		return "", &exec.Error{Name: p, Err: errors.New("empty program path")}
	}
	if len(p) > 2 && isSlash(p[0]) && isSlash(p[1]) {
		return p, nil // \\server\share\path
	}
	if len(p) > 1 && p[1] == ':' && (len(p) == 2 || isSlash(p[2])) {
		if len(p) == 2 {
			return "", &exec.Error{Name: p, Err: errors.New("a bare drive names no program")}
		}
		return p, nil // C:\path
	}
	d, err := fullPath(dir)
	if err != nil {
		return "", &exec.Error{Name: p, Err: err}
	}
	if len(d) > 2 && isSlash(d[0]) && isSlash(d[1]) {
		// StartProcess refuses a UNC working directory for a path it must
		// join, and so does the record.
		return "", &exec.Error{Name: p, Err: errors.New("a path relative to a UNC working directory is not launched")}
	}
	switch {
	case len(p) > 1 && p[1] == ':':
		if strings.EqualFold(p[:1], d[:1]) {
			return dir + `\` + p[2:], nil
		}
		return fullPath(p)
	case isSlash(p[0]):
		return d[:2] + p, nil
	}
	return dir + `\` + p, nil
}
