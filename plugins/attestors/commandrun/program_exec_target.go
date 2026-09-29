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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveExecTarget returns the exact name Start will execute for c. The
// record measures that name and recordProgram writes it back to c.Path, so the
// file hashed and the file started are one string. Seam: tests substitute the
// Windows rule on any host.
var resolveExecTarget = platformExecTarget

// platformExecTarget: on Windows, Start adds the PATHEXT extension to a
// relative or absolute c.Path itself, after exec.Command has returned, and does
// not write it back (os/exec exec.go, Start, "lp, err = lookExtensions(c.Path,
// c.Dir)"). Measuring c.Path there would hash `tool` while `tool.exe` ran.
// Everywhere else c.Path is executed as it stands.
func platformExecTarget(c *exec.Cmd) (string, error) {
	if runtime.GOOS != "windows" {
		return c.Path, nil
	}
	return windowsExecExtension(c.Path, c.Dir, windowsPathExt(os.Getenv("PATHEXT")), statRegularFile)
}

// windowsExecExtension is os/exec's lookExtensions (go1.26 lp_windows.go),
// with PATHEXT and the file check passed in so every host can test it. Given
// its own output it returns that output unchanged while the directory is
// unchanged, which is what makes writing the result back to c.Path safe:
// Start's own lookup then names the same file.
func windowsExecExtension(path, dir string, exts []string, stat func(string) error) (string, error) {
	switch path {
	case "", ".", "..":
		return "", &exec.Error{Name: path, Err: exec.ErrNotFound}
	}
	if filepath.Base(path) == path {
		path = "." + string(filepath.Separator) + path
	}
	if ext := filepath.Ext(path); ext != "" {
		for _, e := range exts {
			if strings.EqualFold(ext, e) {
				return path, nil
			}
		}
	}
	if dir == "" || filepath.VolumeName(path) != "" || (len(path) > 1 && os.IsPathSeparator(path[0])) {
		return windowsFindExecutable(path, exts, stat)
	}
	dirandpath := filepath.Join(dir, path)
	if !strings.ContainsAny(dirandpath, `:\/`) {
		// os/exec would search PATH for this (Dir "."); runCmd's Dir is
		// always absolute, and a lookup this cannot mirror must not run.
		return "", &exec.Error{Name: path, Err: errors.New("the exec target cannot be resolved against a relative working directory")}
	}
	lp, err := windowsFindExecutable(dirandpath, exts, stat)
	if err != nil {
		return "", err
	}
	return path + strings.TrimPrefix(lp, dirandpath), nil
}

// windowsFindExecutable is os/exec's findExecutable for Windows.
func windowsFindExecutable(file string, exts []string, stat func(string) error) (string, error) {
	if len(exts) == 0 {
		if err := stat(file); err != nil {
			return "", &exec.Error{Name: file, Err: err}
		}
		return file, nil
	}
	if windowsHasExt(file) && stat(file) == nil {
		return file, nil
	}
	for _, e := range exts {
		if f := file + e; stat(f) == nil {
			return f, nil
		}
	}
	if windowsHasExt(file) {
		return "", &exec.Error{Name: file, Err: fs.ErrNotExist}
	}
	return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
}

func windowsHasExt(file string) bool {
	i := strings.LastIndex(file, ".")
	if i < 0 {
		return false
	}
	return strings.LastIndexAny(file, `:\/`) < i
}

// windowsPathExt is os/exec's pathExt over the PATHEXT value given.
func windowsPathExt(pathext string) []string {
	if pathext == "" {
		return []string{".com", ".exe", ".bat", ".cmd"}
	}
	var exts []string
	for e := range strings.SplitSeq(strings.ToLower(pathext), ";") {
		if e == "" {
			continue
		}
		if e[0] != '.' {
			e = "." + e
		}
		exts = append(exts, e)
	}
	return exts
}

// statRegularFile is os/exec's chkStat: the name exists and is not a directory.
func statRegularFile(file string) error {
	d, err := os.Stat(file)
	if err != nil {
		return err
	}
	if d.IsDir() {
		return fs.ErrPermission
	}
	return nil
}
