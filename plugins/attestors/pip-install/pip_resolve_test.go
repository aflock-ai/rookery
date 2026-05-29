// Copyright 2026 TestifySec, Inc.
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

package pipinstall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeStub drops an executable shell stub named `name` into dir that echoes
// `stdout` on stdout and exits 0. Used to simulate a pip launcher on PATH.
func writeStub(t *testing.T, dir, name, stdout string) {
	t.Helper()
	// Use the `printf` shell builtin (no external binary) so the stub works
	// even when PATH is restricted to the stub dir itself.
	body := "#!/bin/sh\nprintf '%s\\n' " + shellSingleQuote(stdout) + "\n"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatalf("write stub %s: %v", name, err)
	}
}

// shellSingleQuote wraps s in single quotes, escaping embedded single quotes.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// TestGetInstalledPackagesUsesPip3WhenBarePipAbsent reproduces the reported
// bug: in an environment where only `pip3` is on PATH (the macOS/Homebrew and
// many CI defaults), the attestor must still enumerate packages. The original
// code shelled out to bare `pip`, so getInstalledPackages() errored and
// returned empty. This test stands up a PATH containing only `pip3` (no bare
// `pip`) and asserts a non-empty package list comes back.
func TestGetInstalledPackagesUsesPip3WhenBarePipAbsent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub uses /bin/sh")
	}
	binDir := t.TempDir()
	// Only pip3 exists — NO bare `pip`. This is the broken environment.
	writeStub(t, binDir, "pip3", `[{"name": "requests", "version": "2.32.3"}]`)
	t.Setenv("PATH", binDir)

	pkgs, err := getInstalledPackages()
	if err != nil {
		t.Fatalf("getInstalledPackages with only pip3 on PATH: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("expected packages from pip3, got none — bare-pip fallback not honored")
	}
	if pkgs[0].Name != "requests" || pkgs[0].Version != "2.32.3" {
		t.Fatalf("got %+v, want requests==2.32.3", pkgs[0])
	}
}

// TestResolvePipLauncherPrefersPip3 asserts the launcher resolver prefers pip3
// when both pip3 and pip are present (pip3 is the canonical Python 3 launcher),
// and falls back through pip and `python3 -m pip` as available.
func TestResolvePipLauncherPrefersPip3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub uses /bin/sh")
	}

	t.Run("pip3 only", func(t *testing.T) {
		dir := t.TempDir()
		writeStub(t, dir, "pip3", "")
		t.Setenv("PATH", dir)
		name, pre := resolvePipLauncher()
		if name != "pip3" || len(pre) != 0 {
			t.Fatalf("got (%q, %v), want (pip3, [])", name, pre)
		}
	})

	t.Run("pip only falls back to pip", func(t *testing.T) {
		dir := t.TempDir()
		writeStub(t, dir, "pip", "")
		t.Setenv("PATH", dir)
		name, pre := resolvePipLauncher()
		if name != "pip" || len(pre) != 0 {
			t.Fatalf("got (%q, %v), want (pip, [])", name, pre)
		}
	})

	t.Run("neither pip3 nor pip falls back to python3 -m pip", func(t *testing.T) {
		dir := t.TempDir()
		writeStub(t, dir, "python3", "")
		t.Setenv("PATH", dir)
		name, pre := resolvePipLauncher()
		if name != "python3" || len(pre) != 2 || pre[0] != "-m" || pre[1] != "pip" {
			t.Fatalf("got (%q, %v), want (python3, [-m pip])", name, pre)
		}
	})
}
