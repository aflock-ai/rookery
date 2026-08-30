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

package commandrun

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// TestWrappedCommandSeesSymlinkResolvedWorkdir: `cilock run -- syft dir:.`
// from a checkout under /tmp (a symlink to /private/tmp on macOS) walked
// /private/tmp for twenty minutes. syft resolves `.` through $PWD, gets the
// symlinked spelling, EvalSymlinks it to a path that is not "under" the
// spelling it started from, and re-roots at the parent. cilock already
// resolves the workdir through the OS for its OWN bookkeeping (see
// TestAttestResolvesSymlinkedWorkingDirectoryThroughTheOS); the wrapped
// command must get the same answer: its cwd and $PWD are the kernel path, so
// `.` means the repository root and nothing else.
//
// Both spellings of "no explicit --workingdir" are covered: an explicit
// symlinked WithWorkingDir, and an inherited symlinked process cwd.
func TestWrappedCommandSeesSymlinkResolvedWorkdir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell and symlinks")
	}
	real := t.TempDir()
	want, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	if link == want {
		t.Fatal("fixture broken: the symlink spelling equals the real path")
	}

	run := func(t *testing.T, workdir string) (pwd, physical string) {
		t.Helper()
		actx, err := attestation.NewContext("symlinked-workdir", []attestation.Attestor{}, attestation.WithWorkingDir(workdir))
		if err != nil {
			t.Fatalf("NewContext: %v", err)
		}
		rc := New(
			WithCommand([]string{"sh", "-c", `printf '%s\n%s' "$PWD" "$(pwd -P)"`}),
			WithSilent(true),
		)
		if err := rc.Attest(actx); err != nil {
			t.Fatalf("Attest: %v", err)
		}
		parts := strings.SplitN(rc.Stdout, "\n", 2)
		if len(parts) != 2 {
			t.Fatalf("unexpected stdout %q", rc.Stdout)
		}
		return parts[0], parts[1]
	}

	t.Run("explicit symlinked workingdir", func(t *testing.T) {
		pwd, physical := run(t, link)
		if physical != want {
			t.Fatalf("command ran in %q, want %q", physical, want)
		}
		if pwd != want {
			t.Errorf("$PWD in the wrapped command = %q, want the kernel path %q — tools that resolve `.` through $PWD (syft) re-root on the symlink", pwd, want)
		}
	})

	t.Run("inherited symlinked cwd", func(t *testing.T) {
		t.Chdir(link)
		pwd, physical := run(t, "")
		if physical != want {
			t.Fatalf("command ran in %q, want %q", physical, want)
		}
		if pwd != want {
			t.Errorf("$PWD in the wrapped command = %q, want the kernel path %q", pwd, want)
		}
	})
}
