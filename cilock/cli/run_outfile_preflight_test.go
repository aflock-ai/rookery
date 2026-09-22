// jade:ring local
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

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRunRefusesExistingOutfileBeforeTheCommand pins H6 (a). The compact
// evidence profile refuses to overwrite an existing --outfile (or one of its
// inventory companions), but that refusal used to fire in persistRunResults,
// AFTER the wrapped command had run: a 30-minute test gate ran to completion,
// was signed, and was then thrown away with exit 1. Every input to the
// refusal is known at start, so the run must refuse before the command.
//
// Driven through the real `cilock run` so the ordering against the wrapped
// command is what is asserted, not a helper's return value.
func TestRunRefusesExistingOutfileBeforeTheCommand(t *testing.T) {
	for name, existing := range map[string]func(out string) string{
		"outfile":                     func(out string) string { return out },
		"product inventory companion": func(out string) string { return out + "-product-inventory.json" },
		"material inventory companion": func(out string) string {
			return out + "-material-inventory.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			inventoryProfile(t, "compact", "131072")
			ro, _, key := inventoryRunFixture(t)
			occupied := existing(ro.OutFilePath)
			require.NoError(t, os.WriteFile(occupied, []byte("an earlier run's evidence"), 0o600))
			marker := filepath.Join(ro.WorkingDir, "wrapped-command-ran")

			cmd := RunCmd()
			cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "environment", "-k", key,
				"--workingdir", ro.WorkingDir, "--capture-mode", "walk", "-o", ro.OutFilePath,
				"--", "touch", marker})
			_, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })

			require.ErrorContains(t, err, "refuse existing or inaccessible evidence path")
			require.ErrorContains(t, err, occupied, "the refusal must name the path that is in the way")
			_, statErr := os.Stat(marker)
			require.True(t, os.IsNotExist(statErr), "the wrapped command must not run when the outfile is already taken (stat err: %v)", statErr)
			body, readErr := os.ReadFile(occupied)
			require.NoError(t, readErr)
			require.Equal(t, "an earlier run's evidence", string(body), "the existing file must be left untouched")
		})
	}
}

// TestRunFreshOutfileStillRuns is the control: with nothing in the way the
// preflight must stand down and the wrapped command must run and be written.
func TestRunFreshOutfileStillRuns(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, _, key := inventoryRunFixture(t)
	marker := filepath.Join(ro.WorkingDir, "wrapped-command-ran")
	cmd := RunCmd()
	cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "environment", "-k", key,
		"--workingdir", ro.WorkingDir, "--capture-mode", "walk", "-o", ro.OutFilePath,
		"--", "touch", marker})
	_, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })
	require.NoError(t, err)
	require.FileExists(t, marker)
	require.FileExists(t, ro.OutFilePath)
}

// TestRunRefusesInaccessibleOutfileBeforeTheCommand: an outfile whose state
// cannot be read (its directory is not searchable) is refused like a taken
// one, before the command. An Lstat error other than "does not exist" must
// never be read as "the path is free".
func TestRunRefusesInaccessibleOutfileBeforeTheCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory search permission is a Unix mode bit")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	inventoryProfile(t, "compact", "131072")
	ro, _, key := inventoryRunFixture(t)
	locked := filepath.Join(filepath.Dir(ro.OutFilePath), "locked")
	require.NoError(t, os.Mkdir(locked, 0o700))
	outFile := filepath.Join(locked, "run.json")
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	_, lstatErr := os.Lstat(outFile)
	require.Error(t, lstatErr)
	require.False(t, os.IsNotExist(lstatErr), "fixture must make the outfile unreadable, not absent (got %v)", lstatErr)
	marker := filepath.Join(ro.WorkingDir, "wrapped-command-ran")

	cmd := RunCmd()
	cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "environment", "-k", key,
		"--workingdir", ro.WorkingDir, "--capture-mode", "walk", "-o", outFile,
		"--", "touch", marker})
	_, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })

	require.ErrorContains(t, err, "refuse existing or inaccessible evidence path")
	require.ErrorContains(t, err, outFile)
	_, statErr := os.Stat(marker)
	require.True(t, os.IsNotExist(statErr), "the wrapped command must not run when the outfile cannot be checked (stat err: %v)", statErr)
}
