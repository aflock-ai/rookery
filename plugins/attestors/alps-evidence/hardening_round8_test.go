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

package alpsevidence

// Round 8. Each test here answers one review finding, and each one rests on a
// MEASUREMENT of the installed Codex CLI rather than a reading of it: the
// paths and values below were produced by running codex-cli 0.147.0
// (macos-aarch64) against purpose-built fixtures on 2026-08-26. What was asked
// and what came back is recorded in
// testdata/codex-cli-0.147.0-config-contract.txt.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// physicalTempDir is t.TempDir() with its symlinks resolved.
//
// Every upward walk in this package now starts from the PHYSICAL working
// directory (see physicalDir), so the paths it reports are physical too. On
// macOS t.TempDir() hands back a path under /var, which is itself a symlink to
// /private/var — a fixture that compares a reported path against the raw
// t.TempDir() string would be asserting the lexical answer this package
// deliberately stopped giving.
func physicalTempDir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return resolved
}

// ---------------------------------------------------------------------------
// Finding: "<cwd>/config.toml" was treated as a Codex project configuration
// tier. It is not one. Measured against codex-cli 0.147.0:
//
//	fixture                                        resolved model
//	<repo>/.codex/config.toml + <cwd>/config.toml  the .codex one
//	<cwd>/.codex/config.toml                       the .codex one
//	<cwd>/config.toml only                         $CODEX_HOME's, unchanged
//	<repo-root>/config.toml only                   $CODEX_HOME's, unchanged
//
// A bare config.toml is an extremely common repository file (Hugo, Rust,
// countless others). Treating one as Codex project configuration both signed
// an unrelated file's digest as Codex configuration and suppressed the user
// tier that actually described the run.
// ---------------------------------------------------------------------------

func TestBareWorkingDirectoryConfigIsNotACodexProjectTier(t *testing.T) {
	workingDir := physicalTempDir(t)
	writeFile(t, filepath.Join(workingDir, "config.toml"), `sandbox_mode = "danger-full-access"`)

	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), `sandbox_mode = "read-only"`)

	got := detectWithRepo(t, codexUnderCilock(), 100, workingDir)

	assert.Equal(t, "read-only", settingValue(got.Inspection.Settings, "sandbox_mode"),
		"an unrelated repository config.toml is not a Codex layer, so it must not suppress the user tier")
	for _, source := range got.Inspection.Configuration {
		assert.NotEqual(t, filepath.Join(workingDir, "config.toml"), source.Path,
			"a file Codex never opens must not be digested into signed evidence as Codex configuration")
	}
}

// TestWorkingDirectoryDotCodexIsAProjectTier is the other half: the location
// Codex DOES read at the working directory must still block the lower tier.
func TestWorkingDirectoryDotCodexIsAProjectTier(t *testing.T) {
	workingDir := physicalTempDir(t)
	writeFile(t, filepath.Join(workingDir, ".codex", "config.toml"), `sandbox_mode = "danger-full-access"`)

	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), `sandbox_mode = "read-only"`)

	got := detectWithRepo(t, codexUnderCilock(), 100, workingDir)

	assert.Empty(t, settingValue(got.Inspection.Settings, "sandbox_mode"),
		"the working directory's .codex/config.toml outranks the user tier, so the safer user posture cannot answer")

	projectPath := filepath.Join(workingDir, ".codex", "config.toml")
	found := false
	for _, source := range got.Inspection.Configuration {
		if source.Path == projectPath {
			found = true
			assert.Equal(t, "project", source.Scope)
			assert.NotEmpty(t, source.SHA256)
		}
	}
	assert.True(t, found, "the working directory project layer must be recorded as observed")
}

// TestCodexProjectConfigPathsAreOnlyDotCodexFiles pins the candidate list
// itself, so a reintroduced bare config.toml fails here and not only through
// the end-to-end shape above.
func TestCodexProjectConfigPathsAreOnlyDotCodexFiles(t *testing.T) {
	root := physicalTempDir(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".git"), 0o750))
	workingDir := filepath.Join(root, "sub", "deeper")
	require.NoError(t, os.MkdirAll(workingDir, 0o750))

	paths, complete := codexProjectConfigPaths(workingDir)
	require.True(t, complete)
	require.NotEmpty(t, paths)
	for _, p := range paths {
		assert.Equal(t, ".codex", filepath.Base(filepath.Dir(p)),
			"every Codex project candidate lives in a .codex directory; %s does not", p)
	}
	assert.Contains(t, paths, filepath.Join(workingDir, ".codex", "config.toml"))
	assert.Contains(t, paths, filepath.Join(root, ".codex", "config.toml"))
}

// ---------------------------------------------------------------------------
// The Codex project scan is the SECOND upward walk in this package, and the
// symlink fix that landed for projectRootFromWorkingDir did not cover it. Both
// now go through physicalDir, so they cannot disagree about where the working
// directory physically is.
// ---------------------------------------------------------------------------

func TestCodexProjectPathsResolveSymlinkedWorkingDirectories(t *testing.T) {
	repo := physicalTempDir(t)
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o750))
	real := filepath.Join(repo, "sub")
	require.NoError(t, os.MkdirAll(real, 0o750))

	link := filepath.Join(t.TempDir(), "into-the-repo")
	require.NoError(t, os.Symlink(real, link))

	paths, complete := codexProjectConfigPaths(link)
	require.True(t, complete)
	assert.Contains(t, paths, filepath.Join(repo, ".codex", "config.toml"),
		"the enclosing repository's project layer is reachable through the link and must be scanned")
}

func TestCodexProjectPathsFailClosedWhenResolutionFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-directory")

	paths, complete := codexProjectConfigPaths(missing)
	assert.False(t, complete, "an unresolvable working directory cannot rule out a project override")
	assert.Empty(t, paths)
}

func TestProjectRootFailsClosedWhenResolutionFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-directory")

	root, known := projectRootFromWorkingDir(missing)
	assert.False(t, known, "a working directory that cannot be resolved leaves the applicable project files unknown")
	assert.Empty(t, root)
}

// ---------------------------------------------------------------------------
// Finding (REFUTED): "-p unsafe" was said to select [profiles.unsafe] inside
// config.toml rather than $CODEX_HOME/unsafe.config.toml.
//
// The installed CLI says otherwise, verbatim:
//
//	-p, --profile <CONFIG_PROFILE_V2>
//	    Layer $CODEX_HOME/<name>.config.toml on top of the base user config
//
// The flag's own value type is named CONFIG_PROFILE_V2 because the
// [profiles.<name>] table is the V1 shape it replaced. Resolving that legacy
// table for a current run is the unsafe direction, not the safe one: a stale
// table saying read-only would be signed for a run whose selected overlay
// granted full access.
//
// The refutation is executable rather than prose. It imports the labels the
// observer actually opens, so a revert to the table cannot leave this file
// both compiling and passing, and it drives the legacy table through the real
// resolver to show the table is never consulted.
// ---------------------------------------------------------------------------

func TestCodexProfileOverlayMatchesTheInstalledCLIContract(t *testing.T) {
	contract, err := os.ReadFile(filepath.Join("testdata", "codex-cli-0.147.0-config-contract.txt"))
	require.NoError(t, err, "the measured CLI contract travels with the code that implements it")
	text := string(contract)

	require.Contains(t, text, "Layer $CODEX_HOME/<name>.config.toml on top of the base user config",
		"fixture precondition: the recorded contract is the profile line from codex --help")

	assert.Contains(t, text, strings.ReplaceAll(codexProfileConfigLabel, "<profile>", "<name>"),
		"the observer's profile overlay label must be the path the CLI says it layers")
	assert.Contains(t, text, codexUserConfigLabel,
		"the observer's base label must be the path the CLI says it loads")
}

func TestLegacyProfilesTableIsNeverResolvedForASelectedProfile(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	// The V1 shape, and only the V1 shape: a [profiles.unsafe] table claiming
	// the SAFER posture, with no unsafe.config.toml beside it.
	writeFile(t, filepath.Join(home, ".codex", "config.toml"),
		"sandbox_mode = \"workspace-write\"\n\n[profiles.unsafe]\nsandbox_mode = \"read-only\"\n")

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "-p", "unsafe"}},
	)
	got := detect(t, src, 100)

	assert.Empty(t, settingValue(got.Inspection.Settings, "sandbox_mode"),
		"the selected overlay file is absent, so nothing is resolved; the legacy table must not answer in its place")
	assert.NotContains(t, strings.Join(got.Inspection.Warnings, "\n"), "profiles.unsafe",
		"the legacy table is not part of this CLI's contract and is not reported as if it were")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), codexProfileConfigLabel,
		"the warning must name the overlay file the CLI actually layers")
	assert.Equal(t, "unsafe", got.Inspection.ArgvFields["profile"],
		"-p is clap's short alias for --profile and selects the same overlay")
}

// ---------------------------------------------------------------------------
// Finding (suggestion): TestFifoRegressionsAreInTheBuild assumed every GOOS
// outside {windows, js, plan9} carries the unix build tag. wasip1 does not.
// The expectation now comes from a build-tagged constant, so the list never
// has to be maintained by hand again.
// ---------------------------------------------------------------------------

func TestUnixBuildTagConstantAgreesWithTheFifoRegressions(t *testing.T) {
	assert.Equal(t, platformHasUnixBuildTag, fifoRegressionsCompiled,
		"//go:build unix must select the FIFO regressions on exactly the platforms it selects the constant on (GOOS=%s)", runtime.GOOS)
}
