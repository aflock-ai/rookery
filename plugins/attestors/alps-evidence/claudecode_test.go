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

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClaudeCodeMacOSDaemonChainIsDetected is the regression for the layout that
// motivated this work. The nearest Claude Code ancestor is a background spare
// worker whose image basename is a version number and whose argv[0] is a
// rewritten title. A matcher comparing either to "claude" finds nothing.
func TestClaudeCodeMacOSDaemonChainIsDetected(t *testing.T) {
	got := detect(t, claudeCodeMacOSDaemonChain(), pidCilock)

	require.Equal(t, StatusDetected, got.Status)
	require.NotNil(t, got.Provider)
	assert.Equal(t, "claude-code", got.Provider.Product())
	assert.Equal(t, "anthropic", got.Provider.Vendor())
	assert.Equal(t, pidSpare, got.Process.PID, "the background spare worker is the nearest agent")
	assert.Equal(t, fpClaudeInstallLayout, got.Match.Fingerprint,
		"identity must rest on the install layout, not on the agent-controlled process title")
}

// TestClaudeCodeVersionFromMatchedProcess. The version is readable from the
// matched process itself, because the executable path IS the version. The
// handoff reported the version was only available from the grandparent's argv;
// that was an artifact of reading argv via ps(1), which never shows the image
// path.
func TestClaudeCodeVersionFromMatchedProcess(t *testing.T) {
	got := detect(t, claudeCodeMacOSDaemonChain(), pidCilock)

	require.NotNil(t, got.Inspection.Version)
	assert.Equal(t, "2.1.234", got.Inspection.Version.Value)
	assert.Equal(t, "process.executable", got.Inspection.Version.Source)
	assert.Equal(t, AssuranceInferred, got.Inspection.Version.Assurance,
		"the kernel reported the path, but the version inside it is a layout inference")
}

// TestClaudeCodeVersionFallsBackToVendorChain covers the shape the handoff
// measured: a matched process whose own path carries no version, with the
// version present in a same-vendor ancestor's argv.
func TestClaudeCodeVersionFallsBackToVendorChain(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 200, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{
			PID: 200, PPID: 300,
			Executable: "/opt/claude-launcher/claude",
			Comm:       "claude",
			Argv:       []string{"claude bg-spare", "--bg-spare", "/tmp/x.sock"},
		},
		ProcessInfo{
			PID: 300, PPID: 1,
			Executable: "/opt/claude-launcher/claude",
			Comm:       "claude",
			Argv: []string{
				"claude bg-pty-host", "--bg-pty-host", "/tmp/y.sock", "200", "50",
				"--", "/Users/dev/.local/share/claude/versions/2.1.234", "--bg-spare", "/tmp/x.sock",
			},
		},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/launchd"},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, 200, got.Process.PID, "identity is still the nearest match")
	require.Len(t, got.Chain, 2, "the vendor chain reaches the pty host")
	require.NotNil(t, got.Inspection.Version)
	assert.Equal(t, "2.1.234", got.Inspection.Version.Value)
	assert.Equal(t, "vendor-chain.argv", got.Inspection.Version.Source)
	assert.Equal(t, AssuranceInferred, got.Inspection.Version.Assurance,
		"a version harvested from a versioned install path in an ancestor's argv is inferred, not process-observed")
}

// TestClaudeCodeVersionFromCommWhenLaunchedThroughAShim. When the executable
// path is a launcher with no version in it, the kernel's process name is the
// image that was actually loaded. Graded inferred, not process-observed.
func TestClaudeCodeVersionFromCommWhenLaunchedThroughAShim(t *testing.T) {
	got := detect(t, claudeCodeShimLaunch(), 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, fpClaudeExecutable, got.Match.Fingerprint)
	require.NotNil(t, got.Inspection.Version)
	assert.Equal(t, "2.1.237", got.Inspection.Version.Value)
	assert.Equal(t, "process.comm", got.Inspection.Version.Source)
	assert.Equal(t, AssuranceInferred, got.Inspection.Version.Assurance)
}

// TestClaudeCodeModelIsNotClaimedFromArgv is the honesty regression.
//
// The prototype README asserted Mode 1 "can observe model selection from strong
// local sources such as the agent process argv". For Claude Code that is false:
// the measured argv is ["claude bg-spare", "--bg-spare", "<socket>"] and
// contains no model at all. This test fails if anyone later invents a model
// from that argv.
func TestClaudeCodeModelIsNotClaimedFromArgv(t *testing.T) {
	withHomeDir(t, t.TempDir())
	got := detect(t, claudeCodeMacOSDaemonChain(), pidCilock)

	assert.Nil(t, got.Inspection.Model, "no model is observable in this layout")

	joined := strings.Join(got.Inspection.Warnings, "\n")
	assert.Contains(t, joined, "effective model not observable")
	assert.Contains(t, joined, "Absence here is not evidence",
		"the warning must say what absence does and does not mean")
}

// TestClaudeCodeWarnsWhenTheMatchIsABackgroundWorker. A reader must be told the
// matched process is a daemon worker rather than the interactive session, or
// they will over-read the PID.
func TestClaudeCodeWarnsWhenTheMatchIsABackgroundWorker(t *testing.T) {
	got := detect(t, claudeCodeMacOSDaemonChain(), pidCilock)

	joined := strings.Join(got.Inspection.Warnings, "\n")
	assert.Contains(t, joined, "background worker")
	assert.Equal(t, "bg-spare", got.Inspection.ArgvFields["process_title_role"])
}

// TestClaudeCodeSessionComesFromCilocksOwnEnvironment. The session identifier is
// inherited by cilock and is absent from the matched daemon process, so scope
// matters: reading only the agent's environment would find nothing.
func TestClaudeCodeSessionComesFromCilocksOwnEnvironment(t *testing.T) {
	got := detect(t, claudeCodeMacOSDaemonChain(), pidCilock)

	require.NotNil(t, got.Inspection.Session)
	assert.Equal(t, "6f1c0f5e-6a1a-4a63-9f1e-2f2a4a0b1c33", got.Inspection.Session.Value)
	assert.Equal(t, "cilock-process.environment:CLAUDE_CODE_SESSION_ID", got.Inspection.Session.Source)
	assert.Equal(t, AssuranceEnvironmentObserved, got.Inspection.Session.Assurance)
}

func TestClaudeCodeModelFromEnvironmentIsGradedLowerThanArgv(t *testing.T) {
	withHomeDir(t, t.TempDir())
	// The variable is carried by the AGENT process. Only the agent's own
	// environment can establish the model — see
	// TestReadableAgentEnvironmentDoesNotPromoteCilocksOwnValue for the
	// self-scope refusal.
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Argv: []string{"claude"},
			Env: map[string]string{"ANTHROPIC_MODEL": "claude-from-env"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "claude-from-env", got.Inspection.Model.Value)
	assert.Equal(t, AssuranceEnvironmentObserved, got.Inspection.Model.Assurance)
}

// TestClaudeCodeModelPrecedence walks the settings files in the documented
// order and checks that the file which decided the answer is the only one
// marked effective.
func TestClaudeCodeModelPrecedence(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	repo := t.TempDir()

	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "user-model"})
	writeJSON(t, filepath.Join(repo, ".claude", "settings.json"), map[string]any{"model": "project-model"})
	writeJSON(t, filepath.Join(repo, ".claude", "settings.local.json"), map[string]any{"model": "local-model"})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Argv: []string{"claude"}},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(t.Context(), 100, repo)
	require.NoError(t, err)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "local-model", got.Inspection.Model.Value, "project-local settings outrank project and user")
	assert.Equal(t, AssuranceConfigObserved, got.Inspection.Model.Assurance)

	// Every recorded file is observed. Which one the agent actually loaded is
	// no longer claimed — see ResolutionRole — so the assertion is that each
	// file is recorded with its digest, not that one of them won.
	for _, cfg := range got.Inspection.Configuration {
		assert.Equal(t, RoleObserved, cfg.Role)
		assert.NotEmpty(t, cfg.SHA256, "every config source must carry a digest")
	}
	assert.Len(t, got.Inspection.Configuration, 3)
}

// TestClaudeCodeArgvFlagIsHighestPrecedence.
func TestClaudeCodeArgvFlagBeatsConfig(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "user-model"})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude",
			Argv: []string{"claude", "--model", "argv-model", "--permission-mode", "acceptEdits"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "argv-model", got.Inspection.Model.Value)
	assert.Equal(t, AssuranceProcessObserved, got.Inspection.Model.Assurance)
	assert.Equal(t, "acceptEdits", got.Inspection.ArgvFields["permission_mode"])

	for _, cfg := range got.Inspection.Configuration {
		assert.Equal(t, RoleObserved, cfg.Role, "no file is ever claimed as the one that was loaded")
	}
}

func TestClaudeCodeRecordsDangerousPermissionFlag(t *testing.T) {
	withHomeDir(t, t.TempDir())
	got := detect(t, claudeCodeShimLaunch(), 100)
	assert.Equal(t, "true", got.Inspection.ArgvFields["dangerously_skip_permissions"])
}

func TestIsClaudeVersionsLayout(t *testing.T) {
	cases := map[string]bool{
		"/Users/dev/.local/share/claude/versions/2.1.234": true,
		"/opt/claude/versions/nightly":                    true,
		"/opt/notclaude/versions/2.1.234":                 false,
		"/opt/claude/version/2.1.234":                     false,
		"/opt/claude/versions":                            false,
		"/usr/local/bin/claude":                           false,
		"":                                                false,
	}
	for path, want := range cases {
		assert.Equalf(t, want, isClaudeVersionsLayout(path), "path %q", path)
	}
}

func TestClaudeVersionFromPathRejectsNonVersionLeaf(t *testing.T) {
	assert.Equal(t, "2.1.234", claudeVersionFromPath("/opt/claude/versions/2.1.234"))
	assert.Equal(t, "", claudeVersionFromPath("/opt/claude/versions/nightly"))
}

// withHomeDir points config discovery at a temporary directory so a test never
// reads, or depends on, the developer's real ~/.claude.
func withHomeDir(t *testing.T, dir string) {
	t.Helper()
	previous := homeDirFunc
	homeDirFunc = func() (string, error) { return dir, nil }
	t.Cleanup(func() { homeDirFunc = previous })
}

func writeJSON(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	body, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, body, 0o600))
}

// TestClaudeCodeConfigModelIsMarkedAsADefaultNotAsWhatRan.
//
// A settings file records a configured default. It is not a record of what
// served the session: Claude Code accepts a launch-time override and the model
// can be switched mid-session, neither of which touches the file. Observed on a
// real machine — the settings file named one model while the session ran
// another, and an unhedged predicate would have reported the file's value as
// fact.
func TestClaudeCodeConfigModelIsMarkedAsADefaultNotAsWhatRan(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "configured-default"})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Argv: []string{"claude"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "configured-default", got.Inspection.Model.Value)
	assert.Equal(t, AssuranceConfigObserved, got.Inspection.Model.Assurance)

	joined := strings.Join(got.Inspection.Warnings, "\n")
	assert.Contains(t, joined, "configured default")
	assert.Contains(t, joined, "not a confirmed record of the model that served this session")
}

// TestClaudeCodeArgvModelCarriesNoDefaultCaveat. A model observed on the command
// line is a real observation of this process and must not be hedged as if it
// were a config default.
func TestClaudeCodeArgvModelCarriesNoDefaultCaveat(t *testing.T) {
	withHomeDir(t, t.TempDir())
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude",
			Argv: []string{"claude", "--model", "argv-model"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, AssuranceProcessObserved, got.Inspection.Model.Assurance)
	assert.NotContains(t, strings.Join(got.Inspection.Warnings, "\n"), "configured default")
}

// claudeSettingsBlockingFixture is the shared harness for the two
// blocked-fall-through regressions: a project-local settings file in a given
// state, a user settings file that names a model, and a detected Claude Code
// process. Precedence runs project-local over user, so if the project-local
// file's model value is UNKNOWN the user file must not answer.
func claudeSettingsBlockingFixture(t *testing.T, localContent []byte) Detection {
	t.Helper()
	home := t.TempDir()
	withHomeDir(t, home)
	repo := t.TempDir()

	localPath := filepath.Join(repo, ".claude", "settings.local.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(localPath), 0o750))
	require.NoError(t, os.WriteFile(localPath, localContent, 0o600))
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "user-model"})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Argv: []string{"claude"}},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(t.Context(), 100, repo)
	require.NoError(t, err)
	return got
}

// TestClaudeCodeOversizedHigherPrecedenceSettingsBlockLowerFiles is the
// regression for the fall-through Codex flagged: a settings file that exists
// but exceeds the snapshot bound may hold a model override, so no
// lower-precedence file may answer for the model, and the block must be
// explained.
func TestClaudeCodeOversizedHigherPrecedenceSettingsBlockLowerFiles(t *testing.T) {
	got := claudeSettingsBlockingFixture(t, make([]byte, configDigestLimit+1))

	assert.Nil(t, got.Inspection.Model,
		"a lower-precedence model must not answer past a higher-precedence file whose value is unknown")
	joined := strings.Join(got.Inspection.Warnings, "\n")
	assert.Contains(t, joined, ".claude/settings.local.json")
	assert.Contains(t, joined, "not consulted")

	// Both files are still recorded; the oversize one contributes presence
	// without a digest.
	assert.Len(t, got.Inspection.Configuration, 2)
}

// TestClaudeCodeUnparseableHigherPrecedenceSettingsBlockLowerFiles: the same
// rule for a file whose bytes were snapshotted but do not parse — what it
// sets is just as unknown as an oversize file's contents.
func TestClaudeCodeUnparseableHigherPrecedenceSettingsBlockLowerFiles(t *testing.T) {
	got := claudeSettingsBlockingFixture(t, []byte("{ not json"))

	assert.Nil(t, got.Inspection.Model,
		"a lower-precedence model must not answer past an unparseable higher-precedence file")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "not consulted")
}

// TestClaudeCodeProjectSettingsAreFoundFromANestedWorkingDirectory is the
// regression for treating the working directory as the repository root.
//
// Cilock is routinely invoked from repo/subdir — a Go module, a package
// directory — where the directory itself holds no .claude files while the
// repository root's higher-precedence ones do. The pre-fix discovery looked
// only at workingDir/.claude, found nothing, and signed the USER file's model
// as the configured default over a project file that outranks it.
func TestClaudeCodeProjectSettingsAreFoundFromANestedWorkingDirectory(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "user-model"})

	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o750))
	writeJSON(t, filepath.Join(repo, ".claude", "settings.json"), map[string]any{"model": "project-model"})
	subdir := filepath.Join(repo, "services", "api")
	require.NoError(t, os.MkdirAll(subdir, 0o750))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Argv: []string{"claude"}},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(t.Context(), 100, subdir)
	require.NoError(t, err)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "project-model", got.Inspection.Model.Value,
		"the repository root's settings outrank the user file even when cilock runs from a subdirectory")
	assert.Equal(t, AssuranceConfigObserved, got.Inspection.Model.Assurance)
}

// TestGeminiProjectSettingsAreFoundFromANestedWorkingDirectory pins the same
// contract for the Gemini provider, whose project candidate goes through
// userScopedSettings.
func TestGeminiProjectSettingsAreFoundFromANestedWorkingDirectory(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".gemini", "settings.json"), map[string]any{"model": "user-gemini-model"})

	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o750))
	writeJSON(t, filepath.Join(repo, ".gemini", "settings.json"), map[string]any{"model": "project-gemini-model"})
	subdir := filepath.Join(repo, "cmd", "tool")
	require.NoError(t, os.MkdirAll(subdir, 0o750))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/gemini", Argv: []string{"gemini"}},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(t.Context(), 100, subdir)
	require.NoError(t, err)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "project-gemini-model", got.Inspection.Model.Value)
}

// TestProjectRootFromWorkingDir pins the discovery contract directly: the
// nearest .git boundary wins whether it is a directory (ordinary checkout) or
// a file (worktree, submodule), a marker-less tree keeps the working directory
// as its own root, and an empty working directory stays empty-and-known.
func TestProjectRootFromWorkingDir(t *testing.T) {
	// Expectations are stated on the RESOLVED paths: t.TempDir sits behind a
	// symlink on macOS (/var to /private/var), and discovery resolves the
	// working directory before walking.
	repo, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o750))
	nested := filepath.Join(repo, "a", "b", "c")
	require.NoError(t, os.MkdirAll(nested, 0o750))

	root, known := projectRootFromWorkingDir(nested)
	assert.True(t, known)
	assert.Equal(t, repo, root, "the .git directory boundary is the project root")

	worktree, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: elsewhere\n"), 0o600))
	sub := filepath.Join(worktree, "pkg")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	root, known = projectRootFromWorkingDir(sub)
	assert.True(t, known)
	assert.Equal(t, worktree, root, "a .git FILE (worktree, submodule) is a boundary too")

	bare, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root, known = projectRootFromWorkingDir(bare)
	assert.True(t, known)
	assert.Equal(t, bare, root, "with no repository marker anywhere above, the working directory is its own root")

	root, known = projectRootFromWorkingDir("")
	assert.True(t, known)
	assert.Empty(t, root)
}

// TestClaudeCodeNullProjectSettingsBlockLowerPrecedenceResolution is the
// behavior half of the JSON-null regression: a higher-precedence project file
// whose entire content is `null` must block the model question, not fall
// through to the user file. Before the fix, Go's null-into-map decode made the
// null file read as a parseable object that set nothing, and the user model
// was signed as the configured default under it.
func TestClaudeCodeNullProjectSettingsBlockLowerPrecedenceResolution(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "user-model"})

	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".claude"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(repo, ".claude", "settings.json"), []byte("null"), 0o600))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Argv: []string{"claude"}},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(t.Context(), 100, repo)
	require.NoError(t, err)

	assert.Nil(t, got.Inspection.Model,
		"what a null project file sets is unknown, so the user file may not answer for it")
	joined := strings.Join(got.Inspection.Warnings, "\n")
	assert.Contains(t, joined, "could not be parsed within the snapshot bound",
		"the block must be explained")
}

// TestProjectRootFollowsASymlinkedWorkingDirectory: cilock's working directory
// is routinely a symlink (macOS /tmp, direnv layouts, agent worktree links),
// and the .git boundary lives on the RESOLVED path. A lexical-only walk from
// the symlink's own parent either misses the real repository or, worse, finds
// an unrelated one that happens to sit above the link — and the model from a
// lower-precedence user file is then signed as the configured default. The
// discovery must resolve symlinks before walking.
func TestProjectRootFollowsASymlinkedWorkingDirectory(t *testing.T) {
	repo, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o750))
	subdir := filepath.Join(repo, "services", "api")
	require.NoError(t, os.MkdirAll(subdir, 0o750))

	// The link lives in a directory with NO repository above it, so a lexical
	// walk from the link finds nothing and falls back to the link itself.
	linkParent := t.TempDir()
	link := filepath.Join(linkParent, "workdir-link")
	require.NoError(t, os.Symlink(subdir, link))

	root, known := projectRootFromWorkingDir(link)
	assert.True(t, known)
	assert.Equal(t, repo, root, "the .git boundary is discovered on the resolved path, not the symlink's lexical one")

	// A working directory that cannot be resolved proves nothing about which
	// project files apply: fail closed.
	dangling := filepath.Join(linkParent, "dangling")
	require.NoError(t, os.Symlink(filepath.Join(linkParent, "no-such-target"), dangling))
	root, known = projectRootFromWorkingDir(dangling)
	assert.False(t, known, "an unresolvable working directory must fail closed, not fall back to a lexical walk")
	assert.Empty(t, root)
}
