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

// Round-7 hardening regressions. Each test names the defect it pins; each was
// red against the pre-fix code (the fixes and these tests landed together —
// redness was verified by reverting the non-test files and re-running).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detectWithRepo is detect with a caller-controlled repository root, for tests
// exercising project-scoped configuration.
func detectWithRepo(t *testing.T, src ProcessSource, selfPID int, repoRoot string) Detection {
	t.Helper()
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), selfPID, repoRoot)
	require.NoError(t, err)
	return got
}

func claudeUnderCilock() *fixtureSource {
	return newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Comm: "claude", Argv: []string{"claude"}},
	)
}

func codexUnderCilock() *fixtureSource {
	return newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex", Argv: []string{"codex"}},
	)
}

// ---------------------------------------------------------------------------
// Finding: openAgentPath followed symlinks on agent-chosen paths, so planting
// a link where a config file belongs published the SHA-256 of ANY
// user-readable file into signed evidence — a content-confirmation oracle.
// ---------------------------------------------------------------------------

func TestSymlinkedConfigPathYieldsNoEvidence(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "id_ed25519")
	secretBody := []byte("-----BEGIN OPENSSH PRIVATE KEY----- pretend")
	require.NoError(t, os.WriteFile(secret, secretBody, 0o600))

	home := t.TempDir()
	withHomeDir(t, home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".claude"), 0o750))
	link := filepath.Join(home, ".claude", "settings.json")
	require.NoError(t, os.Symlink(secret, link))

	// The opener itself refuses the link...
	f, info := openAgentPath(link)
	assert.Nil(t, f, "a symlink where a config file belongs is no evidence")
	assert.Nil(t, info)

	// ...and precedence resolution treats it as blocked, not absent. The real
	// agent may follow this link; falling through to a lower file would claim
	// a value the linked file may override.
	snap, denied := loadConfigSnapshot(link)
	assert.Nil(t, snap)
	assert.True(t, denied)

	// End to end: the secret's digest must appear nowhere in the predicate.
	got := detect(t, claudeUnderCilock(), 100)
	require.Equal(t, StatusDetected, got.Status)
	secretDigest := sha256hex(secretBody)
	foundBlockedSource := false
	for _, cs := range got.Inspection.Configuration {
		assert.NotEqual(t, secretDigest, cs.SHA256,
			"the digest of a file reached through a planted symlink must never be signed (%s)", cs.Path)
		if cs.Path == link {
			foundBlockedSource = true
			assert.Empty(t, cs.SHA256, "the refused target's bytes must contribute no digest")
		}
	}
	assert.True(t, foundBlockedSource, "the unresolved precedence tier must remain visible")
}

func TestSymlinkedProjectConfigBlocksLowerUserResolution(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "private-config.toml")
	writeFile(t, secret, "model = \"project-model\"\n")

	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".codex"), 0o750))
	require.NoError(t, os.Symlink(secret, filepath.Join(repo, ".codex", "config.toml")))

	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), "model = \"user-model\"\n")

	got := detectWithRepo(t, codexUnderCilock(), 100, repo)
	assert.Nil(t, got.Inspection.Model,
		"a refused higher-precedence file may override the user config, so the user model is not resolvable")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "could not be read")
}

// TestParentProjectConfigBlocksLowerUserResolution mirrors Codex 0.143's
// project-stack discovery. Codex loads .codex/config.toml files between the
// working directory and its project root; cilock's WorkingDir is not
// necessarily that root. Looking only at WorkingDir/.codex therefore missed a
// higher-precedence parent file and could serialize the safer user posture for
// a run whose project posture granted full access.
func TestParentProjectConfigBlocksLowerUserResolution(t *testing.T) {
	project := physicalTempDir(t)
	writeFile(t, filepath.Join(project, ".codex", "config.toml"), `
model = "project-model"
sandbox_mode = "danger-full-access"
`)
	workingDir := filepath.Join(project, "subdir", "deeper")
	require.NoError(t, os.MkdirAll(workingDir, 0o750))

	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), `
model = "user-model"
sandbox_mode = "read-only"
`)

	got := detectWithRepo(t, codexUnderCilock(), 100, workingDir)
	assert.Nil(t, got.Inspection.Model,
		"a parent project config may override the user model, so the user model is not resolvable")
	assert.Empty(t, settingValue(got.Inspection.Settings, "sandbox_mode"),
		"a parent project config may override the user sandbox, so the safer user posture must not be serialized")

	projectPath := filepath.Join(project, ".codex", "config.toml")
	found := false
	for _, source := range got.Inspection.Configuration {
		if source.Path == projectPath {
			found = true
			assert.Equal(t, "project", source.Scope)
			assert.NotEmpty(t, source.SHA256)
		}
	}
	assert.True(t, found, "the parent project layer must be recorded as observed")
}

// The working-directory tier this once asserted was <cwd>/config.toml, which
// measurement showed is not a Codex configuration file at all. Its
// replacements live in hardening_round8_test.go:
// TestWorkingDirectoryDotCodexIsAProjectTier for the location Codex really
// reads at the working directory, and
// TestBareWorkingDirectoryConfigIsNotACodexProjectTier for the one it does not.

// TestSymlinkedExecutableIsStillDigested guards the other side of the
// O_NOFOLLOW fix: the recorded executable path of a symlink-installed agent
// (the measured shape for both priority agents) must still be digested —
// openExecutable resolves first and the snapshot verifies the resolution
// against the opened handle.
func TestSymlinkedExecutableIsStillDigested(t *testing.T) {
	withHomeDir(t, t.TempDir())
	dir := t.TempDir()
	target := filepath.Join(dir, ".local", "share", "claude", "versions", "2.1.234")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
	body := []byte("claude-binary-bytes")
	require.NoError(t, os.WriteFile(target, body, 0o700))
	link := filepath.Join(dir, "claude")
	require.NoError(t, os.Symlink(target, link))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: link, Comm: "claude", Argv: []string{"claude"}},
	)
	a := attestFixture(t, src, 100)

	require.NotNil(t, a.Invoker)
	assert.Equal(t, sha256hex(body), a.Invoker.Process.SHA256,
		"a symlink-installed agent's image must still be digested through the resolved target")
	canonicalTarget, err := filepath.EvalSymlinks(target)
	require.NoError(t, err)
	assert.Equal(t, canonicalTarget, a.Invoker.Process.ExecutableResolved)
}

// ---------------------------------------------------------------------------
// Finding: an unreadable (EACCES) higher-precedence settings file was silently
// skipped, so a lower-precedence file's model was signed as the configured
// default — with no trace that a file that could override it existed.
// ---------------------------------------------------------------------------

func requireNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("chmod-000 unreadability does not apply to root")
	}
}

func TestUnreadableClaudeSettingsBlocksLowerPrecedence(t *testing.T) {
	requireNonRoot(t)
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "user-model"})

	// Resolved so the recorded ConfigSource.Path — built from the discovered,
	// symlink-resolved project root — compares exactly (t.TempDir sits behind
	// /var -> /private/var on macOS).
	repo, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	projectPath := filepath.Join(repo, ".claude", "settings.json")
	writeJSON(t, projectPath, map[string]any{"model": "project-model"})
	require.NoError(t, os.Chmod(projectPath, 0o000))
	t.Cleanup(func() { _ = os.Chmod(projectPath, 0o600) })

	got := detectWithRepo(t, claudeUnderCilock(), 100, repo)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Model,
		"an unreadable higher-precedence file may set a model, so the user file must not answer")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "could not be read")

	var unreadable *ConfigSource
	for i := range got.Inspection.Configuration {
		if got.Inspection.Configuration[i].Path == projectPath {
			unreadable = &got.Inspection.Configuration[i]
		}
	}
	require.NotNil(t, unreadable, "the unreadable file must still be recorded as present")
	assert.Empty(t, unreadable.SHA256, "nothing was read, so nothing may be digested")
}

func TestUnreadableCodexProjectConfigDegradesUserConfig(t *testing.T) {
	requireNonRoot(t)
	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), "model = \"user-model\"\n")

	repo := t.TempDir()
	projectPath := filepath.Join(repo, ".codex", "config.toml")
	writeFile(t, projectPath, "model = \"project-model\"\n")
	require.NoError(t, os.Chmod(projectPath, 0o000))
	t.Cleanup(func() { _ = os.Chmod(projectPath, 0o600) })

	got := detectWithRepo(t, codexUnderCilock(), 100, repo)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Model,
		"an unreadable project config counts as existing, so the user config must degrade to observed")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "could not be read")
}

// ---------------------------------------------------------------------------
// Finding: the Gemini config loop lacked the fail-closed guard Claude Code
// has — a malformed (or unreadable) project settings file silently fell
// through to the user scope, whose model was then signed.
// ---------------------------------------------------------------------------

func geminiUnderCilock() *fixtureSource {
	return newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"}},
	)
}

func TestGeminiMalformedProjectSettingsBlocksUserModel(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".gemini", "settings.json"), map[string]any{"model": "user-gemini-model"})

	repo := t.TempDir()
	projectPath := filepath.Join(repo, ".gemini", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(projectPath), 0o750))
	require.NoError(t, os.WriteFile(projectPath, []byte("{ this is not json"), 0o600))

	got := detectWithRepo(t, geminiUnderCilock(), 100, repo)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Model,
		"what the malformed project file sets is unknown, so the user file must not answer")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "could not be parsed")
}

func TestGeminiUnreadableProjectSettingsBlocksUserModel(t *testing.T) {
	requireNonRoot(t)
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".gemini", "settings.json"), map[string]any{"model": "user-gemini-model"})

	repo := t.TempDir()
	projectPath := filepath.Join(repo, ".gemini", "settings.json")
	writeJSON(t, projectPath, map[string]any{"model": "project-gemini-model"})
	require.NoError(t, os.Chmod(projectPath, 0o000))
	t.Cleanup(func() { _ = os.Chmod(projectPath, 0o600) })

	got := detectWithRepo(t, geminiUnderCilock(), 100, repo)

	assert.Nil(t, got.Inspection.Model)
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "could not be read")
}

// ---------------------------------------------------------------------------
// Finding: resolveEnvValue's `v != ""` guard read a carried-but-empty value
// as not-carried and fell through, so cilock's own inherited value was
// published as the agent's for exactly the runs where the agent had cleared
// the variable.
// ---------------------------------------------------------------------------

func TestCarriedEmptyEnvValueDoesNotFallThrough(t *testing.T) {
	carriedEmpty := envScope{values: map[string]string{"KEY": ""}, present: map[string]struct{}{"KEY": {}}, read: true}
	lower := envScope{values: map[string]string{"KEY": "lower-value"}, present: map[string]struct{}{"KEY": {}}, read: true}

	v, blocked := resolveEnvValue("KEY", carriedEmpty, lower)
	assert.False(t, blocked)
	assert.Empty(t, v, "an agent that cleared a variable has answered; the lower scope must not be consulted")

	// Not-carried still falls through.
	v, blocked = resolveEnvValue("KEY", envScope{values: map[string]string{}, present: map[string]struct{}{}, read: true}, lower)
	assert.False(t, blocked)
	assert.Equal(t, "lower-value", v)
}

func TestAgentClearedModelIsNotReplacedByCilocksValue(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), `{"model":"lower-config-model"}`)
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock",
			Env: map[string]string{"ANTHROPIC_MODEL": "cilocks-model"}},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Comm: "claude", Argv: []string{"claude"},
			Env: map[string]string{"ANTHROPIC_MODEL": ""}},
	)
	got := detect(t, src, 100)

	assert.Nil(t, got.Inspection.Model,
		"the agent carried ANTHROPIC_MODEL= (explicitly empty); neither cilock's env nor config may answer for it")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "explicitly carried ANTHROPIC_MODEL")
}

func TestGeminiClearedModelIsNotReplacedByConfig(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".gemini", "settings.json"), `{"model":"lower-config-model"}`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"},
			Env: map[string]string{"GEMINI_MODEL": ""}},
	)
	got := detect(t, src, 100)

	assert.Nil(t, got.Inspection.Model,
		"the agent carried GEMINI_MODEL= (explicitly empty); config must not answer for it")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "explicitly carried GEMINI_MODEL")
}

// ---------------------------------------------------------------------------
// Finding: a $CODEX_HOME (or model variable) present only in cilock's own
// inherited environment selected which config file was read — signing a
// configuration the agent never resolved. Location and effective values come
// from the agent's environment alone.
// ---------------------------------------------------------------------------

func TestCilocksOwnCodexHomeDoesNotSelectTheConfig(t *testing.T) {
	evil := t.TempDir()
	writeFile(t, filepath.Join(evil, "config.toml"), "model = \"evil-model\"\n")

	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), "model = \"home-model\"\n")

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock",
			Env: map[string]string{"CODEX_HOME": evil}},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex", Argv: []string{"codex"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "home-model", got.Inspection.Model.Value,
		"the agent's environment was read and carried no CODEX_HOME, so the agent used the default location")
	for _, cs := range got.Inspection.Configuration {
		assert.NotEqual(t, filepath.Join(evil, "config.toml"), cs.Path,
			"a config at cilock's own $CODEX_HOME must not be read at all")
	}
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "does not decide which config file is read")
}

// ---------------------------------------------------------------------------
// Finding: only --profile was recognized, not clap's short alias -p, so
// `codex -p unsafe` attested the top-level (safer) posture.
// ---------------------------------------------------------------------------

func TestCodexShortProfileFlagSelectsTheProfile(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"),
		"sandbox_mode = \"read-only\"\n\n[profiles.unsafe]\nsandbox_mode = \"read-only\"\n")
	writeFile(t, filepath.Join(home, ".codex", "unsafe.config.toml"),
		"sandbox_mode = \"danger-full-access\"\n")

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "-p", "unsafe"}},
	)
	got := detect(t, src, 100)

	var sandbox *SettingObservation
	for i := range got.Inspection.Settings {
		if got.Inspection.Settings[i].Key == "sandbox_mode" {
			sandbox = &got.Inspection.Settings[i]
		}
	}
	require.NotNil(t, sandbox)
	assert.Equal(t, "danger-full-access", sandbox.Value,
		"-p selects the overlay file exactly as --profile does; neither the base nor a stale legacy table describes this run")
	assert.Equal(t, "unsafe", got.Inspection.ArgvFields["profile"])
}

func TestCodexAttachedShortValuesMatchClapParsing(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), `
model = "safe-top-level"
sandbox_mode = "read-only"
`)
	writeFile(t, filepath.Join(home, ".codex", "unsafe.config.toml"), `
model = "unsafe-profile"
sandbox_mode = "danger-full-access"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "-punsafe", "-mcli-model", "-sdanger-full-access", "-aon-request", "-cmodel_reasoning_effort=high"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "cli-model", got.Inspection.Model.Value)
	assert.Equal(t, "unsafe", got.Inspection.ArgvFields["profile"])
	settings := settingsByKey(got.Inspection.Settings)
	assert.Equal(t, "danger-full-access", settings["sandbox_mode"])
	assert.Equal(t, "on-request", settings["approval_policy"])
	assert.Equal(t, "high", settings["model_reasoning_effort"])
}

// ---------------------------------------------------------------------------
// Finding: no length control sat between attacker-controlled bytes and
// predicate serialization; one huge argv value inflated the signed predicate
// without bound.
// ---------------------------------------------------------------------------

func TestOversizeValuesAreCappedAtPredicateAssembly(t *testing.T) {
	withHomeDir(t, t.TempDir())
	huge := strings.Repeat("A", maxPredicateString+1024)
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--model", huge}},
	)
	a := attestFixture(t, src, 100)

	require.NotNil(t, a.Model)
	assert.LessOrEqual(t, len(a.Model.Value), maxPredicateString+len(truncationMarker))
	assert.True(t, strings.HasSuffix(a.Model.Value, truncationMarker),
		"a capped value must be marked as a prefix, never passed off as complete")
	require.NotNil(t, a.Invoker)
	assert.True(t, strings.HasSuffix(a.Invoker.Process.ArgvFields["model"], truncationMarker))
	assert.Contains(t, strings.Join(a.Warnings, "\n"), "truncated")
}

func TestOversizeProcessAndAncestryStringsAreCapped(t *testing.T) {
	withHomeDir(t, t.TempDir())
	huge := strings.Repeat("X", maxPredicateString+1024)
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 90, PPID: 80, Argv: []string{huge}},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex", Argv: []string{huge}},
	)
	a := attestFixture(t, src, 100)

	require.NotNil(t, a.Invoker)
	assert.True(t, strings.HasSuffix(a.Invoker.Process.ArgvProgram, truncationMarker))
	require.Len(t, a.Ancestry, 2)
	assert.True(t, strings.HasSuffix(a.Ancestry[0].Program, truncationMarker))
	assert.Contains(t, strings.Join(a.Warnings, "\n"), "truncated")
}

// ---------------------------------------------------------------------------
// Finding: a ViaResolution match whose snapshot-time resolution EQUALS the
// recorded path means the symlink the fingerprint rested on was swapped for a
// regular file — and the match-time fingerprint was silently published beside
// the new file's digest. And when any match fails revalidation, the ancestry
// entry appended at match time still said Matched:true with the rejected
// fingerprint.
// ---------------------------------------------------------------------------

func TestLinkSwappedForRegularFileDegradesToUnbound(t *testing.T) {
	// Canonicalized, so the only resolution left for the snapshot to find is
	// the path itself — macOS temp dirs otherwise resolve /var to
	// /private/var and land in the plain-mismatch case instead.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	// The recorded path holds a REGULAR file now; the ViaResolution match
	// claims a resolution that can no longer exist.
	path := filepath.Join(dir, "claude-link")
	require.NoError(t, os.WriteFile(path, []byte("binary"), 0o700))

	src := newFixtureSource(ProcessInfo{PID: 7, PPID: 1, Executable: path, Comm: "sh", Argv: []string{"sh"}})
	p, err := src.ReadProcess(7)
	require.NoError(t, err)

	d := NewDetector(src, DefaultProviders())
	var out Detection
	unbound := d.observeMatch(context.Background(), &out, matchedProcess{
		provider: ClaudeCodeProvider{},
		process:  p,
		match:    matchedViaResolution(fpClaudeResolvedLink),
	}, t.TempDir(), ProcessInfo{})

	require.NotEmpty(t, unbound,
		"a resolution-based fingerprint beside a path that now resolves to itself is a contradiction, not a match")
	assert.Contains(t, unbound, "resolved to itself")
	assert.Nil(t, out.Inspection.Model, "no inspection may run for an unbound match")
}

// stubViaResolutionProvider matches every process via a claimed match-time
// resolution, so a full Detect can be driven into the unbound path without a
// filesystem race.
type stubViaResolutionProvider struct{}

func (stubViaResolutionProvider) Vendor() string         { return "stub" }
func (stubViaResolutionProvider) Product() string        { return "stub" }
func (stubViaResolutionProvider) EnvAllowlist() []EnvKey { return nil }
func (stubViaResolutionProvider) Match(ProcessInfo) MatchResult {
	return matchedViaResolution("stub:resolved-symlink")
}
func (stubViaResolutionProvider) Inspect(context.Context, InspectRequest) Inspection {
	return Inspection{}
}

func TestUnboundMatchDoesNotSignAnAncestryClaim(t *testing.T) {
	// Canonicalized for the same reason as above: the snapshot must resolve
	// the recorded path to itself.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	path := filepath.Join(dir, "agent")
	require.NoError(t, os.WriteFile(path, []byte("binary"), 0o700))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: path, Comm: "agent", Argv: []string{"agent"}},
	)
	d := NewDetector(src, []Provider{stubViaResolutionProvider{}})
	got, err := d.Detect(context.Background(), 100, t.TempDir())
	require.NoError(t, err)

	assert.Equal(t, StatusIncomplete, got.Status,
		"an unbound match withholds every positive verdict")
	require.NotEmpty(t, got.Ancestry)
	last := got.Ancestry[len(got.Ancestry)-1]
	assert.False(t, last.Matched,
		"the signed ancestry must not carry the identity claim the snapshot declined to support")
	assert.Empty(t, last.MatchedBy)
}

// ---------------------------------------------------------------------------
// Finding: the run-wide environment redaction configuration
// (attestation.EnvironmentCapturer) — honored by commandrun — was ignored
// here, so a value the operator configured for obfuscation was serialized
// verbatim when a provider allowlisted its key.
// ---------------------------------------------------------------------------

func TestEnvValueKeepDegradesValuesToPresenceOnly(t *testing.T) {
	src := newFixtureSource(ProcessInfo{PID: 1, Env: map[string]string{"AGENT_MODEL": "a-model"}})
	allow := []EnvKey{{Name: "AGENT_MODEL", RecordValue: true}}
	r := InspectRequest{
		Source: src, Process: src.procs[1], Self: src.procs[1],
		EnvValueKeep: func(key, _ string) bool { return key != "AGENT_MODEL" },
	}
	observations, scope := collectEnv(r, EnvScopeAgent, allow)

	require.Len(t, observations, 1)
	assert.True(t, observations[0].Present)
	assert.Empty(t, observations[0].Value, "a value the run-wide policy rejects degrades to presence-only")
	v, blocked := resolveEnvValue("AGENT_MODEL", scope)
	assert.Empty(t, v, "a rejected value must not be resolvable either")
	assert.True(t, blocked,
		"a redacted higher-precedence value is unknown, not absent; lower-precedence sources must not answer")
}

// fakeCapturer implements attestation.EnvironmentCapturer for the adapter
// test: it filters dropKeys out and obfuscates obfuscateKeys.
type fakeCapturer struct {
	drop      map[string]bool
	obfuscate map[string]bool
}

type overbroadEnvSource struct{ ProcessSource }

func (overbroadEnvSource) ReadEnvironment(processInstance, []string) (map[string]string, error) {
	return map[string]string{
		"AGENT_MODEL":     "allowed",
		"UNLISTED_SECRET": "must-not-escape",
	}, nil
}

func TestCollectEnvEnforcesAllowlistAgainstAnOverbroadSource(t *testing.T) {
	process := vouchedFixture(ProcessInfo{PID: 1, Executable: "/bin/agent"})
	r := InspectRequest{
		Source:  overbroadEnvSource{},
		Process: process,
		Self:    process,
	}
	observations, scope := collectEnv(r, EnvScopeAgent,
		[]EnvKey{{Name: "AGENT_MODEL", RecordValue: true}})

	require.Len(t, observations, 1)
	assert.Equal(t, "AGENT_MODEL", observations[0].Key)
	assert.NotContains(t, scope.present, "UNLISTED_SECRET")
	assert.NotContains(t, scope.values, "UNLISTED_SECRET")
}

func (f fakeCapturer) Capture(env []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		key, value := kv[:eq], kv[eq+1:]
		switch {
		case f.drop[key]:
		case f.obfuscate[key]:
			out[key] = "******"
		default:
			out[key] = value
		}
	}
	return out
}

func TestEnvValueKeepFuncTracksTheCapturer(t *testing.T) {
	keep := envValueKeepFunc(fakeCapturer{
		drop:      map[string]bool{"DROPPED": true},
		obfuscate: map[string]bool{"MASKED": true},
	})
	require.NotNil(t, keep)
	assert.True(t, keep("PLAIN", "value"), "a pass-through value is kept")
	assert.False(t, keep("DROPPED", "value"), "a filtered key loses its value")
	assert.False(t, keep("MASKED", "value"),
		"an obfuscated value is not kept: a placeholder masquerading as a real value would be a wrong claim")

	assert.Nil(t, envValueKeepFunc(nil), "no capturer imposes nothing")
}

func TestRunWideCapturerIsHonoredEndToEnd(t *testing.T) {
	withHomeDir(t, t.TempDir())
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Comm: "claude", Argv: []string{"claude"},
			Env: map[string]string{"ANTHROPIC_MODEL": "redact-me"}},
	)
	a := newFixtureAttestor(t, src, 100)
	ctx, err := attestation.NewContext("alps-evidence-test",
		[]attestation.Attestor{a},
		attestation.WithWorkingDir(t.TempDir()),
		attestation.WithEnvironmentCapturer(fakeCapturer{obfuscate: map[string]bool{"ANTHROPIC_MODEL": true}}))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	assert.Nil(t, a.Model, "a value the operator obfuscates run-wide must not surface as the model")
	for _, obs := range a.Environment {
		if obs.Key == "ANTHROPIC_MODEL" {
			assert.Empty(t, obs.Value, "presence survives, the value does not")
		}
	}
}

// TestContextRedactionOptionsApplyWithoutEnvironmentAttestor is the
// scheduling regression for the canonical cilock binary. Pre-material
// attestors run concurrently, so alps-evidence may start before environment
// has installed its capturer. The context options must still win even when
// alps-evidence is the only attestor in the context.
func TestContextRedactionOptionsApplyWithoutEnvironmentAttestor(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "lower-precedence-model"})
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/claude", Comm: "claude", Argv: []string{"claude"},
			Env: map[string]string{"ANTHROPIC_MODEL": "operator-redacted"}},
	)
	a := newFixtureAttestor(t, src, 100)
	ctx, err := attestation.NewContext("alps-evidence-test",
		[]attestation.Attestor{a},
		attestation.WithWorkingDir(t.TempDir()),
		attestation.WithEnvAdditionalKeys([]string{"ANTHROPIC_MODEL"}))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	assert.Nil(t, a.Model,
		"the redacted agent value is unknown rather than absent; the lower-precedence config must not answer")
	for _, obs := range a.Environment {
		if obs.Key == "ANTHROPIC_MODEL" {
			assert.Empty(t, obs.Value, "presence may survive; the operator-redacted value must not")
		}
	}
}
