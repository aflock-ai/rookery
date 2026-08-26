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

// Regression tests for evidence-integrity hazards, each proven red against
// the pre-fix code:
//
//  1. Executable evidence derived through separate path resolutions (resolve,
//     stat, reopen) instead of one bounded handle — a replacement between the
//     steps pairs one binary's size with another's digest, or slips a grown
//     file past the digest cap.
//  2. Flag scanners reading past the "--" option terminator — prompt or tool
//     arguments override the run's real configuration in signed evidence.
//  3. An unreadable environment collapsing into an empty one — a
//     lower-precedence config value gets promoted to "effective" while a
//     higher-precedence environment override was never ruled out.
//  4. Path resolution and version harvesting performed separately from the
//     digest handle — a symlink retargeted mid-collection (an auto-update)
//     makes the version, resolved path, and digest describe DIFFERENT
//     binaries inside one signed predicate.
//  5. The same hazard one layer lower: the path RESOLVED and the path OPENED
//     were two separate lookups inside the snapshot itself, so a retarget
//     between them paired one binary's resolved path and version with
//     another's digest. Fixed structurally — the handle is acquired first and
//     the resolution is bound back to it — rather than by patching the
//     instance.
//  6. Predicate state surviving from one Attest to the next, so a reused
//     attestor signs a previous run's agent as this run's evidence.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// imageHandleSource models a process source that can hand over a handle to the
// running process image itself, the way /proc/<pid>/exe does on Linux.
type imageHandleSource struct {
	*fixtureSource
	images map[int]string
}

func (s *imageHandleSource) OpenProcessImage(instance processInstance) (*os.File, error) {
	path, ok := s.images[instance.pid]
	if !ok {
		return nil, os.ErrNotExist
	}
	return os.Open(path)
}

// unreadableEnvSource wraps a fixture tree with per-PID environment-read
// refusals, reported the way the platform sources report them: as a real
// error, never as an empty environment.
type unreadableEnvSource struct {
	*fixtureSource
	pids map[int]bool
}

func (s *unreadableEnvSource) ReadEnvironment(instance processInstance, keys []string) (map[string]string, error) {
	if s.pids[instance.pid] {
		return map[string]string{}, errors.New("kernel refused the environment read")
	}
	return s.fixtureSource.ReadEnvironment(instance, keys)
}

// TestExecutableEvidenceBindsToTheProcessImageHandle. When the source can open
// the running image itself, every recorded value — size, digest — must come
// from that handle, not from whatever currently occupies the recorded path.
// An auto-update replacing the binary on disk must not be able to put ITS
// size and digest into evidence describing the process that exec'd the old
// binary.
func TestExecutableEvidenceBindsToTheProcessImageHandle(t *testing.T) {
	withHomeDir(t, t.TempDir())
	dir := t.TempDir()

	pathNow := filepath.Join(dir, "codex")
	require.NoError(t, os.WriteFile(pathNow, []byte("impostor now at the recorded path"), 0o700))

	imageContent := []byte("the binary this process actually exec'd")
	image := filepath.Join(dir, "codex-image")
	require.NoError(t, os.WriteFile(image, imageContent, 0o700))

	base := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: pathNow, Comm: "codex", Argv: []string{"codex"}},
	)
	src := &imageHandleSource{fixtureSource: base, images: map[int]string{80: image}}

	a := attestFixture(t, src, 100)
	require.NotNil(t, a.Invoker)
	assert.Equal(t, sha256hex(imageContent), a.Invoker.Process.SHA256,
		"the digest must describe the running image handle, not the path's current occupant")
	assert.Equal(t, int64(len(imageContent)), a.Invoker.Process.SizeBytes,
		"the size must come from the same handle the digest came from")
	assert.Equal(t, "process-image", a.Invoker.Process.DigestBinding,
		"evidence from the image handle must say so")
}

// TestExecutableEvidenceDeclaresPathBinding. Where no image handle exists
// (macOS), the honest posture is a single path-based open with the binding
// published as such — the predicate must not leave a reader to assume the
// stronger binding.
func TestExecutableEvidenceDeclaresPathBinding(t *testing.T) {
	withHomeDir(t, t.TempDir())
	content := []byte("plain agent binary")
	binPath := filepath.Join(t.TempDir(), "codex")
	require.NoError(t, os.WriteFile(binPath, content, 0o700))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)

	a := attestFixture(t, src, 100)
	require.NotNil(t, a.Invoker)
	assert.Equal(t, sha256hex(content), a.Invoker.Process.SHA256)
	assert.Equal(t, "path", a.Invoker.Process.DigestBinding,
		"with no image handle available the evidence must declare its binding is only to the path")
}

// TestCodexFlagScanStopsAtTheOptionTerminator. Everything after a bare "--" is
// positional — prompt text, chosen by whoever typed the prompt. A prompt of
// "--sandbox read-only --yolo -c model=..." must not be able to override the
// run's real posture and model in signed evidence.
func TestCodexFlagScanStopsAtTheOptionTerminator(t *testing.T) {
	withHomeDir(t, t.TempDir())
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{
				"codex", "exec", "--",
				"--sandbox", "read-only", "--yolo", "-c", "model=prompt-smuggled",
				"--model", "prompt-smuggled-2", "--profile", "prompt-smuggled-profile",
			}},
	)
	got := detect(t, src, 100)
	require.Equal(t, StatusDetected, got.Status)

	assert.Nil(t, got.Inspection.Model, "a model override after -- is prompt text, not configuration")
	assert.NotContains(t, settingsByKey(got.Inspection.Settings), "sandbox_mode",
		"a sandbox claim after -- must not become posture evidence")
	for _, field := range []string{"sandbox", "model", "config_override_model", "profile", "dangerously_bypass_approvals_and_sandbox"} {
		assert.NotContains(t, got.Inspection.ArgvFields, field)
	}
	assert.NotContains(t, strings.Join(got.Inspection.Warnings, "\n"), "replaces the sandbox and approval posture",
		"a --yolo after -- must not read as a posture override")
}

// TestClaudeCodeFlagScanStopsAtTheOptionTerminator is the same property for
// the Claude Code scanner, including the boolean allowlist loop.
func TestClaudeCodeFlagScanStopsAtTheOptionTerminator(t *testing.T) {
	withHomeDir(t, t.TempDir())
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 200, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 200, PPID: 1,
			Executable: "/Users/dev/.local/share/claude/versions/2.1.234",
			Comm:       "2.1.234",
			Argv: []string{
				"claude", "-p", "--",
				"--model", "prompt-smuggled", "--permission-mode", "bypassPermissions", "--dangerously-skip-permissions",
			}},
	)
	got := detect(t, src, 100)
	require.Equal(t, StatusDetected, got.Status)

	assert.Nil(t, got.Inspection.Model, "a model override after -- is prompt text, not configuration")
	for _, field := range []string{"model", "permission_mode", "dangerously_skip_permissions"} {
		assert.NotContains(t, got.Inspection.ArgvFields, field)
	}
}

// TestGeminiUnreadableEnvironmentDoesNotPromoteConfigModel. GEMINI_MODEL in
// the environment outranks the settings file. When the environment cannot be
// read, the settings-file model may be recorded as observed but must not be
// claimed effective — the unreadable environment may hold the override.
func TestGeminiUnreadableEnvironmentDoesNotPromoteConfigModel(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".gemini", "settings.json"), map[string]any{"model": "gemini-from-config"})

	base := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"}},
	)
	src := &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{80: true}}
	got := detect(t, src, 100)
	require.Equal(t, StatusDetected, got.Status)

	assert.Nil(t, got.Inspection.Model,
		"a config model must not be reported while a higher-precedence GEMINI_MODEL is unknown")
	require.Len(t, got.Inspection.Configuration, 1)
	assert.Equal(t, RoleObserved, got.Inspection.Configuration[0].Role,
		"the file is evidence of existence, and never of effect")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "neither ruled out nor reportable")
}

// TestCodexUnreadableEnvironmentDoesNotPromoteDefaultHomeConfig. Codex's
// config location itself is environment-controlled ($CODEX_HOME). With the
// environment unreadable, the file found at the fallback ~/.codex may not be
// the configuration this run used, so nothing may be resolved out of it.
func TestCodexUnreadableEnvironmentDoesNotPromoteDefaultHomeConfig(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"),
		"model = \"gpt-from-config\"\nsandbox_mode = \"read-only\"\n")

	base := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex", Argv: []string{"codex"}},
	)
	src := &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{80: true}}
	got := detect(t, src, 100)
	require.Equal(t, StatusDetected, got.Status)

	assert.Nil(t, got.Inspection.Model,
		"a model from a guessed config location must not be claimed while $CODEX_HOME is unknown")
	assert.Empty(t, got.Inspection.Settings,
		"posture settings from a guessed config location must not be claimed either")
	require.Len(t, got.Inspection.Configuration, 1)
	assert.Equal(t, RoleObserved, got.Inspection.Configuration[0].Role)
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "cannot be ruled out")
}

// TestClaudeCodeUnreadableEnvironmentDoesNotPromoteSettingsModel. Claude Code
// honors ANTHROPIC_MODEL above its settings files; with the environment
// unreadable the settings-file model stays an observation, not the effective
// model.
func TestClaudeCodeUnreadableEnvironmentDoesNotPromoteSettingsModel(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "opus-configured"})

	base := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 200, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 200, PPID: 1,
			Executable: "/Users/dev/.local/share/claude/versions/2.1.234",
			Comm:       "2.1.234",
			Argv:       []string{"claude"}},
	)
	src := &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{200: true}}
	got := detect(t, src, 100)
	require.Equal(t, StatusDetected, got.Status)

	assert.Nil(t, got.Inspection.Model,
		"a settings-file model must not be reported while a higher-precedence ANTHROPIC_MODEL is unknown")
	var userConfig *ConfigSource
	for i := range got.Inspection.Configuration {
		if got.Inspection.Configuration[i].Scope == "user" {
			userConfig = &got.Inspection.Configuration[i]
		}
	}
	require.NotNil(t, userConfig, "the settings file is still recorded as evidence")
	assert.Equal(t, RoleObserved, userConfig.Role)
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "neither ruled out nor reportable")
}

// TestUnreadableEnvironmentWarningsCarryNoAbsolutePaths is the regression for
// Codex round 2 on PR #8209: the unreadable-environment warnings embedded the
// absolute settings path, signing the home (or repository) directory into the
// predicate. A warning must name the file by its scope-relative label; the
// concrete file stays identified — with its digest — in ConfigSource, whose
// Path field is the documented identity of the snapshotted bytes.
func TestUnreadableEnvironmentWarningsCarryNoAbsolutePaths(t *testing.T) {
	cases := []struct {
		name  string
		names string
		setup func(t *testing.T, home string) ProcessSource
	}{
		{
			name:  "gemini",
			names: "GEMINI_MODEL",
			setup: func(t *testing.T, home string) ProcessSource {
				writeJSON(t, filepath.Join(home, ".gemini", "settings.json"), map[string]any{"model": "gemini-from-config"})
				base := newFixtureSource(
					ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
					ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"}},
				)
				return &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{80: true}}
			},
		},
		{
			name:  "codex",
			names: "$CODEX_HOME/config.toml",
			setup: func(t *testing.T, home string) ProcessSource {
				writeFile(t, filepath.Join(home, ".codex", "config.toml"), "model = \"gpt-from-config\"\n")
				base := newFixtureSource(
					ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
					ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex", Argv: []string{"codex"}},
				)
				return &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{80: true}}
			},
		},
		{
			name:  "claude-code",
			names: "ANTHROPIC_MODEL",
			setup: func(t *testing.T, home string) ProcessSource {
				writeJSON(t, filepath.Join(home, ".claude", "settings.json"), map[string]any{"model": "opus-configured"})
				base := newFixtureSource(
					ProcessInfo{PID: 100, PPID: 200, Executable: "/usr/local/bin/cilock"},
					ProcessInfo{PID: 200, PPID: 1,
						Executable: "/Users/dev/.local/share/claude/versions/2.1.234",
						Comm:       "2.1.234",
						Argv:       []string{"claude"}},
				)
				return &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{200: true}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			withHomeDir(t, home)
			got := detect(t, tc.setup(t, home), 100)
			require.Equal(t, StatusDetected, got.Status)

			joined := strings.Join(got.Inspection.Warnings, "\n")
			// What the warning must NAME differs by product, and the
			// difference is the narrowing showing through: codex still names
			// the file, because $CODEX_HOME decides which file is read at all.
			// The others name the ENVIRONMENT VARIABLE, because after the
			// withdrawal of the effectiveness claim a settings file is no
			// longer the thing in doubt — the unreadable environment is.
			assert.Contains(t, joined, tc.names,
				"the warning must name what could not be established, by a scope-relative name")
			assert.NotContains(t, joined, home,
				"a warning naming the absolute settings path signs the home directory into the predicate")
		})
	}
}

// TestConfigDecidedModelSourceIsScopeRelative covers the same leak on the
// effective path: when a settings file does decide the model, the
// observation's Source must be the scope-relative label, never the absolute
// path.
func TestConfigDecidedModelSourceIsScopeRelative(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".gemini", "settings.json"), map[string]any{"model": "gemini-2.5-pro"})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"}},
	)
	got := detect(t, src, 100)
	require.Equal(t, StatusDetected, got.Status)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "gemini-2.5-pro", got.Inspection.Model.Value)
	assert.Equal(t, ".gemini/settings.json", got.Inspection.Model.Source)
}

// hookedClaudeProvider matches exactly like ClaudeCodeProvider and runs a
// callback at the start of Inspect. The callback models a concurrent actor —
// an auto-updater retargeting the install symlink — striking in the window
// between detection and everything derived afterwards.
type hookedClaudeProvider struct {
	ClaudeCodeProvider
	hook func()
}

func (p hookedClaudeProvider) Inspect(ctx context.Context, r InspectRequest) Inspection {
	p.hook()
	return p.ClaudeCodeProvider.Inspect(ctx, r)
}

// TestExecutableClaimsSurviveARetargetDuringInspection is hazard 4, hazard
// 1's cross-field sibling: round 1 bound size and digest to one handle, but
// the resolved path and the version parsed from it were still re-derived
// later, so an update retargeting the symlink mid-collection could sign a
// predicate whose version and resolved path describe the NEW binary while
// the digest describes the OLD one. Every executable-describing field must
// come from the one snapshot taken when the process was matched.
func TestExecutableClaimsSurviveARetargetDuringInspection(t *testing.T) {
	withHomeDir(t, t.TempDir())
	base := t.TempDir()

	oldContent := []byte("the binary this process actually exec'd")
	oldTarget := filepath.Join(base, "claude", "versions", "2.1.234")
	require.NoError(t, os.MkdirAll(filepath.Dir(oldTarget), 0o750))
	require.NoError(t, os.WriteFile(oldTarget, oldContent, 0o700))

	newContent := []byte("the auto-updated replacement binary")
	newTarget := filepath.Join(base, "claude", "versions", "9.9.9")
	require.NoError(t, os.WriteFile(newTarget, newContent, 0o700))

	link := filepath.Join(base, "bin", "claude")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
	require.NoError(t, os.Symlink(oldTarget, link))

	// t.TempDir may itself sit behind a symlink (/var -> /private/var on
	// macOS), so expectations are stated against the canonical old target.
	canonicalOldTarget, err := filepath.EvalSymlinks(oldTarget)
	require.NoError(t, err)

	provider := hookedClaudeProvider{hook: func() {
		// The update lands after the match, before inspection finishes.
		require.NoError(t, os.Remove(link))
		require.NoError(t, os.Symlink(newTarget, link))
	}}

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: link, Comm: "claude", Argv: []string{"claude"}},
	)
	a := attestFixture(t, src, 100, WithProviders([]Provider{provider}))

	require.NotNil(t, a.Invoker)
	require.NotNil(t, a.Invoker.Version)
	assert.Equal(t, "2.1.234", a.Invoker.Version.Value,
		"the version must be parsed from the snapshot's resolution, not re-resolved after the retarget")
	assert.Equal(t, AssuranceInferred, a.Invoker.Version.Assurance,
		"a layout-derived version is inferred even when its path came from the snapshot")
	assert.Equal(t, canonicalOldTarget, a.Invoker.Process.ExecutableResolved,
		"the predicate's resolved path must be the snapshot's resolution")
	assert.Equal(t, sha256hex(oldContent), a.Invoker.Process.SHA256,
		"the digest must describe the binary the snapshot opened, not the path's new occupant")
	assert.Equal(t, int64(len(oldContent)), a.Invoker.Process.SizeBytes)
	assert.Equal(t, "path", a.Invoker.Process.DigestBinding)
}

// TestProvidersReceiveTheSnapshotResolution pins the plumbing the previous
// test exercises end to end: the detector hands providers the resolution
// captured in the executable snapshot, so a provider never needs — and never
// gets — a reason to re-resolve the path itself.
func TestProvidersReceiveTheSnapshotResolution(t *testing.T) {
	withHomeDir(t, t.TempDir())
	base := t.TempDir()

	target := filepath.Join(base, "claude", "versions", "2.1.234")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
	require.NoError(t, os.WriteFile(target, []byte("binary"), 0o700))
	link := filepath.Join(base, "bin", "claude")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
	require.NoError(t, os.Symlink(target, link))

	canonicalTarget, err := filepath.EvalSymlinks(target)
	require.NoError(t, err)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: link, Comm: "claude", Argv: []string{"claude"}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, canonicalTarget, got.Image.resolvedPath,
		"the detection must carry the snapshot's resolution")
	require.NotNil(t, got.Inspection.Version)
	assert.Equal(t, "2.1.234", got.Inspection.Version.Value)
	assert.Equal(t, "process.executable(resolved symlink)", got.Inspection.Version.Source,
		"the version must have been parsed from the resolved path the snapshot handed over")
}

// retargetingPathSource models the window Codex round 4 named: the executable
// path is RESOLVED at one moment and OPENED at another, so an auto-update
// retargeting the install symlink in between makes the resolved path — and
// every version parsed from it — describe a different binary than the digest.
//
// It models macOS, where there is NO per-process image handle, so it
// deliberately does not implement processImageOpener and executable evidence
// comes from a single open of the recorded path. The retarget is performed
// while the walk is still reading the process, so the snapshot's open lands
// AFTER the swap.
//
// An earlier version of this double DID implement processImageOpener and
// refused, relying on the fallback to the path. That conflated two different
// platforms — "cannot open images" and "can, but this one failed" — which
// round 7 made a meaningful distinction: the second now fails closed, because
// falling back to the recorded path there digests whatever occupies the name
// now. Modelling macOS as a source that lacks the capability is what macOS
// actually is, and the property under test is unchanged.
type retargetingPathSource struct {
	*fixtureSource
	retargetOn int
	retarget   func()
	fired      bool
}

func (s *retargetingPathSource) ReadProcess(pid int) (ProcessInfo, error) {
	p, err := s.fixtureSource.ReadProcess(pid)
	if err == nil && pid == s.retargetOn && !s.fired {
		s.fired = true
		s.retarget()
	}
	return p, err
}

// TestResolvedPathAndDigestCannotDescribeDifferentBinaries is hazard 5, the
// third appearance of the executable-TOCTOU class and the one that motivated
// removing the defect's expressibility rather than patching another instance.
//
// The assertion is deliberately not "the path equals X". It is that the
// predicate's own fields agree with each other: whatever file the digest
// describes, the resolved path must name THAT file and the version must have
// been parsed from it. A predicate that pairs one binary's path with another
// binary's digest is wrong no matter which binary is "right".
func TestResolvedPathAndDigestCannotDescribeDifferentBinaries(t *testing.T) {
	withHomeDir(t, t.TempDir())
	base := t.TempDir()

	oldContent := []byte("the binary installed when the walk began")
	oldTarget := filepath.Join(base, "claude", "versions", "2.1.234")
	require.NoError(t, os.MkdirAll(filepath.Dir(oldTarget), 0o750))
	require.NoError(t, os.WriteFile(oldTarget, oldContent, 0o700))

	newContent := []byte("the auto-updated replacement binary")
	newTarget := filepath.Join(base, "claude", "versions", "9.9.9")
	require.NoError(t, os.WriteFile(newTarget, newContent, 0o700))

	link := filepath.Join(base, "bin", "claude")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
	require.NoError(t, os.Symlink(oldTarget, link))

	src := &retargetingPathSource{
		fixtureSource: newFixtureSource(
			ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
			ProcessInfo{PID: 80, PPID: 1, Executable: link, Comm: "claude", Argv: []string{"claude"}},
		),
		retargetOn: 80,
		retarget: func() {
			require.NoError(t, os.Remove(link))
			require.NoError(t, os.Symlink(newTarget, link))
		},
	}

	a := attestFixture(t, src, 100)
	require.NotNil(t, a.Invoker)

	// The single open landed after the swap, so the digest describes the new
	// binary. That is fine; what must not happen is any other field
	// describing the old one.
	require.NotEmpty(t, a.Invoker.Process.SHA256)
	assert.Equal(t, sha256hex(newContent), a.Invoker.Process.SHA256,
		"the digest describes the file the one open actually landed on")

	resolved := a.Invoker.Process.ExecutableResolved
	require.NotEmpty(t, resolved,
		"the resolution runs after the open and binds to the handle, so it is recordable here")
	onDisk, err := os.ReadFile(resolved)
	require.NoError(t, err)
	assert.Equal(t, a.Invoker.Process.SHA256, sha256hex(onDisk),
		"the resolved path and the digest must describe the SAME bytes")

	require.NotNil(t, a.Invoker.Version)
	assert.Equal(t, "9.9.9", a.Invoker.Version.Value,
		"the version is parsed from the snapshot's resolution, so it describes the digested binary")
	assert.Equal(t, "path", a.Invoker.Process.DigestBinding,
		"no image handle was available, and the predicate must say so")
}

// newAttestContext builds a fresh collection context for an attestor that is
// being driven directly, rather than through attestFixture's one-shot helper.
func newAttestContext(t *testing.T, a attestation.Attestor) *attestation.AttestationContext {
	t.Helper()
	ctx, err := attestation.NewContext("alps-evidence-reuse",
		[]attestation.Attestor{a}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	return ctx
}

// TestAttestDoesNotCarryAPriorRunsObservationsForward is hazard 6.
//
// Attest used to write into the receiver in place and only assign the fields
// a DETECTED run produced. Reusing the attestor after such a run therefore
// left the previous run's Invoker, model, session, settings, configuration,
// environment, ancestry and warnings sitting in the predicate while Status
// said not-detected or unavailable — signed evidence contradicting itself,
// attributing one run's agent to a run that found none.
//
// The fix is structural: each Attest observes into a fresh zero-valued
// Attestor carrying only configuration forward, so there is no field to
// remember to reset and none can be missed.
func TestAttestDoesNotCarryAPriorRunsObservationsForward(t *testing.T) {
	quietTree := func() *fixtureSource {
		return newFixtureSource(
			ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
			ProcessInfo{PID: 90, PPID: 1, Executable: "/bin/bash"},
			ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init"},
		)
	}
	unreadableTree := func() *fixtureSource {
		src := newFixtureSource(ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"})
		src.readErr[100] = true
		return src
	}

	cases := []struct {
		name       string
		second     ProcessSource
		wantStatus ObservationStatus
		wantErr    bool
	}{
		{name: "detected then not-detected", second: quietTree(), wantStatus: StatusNotDetected},
		// Unavailability is published in the predicate rather than returned
		// as an error — see the unavailable branch of observe.
		{name: "detected then unavailable", second: unreadableTree(), wantStatus: StatusUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHomeDir(t, t.TempDir())

			a := newFixtureAttestor(t, claudeCodeMacOSDaemonChain(), pidCilock)
			require.NoError(t, a.Attest(newAttestContext(t, a)))
			require.NotNil(t, a.Invoker, "the first run must actually detect something")
			require.NotNil(t, a.Session)
			require.NotEmpty(t, a.Environment)
			require.NotEmpty(t, a.Ancestry)
			require.NotEmpty(t, a.Warnings)
			firstInvoker := a.Invoker
			firstWarnings := append([]string(nil), a.Warnings...)

			WithProcessSource(tc.second)(a)
			WithSelfPID(100)(a)
			err := a.Attest(newAttestContext(t, a))
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.wantStatus, a.Status)
			assert.Nil(t, a.Invoker,
				"a run that identified no agent must not publish the previous run's invoker (%v)", firstInvoker)
			assert.Nil(t, a.Model, "the previous run's model must not survive")
			assert.Nil(t, a.Session, "the previous run's session must not survive")
			assert.Empty(t, a.Settings, "the previous run's settings must not survive")
			assert.Empty(t, a.Configuration, "the previous run's configuration files must not survive")
			assert.Empty(t, a.Environment, "the previous run's environment evidence must not survive")
			for _, anc := range a.Ancestry {
				assert.False(t, anc.Matched,
					"the previous run's matched ancestry must not survive: %+v", anc)
			}
			for _, w := range firstWarnings {
				assert.NotContains(t, a.Warnings, w,
					"a warning about the previous run must not be signed as this run's")
			}
			assert.Equal(t, assuranceCaveat, a.Assurance.Caveat,
				"the standing caveat is re-emitted on every run, including this one")
		})
	}
}

// TestCodexDuplicateConfigOverrideAttestsTheEffectiveModel is the signed-
// evidence half of the argv last-wins finding. Codex applies repeated -c
// overrides in order, so `-c model=gpt-old -c model=gpt-new` runs gpt-new; a
// first-match scan put gpt-old — a model this run explicitly overrode — into
// the predicate.
func TestCodexDuplicateConfigOverrideAttestsTheEffectiveModel(t *testing.T) {
	withHomeDir(t, t.TempDir())

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "exec", "-c", "model=gpt-old", "-c", "model=gpt-new"}},
	)

	a := attestFixture(t, src, 100)
	require.NotNil(t, a.Invoker)
	require.NotNil(t, a.Model)
	assert.Equal(t, "gpt-new", a.Model.Value,
		"the last -c assignment is the one Codex applied, so it is the one that may be signed")
	assert.Equal(t, "gpt-new", a.Invoker.Process.ArgvFields["config_override_model"],
		"the recorded argv field must agree with the resolved model")
}

// TestNpmVersionIsNotClaimedWhenTheImageCouldNotBeBound is hazard 7: a version
// read out of a file BESIDE the executable, located through a path the
// executable snapshot never bound.
//
// The npm install layout keeps the version in the package.json of the
// @openai-namespaced package that shipped the binary — a DIFFERENT file from
// the image, two directories up from it. The shape this replaces looked for it
// starting at the kernel-RECORDED path, which asks the filesystem a fresh
// question at inspection time: an npm install landing while the agent runs
// answers with the NEW package's version, and the predicate then publishes it
// beside the OLD image's digest. It did so even here, where the snapshot bound
// no path to the image at all and there is therefore nothing the read could be
// consistent with.
//
// Red against the pre-fix code: version 0.147.0, graded
// configuration-observed, from a process whose image was never opened.
func TestNpmVersionIsNotClaimedWhenTheImageCouldNotBeBound(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64")
	writeJSON(t, filepath.Join(pkgDir, "package.json"), map[string]any{
		"name": "@openai/codex-darwin-arm64", "version": "0.147.0",
	})
	// Deliberately never created on disk: this is the binding-failed case.
	binPath := filepath.Join(pkgDir, "vendor", "aarch64-apple-darwin", "bin", "codex")

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	require.Empty(t, got.Image.resolved(),
		"fixture precondition: the snapshot must have bound no path to the image")

	assert.Nil(t, got.Inspection.Version,
		"a version read through a path the snapshot never bound must not be claimed")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "package.json",
		"the omission must be stated, not silent")
}

// TestNpmVersionIsGradedAsTheLayoutInferenceItIs is the other half of hazard 7.
//
// Binding the lookup to the snapshot narrows the window; it does not make the
// package manifest part of the image. That file is tied to the binary by a
// DIRECTORY-LAYOUT CONVENTION — "the package directory whose parent is
// literally @openai" — which is exactly what AssuranceInferred is defined to
// cover, and exactly how the sibling Caskroom read is already graded. Grading
// it configuration-observed let a policy demanding observed (non-inferred)
// evidence accept a layout guess.
//
// Red against the pre-fix code: AssuranceConfigObserved.
func TestNpmVersionIsGradedAsTheLayoutInferenceItIs(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64")
	binPath := filepath.Join(pkgDir, "vendor", "aarch64-apple-darwin", "bin", "codex")

	require.NoError(t, os.MkdirAll(filepath.Dir(binPath), 0o750))
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/false\n"), 0o600))
	writeJSON(t, filepath.Join(pkgDir, "package.json"), map[string]any{
		"name": "@openai/codex-darwin-arm64", "version": "0.147.0",
	})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Version)
	assert.Equal(t, "0.147.0", got.Inspection.Version.Value)
	assert.Equal(t, AssuranceInferred, got.Inspection.Version.Assurance,
		"a version located by walking the directory layout around the image is an inference, not an observation of the image")
}

// TestFingerprintNamesTheBasisThatActuallyMatched is hazard 8: a fingerprint
// that claims a stronger identity basis than the one that fired.
//
// A product name can be observed in three places, and they are not equally
// trustworthy. The image basename is the kernel's record of what was exec'd.
// The kernel comm is the kernel's own short name for it. argv[0] is written by
// the process being described — ANY binary can set it to "gemini". A provider
// that matched on argv[0] and published "gemini-cli:executable-basename" hands
// a policy author signed evidence of a property nobody observed, which is the
// one thing a fingerprint exists to prevent.
//
// Every provider is listed, not just the three the review named, so a fourth
// cannot regress quietly.
//
// Red against the pre-fix code: Cursor, Gemini and Copilot returned their
// executable fingerprint for all three bases.
func TestFingerprintNamesTheBasisThatActuallyMatched(t *testing.T) {
	for _, tc := range []struct {
		name    string
		agent   ProcessInfo
		want    string
		product string
	}{
		{"cursor-agent by image", ProcessInfo{Executable: "/opt/cursor/cursor-agent", Comm: "cursor-agent", Argv: []string{"cursor-agent"}}, "cursor-agent:executable-basename", "cursor"},
		{"cursor-agent by comm", ProcessInfo{Executable: "/opt/vendor/launcher", Comm: "cursor-agent", Argv: []string{"launcher"}}, "cursor-agent:kernel-comm", "cursor"},
		{"cursor-agent by title", ProcessInfo{Executable: "/tmp/unrelated", Comm: "unrelated", Argv: []string{"cursor-agent --resume"}}, "cursor-agent:argv0-process-title", "cursor"},

		{"cursor by image", ProcessInfo{Executable: "/opt/cursor/cursor", Comm: "cursor", Argv: []string{"cursor"}}, "cursor:executable-basename", "cursor"},
		{"cursor by comm", ProcessInfo{Executable: "/opt/vendor/launcher", Comm: "cursor", Argv: []string{"launcher"}}, "cursor:kernel-comm", "cursor"},
		{"cursor by title", ProcessInfo{Executable: "/tmp/unrelated", Comm: "unrelated", Argv: []string{"cursor"}}, "cursor:argv0-process-title", "cursor"},

		{"gemini by image", ProcessInfo{Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"}}, "gemini-cli:executable-basename", "gemini-cli"},
		{"gemini by comm", ProcessInfo{Executable: "/opt/vendor/launcher", Comm: "gemini", Argv: []string{"launcher"}}, "gemini-cli:kernel-comm", "gemini-cli"},
		{"gemini by title", ProcessInfo{Executable: "/tmp/unrelated-binary", Comm: "unrelated", Argv: []string{"gemini"}}, "gemini-cli:argv0-process-title", "gemini-cli"},

		{"copilot by image", ProcessInfo{Executable: "/usr/local/bin/copilot", Comm: "copilot", Argv: []string{"copilot"}}, "copilot-cli:executable-basename", "copilot-cli"},
		{"copilot by comm", ProcessInfo{Executable: "/opt/vendor/launcher", Comm: "copilot", Argv: []string{"launcher"}}, "copilot-cli:kernel-comm", "copilot-cli"},
		{"copilot by title", ProcessInfo{Executable: "/tmp/unrelated", Comm: "unrelated", Argv: []string{"copilot"}}, "copilot-cli:argv0-process-title", "copilot-cli"},

		{"aider by image", ProcessInfo{Executable: "/usr/local/bin/aider", Comm: "aider", Argv: []string{"aider"}}, "aider:executable-basename", "aider"},
		{"aider by title", ProcessInfo{Executable: "/tmp/unrelated", Comm: "unrelated", Argv: []string{"aider"}}, "aider:argv0-process-title", "aider"},

		{"goose by comm", ProcessInfo{Executable: "/opt/vendor/launcher", Comm: "goose", Argv: []string{"launcher"}}, "goose:kernel-comm", "goose"},
		{"goose by title", ProcessInfo{Executable: "/tmp/unrelated", Comm: "unrelated", Argv: []string{"goose"}}, "goose:argv0-process-title", "goose"},

		{"opencode by image", ProcessInfo{Executable: "/usr/local/bin/opencode", Comm: "opencode", Argv: []string{"opencode"}}, "opencode:executable-basename", "opencode"},
		{"opencode by title", ProcessInfo{Executable: "/tmp/unrelated", Comm: "unrelated", Argv: []string{"opencode"}}, "opencode:argv0-process-title", "opencode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := tc.agent
			agent.PID, agent.PPID = 80, 1
			src := newFixtureSource(
				ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
				agent,
			)
			got := detect(t, src, 100)

			require.Equal(t, StatusDetected, got.Status)
			require.NotNil(t, got.Provider)
			assert.Equal(t, tc.product, got.Provider.Product())
			assert.Equal(t, tc.want, got.Match.Fingerprint)
			require.NotEmpty(t, got.Ancestry)
			assert.Equal(t, tc.want, got.Ancestry[len(got.Ancestry)-1].MatchedBy,
				"the ancestry entry must carry the same basis the match did")
		})
	}
}

// TestAncestryNamesWhereEachProgramNameCameFrom is the same hazard one field
// over, found by sweeping the predicate rather than by review.
//
// An ancestry entry's program name falls back across the same three process
// facts the fingerprints do, and published one undifferentiated string for all
// of them — so a program name on an unmatched ancestor could be the kernel's
// record or a title the process wrote for itself, with no way to tell. The
// fallback order was also inverted relative to every other identity decision in
// this package: it preferred the self-declared argv[0] over the kernel's own
// comm.
//
// Red against the pre-fix code: no basis field existed, and the zsh ancestor
// published "-zsh" from argv[0] while the kernel had a comm for it.
func TestAncestryNamesWhereEachProgramNameCameFrom(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		// No image path and no comm: all that is left is the title the
		// process wrote for itself, and the entry must say so.
		ProcessInfo{PID: 90, PPID: 80, Argv: []string{"gemini-lookalike --serve"}},
		ProcessInfo{PID: 80, PPID: 1, Comm: "zsh", Argv: []string{"-zsh"}},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/launchd", Comm: "launchd"},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusNotDetected, got.Status)
	require.Len(t, got.Ancestry, 3)

	assert.Equal(t, "gemini-lookalike", got.Ancestry[0].Program)
	assert.Equal(t, basisArgv0Title, got.Ancestry[0].ProgramFrom)

	assert.Equal(t, "zsh", got.Ancestry[1].Program, "the kernel's own name beats the process's self-declared title")
	assert.Equal(t, basisKernelComm, got.Ancestry[1].ProgramFrom)

	assert.Equal(t, "launchd", got.Ancestry[2].Program)
	assert.Equal(t, basisExecutableBase, got.Ancestry[2].ProgramFrom)
}

// writeExecutable creates a regular file standing in for an agent binary,
// making every parent directory it needs.
func writeExecutable(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/false\n"), 0o600))
}

// TestOversizeNpmManifestIsRefusedRatherThanRead is the other half of hazard 9.
//
// The manifest sits at a path the agent chooses, so its SIZE is the agent's
// choice too. An unbounded whole-file read there lets a matched process spend
// this attestor's memory during evidence collection, and the file does not have
// to be hostile to hurt — it only has to be large.
//
// The read is bounded one byte past the cap, so a manifest AT the cap is still
// read and one over it is caught by the read itself rather than trusted from an
// earlier size — the same shape hashHandle and loadConfigSnapshot already use.
// A refused manifest yields no version at all: a version this attestor could
// not read within its bound is a version it does not claim.
//
// Red against the pre-fix code: os.ReadFile returns the whole file and the
// version is published.
func TestOversizeNpmManifestIsRefusedRatherThanRead(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64")
	binPath := filepath.Join(pkgDir, "vendor", "bin", "codex")
	writeExecutable(t, binPath)

	// Valid JSON carrying a real version, padded past the cap. Nothing about
	// it is malformed — being oversized is the whole objection.
	padding := strings.Repeat("p", 2*npmManifestReadLimit)
	manifest := `{"name":"@openai/codex-darwin-arm64","version":"9.9.9","pad":"` + padding + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(manifest), 0o600))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Version,
		"a manifest too large to read within the bound must not contribute a version")
}

// TestNpmManifestAtTheBoundIsStillRead pins the other side of that edge, so the
// bound cannot be "fixed" into refusing everything.
func TestNpmManifestAtTheBoundIsStillRead(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64")
	binPath := filepath.Join(pkgDir, "vendor", "bin", "codex")
	writeExecutable(t, binPath)

	head := `{"version":"0.147.0","pad":"`
	tail := `"}`
	padding := strings.Repeat("p", npmManifestReadLimit-len(head)-len(tail))
	manifest := head + padding + tail
	require.Len(t, manifest, npmManifestReadLimit, "fixture must sit exactly ON the cap")
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(manifest), 0o600))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Version)
	assert.Equal(t, "0.147.0", got.Inspection.Version.Value)
}

// TestDirectoryAtTheNpmManifestIsRefused. The regular-file check is not only
// about pipes: a directory where the manifest belongs must read as absence
// rather than as an error worth reporting.
func TestDirectoryAtTheNpmManifestIsRefused(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64")
	binPath := filepath.Join(pkgDir, "vendor", "bin", "codex")
	writeExecutable(t, binPath)
	require.NoError(t, os.MkdirAll(filepath.Join(pkgDir, "package.json"), 0o750))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Version)
}

// ---------------------------------------------------------------------------
// Round 7: one binding, three layers.
//
// Every finding this round was the same principle at a different layer — the
// claim must be bound to the observation that supports it:
//
//	13. the VERDICT was bound to walk completeness for not-detected only, so a
//	    match found past an unreadable ancestor was still signed as "the
//	    invoker" despite a nearer process being unexaminable;
//	14. the FINGERPRINT was bound to the path SHAPE but not to WHICH argument
//	    carried it, so an unrelated node invocation naming a codex path
//	    anywhere in its arguments was attested as Codex;
//	15. the READ was not bound to the process INSTANCE it describes, so an
//	    image-open failure fell back to the recorded path and could digest a
//	    replacement file while pid, argv and ancestry describe the original.
// ---------------------------------------------------------------------------

// TestMatchFoundPastAnUnexaminedAncestorCannotClaimTheInvoker is hazard 13.
//
// first-agent-wins is this attestor's central invariant: the NEAREST recognized
// agent is the invoker. An ancestor closer than the match whose identity could
// not be read breaks the "nearest" half — that process might itself have been a
// supported agent, and nothing here can rule it out. Naming the farther process
// as the invoker would sign an attribution the walk cannot support.
//
// The previous round bound not-detected to walk completeness and left matched
// unbound. Both verdicts now come out of the same computation.
//
// Red against the pre-fix code: status detected, invoker claimed.
func TestMatchFoundPastAnUnexaminedAncestorCannotClaimTheInvoker(t *testing.T) {
	// The middle process is readable as a slot but its identity reads failed —
	// the shape a process that exited mid-walk produces.
	blind := newProcessInfo(90, 80, "").
		executable("", errors.New("kernel refused")).
		comm("", errors.New("kernel refused")).
		argv(nil, errors.New("kernel refused")).
		build()

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 80, PPID: 0, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--model", "gpt-5.6-sol"}},
	)
	src.procs[90] = blind

	got := detect(t, src, 100)

	assert.Equal(t, StatusIncomplete, got.Status,
		"a nearer process that could not be examined may itself have been the agent")
	assert.NotEqual(t, StatusDetected, got.Status)

	a := attestFixture(t, src, 100)
	assert.Nil(t, a.Invoker,
		"no invoker may be published when a nearer process could not be ruled out")
	assert.Contains(t, strings.Join(a.Warnings, "\n"), "90")
}

// TestMatchOverAFullyExaminedAncestryStillClaimsTheInvoker guards the other
// direction, so the fix cannot be "achieved" by degrading every match.
//
// This is the measured common case: on a real machine the agent is found before
// the walk ever reaches the unreadable root, so a normal detection is unchanged.
func TestMatchOverAFullyExaminedAncestryStillClaimsTheInvoker(t *testing.T) {
	got := detect(t, codexLinuxNested(), 100)

	require.Equal(t, StatusDetected, got.Status)
	a := attestFixture(t, codexLinuxNested(), 100)
	require.NotNil(t, a.Invoker)
	assert.Equal(t, "codex", a.Invoker.Product)
}

// TestNodeShimMatchesOnlyTheScriptPositional is hazard 14.
//
// The matcher scanned EVERY node argument for a package path, so
// `node app.js /tmp/@openai/codex/bin/codex.js` — an unrelated program merely
// mentioning the path — was attested as Codex. A fingerprint must name the slot
// its evidence came from, exactly as the basis vocabulary makes a name matcher
// name the process fact it fired on.
//
// Red against the pre-fix code: the unrelated invocation is detected as Codex.
func TestNodeShimMatchesOnlyTheScriptPositional(t *testing.T) {
	const pkg = "/usr/lib/node_modules/@openai/codex/bin/codex.js"

	for _, tc := range []struct {
		name string
		argv []string
		want bool
	}{
		{"the script itself", []string{"node", pkg}, true},
		{"script after the option terminator", []string{"node", "--", pkg}, true},

		{"named as an argument to another script", []string{"node", "app.js", pkg}, false},
		{"named after a flag that takes a value", []string{"node", "-r", pkg, "app.js"}, false},
		{"named in a trailing argument", []string{"node", "app.js", "--config", pkg}, false},
		{"no arguments at all", []string{"node"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newFixtureSource(
				ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
				ProcessInfo{PID: 80, PPID: 0, Executable: "/usr/bin/node", Comm: "node", Argv: tc.argv},
			)
			got := detect(t, src, 100)

			if tc.want {
				require.Equal(t, StatusDetected, got.Status)
				assert.Equal(t, fpCodexNpmShim, got.Match.Fingerprint)
				return
			}
			assert.NotEqual(t, StatusDetected, got.Status,
				"only the script node was told to RUN may attribute the process to that package")
		})
	}
}

// TestImageOpenFailureRefusesRatherThanFallingBackToThePath is hazard 15.
//
// Where a platform CAN hand over the running image (Linux /proc/<pid>/exe), a
// failure to open it means the process this predicate describes is no longer
// there to be read. Falling back to the recorded filesystem path then digests
// whatever occupies that name NOW, while pid, start time, argv and ancestry all
// describe the original — precisely how a replacement file gets signed as the
// original. The fallback exists for platforms with no image handle at all, not
// as a retry for one that failed.
//
// Red against the pre-fix code: the replacement file is opened, digested, and
// published as this process's executable evidence.
func TestImageOpenFailureRefusesRatherThanFallingBackToThePath(t *testing.T) {
	dir := t.TempDir()
	recorded := filepath.Join(dir, "codex")
	require.NoError(t, os.WriteFile(recorded, []byte("the replacement binary"), 0o600))

	// A source that CAN open process images but cannot open this one.
	src := &imageHandleSource{
		fixtureSource: newFixtureSource(
			ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
			ProcessInfo{PID: 80, PPID: 0, Executable: recorded, Comm: "codex", Argv: []string{"codex"}},
		),
		images: map[int]string{}, // no image for pid 80: the open fails
	}
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Empty(t, got.Image.sha256,
		"a digest taken from the recorded path cannot be attributed to a process whose image could not be opened")
	assert.Empty(t, got.Image.resolved())
	assert.Equal(t, digestSkipImageUnavailable, got.Image.digestSkipped)
}

// TestImageOpenSuccessStillDigestsTheImage is the control for hazard 15.
func TestImageOpenSuccessStillDigestsTheImage(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "codex")
	require.NoError(t, os.WriteFile(image, []byte("the real image"), 0o600))

	src := &imageHandleSource{
		fixtureSource: newFixtureSource(
			ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
			ProcessInfo{PID: 80, PPID: 0, Executable: image, Comm: "codex", Argv: []string{"codex"}},
		),
		images: map[int]string{80: image},
	}
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, sha256hex([]byte("the real image")), got.Image.sha256)
	assert.Equal(t, digestBindingProcessImage, got.Image.binding)
}

// TestPathBoundPlatformsStillDigestTheRecordedPath. Refusing after a failed
// image open must not remove the honest ceiling on platforms that have no image
// handle at all — macOS is the measured case, and there the path open IS the
// evidence, declared as such by DigestBinding.
func TestPathBoundPlatformsStillDigestTheRecordedPath(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "codex")
	require.NoError(t, os.WriteFile(image, []byte("path bound image"), 0o600))

	// A plain fixture source implements no image opener.
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 0, Executable: image, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, sha256hex([]byte("path bound image")), got.Image.sha256)
	assert.Equal(t, digestBindingPath, got.Image.binding)
}

// TestProcessInstanceValidationRefusesAReusedPID pins the instance check
// itself.
//
// A PID is reused after wraparound, so a follow-up read addressed by number
// alone can land on a DIFFERENT process. The start time is what distinguishes
// one run of a pid from the next, and it is compared before any evidence
// derived from a second read is accepted.
//
// Forcing a real wraparound is not something a test can do deterministically,
// so this pins the VALIDATION rather than claiming to have reproduced the race:
// given a captured instance and a process that no longer matches it, the read
// is refused.
func TestProcessInstanceValidationRefusesAReusedPID(t *testing.T) {
	const image = "/usr/local/bin/codex"
	captured := ProcessInfo{PID: 4242, StartTime: "1000.000001", Executable: image, execGeneration: "gen-x"}.instance()

	assert.NoError(t, captured.validate(ProcessInfo{PID: 4242, StartTime: "1000.000001", Executable: image, execGeneration: "gen-x"}),
		"the same run of the same pid is the instance that was captured")

	assert.Error(t, captured.validate(ProcessInfo{PID: 4242, StartTime: "9999.999999", Executable: image}),
		"same pid, different start time is a DIFFERENT process wearing a recycled number")
	assert.Error(t, captured.validate(ProcessInfo{PID: 77, StartTime: "1000.000001", Executable: image}),
		"a different pid is not the captured instance")

	// A platform that cannot report a start time cannot vouch for the
	// instance, and must not be treated as though it had.
	assert.Error(t, processInstance{pid: 4242, executable: image}.validate(ProcessInfo{PID: 4242, Executable: image}),
		"an absent start time proves nothing and must not pass as a match")
}

// ---------------------------------------------------------------------------
// Round 8. Three defects and one narrowing.
//
//	16. a lower-priority environment scope was consulted after a HIGHER
//	    priority one failed to read, signing cilock's own inherited value as
//	    the agent's;
//	17. an unavailable home directory turned an absolute user-config path into
//	    a RELATIVE one, so configuration was read from the process working
//	    directory and signed as user configuration;
//	18. instance validation compared pid and start time, both of which SURVIVE
//	    execve, so an agent that exec'd between the walk and the image open
//	    paired a new image's digest with the old executable and argv.
// ---------------------------------------------------------------------------

// TestUnreadableAgentEnvironmentDoesNotPromoteCilocksOwnValue is hazard 16.
//
// The agent's own environment outranks cilock's inherited copy, so cilock's is
// consulted only when the agent's was actually READ and did not carry the key.
// When the higher-priority read FAILED, an ANTHROPIC_MODEL sitting in the
// agent's environment cannot be ruled out, and publishing cilock's value would
// sign a model the run may never have used.
//
// Red against the pre-fix code: the model is reported as cilock's value.
func TestUnreadableAgentEnvironmentDoesNotPromoteCilocksOwnValue(t *testing.T) {
	withHomeDir(t, t.TempDir())

	base := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock",
			Env: map[string]string{"ANTHROPIC_MODEL": "cilocks-inherited-model"}},
		ProcessInfo{PID: 80, PPID: 0, Executable: "/usr/local/bin/claude", Comm: "claude",
			Argv: []string{"claude"},
			Env:  map[string]string{"ANTHROPIC_MODEL": "the-agents-real-model"}},
	)
	src := &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{80: true}}

	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Model,
		"the higher-priority environment was unreadable, so no environment model is observable")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "could not be read")
}

// TestReadableAgentEnvironmentDoesNotPromoteCilocksOwnValue: when the agent's
// environment WAS read and did not carry the key, the question is ANSWERED —
// the agent had no ANTHROPIC_MODEL. A value sitting only in cilock's inherited
// environment was put there by whatever sits between the agent and this
// process (a shell profile export is the ordinary case), and promoting it
// signed a model the agent never resolved, under a Source string naming the
// agent's environment. It stays an environment OBSERVATION, labeled with the
// scope it came from, and the model stays unresolved with a warning saying
// why.
//
// Red against the pre-fix code: Model was "cilocks-inherited-model".
func TestReadableAgentEnvironmentDoesNotPromoteCilocksOwnValue(t *testing.T) {
	withHomeDir(t, t.TempDir())

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock",
			Env: map[string]string{"ANTHROPIC_MODEL": "cilocks-inherited-model"}},
		ProcessInfo{PID: 80, PPID: 0, Executable: "/usr/local/bin/claude", Comm: "claude",
			Argv: []string{"claude"}},
	)
	got := detect(t, src, 100)

	assert.Nil(t, got.Inspection.Model,
		"a model set only in cilock's own environment must not be promoted to the agent's model")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"),
		"cilock's own inherited environment",
		"the self-scope value must be named as recorded-not-promoted")

	var observed *EnvObservation
	for i := range got.Inspection.Environment {
		obs := got.Inspection.Environment[i]
		if obs.Key == "ANTHROPIC_MODEL" && obs.From == string(EnvScopeSelf) {
			observed = &got.Inspection.Environment[i]
		}
	}
	require.NotNil(t, observed, "the self-scope value is still evidence, under its own scope label")
	assert.Equal(t, "cilocks-inherited-model", observed.Value)
}

// TestUnreadableAgentEnvironmentDoesNotTrustCilocksCodexHome is the same hazard
// for a DIRECTORY rather than a value. $CODEX_HOME decides which file is read
// at all, so trusting cilock's copy after the agent's read failed digests a
// config from a directory the agent may never have used.
func TestUnreadableAgentEnvironmentDoesNotTrustCilocksCodexHome(t *testing.T) {
	cilockHome := t.TempDir()
	writeFile(t, filepath.Join(cilockHome, "config.toml"), "model = \"from-cilocks-codex-home\"\n")

	base := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock",
			Env: map[string]string{"CODEX_HOME": cilockHome}},
		ProcessInfo{PID: 80, PPID: 0, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex"}},
	)
	src := &unreadableEnvSource{fixtureSource: base, pids: map[int]bool{80: true}}

	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	if got.Inspection.Model != nil {
		assert.NotEqual(t, "from-cilocks-codex-home", got.Inspection.Model.Value,
			"a config directory named by cilock's environment is not known to be the agent's")
	}
}

// TestUnavailableHomeDirectoryReadsNoConfigAtAll is hazard 17.
//
// filepath.Join("", ".cursor", "cli.json") is ".cursor/cli.json" — a RELATIVE
// path, resolved against the process working directory. A repository that
// happens to contain such a file would have it read and signed as the USER's
// configuration, and the emptiness check meant to prevent this never fired,
// because the joined path is not empty.
//
// Red against the pre-fix code: the working-directory file is read and
// recorded at user scope.
func TestUnavailableHomeDirectoryReadsNoConfigAtAll(t *testing.T) {
	previous := homeDirFunc
	homeDirFunc = func() (string, error) { return "", errors.New("no home directory") }
	t.Cleanup(func() { homeDirFunc = previous })

	// Run from a directory that DOES contain the relative paths those joins
	// would produce, which is what makes the defect observable.
	cwd, err := os.Getwd()
	require.NoError(t, err)
	tmp := t.TempDir()
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	writeJSON(t, filepath.Join(tmp, ".cursor", "cli.json"), map[string]any{"model": "cwd-cursor-model"})
	writeJSON(t, filepath.Join(tmp, ".gemini", "settings.json"), map[string]any{"model": "cwd-gemini-model"})

	for _, tc := range []struct {
		name string
		proc ProcessInfo
	}{
		{"cursor", ProcessInfo{PID: 80, PPID: 0, Executable: "/opt/cursor/cursor-agent", Comm: "cursor-agent", Argv: []string{"cursor-agent"}}},
		{"gemini", ProcessInfo{PID: 80, PPID: 0, Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newFixtureSource(
				ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
				tc.proc,
			)
			got := detect(t, src, 100)

			require.Equal(t, StatusDetected, got.Status)
			for _, cfg := range got.Inspection.Configuration {
				assert.Falsef(t, strings.HasPrefix(cfg.Path, "."),
					"a relative config path means the working directory was read as though it were the home directory: %q", cfg.Path)
			}
			if got.Inspection.Model != nil {
				assert.NotContains(t, got.Inspection.Model.Value, "cwd-",
					"a model read from the working directory must never be reported")
			}
		})
	}
}

// TestExecBetweenTheWalkAndTheImageOpenIsRefused is hazard 18.
//
// pid and start time both SURVIVE execve. An agent that execs a different
// binary between the walk reading it and the image being opened therefore
// passes an instance check built on those two alone, and the new image's digest
// is published beside the OLD executable path, argv, fingerprint and ancestry.
//
// The captured executable is part of the instance for exactly that reason: it
// is the field execve changes.
func TestExecBetweenTheWalkAndTheImageOpenIsRefused(t *testing.T) {
	captured := ProcessInfo{PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex", execGeneration: "gen-x"}.instance()

	assert.NoError(t, captured.validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex", execGeneration: "gen-x",
	}), "same pid, same start time, same image is the captured instance")

	assert.Error(t, captured.validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/bin/something-else",
	}), "pid and start time survive execve, so the image path is what reveals it")

	assert.Error(t, captured.validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "",
	}), "an image path that could not be read cannot confirm the instance")

	assert.Error(t, processInstance{pid: 4242, startTime: "1000.000001"}.validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex",
	}), "a captured instance with no image path cannot vouch for anything")
}

// fifoRegressionsCompiled is set by fsutil_fifo_unix_test.go's init when that
// build-tagged file is part of the build.
var fifoRegressionsCompiled bool

// TestFifoRegressionsAreInTheBuild answers a review claim with a measurement
// instead of a change.
//
// The claim was that //go:build unix is not honoured, so the FIFO regressions
// never run. If that were true those red proofs would have been worthless, so
// it is worth pinning rather than arguing: on any unix GOOS the tagged file
// must be compiled in.
//
// The expectation is DERIVED from the constraint (platformHasUnixBuildTag, set
// in unixtag_unix_test.go / unixtag_notunix_test.go) rather than from a
// hand-written GOOS list. The list this replaced named windows, js and plan9
// and was wrong about wasip1, which carries no unix tag either — the kind of
// error a derived constant cannot make.
func TestFifoRegressionsAreInTheBuild(t *testing.T) {
	if platformHasUnixBuildTag {
		assert.True(t, fifoRegressionsCompiled,
			"//go:build unix must include the FIFO regressions on %s; if this fails the constraint really did stop working and the tests have been inert", runtime.GOOS)
		return
	}
	assert.False(t, fifoRegressionsCompiled, "the unix constraint must exclude %s", runtime.GOOS)
}

// TestManifestVersionIsRefusedWhenThePackageWasReplaced pins the binding the
// manifest read depends on.
//
// npm updates a package by swapping its directory atomically, which replaces
// the binary AND the manifest together. The manifest is read after the image
// handle has closed, from a path rather than a descriptor, so on its own it is
// a fresh question to the filesystem: the version that comes back can belong to
// a package that no longer contains the image this snapshot digested.
//
// The snapshot keeps the fstat of the handle everything else came from, and the
// version is published only while the resolved path still names that very
// inode. This drives the snapshot directly because there is no seam in the walk
// to swap a directory through, and the property is about the snapshot.
func TestManifestVersionIsRefusedWhenThePackageWasReplaced(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64")
	binPath := filepath.Join(pkgDir, "vendor", "bin", "codex")
	writeExecutable(t, binPath)
	writeJSON(t, filepath.Join(pkgDir, "package.json"), map[string]any{"version": "0.147.0"})

	src := newFixtureSource(
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	snap := snapshotExecutable(src, src.procs[80], DefaultDigestSizeLimit)
	require.NotEmpty(t, snap.resolved(), "fixture precondition: the snapshot bound a path")
	require.Equal(t, "0.147.0", snap.npmPackageVersion("@openai"),
		"an untouched package reports its version")

	// The package is replaced the way npm replaces one: the binary at the
	// resolved path is now a DIFFERENT file, and the manifest beside it
	// describes that different package. A real replacement lands later in
	// wall-clock time than the install it displaces, so the fixture stamps the
	// new binary with a later mtime explicitly: within one test both writes
	// otherwise land in the same coarse kernel clock tick on Linux, where the
	// recreated file also reuses the deleted one's inode (ext4/overlayfs) —
	// leaving NOTHING in stat to tell the two apart. That same-tick,
	// same-size, reused-inode swap is the accepted residual of this check;
	// see stillDescribesTheDigestedImage.
	require.NoError(t, os.Remove(binPath))
	writeExecutable(t, binPath)
	replacedAt := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(binPath, replacedAt, replacedAt))
	writeJSON(t, filepath.Join(pkgDir, "package.json"), map[string]any{"version": "9.9.9"})

	assert.Empty(t, snap.npmPackageVersion("@openai"),
		"a manifest that no longer sits beside the digested image must not supply a version for it")
}

// TestNpmVersionWalkStopsAtTheNearestPackageRoot: the manifest walk must not
// continue past the package that shipped the binary. In a nested npm tree
// (a scoped package vendored inside another scoped package), the NEAREST
// directory whose parent is the namespace is the shipping package; if its
// manifest is missing, unreadable, or invalid, nothing can answer — walking
// on would hand back an OUTER package's version and sign it beside the inner
// executable's digest, a version that demonstrably did not ship this binary.
//
// Red against the pre-fix walk: with the inner manifest invalid, the outer
// package's "9.9.9" came back.
func TestNpmVersionWalkStopsAtTheNearestPackageRoot(t *testing.T) {
	root := t.TempDir()
	outerPkg := filepath.Join(root, "node_modules", "@openai", "outer")
	writeJSON(t, filepath.Join(outerPkg, "package.json"), map[string]any{"version": "9.9.9"})

	innerPkg := filepath.Join(outerPkg, "node_modules", "@openai", "inner")
	binPath := filepath.Join(innerPkg, "bin", "codex")
	writeExecutable(t, binPath)
	// The nearest package root's manifest exists but is not a valid manifest.
	writeFile(t, filepath.Join(innerPkg, "package.json"), "not json")

	src := newFixtureSource(
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	snap := snapshotExecutable(src, src.procs[80], DefaultDigestSizeLimit)
	require.NotEmpty(t, snap.resolved(), "fixture precondition: the snapshot bound a path")

	assert.Empty(t, snap.npmPackageVersion("@openai"),
		"the nearest package root could not answer; an outer package's version must not be signed for this binary")

	// The same layout with a VALID nearest manifest still answers from it —
	// the stop-at-nearest rule costs nothing on the measured install shapes.
	require.NoError(t, os.Remove(filepath.Join(innerPkg, "package.json")))
	writeJSON(t, filepath.Join(innerPkg, "package.json"), map[string]any{"version": "0.147.0"})
	snap2 := snapshotExecutable(src, src.procs[80], DefaultDigestSizeLimit)
	assert.Equal(t, "0.147.0", snap2.npmPackageVersion("@openai"))
}
