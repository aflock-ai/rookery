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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCodexHomebrewCaskLayout. Homebrew installs codex behind a symlink into a
// Caskroom directory named by the version, and the real image basename is the
// release target triple — so basename-equals-"codex" does not fire.
func TestCodexHomebrewCaskLayout(t *testing.T) {
	got := detect(t, codexHomebrewCask(), 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, "codex", got.Provider.Product())
	assert.Equal(t, fpCodexReleaseBinary, got.Match.Fingerprint)

	require.NotNil(t, got.Inspection.Version)
	assert.Equal(t, "0.143.0", got.Inspection.Version.Value)
	assert.Equal(t, AssuranceInferred, got.Inspection.Version.Assurance,
		"a version parsed out of a Caskroom directory name is a layout inference, not process state")

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "gpt-5.6-sol", got.Inspection.Model.Value)
	assert.Equal(t, "process.argv:--model", got.Inspection.Model.Source)
}

// TestCodexNpmLayout. The `codex` on PATH is a node script that spawns the
// native binary, so cilock's nearest Codex ancestor is that native binary and
// the node shim sits one further out. First-agent-wins picks the native one.
func TestCodexNpmLayout(t *testing.T) {
	got := detect(t, codexNpmInstall(), 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, 90, got.Process.PID, "the native binary, not the node shim")
	assert.Equal(t, fpCodexExecutable, got.Match.Fingerprint)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "gpt-5.6-sol", got.Inspection.Model.Value)
	assert.Equal(t, "process.argv:-c model=", got.Inspection.Model.Source)
}

// TestCodexNpmShimIsMatchedWhenItIsTheOnlyCodexInTheAncestry.
func TestCodexNpmShimIsMatchedAlone(t *testing.T) {
	const pkgRoot = "/usr/lib/node_modules/@openai/codex"
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{
			PID: 80, PPID: 1,
			Executable: "/usr/bin/node",
			Comm:       "node",
			Argv:       []string{"node", pkgRoot + "/bin/codex.js"},
		},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, "codex", got.Provider.Product())
	assert.Equal(t, fpCodexNpmShim, got.Match.Fingerprint)
}

// TestCodexVersionFromNpmPackageJSON reads the version out of the
// @openai/<pkg>/package.json that shipped the binary. Requires a real directory
// tree, so it is built in a temp dir.
func TestCodexVersionFromNpmPackageJSON(t *testing.T) {
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
	// Inferred, not configuration-observed: the manifest is a different file
	// from the image, found by walking the directory layout around it. See
	// TestNpmVersionIsGradedAsTheLayoutInferenceItIs.
	assert.Equal(t, AssuranceInferred, got.Inspection.Version.Assurance)
	assert.Contains(t, got.Inspection.Version.Source, "snapshot",
		"the source must say the read was made against the snapshot's bound path")
}

// TestCodexVersionIgnoresTheUpdateCheckFile is the honesty regression for
// version.
//
// $CODEX_HOME/version.json holds {"latest_version": ...} — the newest release
// available upstream, which is routinely NOT the version that ran. Reading it
// would produce a confident, wrong version claim.
func TestCodexVersionIgnoresTheUpdateCheckFile(t *testing.T) {
	codexHome := t.TempDir()
	writeJSON(t, filepath.Join(codexHome, "version.json"), map[string]any{
		"latest_version": "0.147.0", "last_checked_at": "2026-08-18T21:51:09Z",
	})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex"}, Env: map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Version, "an available-update version is not the version that ran")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "latest version available upstream")
}

func TestCodexModelFromConfigTOML(t *testing.T) {
	codexHome := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), `
# leading comment
model = "gpt-5.6-luna"
model_reasoning_effort = "medium"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex"}, Env: map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "gpt-5.6-luna", got.Inspection.Model.Value)
	assert.Equal(t, AssuranceConfigObserved, got.Inspection.Model.Assurance)

	settings := settingsByKey(got.Inspection.Settings)
	assert.Equal(t, "medium", settings["model_reasoning_effort"])
	assert.Equal(t, "on-request", settings["approval_policy"])
	assert.Equal(t, "workspace-write", settings["sandbox_mode"])

	require.Len(t, got.Inspection.Configuration, 1)
	assert.Equal(t, RoleObserved, got.Inspection.Configuration[0].Role)
	assert.NotEmpty(t, got.Inspection.Configuration[0].SHA256)
}

func TestCodexProfileOverlayWins(t *testing.T) {
	codexHome := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "top-level-model"
approval_policy = "on-request"
`)
	writeFile(t, filepath.Join(codexHome, "work.config.toml"), `
model = "work-model"
approval_policy = "never"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--profile", "work"},
			Env:  map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "work-model", got.Inspection.Model.Value)
	assert.Equal(t, "never", settingsByKey(got.Inspection.Settings)["approval_policy"])
	assert.Equal(t, "work", got.Inspection.ArgvFields["profile"])
}

// TestCodexProfileFallsBackToTopLevel. A profile that pins no model inherits
// the top-level one.
func TestCodexProfileFallsBackToTopLevel(t *testing.T) {
	codexHome := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "top-level-model"
`)
	writeFile(t, filepath.Join(codexHome, "sparse.config.toml"), `
approval_policy = "never"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--profile", "sparse"},
			Env:  map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "top-level-model", got.Inspection.Model.Value)
}

func TestCodexConfigOverrideDecodesTOMLStrings(t *testing.T) {
	value, ok := codexConfigOverrideFromArgv([]string{"codex", "-c", `model="gpt-5"`}, "model")
	require.True(t, ok)
	assert.Equal(t, "gpt-5", value)

	value, ok = codexConfigOverrideFromArgv([]string{"codex", `--config=approval_policy='on-request'`}, "approval_policy")
	require.True(t, ok)
	assert.Equal(t, "on-request", value)

	value, ok = codexConfigOverrideFromArgv([]string{"codex", `-csandbox_mode="danger-full-access"`}, "sandbox_mode")
	require.True(t, ok)
	assert.Equal(t, "danger-full-access", value)

	value, ok = codexConfigOverrideFromArgv([]string{"codex", "-c", "model_reasoning_effort=high"}, "model_reasoning_effort")
	require.True(t, ok, "invalid TOML falls back to Codex's documented raw-string behavior")
	assert.Equal(t, "high", value)

	_, ok = codexConfigOverrideFromArgv([]string{"codex", "-c", "model=3"}, "model")
	assert.False(t, ok, "a valid non-string TOML value is not coerced into a model name")
}

// TestCodexUnresolvedProjectConfigDegradesUserConfig. This attestor has not
// confirmed whether Codex reads a project-local .codex/config.toml, nor with
// what precedence. Round 1 set the doctrine for the environment tier: a
// higher-precedence override that cannot be ruled out means the lower source
// is recorded but never claimed effective. The config tier gets the same
// treatment: while an unresolved project config exists, nothing from the user
// config may be signed as effective — for all this attestor can prove, the
// project file overrode any of it.
func TestCodexUnresolvedProjectConfigDegradesUserConfig(t *testing.T) {
	codexHome := t.TempDir()
	repo := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"),
		"model = \"user-model\"\nsandbox_mode = \"read-only\"\n")
	writeFile(t, filepath.Join(repo, ".codex", "config.toml"), "model = \"project-model\"\n")

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex"}, Env: map[string]string{"CODEX_HOME": codexHome}},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), 100, repo)
	require.NoError(t, err)

	assert.Nil(t, got.Inspection.Model,
		"the user-config model must not be claimed while a project config with unknown precedence exists")
	assert.Empty(t, got.Inspection.Settings,
		"posture values from the user config must not be claimed either")

	byScope := map[string]ConfigSource{}
	for _, cfg := range got.Inspection.Configuration {
		byScope[cfg.Scope] = cfg
	}
	require.Contains(t, byScope, "project")
	require.Contains(t, byScope, "user")
	assert.Equal(t, RoleObserved, byScope["project"].Role)
	assert.NotEmpty(t, byScope["project"].SHA256, "the file is still evidence even when not effective")
	assert.NotEmpty(t, byScope["user"].SHA256)
	assert.Equal(t, RoleObserved, byScope["user"].Role,
		"the user config may not claim effect while the project file's precedence is unresolved")

	joined := strings.Join(got.Inspection.Warnings, "\n")
	assert.Contains(t, joined, ".codex/config.toml")
	assert.Contains(t, joined, "recorded as observed but not resolved")
	assert.NotContains(t, joined, repo, "warnings must not leak the repository path")
	assert.NotContains(t, joined, codexHome, "warnings must not leak the config directory path")
}

// TestCodexCLIValuesUnaffectedByUnresolvedProjectConfig. The command line is
// confirmed precedence above every file, so argv-derived values stay effective
// evidence even while a project config exists.
func TestCodexCLIValuesUnaffectedByUnresolvedProjectConfig(t *testing.T) {
	codexHome := t.TempDir()
	repo := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), "model = \"user-model\"\n")
	writeFile(t, filepath.Join(repo, ".codex", "config.toml"), "model = \"project-model\"\n")

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--model", "cli-model", "--sandbox", "workspace-write"},
			Env:  map[string]string{"CODEX_HOME": codexHome}},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), 100, repo)
	require.NoError(t, err)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "cli-model", got.Inspection.Model.Value)
	assert.Equal(t, AssuranceProcessObserved, got.Inspection.Model.Assurance)
	assert.Equal(t, "workspace-write", settingsByKey(got.Inspection.Settings)["sandbox_mode"])
}

// TestCodexCLIPostureBeatsConfigFile is the posture twin of CLI-beats-config
// for the model. A config.toml claiming a SAFE posture must not be what gets
// signed when the command line overrode it: --sandbox danger-full-access with
// sandbox_mode = "read-only" on disk is a run with full access, and evidence
// saying otherwise is evidence lying in the dangerous direction.
func TestCodexCLIPostureBeatsConfigFile(t *testing.T) {
	codexHome := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "config-model"
model_reasoning_effort = "low"
approval_policy = "untrusted"
sandbox_mode = "read-only"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{
				"codex", "exec",
				"--sandbox", "danger-full-access",
				"--ask-for-approval", "never",
				"-c", "model_reasoning_effort=xhigh",
			},
			Env: map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	settings := settingsByKey(got.Inspection.Settings)
	assert.Equal(t, "danger-full-access", settings["sandbox_mode"], "the CLI sandbox override is the effective posture")
	assert.Equal(t, "never", settings["approval_policy"])
	assert.Equal(t, "xhigh", settings["model_reasoning_effort"])

	// Every posture value came off the command line, so every one must carry
	// process-observed provenance naming the flag it came from.
	for _, s := range got.Inspection.Settings {
		assert.Equalf(t, AssuranceProcessObserved, s.Assurance, "setting %s", s.Key)
		assert.Containsf(t, s.Source, "process.argv", "setting %s", s.Key)
	}

	// The model was NOT overridden, so the file still decided it.
	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "config-model", got.Inspection.Model.Value)
}

// TestCodexConfigEffectiveOnlyWhenItContributed pins the resolution role to
// actual contribution, per key.
func TestCodexConfigEffectiveOnlyWhenItContributed(t *testing.T) {
	t.Run("postures from file make it effective even when the model came from the CLI", func(t *testing.T) {
		codexHome := t.TempDir()
		writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "config-model"
sandbox_mode = "workspace-write"
`)
		src := newFixtureSource(
			ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
			ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
				Argv: []string{"codex", "--model", "cli-model"},
				Env:  map[string]string{"CODEX_HOME": codexHome}},
		)
		got := detect(t, src, 100)

		require.NotNil(t, got.Inspection.Model)
		assert.Equal(t, "cli-model", got.Inspection.Model.Value)

		require.Len(t, got.Inspection.Configuration, 1)
		cfg := got.Inspection.Configuration[0]
		assert.Equal(t, RoleObserved, cfg.Role)
		// The model was already decided by the CLI, so the file was never
		// consulted for it and must not claim it was.
		assert.NotContains(t, cfg.FieldsUsed, "model")
		assert.Contains(t, cfg.FieldsUsed, "sandbox_mode")
	})

	t.Run("a file that decided nothing is observed, not effective", func(t *testing.T) {
		codexHome := t.TempDir()
		writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "config-model"
model_reasoning_effort = "low"
approval_policy = "untrusted"
sandbox_mode = "read-only"
`)
		src := newFixtureSource(
			ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
			ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
				Argv: []string{
					"codex", "--model", "cli-model",
					"--sandbox", "workspace-write",
					"--ask-for-approval", "on-request",
					"-c", "model_reasoning_effort=high",
				},
				Env: map[string]string{"CODEX_HOME": codexHome}},
		)
		got := detect(t, src, 100)

		require.Len(t, got.Inspection.Configuration, 1)
		assert.Equal(t, RoleObserved, got.Inspection.Configuration[0].Role,
			"every resolved value came from the CLI; the file merely exists")

		// And none of the file's values may leak into the settings.
		settings := settingsByKey(got.Inspection.Settings)
		assert.Equal(t, "workspace-write", settings["sandbox_mode"])
		assert.Equal(t, "on-request", settings["approval_policy"])
		assert.Equal(t, "high", settings["model_reasoning_effort"])
	})
}

// TestCodexBypassFlagsSuppressConfigPosture kills the remaining leak in the
// same class: --full-auto, --yolo, and --dangerously-bypass-approvals-and-sandbox
// replace the sandbox/approval posture without carrying a value. Their
// composite meaning is version-dependent, so no value is invented for them —
// but the config file's posture demonstrably did not survive them either, so
// reporting it would again sign a safer posture than the run had. The flag
// itself stays visible in argv_fields; the settings stay silent; a warning
// says why.
func TestCodexBypassFlagsSuppressConfigPosture(t *testing.T) {
	for _, flag := range []string{
		"--dangerously-bypass-approvals-and-sandbox",
		"--yolo",
		"--full-auto",
	} {
		t.Run(flag, func(t *testing.T) {
			codexHome := t.TempDir()
			writeFile(t, filepath.Join(codexHome, "config.toml"), `
model_reasoning_effort = "low"
approval_policy = "untrusted"
sandbox_mode = "read-only"
`)
			src := newFixtureSource(
				ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
				ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
					Argv: []string{"codex", "exec", flag},
					Env:  map[string]string{"CODEX_HOME": codexHome}},
			)
			got := detect(t, src, 100)

			settings := settingsByKey(got.Inspection.Settings)
			assert.NotContains(t, settings, "sandbox_mode",
				"the file's sandbox_mode did not survive %s; absence never claims a safer posture", flag)
			assert.NotContains(t, settings, "approval_policy")
			// Reasoning effort is not part of the posture these flags replace.
			assert.Equal(t, "low", settings["model_reasoning_effort"])

			assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), flag)
		})
	}
}

// TestOversizeCodexConfigContributesPresenceOnly closes the size-bound bypass.
// configDigestLimit exists so a giant file is recorded without being digested;
// reading VALUES out of that same file through a separate unbounded read
// defeats the bound and, worse, produces values with no digest to bind them
// to. An oversize file contributes presence only: no digest, no values.
func TestOversizeCodexConfigContributesPresenceOnly(t *testing.T) {
	codexHome := t.TempDir()
	var b strings.Builder
	b.WriteString("model = \"oversize-model\"\nsandbox_mode = \"read-only\"\n")
	pad := strings.Repeat("#", 4096)
	for int64(b.Len()) <= configDigestLimit {
		b.WriteString(pad)
		b.WriteString("\n")
	}
	writeFile(t, filepath.Join(codexHome, "config.toml"), b.String())

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex"}, Env: map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	assert.Nil(t, got.Inspection.Model, "a value from a file too large to digest has no evidence to bind it")
	assert.Empty(t, got.Inspection.Settings)

	require.Len(t, got.Inspection.Configuration, 1)
	assert.Empty(t, got.Inspection.Configuration[0].SHA256)
	assert.Equal(t, RoleObserved, got.Inspection.Configuration[0].Role)
}

func TestCodexRecordsSandboxBypassFlags(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "--full-auto"}},
	)
	got := detect(t, src, 100)

	assert.Equal(t, "true", got.Inspection.ArgvFields["dangerously_bypass_approvals_and_sandbox"])
	assert.Equal(t, "true", got.Inspection.ArgvFields["full_auto"])
}

func TestCodexReleaseBinaryNamesAreExact(t *testing.T) {
	matches := []string{
		"/opt/codex-aarch64-apple-darwin",
		"/opt/codex-x86_64-unknown-linux-musl",
		"/opt/codex-x86_64-pc-windows-msvc.exe",
	}
	for _, path := range matches {
		assert.Truef(t, CodexProvider{}.Match(ProcessInfo{Executable: path}).Matched, "path %q", path)
	}

	misses := []string{
		"/opt/codex-aarch64-apple-darwin-patched",
		"/opt/codex-riscv64-unknown-linux-musl",
		"/opt/xcodex-aarch64-apple-darwin",
	}
	for _, path := range misses {
		assert.Falsef(t, CodexProvider{}.Match(ProcessInfo{Executable: path}).Matched, "path %q", path)
	}
}

func TestTOMLScannerRejectsNonStringValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, path, `
model = "ok"
count = 3
list = ["a", "b"]
inline = { model = "nested" }
commented = "value" # trailing comment
`)
	snap, _ := loadConfigSnapshot(path)
	require.NotNil(t, snap)

	v, ok := snap.tomlString("", "model")
	require.True(t, ok)
	assert.Equal(t, "ok", v)

	_, ok = snap.tomlString("", "count")
	assert.False(t, ok)

	_, ok = snap.tomlString("", "list")
	assert.False(t, ok)

	v, ok = snap.tomlString("", "commented")
	require.True(t, ok)
	assert.Equal(t, "value", v)

	_, ok = snap.tomlString("", "missing")
	assert.False(t, ok)
}

func settingsByKey(settings []SettingObservation) map[string]string {
	out := map[string]string{}
	for _, s := range settings {
		out[s.Key] = s.Value
	}
	return out
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

func TestInvalidProfileNameDoesNotOpenAPathOrResolveBase(t *testing.T) {
	codexHome := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "top-level-model"
sandbox_mode = "read-only"
approval_policy = "on-request"
`)
	writeFile(t, filepath.Join(codexHome, "unsafe.prod.config.toml"), `
model = "profile-model"
sandbox_mode = "danger-full-access"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--profile", "unsafe.prod"},
			Env:  map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Model)
	assert.Empty(t, settingValue(got.Inspection.Settings, "sandbox_mode"))
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "plain-name alphabet")
	for _, source := range got.Inspection.Configuration {
		assert.NotEqual(t, filepath.Join(codexHome, "unsafe.prod.config.toml"), source.Path,
			"the current CLI rejects dotted profile names before opening a path; the observer must do the same")
	}
}

// TestUnknownProfileRefusesTheTopLevelValues is the other half of hazard 10.
//
// If the named profile file is not observable, this attestor does not know
// what configured the run. The base file is then NOT the answer: reporting it would claim an effective
// posture the run may never have used. Same fail-closed direction as an
// unreadable environment: record the file, resolve nothing, say why.
//
// Red against the pre-fix code: top-level values are resolved and marked
// effective.
func TestUnknownProfileRefusesTheTopLevelValues(t *testing.T) {
	codexHome := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "top-level-model"
sandbox_mode = "read-only"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--profile", "no-such-profile"},
			Env:  map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Model,
		"a profile this attestor could not locate must not resolve into top-level values")
	assert.Empty(t, settingValue(got.Inspection.Settings, "sandbox_mode"))
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "no-such-profile")

	require.Len(t, got.Inspection.Configuration, 1)
	assert.Equal(t, RoleObserved, got.Inspection.Configuration[0].Role,
		"the file exists and is digested, but nothing was resolved out of it")
}

// TestPlainProfileStillInheritsTopLevelKeys guards the other direction, so the
// fix above cannot be "achieved" by refusing every profile.
//
// A profile overlay that EXISTS but does not pin a key inherits the base value
// — Codex's documented precedence, and a different fact from a profile file
// that is not there at all.
func TestPlainProfileStillInheritsTopLevelKeys(t *testing.T) {
	codexHome := t.TempDir()
	writeFile(t, filepath.Join(codexHome, "config.toml"), `
model = "top-level-model"
approval_policy = "on-request"
`)
	writeFile(t, filepath.Join(codexHome, "work.config.toml"), `
sandbox_mode = "workspace-write"
`)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex", "--profile", "work"},
			Env:  map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detect(t, src, 100)

	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "top-level-model", got.Inspection.Model.Value, "an unpinned key inherits")
	assert.Equal(t, "workspace-write", settingValue(got.Inspection.Settings, "sandbox_mode"))
	assert.Equal(t, "on-request", settingValue(got.Inspection.Settings, "approval_policy"))
}

// TestNpmShimRequiresTheRealPackagePath is hazard 11.
//
// The shim rule accepted any script named codex or codex.js anywhere below an
// element called @openai, so a path an attacker can write — /tmp/@openai/
// unrelated/bin/codex.js — was attributed to the @openai/codex package. The
// fingerprint named a package that was not there, which is the same overclaim
// the basis vocabulary already fixed for the name matchers.
//
// Red against the pre-fix code: the unrelated script matches and the predicate
// carries fpCodexNpmShim.
func TestNpmShimRequiresTheRealPackagePath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		want   bool
	}{
		{"real npm layout", "/usr/lib/node_modules/@openai/codex/bin/codex.js", true},
		{"real npm layout, extensionless", "/usr/lib/node_modules/@openai/codex/bin/codex", true},
		{"attacker path under a fake scope", "/tmp/@openai/unrelated/bin/codex.js", false},
		{"right scope, wrong package", "/usr/lib/node_modules/@openai/codex-sdk/bin/codex.js", false},
		{"right package, wrong scope", "/usr/lib/node_modules/@openai-mirror/codex/bin/codex.js", false},
		{"scope present but not adjacent", "/tmp/@openai/a/b/codex/bin/codex.js", false},
		{"no bin directory", "/usr/lib/node_modules/@openai/codex/codex.js", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newFixtureSource(
				ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
				ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/bin/node", Comm: "node",
					Argv: []string{"node", tc.script}},
			)
			got := detect(t, src, 100)

			if tc.want {
				require.Equal(t, StatusDetected, got.Status)
				assert.Equal(t, fpCodexNpmShim, got.Match.Fingerprint)
				return
			}
			assert.NotEqual(t, StatusDetected, got.Status,
				"a script path that is not the @openai/codex package must not be attributed to it")
		})
	}
}

// settingValue returns the resolved value for one posture key, or "".
func settingValue(settings []SettingObservation, key string) string {
	for _, s := range settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
