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

// The fixtures in this file are transcriptions of a real install
// (@google/gemini-cli 0.57.0 via npm, macOS, nvm-managed node):
//
//   $ readlink $(which gemini)
//   ../lib/node_modules/@google/gemini-cli/bundle/gemini.js
//   $ ps -o comm=,args= -p <pid>
//   node  node /Users/<user>/.nvm/versions/node/v22.13.1/bin/gemini -p "say hi"
//
// Executable and comm are node's; the only mention of Gemini is the script
// argument, on disk the npm bin symlink. The settings fixtures use the v2
// shape the same install writes, model documented at `model.name`.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeminiNpmScriptIsMatched covers `node <pkg>/bundle/gemini.js` — the
// script slot naming the package file directly, no symlink involved.
func TestGeminiNpmScriptIsMatched(t *testing.T) {
	const pkgRoot = "/usr/local/lib/node_modules/@google/gemini-cli"
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{
			PID: 80, PPID: 1,
			Executable: "/usr/bin/node",
			Comm:       "node",
			Argv:       []string{"node", pkgRoot + "/bundle/gemini.js"},
		},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, "gemini-cli", got.Provider.Product())
	assert.Equal(t, fpGeminiNpmScript, got.Match.Fingerprint)
}

// TestGeminiNpmBinSymlinkIsMatchedViaResolution covers the measured everyday
// shape: argv carries the npm bin symlink, and only resolving it reaches the
// package. The layout is built for real because the rule under test IS the
// filesystem resolution.
func TestGeminiNpmBinSymlinkIsMatchedViaResolution(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "lib", "node_modules", "@google", "gemini-cli", "bundle", "gemini.js")
	require.NoError(t, os.MkdirAll(filepath.Dir(script), 0o750))
	require.NoError(t, os.WriteFile(script, []byte("#!/usr/bin/env node\n"), 0o600))
	bin := filepath.Join(root, "bin", "gemini")
	require.NoError(t, os.MkdirAll(filepath.Dir(bin), 0o750))
	require.NoError(t, os.Symlink(script, bin))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{
			PID: 80, PPID: 1,
			Executable: "/usr/bin/node",
			Comm:       "node",
			Argv:       []string{"node", bin, "-p", "say hi"},
		},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, "gemini-cli", got.Provider.Product())
	assert.Equal(t, fpGeminiResolvedScript, got.Match.Fingerprint)
}

// TestGeminiBrewSymlinkChainIsMatchedViaResolution: Homebrew's formula is the
// same npm install placed in libexec (`npm install *std_npm_args` then
// `bin.install_symlink libexec.glob("bin/*")`), so the invoked path is a
// TWO-hop chain: bin/gemini -> libexec/bin/gemini -> the package file.
// Resolution must follow the whole chain.
func TestGeminiBrewSymlinkChainIsMatchedViaResolution(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "libexec", "lib", "node_modules", "@google", "gemini-cli", "bundle", "gemini.js")
	require.NoError(t, os.MkdirAll(filepath.Dir(script), 0o750))
	require.NoError(t, os.WriteFile(script, []byte("#!/usr/bin/env node\n"), 0o600))
	npmBin := filepath.Join(root, "libexec", "bin", "gemini")
	require.NoError(t, os.MkdirAll(filepath.Dir(npmBin), 0o750))
	require.NoError(t, os.Symlink(script, npmBin))
	brewBin := filepath.Join(root, "bin", "gemini")
	require.NoError(t, os.MkdirAll(filepath.Dir(brewBin), 0o750))
	require.NoError(t, os.Symlink(npmBin, brewBin))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{
			PID: 80, PPID: 1,
			Executable: "/usr/bin/node",
			Comm:       "node",
			Argv:       []string{"node", brewBin},
		},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, fpGeminiResolvedScript, got.Match.Fingerprint)
}

// TestGeminiNodeScriptRequiresTheRealPackagePath is the codex hazard-11 rule
// applied here: the tail must be exactly @google/gemini-cli/bundle/gemini.js,
// read from the one slot node was told to run, under a node image.
func TestGeminiNodeScriptRequiresTheRealPackagePath(t *testing.T) {
	const pkgScript = "/usr/local/lib/node_modules/@google/gemini-cli/bundle/gemini.js"
	cases := []struct {
		name    string
		process ProcessInfo
	}{
		{"near-miss npm scope", ProcessInfo{
			PID: 80, PPID: 1, Executable: "/usr/bin/node", Comm: "node",
			Argv: []string{"node", "/usr/local/lib/node_modules/@google-mirror/gemini-cli/bundle/gemini.js"},
		}},
		{"near-miss package name", ProcessInfo{
			PID: 80, PPID: 1, Executable: "/usr/bin/node", Comm: "node",
			Argv: []string{"node", "/usr/local/lib/node_modules/@google/gemini-cli-extra/bundle/gemini.js"},
		}},
		{"package path as an argument to an unrelated script", ProcessInfo{
			PID: 80, PPID: 1, Executable: "/usr/bin/node", Comm: "node",
			Argv: []string{"node", "/srv/app.js", pkgScript},
		}},
		{"option-led argv is unreadable, so it is a miss", ProcessInfo{
			PID: 80, PPID: 1, Executable: "/usr/bin/node", Comm: "node",
			Argv: []string{"node", "-r", pkgScript},
		}},
		{"non-node image with the package path in the script slot", ProcessInfo{
			PID: 80, PPID: 1, Executable: "/usr/bin/python3", Comm: "python3",
			Argv: []string{"python3", pkgScript},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := newFixtureSource(
				ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
				tc.process,
			)
			got := detect(t, src, 100)
			assert.NotEqual(t, StatusDetected, got.Status, "must not be attributed to gemini-cli")
		})
	}
}

// TestGeminiSettingsV2NestedModelIsRead: the documented current shape,
// `{"model": {"name": ...}}`, decides the model the same way the flat v1
// string always has.
func TestGeminiSettingsV2NestedModelIsRead(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".gemini", "settings.json"),
		map[string]any{"model": map[string]any{"name": "gemini-2.5-pro"}})

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

// TestGeminiSettingsModelGroupWithoutNameClaimsNothing: a v2 model group that
// sets other knobs but no name must not be read as a model — the group is an
// object, so the legacy flat-string read must not fire on it either.
func TestGeminiSettingsModelGroupWithoutNameClaimsNothing(t *testing.T) {
	home := t.TempDir()
	withHomeDir(t, home)
	writeJSON(t, filepath.Join(home, ".gemini", "settings.json"),
		map[string]any{"model": map[string]any{"maxSessionTurns": 10}})

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/gemini", Comm: "gemini", Argv: []string{"gemini"}},
	)
	got := detect(t, src, 100)
	require.Equal(t, StatusDetected, got.Status)

	assert.Nil(t, got.Inspection.Model)
}
