// jade:ring local

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

package secretscan

import (
	"crypto"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
)

// These tests pin the routes the second review of the path-exception fix
// found (2026-09-21). A pusher chooses every file name, so gitleaks' built-in
// path exceptions (node_modules, lockfiles, "gitleaks.toml", vendored trees)
// must not exempt a file however they reach the config: a copy of the
// built-in config, an [extend].path to a vendored copy, or a relative
// [extend].path that gitleaks would resolve inside the pushed repository.

// builtinNamedFiles each hold one GitHub token under a name one of gitleaks'
// built-in path exceptions matches, plus a control under src/ that none does.
var builtinNamedFiles = map[string]string{
	"node_modules/x/leak.js":       "token " + scopePAT + "\n",
	"package-lock.json":            "token " + scopePAT + "\n",
	"config/gitleaks.toml.example": "token " + scopePAT + "\n",
	"docs/diagram.svg":             "token " + scopePAT + "\n",
	"go.sum":                       "token " + scopePAT + "\n",
	"vendor/modules.txt":           "token " + scopePAT + "\n",
	"foo-1.0.dist-info/METADATA":   "token " + scopePAT + "\n",
	"src/leak.txt":                 "token " + scopePAT + "\n",
}

var allBuiltinNamedLocations = []string{
	"file:config/gitleaks.toml.example",
	"file:docs/diagram.svg",
	"file:foo-1.0.dist-info/METADATA",
	"file:go.sum",
	"file:node_modules/x/leak.js",
	"file:package-lock.json",
	"file:src/leak.txt",
	"file:vendor/modules.txt",
}

// builtinWithOperatorPath is gitleaks' built-in config as an operator vendors
// it, with one path exception of the operator's own written into the same
// global entry as the built-in ones.
func builtinWithOperatorPath(t *testing.T) string {
	t.Helper()
	const anchor = "paths = [\n    '''gitleaks\\.toml''',"
	out := strings.Replace(config.DefaultConfig, anchor, "paths = [\n    '''^fixtures/''',\n    '''gitleaks\\.toml''',", 1)
	require.NotEqual(t, config.DefaultConfig, out, "the built-in config no longer has the anchor this test edits")
	return out
}

// scanTree scans dir with the given options and fails the test if the
// attestor refused, so a refused config never reads as zero findings.
func scanTree(t *testing.T, dir string, opts ...Option) []string {
	t.Helper()
	scan := New(append([]Option{WithScope(string(ScopeTree)), WithScanAttestations(false)}, opts...)...)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	for _, c := range ctx.CompletedAttestors() {
		require.NoError(t, c.Error, "attestor %s", c.Attestor.Name())
	}
	return findingLocations(scan)
}

// freshProcessEnv names the test a re-executed test binary should run.
const freshProcessEnv = "SECRETSCAN_FRESH_PROCESS_TEST"

// inFreshProcess reports whether the caller is running in a process of its
// own. gitleaks counts extensions in a package global it never resets
// (config.go extendDepth) and stops extending on the third load in a
// process, so every test that loads a config which extends another runs in
// a fresh copy of the test binary. The parent requires the child to have run
// and passed this very test, so a filter that matched nothing cannot pass.
func inFreshProcess(t *testing.T) bool {
	t.Helper()
	if os.Getenv(freshProcessEnv) == t.Name() {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v") //nolint:gosec // G204: re-executes this test binary
	cmd.Env = append(os.Environ(), freshProcessEnv+"="+t.Name())
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "fresh-process run of %s:\n%s", t.Name(), out)
	require.Contains(t, string(out), "--- PASS: "+t.Name(), "the fresh process did not run the test:\n%s", out)
	return false
}

// TestCopiedBuiltinConfigAppliesNoBuiltinPathException: operators copy
// gitleaks' built-in config as a starting point, with no [extend] at all. The
// copy's path exceptions are the built-in ones verbatim, so they exempt
// nothing; the operator's own path in the same entry still does.
func TestCopiedBuiltinConfigAppliesNoBuiltinPathException(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, builtinNamedFiles)
	require.Equal(t, allBuiltinNamedLocations, scanTree(t, dir, WithConfigPath(writeGitleaksConfig(t, config.DefaultConfig))),
		"an exact copy of the built-in config")

	writeFiles(t, dir, map[string]string{"fixtures/sample.txt": "token " + scopePAT + "\n"})
	require.Equal(t, allBuiltinNamedLocations, scanTree(t, dir, WithConfigPath(writeGitleaksConfig(t, builtinWithOperatorPath(t)))),
		"a vendored copy with the operator's ^fixtures/ beside the built-in paths: only the fixture is exempt")
}

// TestExtendPathToVendoredBuiltinConfig: the same vendored copy reached
// through [extend].path. Inherited or copied, a built-in path pattern is the
// same text and exempts nothing.
func TestExtendPathToVendoredBuiltinConfig(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	dir := t.TempDir()
	writeFiles(t, dir, builtinNamedFiles)
	writeFiles(t, dir, map[string]string{"fixtures/sample.txt": "token " + scopePAT + "\n"})
	base := writeGitleaksConfig(t, builtinWithOperatorPath(t))
	require.Equal(t, allBuiltinNamedLocations, scanTree(t, dir, WithConfigPath(writeGitleaksConfig(t, fmt.Sprintf("[extend]\npath = %q\n", base)))))
}

// TestRelativeExtendPathResolvesBesideTheConfig: gitleaks resolves a relative
// [extend].path against the process's working directory, which for a cilock
// run is the pushed repository. There the pusher can add base.toml with
// a path exception of .* and exempt every file. cilock resolves it against the
// directory of the config that names it instead.
func TestRelativeExtendPathResolvesBesideTheConfig(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{
		"src/leak.txt": "token " + scopePAT + "\n",
		"base.toml":    "[allowlist]\ndescription = \"pusher-written\"\npaths = ['''.*''']\n",
	})
	t.Chdir(repo)

	operatorDir := t.TempDir()
	operator := filepath.Join(operatorDir, "gitleaks.toml")
	require.NoError(t, os.WriteFile(operator, []byte(`[extend]
path = "base.toml"

[[rules]]
id = "operator-github-pat"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]
`), 0o600))

	_, err := New(WithConfigPath(operator)).initGitleaksDetector()
	require.Error(t, err, "no base.toml beside the operator's config: refused, never read from the repository")

	require.NoError(t, os.WriteFile(filepath.Join(operatorDir, "base.toml"), []byte(e3Rule), 0o600))
	require.Equal(t, []string{"file:src/leak.txt"}, scanTree(t, repo, WithConfigPath(operator)),
		"the operator's base.toml is the one extended; the pusher's .* exempts nothing")
}

// TestNestedRelativeExtendPathIsRefused: the file an operator's config
// extends may itself extend another. gitleaks resolves that one against the
// working directory too and cilock does not get to rewrite it, so a relative
// path there is refused.
func TestNestedRelativeExtendPathIsRefused(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{"base.toml": "[allowlist]\ndescription = \"pusher-written\"\npaths = ['''.*''']\n"})
	t.Chdir(repo)
	middle := writeGitleaksConfig(t, "[extend]\npath = \"base.toml\"\n"+e3Rule)
	_, err := New(WithConfigPath(writeGitleaksConfig(t, fmt.Sprintf("[extend]\npath = %q\n", middle)))).initGitleaksDetector()
	require.ErrorContains(t, err, "relative")
}

// TestNonTOMLExtendedFileIsRefused: gitleaks reads an extended file with
// viper by its extension, so a YAML base.yaml loads there even though cilock
// cannot read it as TOML to check its own extend.path. Skipping the check
// instead of refusing reopens the relative-path route: the YAML file extends
// rel.toml, gitleaks resolves it in the pushed repository, and the pusher's
// .* exempts every file.
func TestNonTOMLExtendedFileIsRefused(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{
		"src/leak.txt": "token " + scopePAT + "\n",
		"rel.toml":     "[allowlist]\ndescription = \"pusher-written\"\npaths = ['''.*''']\n",
	})
	t.Chdir(repo)
	yml := filepath.Join(t.TempDir(), "base.yaml")
	require.NoError(t, os.WriteFile(yml, []byte("extend:\n  path: rel.toml\nrules:\n  - id: yaml-pat\n    regex: 'ghp_[0-9a-zA-Z]{36}'\n    keywords: ['ghp_']\n"), 0o600))
	_, err := New(WithConfigPath(writeGitleaksConfig(t, fmt.Sprintf("[extend]\npath = %q\n", yml)+e3Rule))).initGitleaksDetector()
	require.ErrorContains(t, err, "is not a TOML gitleaks config")
}

// TestConfigThatLoadsNoRulesIsRefused: a config with no rules scans for
// nothing and reports a clean run. It is refused, not warned about.
func TestConfigThatLoadsNoRulesIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"empty file":     "",
		"title only":     "title = \"ours\"\n",
		"allowlist only": "[allowlist]\nregexes = ['''x''']\n",
	} {
		_, err := New(WithConfigPath(writeGitleaksConfig(t, body))).initGitleaksDetector()
		require.ErrorContains(t, err, "no rules", name)
	}
	_, err := New(WithConfigPath(writeGitleaksConfig(t, e3Rule))).initGitleaksDetector()
	require.NoError(t, err, "control: one rule loads")
}

// TestThirdExtendPathLoadInOneProcessIsRefused: gitleaks merges nothing on
// the third extending load in a process. A config whose rules all come from
// the extended file then loads zero rules, and that is refused.
func TestThirdExtendPathLoadInOneProcessIsRefused(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	op := writeGitleaksConfig(t, fmt.Sprintf("[extend]\npath = %q\n", writeGitleaksConfig(t, e3Rule)))
	for load := 1; load <= 2; load++ {
		d, err := New(WithConfigPath(op)).initGitleaksDetector()
		require.NoError(t, err, "load %d", load)
		require.Len(t, d.Config.Rules, 1, "load %d", load)
	}
	_, err := New(WithConfigPath(op)).initGitleaksDetector()
	require.ErrorContains(t, err, "no rules", "load 3")
}
