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
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// These tests pin that an operator's gitleaks config means what gitleaks says
// it means. Found by the Pushgate onboarding acceptance run (2026-09-21): a
// path-only [allowlist] entry and an [[allowlists]] entry with
// condition = "AND" both parsed cleanly and exempted nothing, because the
// scanner never told gitleaks which file it was reading. A path exception that
// looks reviewed and does nothing is a false control.

const e3Rule = `
[[rules]]
id = "e3-probe"
description = "acceptance probe"
regex = '''E3PROBE_[A-Z0-9]{20}'''
keywords = ["e3probe_"]
`

var (
	e3Allowed = "E3PROBE_" + "ALLOWEDALLOWED000001"
	e3Other   = "E3PROBE_" + "OTHERSECRET000000002"
)

func writeGitleaksConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gitleaks.toml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func treeScanWithConfig(t *testing.T, files map[string]string, config string) []string {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, files)
	scan := runScanOnly(t, dir, WithScope(string(ScopeTree)), WithScanAttestations(false), WithConfigPath(writeGitleaksConfig(t, config)))
	return findingLocations(scan)
}

func TestConfigAllowlistPathsExemptOnlyThosePaths(t *testing.T) {
	files := map[string]string{
		"fixtures/sample.txt": "key " + e3Allowed + "\n",
		"src/leak.txt":        "key " + e3Allowed + "\n",
	}
	require.Equal(t, []string{"file:fixtures/sample.txt", "file:src/leak.txt"}, treeScanWithConfig(t, files, e3Rule),
		"control: without an allowlist both files are findings")

	require.Equal(t, []string{"file:src/leak.txt"}, treeScanWithConfig(t, files, e3Rule+`
[allowlist]
paths = ['''^fixtures/''']
`), "[allowlist].paths exempts the fixture and nothing else")

	require.Equal(t, []string{"file:src/leak.txt"}, treeScanWithConfig(t, files, e3Rule+`
[[allowlists]]
targetRules = ["e3-probe"]
paths = ['''^fixtures/''']
`), "a rule-targeted [[allowlists]] path entry exempts the same way")
}

func TestConfigAllowlistsAndConditionRequiresEveryCheck(t *testing.T) {
	files := map[string]string{
		"fixtures/both.txt":      "key " + e3Allowed + "\n", // path and regex match: exempt
		"fixtures/path-only.txt": "key " + e3Other + "\n",   // path matches, regex does not
		"src/regex-only.txt":     "key " + e3Allowed + "\n", // regex matches, path does not
	}
	require.Equal(t, []string{"file:fixtures/path-only.txt", "file:src/regex-only.txt"}, treeScanWithConfig(t, files, e3Rule+`
[[allowlists]]
description = "the documented fixture key, in fixtures only"
condition = "AND"
paths = ['''^fixtures/''']
regexes = ['''ALLOWEDALLOWED''']
`))
}

// TestDefaultScanDoesNotInheritGitleaksBuiltinPathSkips: gitleaks' built-in
// config skips node_modules, lockfiles and vendored trees by path. The default
// scan never applied that list, and honouring an operator's paths must not
// start applying it to a scan nobody configured.
func TestDefaultScanDoesNotInheritGitleaksBuiltinPathSkips(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"node_modules/pkg/leak.js": "token " + scopePAT + "\n",
		"package-lock.json":        "token " + scopePAT + "\n",
	})
	scan := runScanOnly(t, dir, WithScope(string(ScopeTree)), WithScanAttestations(false))
	require.Equal(t, []string{"file:node_modules/pkg/leak.js", "file:package-lock.json"}, findingLocations(scan))
}

// TestExtendedDefaultAppliesOnlyTheOperatorsPathExceptions: useDefault merges
// in gitleaks' built-in config, whose exceptions skip any path containing
// "gitleaks.toml", node_modules and lockfiles, and an @octokit README for the
// github-pat rule. The person pushing chooses those names and the operator
// never wrote them, so only the operator's own path exception may exempt a
// file. The built-in stopword still applies: it judges the secret, not the name.
//
// gitleaks counts extensions in a package global it never resets: it stops
// extending on the third load in a process, and after the first one every
// later load in the process skips rule validation and drops targetRules
// allowlists. So this runs in a fresh process (inFreshProcess), which keeps
// the rest of the package correct under -count=N.
func TestExtendedDefaultAppliesOnlyTheOperatorsPathExceptions(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	token := "token " + scopePAT + "\n"
	files := map[string]string{
		"config/gitleaks.toml.example":      token,
		"node_modules/x/leak.js":            token,
		"package-lock.json":                 token,
		"src/@octokit/auth-token/README.md": token,
		"src/leak.txt":                      token,
		"fixtures/sample.txt":               token,
		"src/stopword.txt":                  "token ghp_" + "abcdefghijklmnopqrstuvwxyz" + "0123456789\n",
	}
	require.Equal(t, []string{
		"file:config/gitleaks.toml.example",
		"file:node_modules/x/leak.js",
		"file:package-lock.json",
		"file:src/@octokit/auth-token/README.md",
		"file:src/leak.txt",
	}, treeScanWithConfig(t, files, `
[extend]
useDefault = true

[[allowlists]]
description = "the operator's own exception"
paths = ['''^fixtures/''']
`))
}

// TestInheritedPathExceptionsAreRemovedWithoutWideningTheRest: removing an
// entry's paths must neither leave the compiled path pattern in force nor turn
// an "AND" entry into a broader regex-only one.
func TestInheritedPathExceptionsAreRemovedWithoutWideningTheRest(t *testing.T) {
	re := regexp.MustCompile
	or := &config.Allowlist{Paths: []*regexp.Regexp{re(`node_modules`)}, Regexes: []*regexp.Regexp{re(`^EXAMPLE`)}, StopWords: []string{"placeholder"}}
	pathsOnly := &config.Allowlist{Paths: []*regexp.Regexp{re(`\.lock$`)}}
	and := &config.Allowlist{MatchCondition: config.AllowlistMatchAnd, Paths: []*regexp.Regexp{re(`\.bb$`)}, Regexes: []*regexp.Regexp{re(`LICENSE`)}}
	noPaths := &config.Allowlist{Regexes: []*regexp.Regexp{re(`^true$`)}}
	mixed := &config.Allowlist{Paths: []*regexp.Regexp{re(`node_modules`), re(`^fixtures/`)}}
	ownAnd := &config.Allowlist{MatchCondition: config.AllowlistMatchAnd, Paths: []*regexp.Regexp{re(`^fixtures/`)}, Regexes: []*regexp.Regexp{re(`LICENSE`)}}
	for _, a := range []*config.Allowlist{or, pathsOnly, and, noPaths, mixed, ownAnd} {
		require.NoError(t, a.Validate(), "as Translate leaves them")
	}

	builtin := map[string]struct{}{`node_modules`: {}, `\.lock$`: {}, `\.bb$`: {}}
	var dropped int
	got := withoutBuiltinPaths([]*config.Allowlist{or, pathsOnly, and, noPaths, mixed, ownAnd}, builtin, &dropped)
	require.Equal(t, 4, dropped, "each built-in pattern removed is counted")
	require.Len(t, got, 4, "a paths-only entry and an AND entry whose only path is built-in are dropped whole")
	require.False(t, got[0].PathAllowed("node_modules/x/leak.js"))
	require.True(t, got[0].RegexAllowed("EXAMPLE_KEY"))
	stop, _ := got[0].ContainsStopWord("a placeholder value")
	require.True(t, stop)
	require.Same(t, noPaths, got[1])
	require.False(t, got[2].PathAllowed("node_modules/x/leak.js"), "the built-in path beside the operator's is gone")
	require.True(t, got[2].PathAllowed("fixtures/sample.txt"), "the operator's own path in the same entry stands")
	require.Same(t, ownAnd, got[3], "an AND entry of the operator's own is untouched")
}

// TestUseDefaultThatMergedSomethingElseIsRefused: under useDefault the built-in
// allowlists must be where gitleaks puts them. Anywhere else cilock cannot
// tell which exceptions the operator wrote, so the config is refused. That
// includes gitleaks' third in-process load, which merges nothing.
func TestUseDefaultThatMergedSomethingElseIsRefused(t *testing.T) {
	builtin, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	// What the third load gives a config with one allowlist of its own: that
	// allowlist, in the place the built-in one goes.
	third := config.Config{
		Extend:     config.Extend{UseDefault: true},
		Allowlists: []*config.Allowlist{{Paths: []*regexp.Regexp{regexp.MustCompile(`^fixtures/`)}}},
		Rules:      map[string]config.Rule{},
	}
	require.ErrorContains(t, dropInheritedPathExceptions(&third), "[extend].useDefault")
	third.Extend = config.Extend{Path: "other.toml"}
	require.NoError(t, dropInheritedPathExceptions(&third), "an extended file need not reach the built-in config")
	require.NotEmpty(t, third.Allowlists[0].Paths, "and then the config's own paths stand")
	require.NoError(t, dropInheritedPathExceptions(&config.Config{Extend: config.Extend{Path: "other.toml"}}))

	bare := config.Config{
		Extend:     config.Extend{UseDefault: true},
		Allowlists: builtin.Config.Allowlists,
		Rules:      map[string]config.Rule{"github-pat": {RuleID: "github-pat"}},
	}
	require.ErrorContains(t, dropInheritedPathExceptions(&bare), `rule "github-pat"`)
	require.Same(t, builtin.Config.Allowlists[0], bare.Allowlists[0], "a refused config is left as it was")
	bare.Extend.DisabledRules = []string{"github-pat"}
	require.NoError(t, dropInheritedPathExceptions(&bare), "a disabled rule inherited nothing")
	require.Empty(t, bare.Allowlists[0].Paths)
	require.NotEmpty(t, bare.Allowlists[0].Regexes)
}

// TestConfigPathAllowlistNeverExemptsAttestations: a gitleaks path names a file
// in the repository. A prior attestation is not one, so no path pattern, not
// even one that matches everything, may exempt what it carries.
func TestConfigPathAllowlistNeverExemptsAttestations(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"src/leak.txt": "key " + e3Allowed + "\n"})
	scan := New(WithScope(string(ScopeTree)), WithConfigPath(writeGitleaksConfig(t, e3Rule+`
[allowlist]
paths = ['''.*''']
`)))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{&leakingAttestor{Note: "key " + e3Allowed}, scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.Equal(t, []string{"attestation:leaky"}, findingLocations(scan))
}

// TestConfigRefusesWhatItWouldIgnore: a key the loader does not read, and an
// [extend] section that cannot take effect, fail the run naming the field
// instead of loading a config that silently does less than it says.
func TestConfigRefusesWhatItWouldIgnore(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"unknown allowlist key": {e3Rule + `
[allowlist]
regexes = ['''ALLOWEDALLOWED''']
pathz = ['''^fixtures/''']
`, "allowlist.pathz"},
		"extend by url, which gitleaks never implemented": {`
[extend]
url = "https://example.invalid/gitleaks.toml"
` + e3Rule, "[extend].url"},
		"disabledRules without a config to extend": {`
[extend]
disabledRules = ["generic-api-key"]
` + e3Rule, "disabledRules"},
		"disabledRules naming a cilock env-value rule": {`
[extend]
useDefault = true
disabledRules = ["witness-env-value-PWD"]
`, "--env-allow-sensitive-key"},
	} {
		_, err := New(WithConfigPath(writeGitleaksConfig(t, tc.body))).initGitleaksDetector()
		require.Error(t, err, name)
		require.Contains(t, err.Error(), tc.want, name)
	}
	// Checked directly: loading a config that extends another mutates
	// process-global state inside gitleaks.
	require.NoError(t, checkExtend(config.Extend{UseDefault: true, DisabledRules: []string{"generic-api-key"}}))
}

// TestGitleaksOwnDefaultConfigLoadsStrictly: the strict decode refuses keys
// gitleaks does not read, so the config gitleaks itself ships, which operators
// copy as a starting point, must still load.
func TestGitleaksOwnDefaultConfigLoadsStrictly(t *testing.T) {
	detector, err := New(WithConfigPath(writeGitleaksConfig(t, config.DefaultConfig))).initGitleaksDetector()
	require.NoError(t, err)
	require.NotEmpty(t, detector.Config.Rules)
}
