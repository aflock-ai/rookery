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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every file an operator's config extends reaches the detector as surely as
// the config itself, so it is held to the same rules: a key gitleaks does not
// read is refused, not dropped, and its [extend] section is checked the same
// way. A dropped "regexes" in an extended "AND" entry leaves a path-only
// exception, which exempts every secret under that path. The chain itself is
// bounded: gitleaks follows two [extend] hops and silently ignores a third, so
// a deeper chain or a cycle is refused rather than truncated.
func TestExtendedConfigsAreCheckedLikeTheMainOne(t *testing.T) {
	files := map[string]string{
		"fixtures/allowed.txt": "key " + e3Allowed + "\n",
		"fixtures/other.txt":   "key " + e3Other + "\n",
		"src/allowed.txt":      "key " + e3Allowed + "\n",
		"src/other.txt":        "key " + e3Other + "\n",
		"src/pat.txt":          "token " + scopePAT + "\n",
	}
	const andFixtures = `
[[allowlists]]
description = "approved fixture value"
condition = "AND"
paths = ['''^fixtures/''']
regexes = ['''ALLOWED''']
`
	const patRule = `
[[rules]]
id = "chain-github-pat"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]
`
	e3Everywhere := []string{"file:fixtures/allowed.txt", "file:fixtures/other.txt", "file:src/allowed.txt", "file:src/other.txt"}

	// chain returns the main config's path for configs[0] extending
	// configs[1] extending configs[2] ..., each an absolute path in a
	// directory of its own. "%q" in a body is the next file's path, and in
	// the last body it is the main config's path, for cycles.
	chain := func(t *testing.T, bodies ...string) string {
		t.Helper()
		paths := make([]string, len(bodies))
		// Not t.TempDir: its path carries the subtest's name, which an
		// error message quoting the path would then match.
		root, err := os.MkdirTemp("", "chain")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(root) })
		for i := range bodies {
			paths[i] = filepath.Join(root, fmt.Sprintf("dir%d", i), fmt.Sprintf("level%d.toml", i))
			require.NoError(t, os.MkdirAll(filepath.Dir(paths[i]), 0o750))
		}
		for i, body := range bodies {
			next := paths[0]
			if i+1 < len(paths) {
				next = paths[i+1]
			}
			if strings.Contains(body, "%q") {
				body = fmt.Sprintf(body, next)
			}
			require.NoError(t, os.WriteFile(paths[i], []byte(body), 0o600))
		}
		return paths[0]
	}
	extendNext := "[extend]\npath = %q\n"

	for name, tc := range map[string]struct {
		bodies  []string
		want    []string // findings when the config loads
		wantErr string   // refusal when it must not
	}{
		// The finding: a misspelled key in an extended AND entry.
		"misspelled regexes key in an extended AND entry": {
			bodies:  []string{extendNext + e3Rule, "[[allowlists]]\ncondition = \"AND\"\npaths = ['''^fixtures/''']\nregexs = ['''ALLOWED''']\n"},
			wantErr: "regexs",
		},
		"unknown top-level key in an extended file": {
			bodies:  []string{extendNext + e3Rule, "[allowlistz]\npaths = ['''^fixtures/''']\n"},
			wantErr: "allowlistz",
		},
		"misspelled key two levels down": {
			bodies:  []string{extendNext + e3Rule, extendNext, "[[allowlists]]\ncondition = \"AND\"\npaths = ['''^fixtures/''']\nregex = ['''ALLOWED''']\n"},
			wantErr: "allowlists.regex",
		},
		"extended file extends by url, which gitleaks never implemented": {
			bodies:  []string{extendNext + e3Rule, "[extend]\nurl = \"https://example.test/base.toml\"\n" + andFixtures},
			wantErr: "[extend].url",
		},
		"extended file disables a rule while extending nothing": {
			bodies:  []string{extendNext + e3Rule, "[extend]\ndisabledRules = [\"e3-probe\"]\n" + andFixtures},
			wantErr: "[extend].disabledRules",
		},
		"extended file names cilock's environment-value check": {
			bodies:  []string{extendNext + e3Rule, "[extend]\nuseDefault = true\ndisabledRules = [\"witness-env-value-PWD\"]\n"},
			wantErr: "--env-allow-sensitive-key",
		},
		"extended file targets rules, which gitleaks drops below the main file": {
			bodies:  []string{extendNext + e3Rule, "[[allowlists]]\ntargetRules = [\"e3-probe\"]\ncondition = \"AND\"\npaths = ['''^fixtures/''']\nregexes = ['''ALLOWED''']\n"},
			wantErr: "has an allowlist with targetRules",
		},
		"extend cycle back to the main config": {
			bodies:  []string{extendNext + e3Rule, extendNext},
			wantErr: "is already in this config's extend chain",
		},
		"chain deeper than gitleaks follows": {
			bodies:  []string{extendNext + e3Rule, extendNext, extendNext, patRule},
			wantErr: "follows at most 2 [extend] levels",
		},
		"extended file at the last level gitleaks follows asks for the default": {
			bodies:  []string{extendNext + e3Rule, extendNext, "[extend]\nuseDefault = true\n"},
			wantErr: "follows at most 2 [extend] levels",
		},
		// Still accepted.
		"valid extended AND allowlist": {
			bodies: []string{extendNext + e3Rule, andFixtures},
			want:   []string{"file:fixtures/other.txt", "file:src/allowed.txt", "file:src/other.txt"},
		},
		"valid two-level chain": {
			bodies: []string{extendNext + e3Rule, extendNext + patRule, andFixtures},
			want:   []string{"file:fixtures/other.txt", "file:src/allowed.txt", "file:src/other.txt", "file:src/pat.txt"},
		},
		"disabledRules drops an extended rule, which is then not required to load": {
			bodies: []string{"[extend]\npath = %q\ndisabledRules = [\"chain-github-pat\"]\n" + e3Rule, patRule},
			want:   e3Everywhere,
		},
		"disabledRules reaches a rule two levels down": {
			bodies: []string{"[extend]\npath = %q\ndisabledRules = [\"chain-github-pat\"]\n" + e3Rule, extendNext, patRule},
			want:   e3Everywhere,
		},
		"extended file that uses useDefault": {
			bodies: []string{extendNext + e3Rule, "[extend]\nuseDefault = true\n" + andFixtures},
			want:   []string{"file:fixtures/other.txt", "file:src/allowed.txt", "file:src/other.txt", "file:src/pat.txt"},
		},
		"control: main file alone": {
			bodies: []string{e3Rule},
			want:   e3Everywhere,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if !inFreshProcess(t) {
				return
			}
			main := chain(t, tc.bodies...)
			if tc.wantErr != "" {
				_, err := New(WithConfigPath(main)).initGitleaksDetector()
				require.Error(t, err, "must be refused, not loaded")
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			dir := t.TempDir()
			writeFiles(t, dir, files)
			require.Equal(t, tc.want, scanTree(t, dir, WithConfigPath(main)))
		})
	}
}

// TestExtendedRulesThatDoNotReachTheDetectorAreRefused: gitleaks counts
// extensions in a process-wide global it never resets, so a later load in the
// same process extends nothing, silently. A config with rules of its own
// then loads without the extended file's rules and scans for less than it
// says; that is refused rather than reported clean.
func TestExtendedRulesThatDoNotReachTheDetectorAreRefused(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	base := writeGitleaksConfig(t, `
[[rules]]
id = "base-github-pat"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]
`)
	op := writeGitleaksConfig(t, fmt.Sprintf("[extend]\npath = %q\n", base)+e3Rule)
	d, err := New(WithConfigPath(op)).initGitleaksDetector()
	require.NoError(t, err, "load 1 extends")
	require.Contains(t, d.Config.Rules, "base-github-pat")
	d, err = New(WithConfigPath(op)).initGitleaksDetector()
	require.NoError(t, err, "load 2 extends")
	require.Contains(t, d.Config.Rules, "base-github-pat")
	_, err = New(WithConfigPath(op)).initGitleaksDetector()
	require.ErrorContains(t, err, "base-github-pat", "load 3 extends nothing and keeps only the main file's rule")
}
