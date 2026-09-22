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
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// gitleaksRepoNamedFiles each hold a PAT under a name one path text of
// gitleaks' own repo-root .gitleaks.toml matches, plus a control that none
// does. .*test\.go is unanchored, so it matches latest.go as well as
// deploy_test.go, and testdata matches any path containing the word.
var gitleaksRepoNamedFiles = map[string]string{
	"src/plain.txt":                     "token " + scopePAT + "\n",
	"testdata/leak.txt":                 "token " + scopePAT + "\n",
	"a/mytestdata2/leak.txt":            "token " + scopePAT + "\n",
	"pkg/deploy_test.go":                "token " + scopePAT + "\n",
	"pkg/latest.go":                     "token " + scopePAT + "\n",
	"cmd/generate/config/rules/k.txt":   "token " + scopePAT + "\n",
	"x/cmd/generate/config/rules/k.txt": "token " + scopePAT + "\n",
}

// TestGitleaksRepoConfigCopyExemptsNothingByName: gitleaks ships a third
// config beside config/gitleaks.toml and the README examples, its own
// repo-root .gitleaks.toml (every tag from v8.21.2, and master). It is named
// the way operators name theirs and is a useDefault template, so operators
// copy it. testdata holds it verbatim (git show b58d3f102c:.gitleaks.toml).
// Its path texts are gitleaks', not the operator's, and all three are
// unanchored: with it as the config, the README fix before this one reported
// 1 of 6 named files (only src/plain.txt), against 6 of 6 on main, which never
// passed the path. useDefault extends, so this runs in a process of its own.
func TestGitleaksRepoConfigCopyExemptsNothingByName(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	body, err := os.ReadFile(filepath.Join("testdata", "gitleaks-repo", "dot-gitleaks-b58d3f102c.toml"))
	require.NoError(t, err)
	dir := t.TempDir()
	writeFiles(t, dir, gitleaksRepoNamedFiles)
	got := map[string]bool{}
	for _, loc := range scanTree(t, dir, WithConfigPath(writeGitleaksConfig(t, string(body)))) {
		got[loc] = true
	}
	var exempted []string
	for k := range gitleaksRepoNamedFiles {
		if !got["file:"+k] {
			exempted = append(exempted, k)
		}
	}
	sort.Strings(exempted)
	require.Empty(t, exempted, "a verbatim copy of gitleaks' own .gitleaks.toml exempted these files by name")
}

// TestGitleaksRepoTomlPathTextsArePinned names every path text that a .toml
// file in the gitleaks tree carries outside config/gitleaks.toml and the
// README: the repo-root .gitleaks.toml, and the test and example configs
// under testdata/, test_data/ and examples/, at every v8 tag and every master
// commit that touched one. They are gitleaks-written configs in the same
// repository, one allowlist form per file, so they are copied the same way,
// and a pinned text that no operator copied only drops an exception: it fails
// closed. Dropping one from the generator fails here even when no file name
// in the scan above would reach it.
func TestGitleaksRepoTomlPathTextsArePinned(t *testing.T) {
	pinned := map[string]struct{}{}
	for _, p := range gitleaksReleasedPathPatterns {
		pinned[p] = struct{}{}
	}
	for _, p := range []string{
		// .gitleaks.toml
		`(^|/)cmd/generate/config/rules`,
		`.*test\.go`,
		`testdata`,
		// testdata/config/ at v8 tags
		`.go`,
		`\.env\.prod$`,
		`^.*\.(xml|log|json)$`,
		`^node_modules/.*`,
		`^path/to/your/problematic/file\.js$`,
		`ignore\.xaml`,
		`something.py`,
		// test_data/ and examples/ at master commits before v8
		`(.*)?ssh`,
		`.docx`,
		`.git`,
		`.py`,
		`.zip`,
		`config(uration)?`,
	} {
		_, ok := pinned[p]
		require.True(t, ok, "gitleaks repo .toml path text %q is not in gitleaksReleasedPathPatterns; rerun plugins/attestors/secretscan/gen_gitleaks_path_patterns.py", p)
	}
}
