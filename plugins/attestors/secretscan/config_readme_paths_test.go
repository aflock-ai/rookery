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
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// The gitleaks README ships an example config that operators copy. These are
// its allowlist blocks, verbatim from README.md at gitleaks master b58d3f102c
// (the same path texts appear in the README at every v8 tag since v8.5.1).
// gitleaks wrote these path texts, not the operator, and they are unanchored:
// (.*?)(jpg|gif|doc) exempts any path that contains "doc", "gif" or "jpg",
// and go\.mod exempts any path that contains "go.mod".
const readmeGlobalAllowlist = `
[[allowlists]]
description = "global allow list"
commits = [ "commit-A", "commit-B", "commit-C"]
paths = [
  '''gitleaks\.toml''',
  '''(.*?)(jpg|gif|doc)'''
]
# note: (global) regexTarget defaults to check the _Secret_ in the finding.
# Acceptable values for regexTarget are "match" and "line"
regexTarget = "match"
regexes = [
  '''219-09-9999''',
  '''078-05-1120''',
  '''(9[0-9]{2}|666)-\d{2}-\d{4}''',
]
# note: stopwords targets the extracted secret, not the entire regex match
# like 'regexes' does. (stopwords introduced in 8.8.0)
stopwords = [
  '''client''',
  '''endpoint''',
]
`

// readmeRuleAllowlist is the README's first [[rules.allowlists]] block,
// under an operator rule.
const readmeRuleAllowlist = `
[[rules]]
id = "operator-github-pat"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]

    [[rules.allowlists]]
    description = "ignore commit A"
    # When multiple criteria are defined the default condition is "OR".
    # e.g., this can match on |commits| OR |paths| OR |stopwords|.
    condition = "OR"
    commits = [ "commit-A", "commit-B"]
    paths = [
      '''go\.mod''',
      '''go\.sum'''
    ]
    # note: stopwords targets the extracted secret, not the entire regex match
    # like 'regexes' does. (stopwords introduced in 8.8.0)
    stopwords = [
      '''client''',
      '''endpoint''',
    ]
`

// readmeTargetRulesAllowlist is the README's targetRules block (v8.25.0 on),
// pointed at the operator's rule.
const readmeTargetRulesAllowlist = `
[[allowlists]]
targetRules = ["operator-github-pat"]
description = "Our test assets trigger false-positives in a couple rules."
paths = ['''tests/expected/._\.json$''']
`

const operatorPATRule = `
[[rules]]
id = "operator-github-pat"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]
`

// readmeNamedFiles each hold a PAT under a name one README path text matches.
var readmeNamedFiles = map[string]string{
	"src/plain.txt":          "token " + scopePAT + "\n",
	"docs/setup.txt":         "token " + scopePAT + "\n",
	"src/doctor.txt":         "token " + scopePAT + "\n",
	"src/gifted/leak.txt":    "token " + scopePAT + "\n",
	"go.mod.bak/leak.txt":    "token " + scopePAT + "\n",
	"x/go.sum.d/leak.txt":    "token " + scopePAT + "\n",
	"tests/expected/a_.json": "token " + scopePAT + "\n",
}

var allReadmeNamedLocations = func() []string {
	out := make([]string, 0, len(readmeNamedFiles))
	for k := range readmeNamedFiles {
		out = append(out, "file:"+k)
	}
	sort.Strings(out)
	return out
}()

// TestReadmeExampleAllowlistsExemptNothingByName: an operator config that
// pastes the gitleaks README's example allowlists exempted, on the path fix
// before this one, every file whose name contained doc, gif, jpg, go.mod or
// go.sum (measured 3/6 and 4/6 reported, against 6/6 on main, which never
// passed the path). The pinned list now carries every path text from the
// README's toml examples too.
func TestReadmeExampleAllowlistsExemptNothingByName(t *testing.T) {
	for name, body := range map[string]string{
		"PAT rule + README global allowlist": operatorPATRule + readmeGlobalAllowlist,
		"PAT rule + README rule allowlist":   readmeRuleAllowlist,
		"PAT rule + README targetRules":      operatorPATRule + readmeTargetRulesAllowlist,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, readmeNamedFiles)
			require.Equal(t, allReadmeNamedLocations, scanTree(t, dir, WithConfigPath(writeGitleaksConfig(t, body))),
				"%s: a README path text exempted a file by name", name)
		})
	}
}

// TestReadmeGlobalAllowlistUnderUseDefaultExemptsNothingByName: the same
// README global allowlist beside useDefault (measured 3/6 before the fix).
// useDefault extends, so this runs in a process of its own.
func TestReadmeGlobalAllowlistUnderUseDefaultExemptsNothingByName(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	dir := t.TempDir()
	files := map[string]string{}
	for k, v := range readmeNamedFiles {
		if k != "tests/expected/a_.json" {
			files[k] = v
		}
	}
	writeFiles(t, dir, files)
	got := scanTree(t, dir, WithConfigPath(writeGitleaksConfig(t, "[extend]\nuseDefault = true\n"+readmeGlobalAllowlist)))
	for k := range files {
		require.Contains(t, got, "file:"+k, "useDefault + README global allowlist exempted %s by name", k)
	}
}

// TestReadmePathTextsArePinned names the README path texts the scans above
// sample, so dropping one from the generator fails here even when no sampled
// file name would reach it.
func TestReadmePathTextsArePinned(t *testing.T) {
	pinned := map[string]struct{}{}
	for _, p := range gitleaksReleasedPathPatterns {
		pinned[p] = struct{}{}
	}
	for _, p := range []string{
		`gitleaks\.toml`,
		`(.*?)(jpg|gif|doc)`,
		`go\.mod`,
		`go\.sum`,
		`package-lock\.json`,
		`tests/expected/._\.json$`,
		`one-file-path-regex`,
		`path-regex-a`,
		`path-regex-b`,
	} {
		_, ok := pinned[p]
		require.True(t, ok, "README path text %q is not in gitleaksReleasedPathPatterns; rerun plugins/attestors/secretscan/gen_gitleaks_path_patterns.py", p)
	}
}
