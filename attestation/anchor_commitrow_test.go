// jade:ring local
// Copyright 2026 The Aflock Authors
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

package attestation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// D15-3 (docs/design/attestation-anchors.md 3.7, row D15-b), the registry
// half: the git commithash: row, commithash: off the prefix denylist, the
// rule that only the hardened git type may register it, A15's one named
// exception (an anchor row of role about, for git-commit only), and the
// git-commit-object measurement.

func commitRow() map[string]any {
	return map[string]any{
		"attestor":       hardenedGitType,
		"prefix":         "commithash:",
		"class":          "anchor",
		"kind":           "git-commit",
		"role":           "about",
		"basis":          "measured",
		"algorithm":      "sha1",
		"signed_path":    "$.commithash",
		"normalization":  "bare-hex",
		"gate":           "the exact hardened git type and $.commithashverified == true",
		"measurement":    "git-commit-object",
		"recompute_from": "predicate",
		"evidence":       "plugins/attestors/git/git.go:261-288",
		"since":          "4.5.0",
	}
}

func TestParseAnchorRegistry_AcceptsTheCommitRow(t *testing.T) {
	sha256Repo := commitRow()
	sha256Repo["algorithm"] = "sha256"
	for _, r := range []map[string]any{commitRow(), sha256Repo} {
		rows, err := parseAnchorRegistry(encodeRegistry(t, r))
		require.NoError(t, err)
		require.Len(t, rows, 1)
	}
}

func TestParseAnchorRegistry_RefusesCommitRowVariants(t *testing.T) {
	cases := map[string]func(r map[string]any){
		"legacy git type":                                   func(r map[string]any) { r["attestor"] = "https://witness.dev/attestations/git/v0.1" },
		"another attestor":                                  func(r map[string]any) { r["attestor"] = "https://aflock.ai/attestations/github/v0.1" },
		"parenthash as a git-commit anchor":                 func(r map[string]any) { r["prefix"] = "parenthash:" },
		"another prefix of kind git-commit":                 func(r map[string]any) { r["prefix"] = "headcommit:" },
		"role produced: a step does not produce its commit": func(r map[string]any) { r["role"] = "produced" },
		"git-commit acceptor":                               func(r map[string]any) { r["class"] = "acceptor" },
		"sha512":                                            func(r map[string]any) { r["algorithm"] = "sha512" },
		"commithash as an image kind":                       func(r map[string]any) { r["kind"] = "image-config" },
		"observed commit":                                   func(r map[string]any) { r["basis"] = "observed"; delete(r, "measurement") },
		"another measurement":                               func(r map[string]any) { r["measurement"] = "oci-config-blob" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := commitRow()
			mutate(r)
			_, err := parseAnchorRegistry(encodeRegistry(t, r))
			require.Error(t, err)
		})
	}
}

// git-commit-object frames the commit content as git hashes it; the check
// hashes the frame with the identity's algorithm.
func TestMeasureGitCommitObject(t *testing.T) {
	content := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\nempty\n")
	p := filepath.Join(t.TempDir(), "commit")
	require.NoError(t, os.WriteFile(p, content, 0o600))

	m, ok := LookupMeasurement(MeasurementGitCommitObject)
	require.True(t, ok)
	got, err := m(p)
	require.NoError(t, err)
	assert.Equal(t, append([]byte("commit 140\x00"), content...), got)

	empty := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	_, err = m(empty)
	require.Error(t, err, "an empty file is no commit object")
	_, err = m(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}
