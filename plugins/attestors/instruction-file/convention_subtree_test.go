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

package instructionfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanDoesNotPruneInsideDeclaredConventionSubtrees is the regression for
// the walk silently skipping real instructions.
//
// `.cursor/rules` is a declared convention that activates this attestor through
// an exact file_exists stat. Everything under it is Cursor rule content. The
// walk nevertheless applied its two general pruning rules inside that subtree:
// `vendor` is on the ignore list and `.private` is hidden, so both were skipped
// with no record and no warning, and the predicate then reported `status:
// complete` for a workspace whose instructions it had declined to read.
//
// Both files must be digested, and the scan must be complete because nothing
// was refused.
func TestScanDoesNotPruneInsideDeclaredConventionSubtrees(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()

	rules := filepath.Join(workspace, ".cursor", "rules")
	vendored := filepath.Join(rules, "vendor")
	private := filepath.Join(rules, ".private")
	for _, d := range []string{vendored, private} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	want := map[string]string{
		".cursor/rules/top.mdc":           "# top level rule\n",
		".cursor/rules/vendor/rule.mdc":   "# a vendored rule, still a real instruction\n",
		".cursor/rules/.private/rule.mdc": "# a hidden rule, still a real instruction\n",
	}
	for rel, body := range want {
		p := filepath.Join(workspace, filepath.FromSlash(rel))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	files, warnings, err := scan(workspace)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}

	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
		if f.SkipReason != "" {
			t.Errorf("%s: unexpected SkipReason %q", f.Path, f.SkipReason)
		}
		if len(f.Digest) == 0 {
			t.Errorf("%s: no digest recorded", f.Path)
		}
		if f.Convention != "cursor" {
			t.Errorf("%s: convention = %q, want cursor", f.Path, f.Convention)
		}
	}

	for rel := range want {
		if !got[rel] {
			t.Errorf("scan missed %s; declared convention subtrees must be walked in full (found: %v)", rel, keys(got))
		}
	}
}

// TestIgnoredDirsStillPruneOutsideDeclaredSubtrees is the control for the test
// above: lifting the pruning rules INSIDE a declared subtree must not lift them
// everywhere. A CLAUDE.md under a top-level `vendor/` is still out of scope,
// because the pre-gate's glob would not have found it either and the scan must
// agree with the gate that decides whether it runs at all.
func TestIgnoredDirsStillPruneOutsideDeclaredSubtrees(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()

	vendored := filepath.Join(workspace, "vendor")
	if err := os.MkdirAll(vendored, 0o755); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vendored, "CLAUDE.md"), []byte("# vendored\n"), 0o600); err != nil {
		t.Fatalf("write vendor/CLAUDE.md: %v", err)
	}

	files, _, err := scan(workspace)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	for _, f := range files {
		if strings.HasPrefix(f.Path, "vendor/") {
			t.Errorf("scan descended into an ignored top-level directory and recorded %s", f.Path)
		}
	}
}

// TestUnderDeclaredConventionTree pins the prefix boundary. Without the
// trailing separator ".cursor/rulesX" would count as living inside
// ".cursor/rules", which is the same off-by-one matchConvention guards against.
func TestUnderDeclaredConventionTree(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		".cursor/rules":                true,
		".cursor/rules/vendor":         true,
		".cursor/rules/.private/deep":  true,
		".cursor/rulesX":               false,
		".cursor/rulesX/vendor":        false,
		".cursor":                      false,
		"vendor":                       false,
		".github/copilot-instructions": false,
	}

	for rel, want := range cases {
		if got := underDeclaredConventionTree(rel); got != want {
			t.Errorf("underDeclaredConventionTree(%q) = %v, want %v", rel, got, want)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
