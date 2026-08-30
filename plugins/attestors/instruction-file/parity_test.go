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

	"github.com/aflock-ai/rookery/attestation/detection"
)

// ---------------------------------------------------------------------------
// The detector and the scanner must agree about what this attestor covers.
// ---------------------------------------------------------------------------
//
// Two independent mechanisms decide whether a file becomes evidence:
//
//   - detector.yaml's pre-gate decides whether the attestor RUNS.
//   - the conventions table plus the walk decide what the run RECOGNIZES.
//
// Every earlier round of findings here was a disagreement between those two,
// and asserting the specific pair that was reported is what let the next pair
// through. `.aider.conf.yml` was missing from the gate; fixed. Nested basenames
// were unreachable by the gate; fixed. Then `.cursor/rules` turned out to be a
// DIRECTORY that the gate stats successfully and the walk can never hand to
// inspectFile, and hidden directories turned out to be walked by the scan but
// skipped by the gate's glob. Four instances of one class.
//
// So this sweep does not assert coverage. It asserts AGREEMENT — for every
// convention in the table, in every placement that convention admits, the gate
// fires if and only if the scan finds something. Both-yes passes. Both-no
// passes, and is the honest way to express a documented scope boundary such as
// hidden directories. Only a disagreement fails, because a disagreement is the
// defect: activation without evidence produces a `complete` predicate with no
// subjects, and evidence without activation produces no predicate at all.
//
// Ranging over the table means a convention added later is covered on the day
// it lands, in every placement, without anyone remembering to add a case.

// placement is one location a convention's file can occupy.
type placement struct {
	label string
	rel   string
}

// placementsFor enumerates where a convention can legitimately appear.
//
// Base-name conventions get three, and the third is deliberate: a hidden
// directory is the placement where the two mechanisms most recently disagreed,
// so it must stay in the sweep even though both are now expected to skip it.
// A future change that taught the scan to walk hidden directories without
// teaching the gate to glob them would re-open the gap silently, and this is
// the case that catches it.
func placementsFor(c convention) []placement {
	switch c.Match {
	case MatchBasename:
		return []placement{
			{label: "root", rel: c.Pattern},
			{label: "nested", rel: "services/api/" + c.Pattern},
			{label: "hidden-dir", rel: ".hidden/" + c.Pattern},
		}
	case MatchRelPath:
		return []placement{
			{label: "declared-path-as-file", rel: c.Pattern},
			// The DIRECTORY shape. The pre-gate's file_exists is a stat and a
			// stat succeeds on a directory, so this placement activates the
			// attestor for every relpath convention whether or not anyone
			// intended it to. If matching does not follow, the run emits a
			// complete predicate with no subjects.
			{label: "declared-path-as-directory", rel: c.Pattern + "/rule.mdc"},
		}
	}
	return nil
}

// TestSweep_DetectorAndScannerAgreeOnEveryConventionPlacement is the parity
// invariant.
func TestSweep_DetectorAndScannerAgreeOnEveryConventionPlacement(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	for _, c := range conventions {
		for _, p := range placementsFor(c) {
			name := strings.ReplaceAll(c.Pattern, "/", "_") + "/" + p.label
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				full := filepath.Join(root, filepath.FromSlash(p.rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(full, []byte("instructions\n"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}

				detectorFires := preGateFires(t, reg, root)

				files, _, err := scan(root)
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				scannerFinds := len(files) > 0

				if detectorFires != scannerFinds {
					switch {
					case detectorFires:
						t.Errorf("DISAGREEMENT for %q at %s: the pre-gate activates the attestor but the scan recognizes nothing there. The run produces a predicate with status complete and no subjects — a signed statement that the workspace was examined and held no instruction files, while this one sat in it", p.rel, p.label)
					default:
						t.Errorf("DISAGREEMENT for %q at %s: the scan recognizes this file but the pre-gate never activates the attestor, so no predicate is produced at all. The same file becomes evidence or does not depending on whether something ELSE in the tree happened to trip the gate", p.rel, p.label)
					}
				}
			})
		}
	}
}

// preGateFires runs the real pre-plan against a real workspace and reports
// whether this attestor was selected.
//
// It drives detection.RunPrePlanWith rather than inspecting the parsed YAML,
// so a trigger that is present but malformed, misspelled or shadowed reads as
// "does not fire" exactly as a missing one does. A string comparison against
// the YAML would call all three of those a pass.
func preGateFires(t *testing.T, reg *detection.Registry, cwd string) bool {
	t.Helper()
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"echo", "hi"},
		Cwd:  cwd,
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			return true
		}
	}
	return false
}

// TestSweep_EveryDeclaredPathMatchesFilesBeneathItWhenItIsADirectory asserts
// the POSITIVE, which the parity sweep alone cannot.
//
// Parity is an equivalence, so both-mechanisms-miss counts as agreement. For
// the directory shape that would be agreement on the wrong answer: the
// pre-gate's stat activates the attestor either way, and a run that activates
// and recognizes nothing emits `complete` with no subjects. Cursor's current
// layout is a directory holding live instructions, so "consistently ignore it"
// is not an acceptable resolution.
//
// The quantifier ranges over every MatchRelPath convention rather than the one
// vendor that exposed the bug, so a declared path that grows a directory form
// later is covered without anyone noticing it needs to be.
func TestSweep_EveryDeclaredPathMatchesFilesBeneathItWhenItIsADirectory(t *testing.T) {
	exercised := 0
	for _, c := range conventions {
		if c.Match != MatchRelPath {
			continue
		}
		exercised++
		t.Run(strings.ReplaceAll(c.Pattern, "/", "_"), func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, filepath.FromSlash(c.Pattern))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			for _, n := range []string{"style.mdc", "testing.mdc"} {
				if err := os.WriteFile(filepath.Join(dir, n), []byte("rule "+n+"\n"), 0o600); err != nil {
					t.Fatalf("write %s: %v", n, err)
				}
			}

			files, _, err := scan(root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(files) != 2 {
				t.Fatalf("scan found %d files beneath %q, want 2; a convention declared as a directory must digest what is inside it, or activation produces an empty predicate", len(files), c.Pattern)
			}
			for _, f := range files {
				if f.Convention != c.Convention {
					t.Errorf("file %q reported convention %q, want %q", f.Path, f.Convention, c.Convention)
				}
				if len(f.Digest) == 0 {
					t.Errorf("file %q beneath a declared directory was not digested: %s", f.Path, f.SkipReason)
				}
			}
		})
	}

	// A universal quantifier over an empty set passes without testing anything.
	// Removing the last MatchRelPath convention would do exactly that, and the
	// parity sweep would not notice either — with no declared path there is no
	// directory placement to disagree about.
	if exercised == 0 {
		t.Fatal("no MatchRelPath convention is declared, so this sweep tested nothing")
	}
}
