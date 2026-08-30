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
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

// ---------------------------------------------------------------------------
// Detection parity: the detector must ACTIVATE for everything the scan can see.
// ---------------------------------------------------------------------------
//
// The scan side of this parity is already swept by
// TestSweep_EveryConventionIsDiscovered: build a tree containing every declared
// convention, assert the walk finds each one. That sweep is necessary and not
// sufficient, because it starts AFTER the attestor has been asked to run.
//
// detector.yaml decides whether the attestor runs at all. When its pre-gate
// misses a convention the scan would have digested, the attestor never fires,
// the predicate is never produced, and the result is not an error — it is a
// clean run with no evidence in it. That is the worse of the two failures: an
// omission that reports as success stops anyone looking. So the two tables must
// agree in BOTH directions, and this file is the direction that was missing.

// TestSweep_EveryConventionActivatesTheDetector ranges over the COMPLETE
// conventions table — the same authoritative allowlist the scan is derived
// from — and asserts each entry actually fires the shipped detector.yaml
// pre-gate against a real workspace.
//
// It is deliberately not a string search over the YAML. It registers the
// embedded detector with the real registry and runs the real pre-plan against a
// real temp directory, so a trigger that is present but malformed, misspelled
// or shadowed fails here exactly as a missing one does.
//
// Because the quantifier ranges over `conventions` rather than over a list
// written out in this file, a convention added later fails this test on the day
// it is added, until detector.yaml grows a trigger for it. That is the property
// that matters: the previous round's gap (.aider.conf.yml and .cursor/rules
// declared in the table, absent from the detector) was reachable precisely
// because no test derived its cases from the table.
func TestSweep_EveryConventionActivatesTheDetector(t *testing.T) {
	for _, c := range conventions {
		t.Run(subtestName(c.Pattern), func(t *testing.T) {
			detectiontest.AssertPreGateFiresOnFile(t, Name, detectorYAML, c.Pattern)
		})
	}
}

// TestSweep_EveryBasenameConventionActivatesTheDetectorWhenNested closes the
// root-vs-nested asymmetry as its own sweep.
//
// A basename convention matches anywhere in the tree on the scan side —
// matchConvention compares against the base name, and scopeFor exists solely to
// promote such a match found below the root to directory scope. Nested
// instruction files are therefore a DESIGNED case, not an accident. A pre-gate
// that only stats the workspace root disagrees with that design, and the
// disagreement is silent: a repository whose only CLAUDE.md sits in a
// subdirectory produces no predicate at all.
//
// The quantifier again ranges over the table, restricted to the basename match
// kind, so a basename convention added later must satisfy both placements.
func TestSweep_EveryBasenameConventionActivatesTheDetectorWhenNested(t *testing.T) {
	for _, c := range conventions {
		if c.Match != MatchBasename {
			continue
		}
		t.Run(subtestName(c.Pattern), func(t *testing.T) {
			detectiontest.AssertPreGateFiresOnFile(t, Name, detectorYAML, "services/api/"+c.Pattern)
		})
	}
}

// TestSweep_EveryDetectorTriggerNamesADeclaredConvention is the reverse
// direction, and it is the half that keeps the parity honest.
//
// Without it the previous sweeps have a trivial passing strategy: widen
// detector.yaml until it fires on anything. A trigger that activates the
// attestor for a file the scan does not recognize is its own defect — it costs
// a run and produces a predicate with an empty files list, which reads as
// "looked, found nothing" rather than "was never asked".
//
// Every path named by a file_exists trigger, and every literal glob stem named
// by a file_glob trigger, must therefore resolve to an entry in the conventions
// table.
func TestSweep_EveryDetectorTriggerNamesADeclaredConvention(t *testing.T) {
	parsed, err := detection.ParseDetectorYAML(detectorYAML)
	if err != nil {
		t.Fatalf("parse detector.yaml: %v", err)
	}
	if parsed.Pre == nil || parsed.Pre.Match == nil {
		t.Fatal("detector.yaml declares no pre-gate match block; the attestor would never activate")
	}

	triggers := collectFileTriggers(parsed.Pre.Match)
	if len(triggers) == 0 {
		t.Fatal("detector.yaml pre-gate names no file triggers")
	}

	for _, trg := range triggers {
		if !isDeclaredConvention(trg) {
			t.Errorf("detector trigger %q names no entry in the conventions table; the attestor would activate for a file the scan does not recognize, producing an empty predicate that reads as a clean result", trg)
		}
	}
}

// collectFileTriggers flattens the pre-gate tree into the set of workspace
// paths its file predicates key on. Glob patterns are reduced to the literal
// base name they end in, which is the form the conventions table declares.
func collectFileTriggers(m *detection.Predicate) []string {
	if m == nil {
		return nil
	}
	out := []string{}
	if m.FileExists != "" {
		out = append(out, m.FileExists)
	}
	for _, g := range m.FileGlob {
		out = append(out, strings.TrimPrefix(g, "**/"))
	}
	for i := range m.AnyOf {
		out = append(out, collectFileTriggers(&m.AnyOf[i])...)
	}
	for i := range m.AllOf {
		out = append(out, collectFileTriggers(&m.AllOf[i])...)
	}
	return out
}

// isDeclaredConvention reports whether a trigger path corresponds to a declared
// convention: either an exact relative-path entry or a base-name entry.
func isDeclaredConvention(trigger string) bool {
	for _, c := range conventions {
		if c.Pattern == trigger {
			return true
		}
	}
	return false
}

// subtestName renders a convention pattern as a flat subtest name. Patterns
// contain slashes (".github/copilot-instructions.md"), and an unescaped slash
// would split one subtest into a nested hierarchy that -run cannot address as a
// unit.
func subtestName(pattern string) string {
	return strings.ReplaceAll(pattern, "/", "_")
}
