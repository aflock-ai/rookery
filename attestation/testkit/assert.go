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

package testkit

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// updateGolden is the -catalog.update flag; when set, AssertContract rewrites
// golden predicate files instead of comparing. Namespaced to avoid colliding
// with other packages' -update flags in the same test binary.
var updateGolden = flag.Bool("catalog.update", false, "rewrite golden predicate fixtures instead of comparing")

// Update reports whether goldens should be rewritten this run.
func Update() bool { return *updateGolden }

// AssertContract proves every claim the fixture's expect block makes against
// the run Result. One call replaces the ~10 hand-rolled assertions in the
// validate tests. Each failed claim is a t.Errorf (not Fatalf) so a single run
// surfaces all violations.
func (r *Result) AssertContract(t *testing.T, fx *Fixture) {
	t.Helper()

	// Negative fixture: assert the no-evidence exit behavior, then stop.
	if fx.Expect.Exit != nil {
		assertExit(t, fx, r)
		return
	}

	if r.RunErr != nil {
		t.Fatalf("attestor %q failed on fixture %q: %v", fx.Attestor, fx.Name, r.RunErr)
	}

	// Predicate type.
	if r.PredType != fx.Expect.PredicateType {
		t.Errorf("predicate type = %q, want %q", r.PredType, fx.Expect.PredicateType)
	}

	// RunType.
	if fx.Expect.RunType != "" {
		if got := string(r.Attestor.RunType()); got != fx.Expect.RunType {
			t.Errorf("run type = %q, want %q", got, fx.Expect.RunType)
		}
	}

	// Subjects — subject keys are content-derived (deterministic), so exact or
	// prefix matching is reliable.
	for _, want := range fx.Expect.Subjects.Keys {
		if !subjectPresent(r.Subjects, want, fx.Expect.Subjects.Match) {
			t.Errorf("subject %q (%s) not found; have: %v", want, fx.Expect.Subjects.Match, keysOf(r.Subjects))
		}
	}

	// Materials / Products — keys are file PATHS (non-deterministic temp dirs),
	// so assert PRESENCE (the EmitsMaterials/EmitsProducts contract), not exact
	// keys. The golden (if present) catches exact predicate content.
	if len(fx.Expect.Materials) > 0 && len(r.Materials) == 0 {
		t.Errorf("expected materials, attestor emitted none")
	}
	if len(fx.Expect.Products) > 0 && len(r.Products) == 0 {
		t.Errorf("expected products, attestor emitted none")
	}

	// Schema must be present AND the produced predicate must VALIDATE against
	// it — the real JSON-shape gate, not merely "a schema exists".
	if r.Schema == nil {
		t.Errorf("attestor Schema() is nil")
	} else if len(r.Predicate) > 0 {
		assertPredicateMatchesSchema(t, fx, r)
	}

	// Golden predicate (opt-in).
	if fx.GoldenPath != "" {
		r.assertGolden(t, fx)
	}

	// Provenance: if the fixture was recorded from a real tool run, verify the
	// recorded cilock attestation is conformant — the documented invocation
	// really produced these subject families, at a captured tool version/hash.
	// This is the attestation-kit half: the hermetic replay above proves the
	// attestor CODE; this proves the real TOOL output matches the contract.
	if fx.Recording != nil && fx.Recording.AttestationPath != "" {
		r.assertRecording(t, fx)
	}
}

func (r *Result) assertRecording(t *testing.T, fx *Fixture) {
	t.Helper()
	rec, err := loadRecordedAttestation(fx.Recording.AttestationPath)
	if err != nil {
		t.Fatalf("load recorded attestation %s: %v", fx.Recording.AttestationPath, err)
	}
	// The committed file must be a well-formed, non-empty signed DSSE collection
	// — not a hand-authored or predicate-stripped JSON blob masquerading as
	// recorded evidence. (This is a conformance check, not crypto signature
	// verification; verifying the signature against the recording trust root is
	// tracked separately — it needs the Fulcio/dev root wired into the test.)
	if rec.PayloadType == "" || rec.SignatureCount == 0 {
		t.Errorf("recorded attestation is not a signed DSSE envelope (payloadType=%q signatures=%d) — re-record with cilock, do not hand-author", rec.PayloadType, rec.SignatureCount)
	}
	if len(rec.Subjects) == 0 || len(rec.ByType) == 0 {
		t.Errorf("recorded attestation has no subjects/attestations (subjects=%d types=%d) — empty evidence", len(rec.Subjects), len(rec.ByType))
	}

	// A recording MUST declare its provenance argv, and it must equal the argv
	// actually executed in the recorded run. Required (not best-effort): without
	// it nothing ties the contract to the recorded invocation.
	if len(fx.Recording.Argv) == 0 {
		t.Errorf("recording present but recording.argv is empty — declare the exact command that produced the evidence")
	} else if !equalStrs(rec.Argv, fx.Recording.Argv) {
		t.Errorf("recorded attestation command-run argv %v != fixture provenance argv %v", rec.Argv, fx.Recording.Argv)
	}

	// The REAL run must have emitted every subject family the contract claims —
	// proving the validated invocation produces a conformant attestation, not
	// just that the attestor parses a hand-picked sample.
	for _, want := range fx.Expect.Subjects.Keys {
		if !rec.hasSubjectMatching(want) {
			t.Errorf("recorded real run emitted no subject containing %q (real subjects: %d)", want, len(rec.Subjects))
		}
	}

	// THE recorded-evidence cross-check: the predicate the attestor produced in
	// the real recorded run must match what it produces on hermetic replay
	// (after redacting the documented volatile fields). Without this the
	// recorded half proves nothing — a tampered or mismatched recording would
	// ride green. Both sides are canonicalized with the same redaction.
	recPred, ok := rec.ByType[r.PredType]
	if !ok {
		t.Errorf("recorded attestation has no predicate of type %q (recorded types: %v)", r.PredType, rec.types())
	} else if r.RunErr == nil && len(r.Predicate) > 0 {
		recCanon, errR := canonicalize(recPred, fx.Expect.Redact)
		replayCanon, errP := canonicalize(r.Predicate, fx.Expect.Redact)
		if errR == nil && errP == nil && string(recCanon) != string(replayCanon) {
			t.Errorf("replayed predicate != recorded real-run predicate for %q (after redacting %v) — the fixture's replay source does not match the recorded evidence; re-record or widen volatile_fields/redact\n--- recorded ---\n%s\n--- replayed ---\n%s", r.PredType, fx.Expect.Redact, truncForDiff(recCanon), truncForDiff(replayCanon))
		}
	}

	// Provenance must capture what produced the fixture — the staleness signal.
	if fx.Recording.Version == "" || fx.Recording.BinarySHA256 == "" {
		t.Errorf("recording provenance incomplete: version=%q binary_sha256=%q", fx.Recording.Version, fx.Recording.BinarySHA256)
	}
}

// assertPredicateMatchesSchema validates the produced predicate against the
// attestor's OWN Schema(). invopop/jsonschema generates the schema; santhosh-
// tekuri validates against it. "Schema() != nil" was never a shape gate — a
// predicate that doesn't conform to its declared schema is a contract no
// verifier can rely on, and exactly the drift an AI-authored attestor
// introduces (the struct and Schema() falling out of sync).
func assertPredicateMatchesSchema(t *testing.T, fx *Fixture, r *Result) {
	t.Helper()
	schemaJSON, err := json.Marshal(r.Schema)
	if err != nil {
		t.Fatalf("marshal Schema() for %q: %v", fx.Attestor, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("attestor.schema.json", bytes.NewReader(schemaJSON)); err != nil {
		t.Fatalf("add schema resource for %q: %v", fx.Attestor, err)
	}
	sch, err := c.Compile("attestor.schema.json")
	if err != nil {
		t.Fatalf("compile Schema() for %q: %v", fx.Attestor, err)
	}
	var pred any
	if err := json.Unmarshal(r.Predicate, &pred); err != nil {
		t.Fatalf("unmarshal predicate for %q: %v", fx.Attestor, err)
	}
	if err := sch.Validate(pred); err != nil {
		t.Errorf("attestor %q predicate does not validate against its own Schema(): %v", fx.Attestor, err)
	}
}

// truncForDiff caps a canonical predicate for readable failure output.
func truncForDiff(b []byte) string {
	const max = 1200
	if len(b) > max {
		return string(b[:max]) + "\n…(truncated)"
	}
	return string(b)
}

// AssertDeterministic re-runs the attestor on the SAME fixture and asserts the
// predicate is identical to the first run after redacting volatile fields.
// Signed evidence must be reproducible: a stability claim is only honest if the
// attestor produces the same output for the same input + tool version. This
// catches the map-iteration / unsorted-output nondeterminism class (the bug
// that let scubagoggles attest the wrong file) HERMETICALLY — no tool run, on
// every PR. Negative/exit fixtures and errored runs have no predicate to
// compare and are skipped.
func AssertDeterministic(t *testing.T, fx *Fixture, first *Result) {
	t.Helper()
	if fx.Expect.Exit != nil || first == nil || first.RunErr != nil || len(first.Predicate) == 0 {
		return
	}
	second := RunAttestorWithFixture(t, fx)
	if second.RunErr != nil {
		t.Errorf("determinism: second run of %q errored: %v", fx.Attestor, second.RunErr)
		return
	}
	c1, err1 := canonicalize(first.Predicate, fx.Expect.Redact)
	c2, err2 := canonicalize(second.Predicate, fx.Expect.Redact)
	if err1 != nil || err2 != nil {
		t.Fatalf("determinism: canonicalize %q: %v / %v", fx.Attestor, err1, err2)
	}
	if string(c1) != string(c2) {
		t.Errorf("attestor %q is NON-DETERMINISTIC: two runs on the same input produced different predicates (after redacting %v) — signed evidence must be reproducible; check for Go map-iteration order or unsorted slices in the output\n--- run 1 ---\n%s\n--- run 2 ---\n%s",
			fx.Attestor, fx.Expect.Redact, truncForDiff(c1), truncForDiff(c2))
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func assertExit(t *testing.T, fx *Fixture, r *Result) {
	t.Helper()
	switch fx.Expect.Exit.OnNoEvidence {
	case "error":
		if r.RunErr == nil {
			t.Errorf("expected an error on no-evidence, got nil")
			return
		}
		if sub := fx.Expect.Exit.ErrorContains; sub != "" && !strings.Contains(r.RunErr.Error(), sub) {
			t.Errorf("error %q does not contain %q", r.RunErr.Error(), sub)
		}
	case "empty":
		if r.RunErr != nil {
			t.Errorf("expected empty (no error) on no-evidence, got: %v", r.RunErr)
		}
	}
}

// assertGolden canonicalizes the predicate (redacting volatile fields) and
// compares to / rewrites the golden file.
func (r *Result) assertGolden(t *testing.T, fx *Fixture) {
	t.Helper()
	got, err := canonicalize(r.Predicate, fx.Expect.Redact)
	if err != nil {
		t.Fatalf("canonicalize predicate: %v", err)
	}
	if Update() {
		if err := os.WriteFile(fx.GoldenPath, got, 0o600); err != nil {
			t.Fatalf("update golden %s: %v", fx.GoldenPath, err)
		}
		t.Logf("updated golden %s", fx.GoldenPath)
		return
	}
	want, err := os.ReadFile(fx.GoldenPath) //nolint:gosec // path from fixture manifest
	if err != nil {
		t.Fatalf("read golden %s (run with -catalog.update to create): %v", fx.GoldenPath, err)
	}
	if string(got) != string(want) {
		t.Errorf("predicate does not match golden %s (run -catalog.update to refresh)\n--- got ---\n%s", fx.GoldenPath, got)
	}
}

// canonicalize parses the predicate JSON, zeroes the redact paths, and
// re-marshals with sorted keys + 2-space indent so goldens are reproducible.
func canonicalize(raw json.RawMessage, redact []string) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	for _, path := range redact {
		applyRedact(v, strings.Split(path, "."))
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// applyRedact walks a dotted path and sets the leaf to nil. A "[]" segment
// fans out across every element of an array. Missing paths are ignored.
func applyRedact(node any, path []string) {
	if len(path) == 0 {
		return
	}
	seg := path[0]
	if seg == "[]" {
		if arr, ok := node.([]any); ok {
			for _, el := range arr {
				applyRedact(el, path[1:])
			}
		}
		return
	}
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if len(path) == 1 {
		if _, exists := m[seg]; exists {
			m[seg] = nil
		}
		return
	}
	applyRedact(m[seg], path[1:])
}

func subjectPresent(subjects map[string]cryptoutil.DigestSet, want, match string) bool {
	for k := range subjects {
		if match == MatchExact && k == want {
			return true
		}
		if match == MatchPrefix && strings.HasPrefix(k, want) {
			return true
		}
	}
	return false
}

func keysOf(subjects map[string]cryptoutil.DigestSet) []string {
	out := make([]string, 0, len(subjects))
	for k := range subjects {
		out = append(out, k)
	}
	return out
}
