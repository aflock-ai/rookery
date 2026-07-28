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

package detection

import (
	"encoding/json"
	"strings"
	"testing"
)

// captureYAML is a minimal detector.yaml carrying one always-expected subject
// and one when-available subject — the two halves of the capture vocabulary.
const captureYAML = `
apiVersion: cilock.detection/v0.1
name: demo
description: "demo attestor for capture-completeness tests"
pre:
  match:
    any_of:
      - argv_prefix: ["docker", "save"]
post:
  match:
    any_of:
      - product_glob: ["*.oci.tar"]
contract:
  predicate_type: https://aflock.ai/attestations/demo/v0.1
  run_type: postproduct
  subjects:
    - prefix: "manifestdigest:"
      description: "sha256 of the raw manifest bytes"
    - prefix: "registrydigest:"
      description: "the registry manifest digest"
      capture:
        expectation: when-available
        available_when: "the image is resolved from a registry reference, not a local tar"
    - prefix: "imageid:"
      description: "sha256 of the image config blob"
      capture:
        expectation: always
        remedy: "attest the build step that produces the image config"
`

// noCaptureYAML mirrors every detector.yaml authored before the capture block
// existed: subjects declared, no expectations.
const noCaptureYAML = `
apiVersion: cilock.detection/v0.1
name: legacy
description: "an attestor that predates capture expectations"
post:
  match:
    any_of:
      - product_glob: ["*.legacy"]
contract:
  predicate_type: https://aflock.ai/attestations/legacy/v0.1
  run_type: product
  subjects:
    - prefix: "manifestdigest:"
      description: "sha256 of the raw manifest bytes"
`

func captureRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	r.Register("demo", []byte(captureYAML))
	r.Register("legacy", []byte(noCaptureYAML))
	// Assert the fixtures actually PARSE. CheckCapture deliberately swallows a
	// lookup error at run time (a malformed detector.yaml must not crash a
	// user's build), which means a broken fixture here would return "no gaps"
	// and every silence assertion below would pass for the wrong reason.
	for _, name := range []string{"demo", "legacy"} {
		d, ok, err := r.Lookup(name)
		if err != nil || !ok || d == nil {
			t.Fatalf("test fixture %q did not parse (ok=%v err=%v) — fix the fixture, not the assertion", name, ok, err)
		}
	}
	return r
}

// TestCheckCapture_CompleteCaptureIsSilent is the noise gate. A warning that
// always fires gets filtered out and the signal dies, so a run that captured
// everything expected of it MUST produce nothing at all.
func TestCheckCapture_CompleteCaptureIsSilent(t *testing.T) {
	r := captureRegistry(t)
	emitted := []string{
		"manifestdigest:sha256:aaaa",
		"registrydigest:sha256:bbbb",
		"imageid:sha256:cccc",
	}
	if gaps := r.CheckCapture("demo", emitted); len(gaps) != 0 {
		t.Fatalf("complete capture produced %d warning(s), want 0: %+v", len(gaps), gaps)
	}

	rep := r.BuildCaptureReport(map[string][]string{"demo": emitted})
	if !rep.Complete() {
		t.Errorf("report over a complete capture is not Complete(): %+v", rep.Gaps)
	}
	if len(rep.Attestors) != 1 || rep.Attestors[0] != "demo" {
		t.Errorf("checked attestors = %v, want [demo] — a silent report must still record that it looked", rep.Attestors)
	}
}

// TestCheckCapture_MissingWhenAvailableSubject is the motivating oci case: the
// registry digest is declared, the run could not produce it, and the user gets
// exactly ONE warning naming the subject and the remedy.
func TestCheckCapture_MissingWhenAvailableSubject(t *testing.T) {
	r := captureRegistry(t)
	// Everything a docker-save tar can yield — no registry digest.
	emitted := []string{"manifestdigest:sha256:aaaa", "imageid:sha256:cccc"}

	gaps := r.CheckCapture("demo", emitted)
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want exactly 1: %+v", len(gaps), gaps)
	}
	g := gaps[0]
	if g.Subject != "registrydigest:" {
		t.Errorf("gap subject = %q, want %q", g.Subject, "registrydigest:")
	}
	if g.Code != CodeCaptureIncomplete {
		t.Errorf("gap code = %q, want %q", g.Code, CodeCaptureIncomplete)
	}
	if g.Expectation != CaptureWhenAvailable {
		t.Errorf("gap expectation = %q, want %q", g.Expectation, CaptureWhenAvailable)
	}
	if g.Remedy == "" {
		t.Fatal("gap carries no remedy — an unactionable warning is noise")
	}

	// The rendered warning must be actionable on its own: it names the
	// attestor, the subject, why it was unavailable, and what to do.
	w := g.Warning()
	for _, want := range []string{
		CodeCaptureIncomplete,
		"demo",
		"registrydigest:",
		"available when:",
		"remedy:",
		"wrap the command that produces it",
		"`docker save`",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warning does not mention %q:\n%s", want, w)
		}
	}
}

// TestCheckCapture_MissingAlwaysSubject proves the always arm words the
// warning differently — "the attestor is broken" and "your invocation could
// not yield this" are different actions for the reader.
func TestCheckCapture_MissingAlwaysSubject(t *testing.T) {
	r := captureRegistry(t)
	emitted := []string{"manifestdigest:sha256:aaaa", "registrydigest:sha256:bbbb"}

	gaps := r.CheckCapture("demo", emitted)
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want exactly 1: %+v", len(gaps), gaps)
	}
	if gaps[0].Expectation != CaptureAlways {
		t.Fatalf("expectation = %q, want %q", gaps[0].Expectation, CaptureAlways)
	}
	w := gaps[0].Warning()
	if strings.Contains(w, "available when:") {
		t.Errorf("an always-expected subject must not claim a precondition:\n%s", w)
	}
	if !strings.Contains(w, "evidence is incomplete") {
		t.Errorf("always-arm warning does not say the evidence is incomplete:\n%s", w)
	}
}

// TestCheckCapture_NoExpectationsNeverWarns is the ~40-detector safety net.
// Every contract authored before the capture block existed must stay silent no
// matter what it did or did not emit — otherwise shipping this mechanism turns
// the whole catalog into noise overnight.
func TestCheckCapture_NoExpectationsNeverWarns(t *testing.T) {
	r := captureRegistry(t)
	// The legacy attestor emitted NOTHING, yet declares a subject.
	if gaps := r.CheckCapture("legacy", nil); gaps != nil {
		t.Fatalf("a contract with no capture block produced warnings: %+v", gaps)
	}
	rep := r.BuildCaptureReport(map[string][]string{"legacy": nil})
	if len(rep.Attestors) != 0 {
		t.Errorf("legacy attestor was reported as checked (%v) — it declares no expectation, so checking it means nothing", rep.Attestors)
	}
	if len(rep.Gaps) != 0 {
		t.Errorf("legacy attestor produced gaps: %+v", rep.Gaps)
	}
}

// TestCheckCapture_UnknownAttestor guards the runtime path against an attestor
// with no registered detector.yaml (a custom build, a test double).
func TestCheckCapture_UnknownAttestor(t *testing.T) {
	r := captureRegistry(t)
	if gaps := r.CheckCapture("does-not-exist", []string{"x:1"}); gaps != nil {
		t.Fatalf("unknown attestor produced warnings: %+v", gaps)
	}
}

// TestCheckCapture_PrefixMatching proves membership is by PREFIX — subject
// keys carry dynamic tails, so an exact-match check would report every
// populated subject as missing.
func TestCheckCapture_PrefixMatching(t *testing.T) {
	r := captureRegistry(t)
	// Keys with real dynamic tails.
	emitted := []string{
		"registrydigest:sha256:0123456789abcdef",
		"imageid:sha256:fedcba9876543210",
	}
	if gaps := r.CheckCapture("demo", emitted); len(gaps) != 0 {
		t.Fatalf("prefix matching failed, got gaps: %+v", gaps)
	}
}

// TestCaptureReport_JSONIsMachineReadable proves the delta survives to a form
// a CI job or the platform can consume — the point of emitting it at capture
// time rather than discovering the blind spot in production months later.
func TestCaptureReport_JSONIsMachineReadable(t *testing.T) {
	r := captureRegistry(t)
	rep := r.BuildCaptureReport(map[string][]string{
		"demo": {"manifestdigest:sha256:aaaa", "imageid:sha256:cccc"},
	})
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var round struct {
		Gaps []struct {
			Code          string `json:"code"`
			Attestor      string `json:"attestor"`
			Subject       string `json:"subject"`
			Expectation   string `json:"expectation"`
			AvailableWhen string `json:"available_when"`
			Remedy        string `json:"remedy"`
		} `json:"gaps"`
		Checked []string `json:"checked_attestors"`
	}
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(round.Gaps) != 1 {
		t.Fatalf("round-tripped %d gaps, want 1: %s", len(round.Gaps), raw)
	}
	g := round.Gaps[0]
	if g.Code != CodeCaptureIncomplete || g.Attestor != "demo" || g.Subject != "registrydigest:" {
		t.Errorf("round-tripped gap is wrong: %+v", g)
	}
	if g.Remedy == "" || g.AvailableWhen == "" {
		t.Errorf("round-tripped gap lost its guidance: %+v", g)
	}
	if len(round.Checked) != 1 || round.Checked[0] != "demo" {
		t.Errorf("checked_attestors = %v, want [demo]", round.Checked)
	}
}

// TestCodeCaptureIncompleteIsCore keeps the new diagnostic code inside the
// stable core-code namespace consumers branch on.
func TestCodeCaptureIncompleteIsCore(t *testing.T) {
	if !IsCoreCode(CodeCaptureIncomplete) {
		t.Errorf("%s is not recognized as a core code", CodeCaptureIncomplete)
	}
}

// TestValidateCaptureExpectation covers the build-time half: the vocabulary is
// opt-in (nil is valid, which is what keeps every pre-existing detector.yaml
// valid), and a declared block must be actionable.
func TestValidateCaptureExpectation(t *testing.T) {
	cases := []struct {
		name    string
		ce      *CaptureExpectation
		wantErr bool
	}{
		{
			name: "nil is valid — the field is opt-in",
			ce:   nil,
		},
		{
			name: "valid when-available",
			ce:   &CaptureExpectation{Expectation: CaptureWhenAvailable, AvailableWhen: "pulled from a registry", Remedy: "attest the push step too"},
		},
		{
			name: "valid always",
			ce:   &CaptureExpectation{Expectation: CaptureAlways, Remedy: "re-run against a readable image"},
		},
		{
			name:    "unknown expectation rejected",
			ce:      &CaptureExpectation{Expectation: "maybe", Remedy: "x"},
			wantErr: true,
		},
		{
			name:    "empty expectation rejected",
			ce:      &CaptureExpectation{Remedy: "x"},
			wantErr: true,
		},
		{
			name: "empty remedy is fine — guidance derives from the match block",
			ce:   &CaptureExpectation{Expectation: CaptureAlways},
		},
		{
			name:    "when-available without available_when rejected",
			ce:      &CaptureExpectation{Expectation: CaptureWhenAvailable, Remedy: "x"},
			wantErr: true,
		},
		{
			name:    "always with available_when rejected as contradictory",
			ce:      &CaptureExpectation{Expectation: CaptureAlways, AvailableWhen: "sometimes", Remedy: "x"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCaptureExpectation(tc.ce, "demo", 0, "registrydigest:")
			if tc.wantErr && err == nil {
				t.Errorf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateOutputContract_CaptureReachedFromContract proves the per-subject
// capture block is actually validated through the top-level contract validator
// (not merely by the helper in isolation).
func TestValidateOutputContract_CaptureReachedFromContract(t *testing.T) {
	c := &OutputContract{
		PredicateType: "https://aflock.ai/attestations/demo/v0.1",
		RunType:       ContractRunPostProduct,
		Subjects: []SubjectClaim{
			{Prefix: "registrydigest:", Capture: &CaptureExpectation{Expectation: "bogus", Remedy: "x"}},
		},
	}
	if err := validateOutputContract(c, "demo"); err == nil {
		t.Fatal("expected validateOutputContract to reject an invalid capture block")
	}
}

// TestDeriveRemedy_FromMatchBlock proves guidance comes from the detector's OWN
// match block. This is the property that makes the mechanism scale to ~40
// attestors without anyone writing prose, and that stops guidance drifting the
// moment someone edits a match pattern.
func TestDeriveRemedy_FromMatchBlock(t *testing.T) {
	r := captureRegistry(t)
	gaps := r.CheckCapture("demo", []string{"manifestdigest:sha256:aaaa", "imageid:sha256:cccc"})
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1: %+v", len(gaps), gaps)
	}
	g := gaps[0]
	if !g.RemedyDerived {
		t.Errorf("remedy was not derived (remedy=%q) — derivation is the default path", g.Remedy)
	}
	// argv matches render as "wrap this command"; product globs render
	// separately as "produce this artifact". They are different instructions.
	if !strings.Contains(g.Remedy, "`docker save`") {
		t.Errorf("derived remedy does not name the argv the detector matches on: %q", g.Remedy)
	}
	if !strings.Contains(g.Remedy, "`*.oci.tar`") {
		t.Errorf("derived remedy does not name the product glob: %q", g.Remedy)
	}
	if strings.Contains(g.Remedy, "--") {
		t.Errorf("derived remedy contains a flag: %q", g.Remedy)
	}
}

// TestDeriveRemedy_OverrideWins covers the exception: a subject whose capture
// precondition is narrower than the detector's match block supplies its own
// text, and the gap records that it was NOT derived.
func TestDeriveRemedy_OverrideWins(t *testing.T) {
	r := captureRegistry(t)
	gaps := r.CheckCapture("demo", []string{"manifestdigest:sha256:aaaa", "registrydigest:sha256:bbbb"})
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1: %+v", len(gaps), gaps)
	}
	if gaps[0].RemedyDerived {
		t.Errorf("an overridden remedy was marked derived: %q", gaps[0].Remedy)
	}
	if gaps[0].Remedy != "attest the build step that produces the image config" {
		t.Errorf("override text was not used: %q", gaps[0].Remedy)
	}
}

// TestDeriveRemedy_SkipsNegatedBranches — a `not:` branch says what must be
// ABSENT. Inverting it into guidance would tell the user to run the one thing
// that stops the attestor firing.
func TestDeriveRemedy_SkipsNegatedBranches(t *testing.T) {
	d := &DetectorYAML{
		Name: "x",
		Pre: &GateBlock{Match: &Predicate{AnyOf: []Predicate{
			{ArgvPrefix: []string{"good", "cmd"}},
			{Not: &Predicate{ArgvPrefix: []string{"bad", "cmd"}}},
		}}},
	}
	got := deriveRemedy(d)
	if !strings.Contains(got, "`good cmd`") {
		t.Errorf("derived remedy lost the positive branch: %q", got)
	}
	if strings.Contains(got, "bad cmd") {
		t.Errorf("derived remedy recommends a NEGATED command: %q", got)
	}
}

// TestValidateCaptureGuidance_RejectsUnderivable is the build-time gate: a
// detector whose match block has no argv_prefix and no product_glob cannot
// produce guidance, so declaring a capture expectation without an override is
// rejected rather than shipping an empty remedy.
func TestValidateCaptureGuidance_RejectsUnderivable(t *testing.T) {
	d := &DetectorYAML{
		Name: "envonly",
		// env_set is a real predicate but yields no "wrap this" direction.
		Pre: &GateBlock{Match: &Predicate{EnvSet: "SOME_VAR"}},
		Contract: &OutputContract{
			PredicateType: "https://aflock.ai/attestations/envonly/v0.1",
			RunType:       ContractRunPreMaterial,
			Subjects: []SubjectClaim{
				{Prefix: "thing:", Capture: &CaptureExpectation{Expectation: CaptureAlways}},
			},
		},
	}
	if err := validateCaptureGuidance(d); err == nil {
		t.Fatal("expected rejection: no derivable guidance and no override")
	}
	// With an override it is fine.
	d.Contract.Subjects[0].Capture.Remedy = "attest the step that sets it"
	if err := validateCaptureGuidance(d); err != nil {
		t.Fatalf("override should satisfy the gate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Conjunctions: all_of must never be flattened into "or" guidance.
// ---------------------------------------------------------------------------

// conjunctionNoRemedyYAML declares a capture expectation on a detector whose
// match is a real conjunction (all_of) and supplies NO explicit remedy.
// Derivation must refuse (a flat "wrap X or Y" would recommend an action that
// still won't match), so the build-time gate must reject this fixture.
const conjunctionNoRemedyYAML = `
apiVersion: cilock.detection/v0.1
name: conj
description: "conjunction demo: derivation must refuse, gate must demand a remedy"
pre:
  match:
    all_of:
      - argv_prefix: ["docker", "push"]
      - env_set: "CI"
contract:
  predicate_type: https://aflock.ai/attestations/conj/v0.1
  run_type: postproduct
  subjects:
    - prefix: "registrydigest:"
      description: "registry manifest digest"
      capture:
        expectation: when-available
        available_when: "the run pushes an image while CI is set"
`

// conjunctionWithRemedyYAML is the same conjunction with the author supplying
// the compound instruction in words — the only honest way to express it.
const conjunctionWithRemedyYAML = `
apiVersion: cilock.detection/v0.1
name: conjok
description: "conjunction demo with an explicit authored remedy"
pre:
  match:
    all_of:
      - argv_prefix: ["docker", "push"]
      - env_set: "CI"
contract:
  predicate_type: https://aflock.ai/attestations/conjok/v0.1
  run_type: postproduct
  subjects:
    - prefix: "registrydigest:"
      description: "registry manifest digest"
      capture:
        expectation: when-available
        available_when: "the run pushes an image while CI is set"
        remedy: "run the push under CI (CI env var set) and wrap the docker push with cilock"
`

// nestedConjunctionYAML hides the all_of one level down inside an any_of
// branch — refusal must apply at any depth, not just the root.
const nestedConjunctionYAML = `
apiVersion: cilock.detection/v0.1
name: nestedconj
description: "any_of branch containing an all_of conjunction"
pre:
  match:
    any_of:
      - argv_prefix: ["crane", "push"]
      - all_of:
          - argv_prefix: ["docker", "push"]
          - env_set: "CI"
contract:
  predicate_type: https://aflock.ai/attestations/nestedconj/v0.1
  run_type: postproduct
  subjects:
    - prefix: "registrydigest:"
      description: "registry manifest digest"
      capture:
        expectation: when-available
        available_when: "a push is observed"
`

func TestDeriveRemedy_RefusesConjunctiveMatch(t *testing.T) {
	for name, yaml := range map[string]string{
		"root all_of":   conjunctionNoRemedyYAML,
		"nested all_of": nestedConjunctionYAML,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDetectorYAML([]byte(yaml))
			if err == nil {
				t.Fatalf("a conjunctive match with a remedy-less capture expectation must be rejected at build time")
			}
			// Validation refused — that IS the contract under test. Now prove
			// the refusal came from derivation, not some unrelated error.
			if !strings.Contains(err.Error(), "capture.remedy") {
				t.Fatalf("rejection is not the capture-guidance gate: %v", err)
			}
		})
	}
}

// TestDeriveRemedy_ConjunctionRefusalIsDerivationNotParsing separates the two
// halves: the same conjunctive match WITHOUT any capture block parses fine
// (conjunctions are legal detectors), proving the rejection above is the
// capture-guidance gate and not the predicate validator.
func TestDeriveRemedy_ConjunctionRefusalIsDerivationNotParsing(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: conjplain
description: "conjunction with no capture expectation"
pre:
  match:
    all_of:
      - argv_prefix: ["docker", "push"]
      - env_set: "CI"
`
	d, err := ParseDetectorYAML([]byte(yaml))
	if err != nil || d == nil {
		t.Fatalf("a conjunctive match without capture expectations must stay valid: %v", err)
	}
	if got := deriveRemedy(d); got != "" {
		t.Fatalf("deriveRemedy flattened a conjunction into %q — all_of must refuse derivation", got)
	}
}

func TestCheckCapture_ConjunctionUsesAuthoredRemedy(t *testing.T) {
	r := NewRegistry()
	r.Register("conjok", []byte(conjunctionWithRemedyYAML))
	d, ok, err := r.Lookup("conjok")
	if err != nil || !ok || d == nil {
		t.Fatalf("fixture with explicit remedy must validate (ok=%v err=%v)", ok, err)
	}

	gaps := r.CheckCapture("conjok", []string{"unrelated:sha256:aaaa"})
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1: %+v", len(gaps), gaps)
	}
	g := gaps[0]
	if g.RemedyDerived {
		t.Error("remedy for a conjunctive detector must be the authored override, not derived")
	}
	if !strings.Contains(g.Remedy, "CI") || !strings.Contains(g.Remedy, "docker push") {
		t.Errorf("authored compound remedy was not carried through: %q", g.Remedy)
	}
	// The flattened, misleading form must not appear anywhere.
	if strings.Contains(g.Remedy, " or ") {
		t.Errorf("remedy reads as alternatives for a conjunctive match: %q", g.Remedy)
	}
}

// TestGlobGuidance_VerbatimOrNothing pins the no-transformation rule. Two
// review rounds each caught a "readability" reduction misrecommending —
// stripped directories told the user to produce dist/report.json at the
// root, and a collapsed leading */ read a one-directory-deep requirement as
// any-depth. A pattern is quoted verbatim or (when it has no literal content
// at all) contributes nothing; there is no third case to get wrong.
func TestGlobGuidance_VerbatimOrNothing(t *testing.T) {
	for glob, want := range map[string]string{
		"dist/report.json":    "dist/report.json",
		"**/dist/report.json": "**/dist/report.json",
		"**/index.json":       "**/index.json",
		"*/index.json":        "*/index.json",
		"index.json":          "index.json",
		"dist/*.json":         "dist/*.json",
		"*.oci.tar":           "*.oci.tar",
		"*":                   "",
		"**":                  "",
		"**/*":                "",
	} {
		if got := globGuidance(glob); got != want {
			t.Errorf("globGuidance(%q) = %q, want %q", glob, got, want)
		}
	}
}

// TestDeriveRemedy_GlobPatternsQuotedVerbatim is the end-to-end half: derived
// guidance must carry each product glob exactly as the detector matches it.
// `*/index.json` requires exactly one directory component and `**/x` does not
// match a root-level x under the matcher, so any reduced form recommends
// producing a file the detector would not fire on.
func TestDeriveRemedy_GlobPatternsQuotedVerbatim(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: distglob
description: "detector gated on directory-constrained product globs"
post:
  match:
    any_of:
      - product_glob: ["dist/report.json", "*/index.json", "**/nested/summary.json"]
contract:
  predicate_type: https://aflock.ai/attestations/distglob/v0.1
  run_type: postproduct
  subjects:
    - prefix: "report:"
      description: "the report digest"
      capture:
        expectation: always
`
	d, err := ParseDetectorYAML([]byte(yaml))
	if err != nil || d == nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	remedy := deriveRemedy(d)
	for _, want := range []string{"`dist/report.json`", "`*/index.json`", "`**/nested/summary.json`"} {
		if !strings.Contains(remedy, want) {
			t.Errorf("derived guidance must quote the pattern verbatim, missing %s: %q", want, remedy)
		}
	}
	// No reduced spellings: a bare or depth-stripped form recommends a file
	// the pattern does not match.
	if strings.Contains(remedy, "`report.json`") || strings.Contains(remedy, "`index.json`") || strings.Contains(remedy, "`nested/summary.json`") {
		t.Errorf("derived guidance contains a reduced glob spelling: %q", remedy)
	}
}

// ---------------------------------------------------------------------------
// Subject provenance: operator-supplied subjects may satisfy when-available
// expectations (the run's evidence IS findable by that identifier) but must
// never mask an attestor-level `always` failure.
// ---------------------------------------------------------------------------

func TestCheckCaptureSupplemented_SupplementalNeverSatisfiesAlways(t *testing.T) {
	r := captureRegistry(t)
	// The demo attestor emitted only manifestdigest. The operator pasted BOTH
	// remaining declared subjects. registrydigest (when-available) is thereby
	// closed; imageid (always) is an attestor-contract failure and must warn.
	attestorKeys := []string{"manifestdigest:sha256:aaaa"}
	supplemental := []string{
		"registrydigest:sha256:bbbb",
		"imageid:sha256:cccc",
	}

	gaps := r.CheckCaptureSupplemented("demo", attestorKeys, supplemental)
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want exactly 1 (the always subject): %+v", len(gaps), gaps)
	}
	if gaps[0].Subject != "imageid:" || gaps[0].Expectation != CaptureAlways {
		t.Fatalf("gap = %+v, want the imageid: always expectation", gaps[0])
	}
}

func TestCheckCaptureSupplemented_AttestorKeysSatisfyAlways(t *testing.T) {
	r := captureRegistry(t)
	// Same shape, but the attestor ITSELF emitted the always subject — silent.
	attestorKeys := []string{"manifestdigest:sha256:aaaa", "imageid:sha256:cccc"}
	supplemental := []string{"registrydigest:sha256:bbbb"}

	if gaps := r.CheckCaptureSupplemented("demo", attestorKeys, supplemental); len(gaps) != 0 {
		t.Fatalf("a fully captured run still warned: %+v", gaps)
	}
}

func TestBuildCaptureReportSupplemented_FalseCompleteIsPinned(t *testing.T) {
	r := captureRegistry(t)
	rep := r.BuildCaptureReportSupplemented(
		map[string][]string{"demo": {"manifestdigest:sha256:aaaa", "registrydigest:sha256:bbbb"}},
		[]string{"imageid:sha256:cccc"}, // pasted, not emitted
	)
	if rep.Complete() {
		t.Fatal("supplemental subject masked an attestor-level always failure — false Complete() report")
	}
	if len(rep.Gaps) != 1 || rep.Gaps[0].Subject != "imageid:" {
		t.Fatalf("gaps = %+v, want exactly the imageid: always gap", rep.Gaps)
	}
}
