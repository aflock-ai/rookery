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

package cli

import (
	"crypto"
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/invopop/jsonschema"
)

// =====================================================================
// Capture-completeness warning (CILOCK_CAPTURE_INCOMPLETE)
// =====================================================================
//
// These pin the CLI-side half: which attestors get checked, and what counts
// as "captured". The detection package owns the prefix matching and the
// warning text (attestation/detection/capture_test.go).

// captureFake is a minimal Subjecter attestor whose emitted subject keys the
// test controls directly.
type captureFake struct {
	name     string
	subjects map[string]cryptoutil.DigestSet
}

func (f *captureFake) Name() string                                 { return f.name }
func (f *captureFake) Type() string                                 { return "https://aflock.ai/attestations/" + f.name + "/v0.1" }
func (f *captureFake) RunType() attestation.RunType                 { return attestation.PostProductRunType }
func (f *captureFake) Attest(*attestation.AttestationContext) error { return nil }
func (f *captureFake) Schema() *jsonschema.Schema                   { return nil }
func (f *captureFake) Subjects() map[string]cryptoutil.DigestSet    { return f.subjects }

func sha256Set(v string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: v}
}

// captureTestYAML declares one when-available subject so the check has
// something to be unsatisfied about. Registered under a name no real plugin
// uses, into the DEFAULT registry (which is what collectCaptureGaps reads).
const captureTestYAML = `
apiVersion: cilock.detection/v0.1
name: capturefake
description: "fake attestor pinning the CLI capture-gap wiring"
post:
  match:
    any_of:
      - product_glob: ["*.capturefake"]
contract:
  predicate_type: https://aflock.ai/attestations/capturefake/v0.1
  run_type: postproduct
  subjects:
    - prefix: "registrydigest:"
      description: "the registry manifest digest"
      capture:
        expectation: when-available
        available_when: "the image came from a registry reference"
        remedy: "wrap the push step in cilock too so the registry digest is captured"
`

func registerCaptureFake(t *testing.T) {
	t.Helper()
	detection.Default().Register("capturefake", []byte(captureTestYAML))
	// Prove it parsed. collectCaptureGaps swallows a lookup error by design, so
	// a broken fixture would make every "no gaps" assertion below pass for the
	// wrong reason.
	d, ok, err := detection.Default().Lookup("capturefake")
	if err != nil || !ok || d == nil || d.Contract == nil {
		t.Fatalf("capturefake detector.yaml did not parse (ok=%v err=%v)", ok, err)
	}
}

// TestCollectCaptureGaps_ReportsMissingSubject is the baseline: the attestor
// ran, did not emit the declared subject, and the delta says so.
func TestCollectCaptureGaps_ReportsMissingSubject(t *testing.T) {
	registerCaptureFake(t)
	a := &captureFake{name: "capturefake", subjects: map[string]cryptoutil.DigestSet{
		"manifestdigest:aaaa": sha256Set("aaaa"),
	}}

	rep := collectCaptureGaps([]attestation.Attestor{a}, nil, nil)
	if rep == nil {
		t.Fatal("no capture report — the declared expectation was not checked at all")
	}
	if len(rep.Gaps) != 1 || rep.Gaps[0].Subject != "registrydigest:" {
		t.Fatalf("gaps = %+v, want exactly one registrydigest: gap", rep.Gaps)
	}
}

// TestCollectCaptureGaps_AdditionalSubjectsSatisfyExpectation covers the
// pre-existing --subjects escape hatch. It is NOT the recommended remedy (no
// guidance may tell a user to paste a flag), but when an operator does supply
// the value it lands as a COLLECTION subject rather than on the attestor. If
// those aren't counted, the warning survives the gap actually being closed —
// the fastest way to train people to ignore the whole class of signal.
func TestCollectCaptureGaps_AdditionalSubjectsSatisfyExpectation(t *testing.T) {
	registerCaptureFake(t)
	a := &captureFake{name: "capturefake", subjects: map[string]cryptoutil.DigestSet{
		"manifestdigest:aaaa": sha256Set("aaaa"),
	}}
	additional := map[string]cryptoutil.DigestSet{
		"registrydigest:sha256:bbbb": sha256Set("bbbb"),
	}

	rep := collectCaptureGaps([]attestation.Attestor{a}, nil, additional)
	if rep == nil {
		t.Fatal("no capture report — the attestor should still be recorded as checked")
	}
	if len(rep.Gaps) != 0 {
		t.Fatalf("the subject was present in the run and the gap STILL warned: %+v", rep.Gaps)
	}
	if len(rep.Attestors) != 1 {
		t.Errorf("checked attestors = %v, want [capturefake]", rep.Attestors)
	}
}

// TestCollectCaptureGaps_SkipsFailedAttestor: when an attestor errored the
// error is the signal. Stacking "you didn't capture X" on top of "the attestor
// blew up" buries both.
func TestCollectCaptureGaps_SkipsFailedAttestor(t *testing.T) {
	registerCaptureFake(t)
	a := &captureFake{name: "capturefake", subjects: map[string]cryptoutil.DigestSet{}}
	runErr := &workflow.AttestorRunErrors{
		Legs: []workflow.AttestorErrorLeg{{Attestor: "capturefake", Err: errors.New("boom")}},
	}

	if rep := collectCaptureGaps([]attestation.Attestor{a}, runErr, nil); rep != nil {
		t.Fatalf("a failed attestor was still checked for capture gaps: %+v", rep)
	}
}

// TestCollectCaptureGaps_NoExpectationsReturnsNil is the ~40-detector safety
// net at the CLI seam. nil, not an empty report: an empty report in the JSON
// summary would read as "capture verified, no gaps", a stronger claim than
// "nobody checked".
func TestCollectCaptureGaps_NoExpectationsReturnsNil(t *testing.T) {
	a := &captureFake{name: "no-such-detector", subjects: map[string]cryptoutil.DigestSet{}}
	if rep := collectCaptureGaps([]attestation.Attestor{a}, nil, nil); rep != nil {
		t.Fatalf("an attestor with no declared expectations produced a report: %+v", rep)
	}
}

// TestWarnCaptureGaps_NilIsSafe — the warning path must never panic on the
// common (nil) case, since it runs on every single cilock run.
func TestWarnCaptureGaps_NilIsSafe(t *testing.T) {
	warnCaptureGaps(nil)
	warnCaptureGaps(&detection.CaptureReport{})
}

// captureAlwaysYAML declares an ALWAYS subject: a claim about what the
// attestor itself emits on every run, which operator-supplied subjects must
// never satisfy.
const captureAlwaysYAML = `
apiVersion: cilock.detection/v0.1
name: capturealways
description: "fake attestor pinning always-expectation provenance at the CLI seam"
post:
  match:
    any_of:
      - product_glob: ["*.capturealways"]
contract:
  predicate_type: https://aflock.ai/attestations/capturealways/v0.1
  run_type: postproduct
  subjects:
    - prefix: "imageid:"
      description: "the image config digest"
      capture:
        expectation: always
`

// TestCollectCaptureGaps_AdditionalSubjectsDoNotMaskAlways: --subjects entries
// land on the COLLECTION, not on the attestor, so they cannot make an
// attestor-level always claim true. Counting them produced a false Complete()
// report over a run whose attestor failed to emit its contractual subject.
func TestCollectCaptureGaps_AdditionalSubjectsDoNotMaskAlways(t *testing.T) {
	detection.Default().Register("capturealways", []byte(captureAlwaysYAML))
	d, ok, err := detection.Default().Lookup("capturealways")
	if err != nil || !ok || d == nil || d.Contract == nil {
		t.Fatalf("capturealways detector.yaml did not parse (ok=%v err=%v)", ok, err)
	}

	a := &captureFake{name: "capturealways", subjects: map[string]cryptoutil.DigestSet{
		"manifestdigest:aaaa": sha256Set("aaaa"),
	}}
	additional := map[string]cryptoutil.DigestSet{
		"imageid:sha256:cccc": sha256Set("cccc"), // pasted, not emitted
	}

	rep := collectCaptureGaps([]attestation.Attestor{a}, nil, additional)
	if rep == nil {
		t.Fatal("no capture report — the always expectation was not checked at all")
	}
	if len(rep.Gaps) != 1 || rep.Gaps[0].Subject != "imageid:" {
		t.Fatalf("gaps = %+v, want exactly one imageid: gap — a pasted subject must not mask an always failure", rep.Gaps)
	}
	if rep.Complete() {
		t.Fatal("false Complete() report: supplemental subject masked the attestor-level always failure")
	}
}
