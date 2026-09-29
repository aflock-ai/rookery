// jade:ring local

package policyverify

import (
	"encoding/json"
	"testing"
)

// A VSA predicate written by `cilock verify` carries the stepResults extension. Read back
// through this attestor (as a parent policy's external is), the extension must survive:
// input.external.<name>.stepResults is the only place a parent sees which checks the child denied.
func TestVSAStepResultsSurviveParse(t *testing.T) {
	in := []byte(`{"verifier":{"id":"v"},"timeVerified":"2026-09-28T18:57:40Z","policy":{"uri":"u","digest":{"sha256":"ab"}},
		"inputAttestations":[],"verificationResult":"FAILED",
		"stepResults":[{"step":"a","passed":[],"rejected":[{"reference":"r","collection":"a","reason":"denied","denies":["check:x"]}]},
		               {"step":"b","passed":["c1"],"rejected":[]}]}`)
	a := New()
	if err := json.Unmarshal(in, a); err != nil {
		t.Fatal(err)
	}
	if len(a.Steps) != 2 || a.Steps[0].Step != "a" || len(a.Steps[0].Rejected) != 1 || a.Steps[0].Rejected[0].Denies[0] != "check:x" {
		t.Fatalf("stepResults not parsed: %+v", a.Steps)
	}
	out, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	steps, ok := back["stepResults"].([]any)
	if !ok || len(steps) != 2 {
		t.Fatalf("stepResults lost on re-marshal: %s", out)
	}
}

// A VSA without the extension still parses, and marshals without an empty stepResults key.
func TestVSAWithoutStepResults(t *testing.T) {
	a := New()
	if err := json.Unmarshal([]byte(`{"verificationResult":"PASSED"}`), a); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(a)
	var back map[string]any
	_ = json.Unmarshal(out, &back)
	if _, has := back["stepResults"]; has {
		t.Fatalf("empty stepResults emitted: %s", out)
	}
}
