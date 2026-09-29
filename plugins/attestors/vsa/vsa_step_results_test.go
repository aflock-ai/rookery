// jade:ring local

package vsa

import (
	"encoding/json"
	"testing"
)

// The typed factory is the other registered reader of the VSA predicate type:
// where a binary imports both, whichever registers last wins FactoryByType. A parent
// policy reading a child VSA through it must see the stepResults extension too.
func TestStepResultsSurviveTheTypedFactory(t *testing.T) {
	in := []byte(`{"verifier":{"id":"v"},"timeVerified":"2026-09-28T18:57:40Z","policy":{"uri":"u","digest":{"sha256":"ab"}},
		"inputAttestations":[],"verificationResult":"FAILED",
		"stepResults":[{"step":"a","passed":[],"rejected":[{"reference":"r","collection":"a","reason":"denied","denies":["check:x, y"]}]}]}`)
	a := New()
	if err := json.Unmarshal(in, a); err != nil {
		t.Fatal(err)
	}
	if len(a.Predicate.StepResults) != 1 || a.Predicate.StepResults[0].Rejected[0].Denies[0] != "check:x, y" {
		t.Fatalf("stepResults not decoded: %+v", a.Predicate.StepResults)
	}
	out, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back["stepResults"]; !ok {
		t.Fatalf("stepResults lost on re-marshal (Rego input): %s", out)
	}

	b := New()
	if err := json.Unmarshal([]byte(`{"verificationResult":"PASSED"}`), b); err != nil {
		t.Fatal(err)
	}
	out, _ = json.Marshal(b)
	back = nil
	_ = json.Unmarshal(out, &back)
	if _, has := back["stepResults"]; has {
		t.Fatalf("a VSA without the extension gained one: %s", out)
	}
}
