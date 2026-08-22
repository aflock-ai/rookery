package commandrun

import (
	"encoding/json"
	"testing"
)

// The exit code must survive marshalling, including when it is ZERO.
//
// It did not. `json:"exitcode,omitempty"` dropped zero, and zero is the only
// value that ever reaches this marshaller — a non-zero exit fails the attestor
// and produces no attestation at all. So the exit status was absent from the
// wire under every outcome, and consumers were left inferring success from the
// attestation merely existing.
//
// That inference is what refused every honest push through pushgate: its policy
// asked "did this command exit 0?", found no field to answer with, and treated
// an unreadable answer as a failed one. Correctly, too — a gate should not
// guess.
func TestExitCodeZeroIsRecorded(t *testing.T) {
	body, err := json.Marshal(&V02Predicate{
		Meta:     V02Meta{Version: "v0.2"},
		Cmd:      []string{"/bin/sh", "-c", "exit 0"},
		ExitCode: 0,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	raw, present := got["exitcode"]
	if !present {
		t.Fatalf("a successful run records NO exit code — consumers can only infer "+
			"success from the attestation existing, which is what this field exists to state.\nbody: %s", body)
	}
	if n, ok := raw.(float64); !ok || n != 0 {
		t.Fatalf("exitcode = %v, want 0", raw)
	}
}

// A non-zero code still round-trips. The attestor refuses to produce an
// attestation for a failing command today, but the library supports recording
// one (WithIgnoreExitCode), and if that is ever exposed the value must be
// faithful rather than silently dropped.
func TestNonZeroExitCodeSurvives(t *testing.T) {
	body, err := json.Marshal(&V02Predicate{Meta: V02Meta{Version: "v0.2"}, ExitCode: 3})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n, ok := got["exitcode"].(float64); !ok || n != 3 {
		t.Fatalf("exitcode = %v, want 3", got["exitcode"])
	}
}

// The value must survive the full round trip a verifier performs, not merely
// appear in the encoding: rego reads Data() after UnmarshalJSON, so a field
// that marshals but does not decode is no better than one that never shipped.
func TestExitCodeRoundTripsThroughDecode(t *testing.T) {
	body, err := json.Marshal(&V02Predicate{
		Meta:     V02Meta{Version: "v0.2"},
		Cmd:      []string{"go", "test", "./..."},
		ExitCode: 0,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back CommandRun
	if err := back.UnmarshalJSON(body); err != nil {
		t.Fatalf("unmarshal into CommandRun: %v", err)
	}
	if back.ExitCode != 0 {
		t.Fatalf("ExitCode after round trip = %d, want 0", back.ExitCode)
	}
}
