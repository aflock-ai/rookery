package commandrun

import (
	"encoding/json"
	"testing"
)

// These tests go through THE PRODUCTION PATH, and that distinction is the whole
// point of the file.
//
// v2_exitcode_test.go marshals a V02Predicate with json.Marshal — the
// reflection encoder, which honours struct tags. Production does not use it.
// MarshalJSON (commandrun.go:996) calls MarshalV02WithSections, a hand-written
// section encoder that emits only the fields in an explicit list, each behind
// its own inclusion predicate.
//
// So removing `omitempty` from the struct tag made three tests go green and
// changed NOTHING on the wire: the section spec carried its own
// `p.ExitCode != 0` gate, deliberately mirroring the tag, and was left behind.
// A real cilock built from that commit still emitted a body with no exitcode.
//
// It ended up worse than the bug it claimed to fix. The policy had by then
// learned to DENY an absent exit code — correctly — so a producer that still
// never emitted it refused every honest push, including `cilock run -- true`
// from the very same commit. A gate that fails closed on all input is an
// outage, and it was invisible because the tests measured the wrong encoder.
//
// The rule this file enforces: assert on the bytes the SIGNER produces.

// marshalProduction returns the top-level keys of the signed body, via the
// exact call MarshalJSON makes.
func marshalProduction(t *testing.T, p *V02Predicate) (map[string]json.RawMessage, []byte) {
	t.Helper()

	body, _, err := MarshalV02WithSections(p)
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		t.Fatalf("unmarshal produced body: %v\nbody: %s", err, body)
	}
	return keys, body
}

// The zero exit code must reach the wire.
//
// Zero is the ONLY value that ever reaches this marshaller, because a non-zero
// exit fails the attestor before an attestation is produced. A test that only
// covers non-zero therefore covers the case that cannot happen and misses the
// one that always does — which is exactly how both prior guard tests
// (v2_marshal_sections_guard_test.go, fixtures at ExitCode 7 and 3) stayed
// green through the outage.
func TestProductionMarshalEmitsZeroExitCode(t *testing.T) {
	keys, body := marshalProduction(t, &V02Predicate{
		Meta:     V02Meta{Version: "v0.2"},
		Cmd:      []string{"/bin/sh", "-c", "exit 0"},
		ExitCode: 0,
	})

	raw, present := keys["exitcode"]
	if !present {
		t.Fatalf("the SIGNED body carries no exitcode for a successful run, so a verifier "+
			"can only infer success from the attestation existing — the inference this field exists to replace.\nbody: %s", body)
	}

	var got int
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("exitcode is not a number: %s", raw)
	}
	if got != 0 {
		t.Fatalf("exitcode = %d, want 0", got)
	}
}

// A non-zero code still reaches the wire. The attestor refuses to produce an
// attestation for a failing command today, but WithIgnoreExitCode exists, and
// if it is ever exposed the recorded value must be faithful.
func TestProductionMarshalEmitsNonZeroExitCode(t *testing.T) {
	keys, body := marshalProduction(t, &V02Predicate{
		Meta:     V02Meta{Version: "v0.2"},
		ExitCode: 3,
	})

	raw, present := keys["exitcode"]
	if !present {
		t.Fatalf("non-zero exitcode missing from signed body: %s", body)
	}
	var got int
	if err := json.Unmarshal(raw, &got); err != nil || got != 3 {
		t.Fatalf("exitcode = %s, want 3", raw)
	}
}

// The value survives the round trip a verifier performs.
//
// rego reads the decoded predicate, so a field that is emitted but does not
// decode is no better than one that never shipped.
func TestProductionMarshalExitCodeDecodes(t *testing.T) {
	_, body := marshalProduction(t, &V02Predicate{
		Meta:     V02Meta{Version: "v0.2"},
		Cmd:      []string{"go", "test", "./..."},
		ExitCode: 0,
	})

	var back CommandRun
	if err := back.UnmarshalJSON(body); err != nil {
		t.Fatalf("decode the production body: %v\nbody: %s", err, body)
	}
	if back.ExitCode != 0 {
		t.Fatalf("ExitCode after round trip = %d, want 0", back.ExitCode)
	}
}

// MarshalJSON itself — the method a signer actually calls — must agree.
//
// The tests above call MarshalV02WithSections directly. This one goes through
// the public entry point, so a future change that routes MarshalJSON somewhere
// else cannot quietly reintroduce the gap.
func TestMarshalJSONEmitsZeroExitCode(t *testing.T) {
	cr := &CommandRun{Cmd: []string{"/bin/true"}, ExitCode: 0}

	body, err := cr.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := keys["exitcode"]; !present {
		t.Fatalf("MarshalJSON — the call a signer makes — omits exitcode on success.\nbody: %s", body)
	}
}
