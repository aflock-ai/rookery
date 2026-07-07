// Copyright (c) Wassim Chegham — MIT license; see LICENSE.
//
// Round-trip / behavior tests for the TestifySec-rewritten json.go. The
// goal is to verify equivalence with upstream wk8 behavior without
// depending on either of the upstream JSON libs we just dropped. Tests
// use stdlib only.

package orderedmap_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/wk8/go-ordered-map/v2"
)

// TestRoundTrip verifies the canonical case: marshal an OrderedMap into
// JSON, unmarshal it back, get the same keys in the same order.
func TestRoundTrip(t *testing.T) {
	om := orderedmap.New[string, any]()
	om.Set("z", 1)
	om.Set("a", "two")
	om.Set("m", []any{1.0, 2.0, 3.0})

	encoded, err := json.Marshal(om)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Expect insertion order preserved in the on-wire JSON.
	expectedPrefix := `{"z":1,"a":"two","m":`
	if !bytes.HasPrefix(encoded, []byte(expectedPrefix)) {
		t.Errorf("expected JSON to start with %q, got %s", expectedPrefix, encoded)
	}

	decoded := orderedmap.New[string, any]()
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	wantKeys := []string{"z", "a", "m"}
	gotKeys := make([]string, 0, decoded.Len())
	for pair := decoded.Oldest(); pair != nil; pair = pair.Next() {
		gotKeys = append(gotKeys, pair.Key)
	}
	if strings.Join(gotKeys, ",") != strings.Join(wantKeys, ",") {
		t.Errorf("key order not preserved through round-trip: got %v, want %v", gotKeys, wantKeys)
	}
}

// TestUnmarshalPreservesKeyOrder is the load-bearing case for
// invopop/jsonschema: it relies on the OrderedMap to keep JSON property
// order. The rewritten Unmarshal MUST use json.Decoder.Token() (stream
// order), not json.Unmarshal into map[string]any (random order).
func TestUnmarshalPreservesKeyOrder(t *testing.T) {
	input := []byte(`{"id":"identity-1","schema_id":"default","traits":{"email":"a@b.c"},"state":"active","verifiable_addresses":[]}`)

	om := orderedmap.New[string, json.RawMessage]()
	if err := json.Unmarshal(input, om); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := []string{"id", "schema_id", "traits", "state", "verifiable_addresses"}
	got := make([]string, 0, om.Len())
	for pair := om.Oldest(); pair != nil; pair = pair.Next() {
		got = append(got, pair.Key)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("key order not preserved: got %v, want %v", got, want)
	}
}

// TestMarshalNil verifies the nil-handling path emits "null" like
// upstream (rather than panicking).
func TestMarshalNil(t *testing.T) {
	var om *orderedmap.OrderedMap[string, any]
	b, err := json.Marshal(om)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "null" {
		t.Errorf("nil OrderedMap should marshal to 'null', got %s", b)
	}
}

// TestIntKey verifies that integer keys are stringified on the wire (the
// JSON spec requires object keys to be strings; upstream did this with
// easyjson.IntStr).
func TestIntKey(t *testing.T) {
	om := orderedmap.New[int, string]()
	om.Set(1, "one")
	om.Set(2, "two")

	encoded, err := json.Marshal(om)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(encoded) != `{"1":"one","2":"two"}` {
		t.Errorf("expected stringified int keys, got %s", encoded)
	}

	decoded := orderedmap.New[int, string]()
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := decoded.Get(1); !ok || v != "one" {
		t.Errorf("expected decoded[1]='one', got %q (ok=%v)", v, ok)
	}
}

// textMarshalerKey is a type whose MarshalText output contains JSON
// metacharacters (`"`, `\`, control bytes). Encoding its value as a map
// key must JSON-escape the bytes — writing them raw would emit invalid
// JSON.
type textMarshalerKey string

func (t textMarshalerKey) MarshalText() ([]byte, error) {
	return []byte(string(t)), nil
}

func (t *textMarshalerKey) UnmarshalText(b []byte) error {
	*t = textMarshalerKey(b)
	return nil
}

// TestTextMarshalerKey_SpecialChars guards against the JSON-injection /
// invalid-JSON regression where a TextMarshaler-produced byte slice was
// written between surrounding quotes without escaping.
func TestTextMarshalerKey_SpecialChars(t *testing.T) {
	om := orderedmap.New[textMarshalerKey, string]()
	om.Set(`has "quotes"`, "v1")
	om.Set(`has\backslash`, "v2")
	om.Set("has\tcontrol", "v3")

	encoded, err := json.Marshal(om)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Output must be valid JSON when handed back to the stdlib decoder.
	var roundtrip map[string]string
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatalf("marshalled output is not valid JSON: %v\nencoded: %s", err, encoded)
	}
	if roundtrip[`has "quotes"`] != "v1" || roundtrip[`has\backslash`] != "v2" || roundtrip["has\tcontrol"] != "v3" {
		t.Errorf("keys not preserved through round-trip: %#v", roundtrip)
	}
}

// TestLargeUint64WrapperKey guards against silent precision loss when
// decoding wrapper-typed numeric keys (`type MyID uint64`). Previously
// the code unmarshalled into `any` (→ float64), which round-trips lossily
// for values > 2^53.
func TestLargeUint64WrapperKey(t *testing.T) {
	type myID uint64
	const big myID = 9007199254740993 // 2^53 + 1 — not exactly representable as float64

	encoded := []byte(fmt.Sprintf(`{"%d":"v"}`, big))
	om := orderedmap.New[myID, string]()
	if err := json.Unmarshal(encoded, om); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, ok := om.Get(big)
	if !ok {
		// Walk what we have to surface what got decoded.
		var got myID
		for pair := om.Oldest(); pair != nil; pair = pair.Next() {
			got = pair.Key
			break
		}
		t.Fatalf("expected key %d to decode exactly; got %d (off by %d)", big, got, int64(got)-int64(big))
	}
	if v != "v" {
		t.Errorf("value mismatch: %q", v)
	}
}

// TestNestedJSON exercises the json.RawMessage path that
// invopop/jsonschema actually uses — values are arbitrary JSON, not
// typed. The Unmarshal path must hand off to json.Unmarshal for value
// decoding (we use json.RawMessage to keep the value intact).
func TestNestedJSON(t *testing.T) {
	input := []byte(`{"outer":{"inner":{"deep":true}}}`)
	om := orderedmap.New[string, json.RawMessage]()
	if err := json.Unmarshal(input, om); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := om.Get("outer")
	if !ok {
		t.Fatal("missing 'outer' key")
	}
	if string(raw) != `{"inner":{"deep":true}}` {
		t.Errorf("nested value not preserved: %s", raw)
	}
}
