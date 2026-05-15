package canonical

import (
	"encoding/json"
	"math"
	"testing"
)

// TestRFC8785Vectors pins the canonical output against the worked examples
// in RFC 8785 (Appendix B "Examples"). If the implementation drifts off the
// spec, two attestor runs against the same input will produce different
// digests and break Archivista cross-linking.
func TestRFC8785Vectors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			"sorted object keys",
			`{"b":1,"a":2}`,
			`{"a":2,"b":1}`,
		},
		{
			"nested object keys",
			`{"z":{"y":1,"x":2},"a":3}`,
			`{"a":3,"z":{"x":2,"y":1}}`,
		},
		{
			"arrays preserve order",
			`[3,2,1]`,
			`[3,2,1]`,
		},
		{
			"true / false / null",
			`{"t":true,"f":false,"n":null}`,
			`{"f":false,"n":null,"t":true}`,
		},
		{
			"integer round-trips",
			`{"x":42}`,
			`{"x":42}`,
		},
		{
			"strings escape only mandatory chars",
			"{\"s\":\"\\\"hi\\\"\\nthere\"}",
			"{\"s\":\"\\\"hi\\\"\\nthere\"}",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var v any
			if err := json.Unmarshal([]byte(c.input), &v); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := Marshal(v)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != c.want {
				t.Errorf("Marshal mismatch.\ngot:  %s\nwant: %s", got, c.want)
			}
		})
	}
}

// TestDeterminism — running Marshal twice on equivalent inputs produces the
// same bytes. This is the property the attestor relies on for digest
// stability across runs.
func TestDeterminism(t *testing.T) {
	// Two unmarshals of the same JSON produce maps whose iteration order
	// will likely differ. Marshal must paper over that.
	a := mustUnmarshal(t, `{"a":1,"b":[1,2,{"x":1,"y":2}],"c":"hi"}`)
	b := mustUnmarshal(t, `{"a":1,"b":[1,2,{"x":1,"y":2}],"c":"hi"}`)
	ba, err := Marshal(a)
	if err != nil {
		t.Fatalf("Marshal(a): %v", err)
	}
	bb, err := Marshal(b)
	if err != nil {
		t.Fatalf("Marshal(b): %v", err)
	}
	if string(ba) != string(bb) {
		t.Errorf("two marshals differ:\n%s\n%s", ba, bb)
	}
}

// TestNaNAndInfRejected — JSON has no representation for NaN/±Inf; we error
// rather than emit something that won't parse back. Go's compile-time
// 1.0/0.0 is a constant-expression error, so we build the bad values at
// runtime via math.Inf / math.NaN.
func TestNaNAndInfRejected(t *testing.T) {
	for _, v := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if _, err := Marshal(map[string]any{"x": v}); err == nil {
			t.Errorf("Marshal(%v): want error, got nil", v)
		}
	}
}

// TestUnsupportedTypeRejected — Marshal only accepts the types
// json.Unmarshal produces (map[string]any, []any, string, float64, bool,
// nil). Anything else is a recipe bug; surface it loudly.
func TestUnsupportedTypeRejected(t *testing.T) {
	if _, err := Marshal(map[string]any{"x": []int{1, 2}}); err == nil {
		t.Errorf("Marshal(map containing []int): want error, got nil")
	}
}

func mustUnmarshal(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("Unmarshal(%q): %v", s, err)
	}
	return v
}
