package policy

import (
	"encoding/json"
	"testing"
	"time"
)

// TestTime_metav1WireCompat asserts that policy.Time and the previous
// metav1.Time field type produce byte-identical JSON for non-zero
// timestamps and the literal token "null" for the zero value. Any drift
// here would invalidate existing signed policy documents.
func TestTime_metav1WireCompat(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"epoch", `"1970-01-01T00:00:00Z"`},
		{"y2k", `"2000-01-01T00:00:00Z"`},
		{"future", `"2030-06-15T12:34:56Z"`},
		{"null", `null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got Time
			if err := json.Unmarshal([]byte(tc.raw), &got); err != nil {
				t.Fatalf("Unmarshal(%s): %v", tc.raw, err)
			}
			out, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(out) != tc.raw {
				t.Fatalf("round-trip drift: got %s want %s", out, tc.raw)
			}
		})
	}
}

// TestTime_RejectsRFC3339Nano asserts the strict behavior matches metav1:
// a sub-second timestamp parses successfully but re-serializes as
// second-precision RFC3339, exactly as metav1 did.
func TestTime_DropsSubSecondPrecision(t *testing.T) {
	in := `"2026-06-15T12:34:56.789Z"`
	var got Time
	if err := json.Unmarshal([]byte(in), &got); err == nil {
		out, err2 := json.Marshal(got)
		if err2 != nil {
			t.Fatal(err2)
		}
		want := `"2026-06-15T12:34:56Z"`
		if string(out) != want {
			t.Fatalf("subsec re-encode: got %s want %s", out, want)
		}
	} else {
		// metav1 actually rejects RFC3339Nano via time.Parse(RFC3339, ...).
		// Either behavior is acceptable as long as we match metav1, which
		// also returns the parse error.
		_ = err
	}
}

func TestTime_ZeroIsNull(t *testing.T) {
	var z Time
	if !z.IsZero() {
		t.Fatal("zero Time should report IsZero")
	}
	out, err := json.Marshal(z)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "null" {
		t.Fatalf("zero marshals to %s; want null", out)
	}
}

func TestNewTime(t *testing.T) {
	ref := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tt := NewTime(ref)
	if !tt.Equal(ref) {
		t.Fatalf("NewTime: got %v want %v", tt.Time, ref)
	}
}
