package policy

import (
	"encoding/json"
	"time"
)

// Time is a thin wrapper around time.Time that marshals to / unmarshals from
// JSON using exactly the wire format that k8s.io/apimachinery/pkg/apis/meta/v1.Time
// used (RFC3339 in UTC, with "null" for the zero value). Drop-in replacement
// for the field type previously imported from metav1 — keeps all existing
// signed policy documents valid without touching the on-wire bytes.
type Time struct {
	time.Time
}

// NewTime constructs a Time from a stdlib time.Time.
func NewTime(t time.Time) Time {
	return Time{Time: t}
}

// MarshalJSON encodes the timestamp as an RFC3339 string in UTC, matching
// metav1.Time. A zero time is encoded as JSON "null".
func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	buf := make([]byte, 0, len(time.RFC3339)+2)
	buf = append(buf, '"')
	buf = t.UTC().AppendFormat(buf, time.RFC3339)
	buf = append(buf, '"')
	return buf, nil
}

// UnmarshalJSON accepts "null" (zero value) or an RFC3339 string, matching
// metav1.Time.
func (t *Time) UnmarshalJSON(b []byte) error {
	if len(b) == 4 && string(b) == "null" {
		t.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = parsed.Local()
	return nil
}
