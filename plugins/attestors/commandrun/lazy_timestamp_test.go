// Copyright 2026 The Rookery Contributors
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

package commandrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLazyTimestamp_WireFormatUnchanged is the contract test for the
// commandrun perf optimization that moved Timestamp from `string` to
// `time.Time`. Every captured-event type must round-trip through JSON
// with the timestamp serialized as an RFC3339Nano string so verifiers
// and existing on-disk attestations remain readable. This test loops
// over every event struct that carries a Timestamp and asserts the
// emitted JSON is identical to what the old `Format(time.RFC3339Nano)`
// path produced.
func TestLazyTimestamp_WireFormatUnchanged(t *testing.T) {
	// A deliberately-precise sub-second value catches any truncation
	// or rounding bug introduced by the lazy-format path.
	ts := time.Date(2026, 5, 23, 12, 34, 56, 123456789, time.UTC)
	want := "2026-05-23T12:34:56.123456789Z"
	require.Equal(t, want, ts.Format(time.RFC3339Nano),
		"sanity: time.Time formats to expected RFC3339Nano literal")

	cases := []struct {
		name string
		val  interface{}
	}{
		{"FileWrite", FileWrite{Path: "/x", Bytes: 1, Timestamp: ts}},
		{"FileRename", FileRename{OldPath: "/a", NewPath: "/b", Timestamp: ts}},
		{"FileDelete", FileDelete{Path: "/x", Timestamp: ts}},
		{"FilePermChange", FilePermChange{Path: "/x", Mode: 0o755, SetExec: true, Timestamp: ts}},
		{"FileLink", FileLink{SourcePath: "/a", LinkPath: "/b", IsSymlink: true, Timestamp: ts}},
		{"FileTruncate", FileTruncate{Path: "/x", NewSize: 100, Timestamp: ts}},
		{"DirOp", DirOp{Path: "/x", Op: "mkdir", Mode: 0o700, Timestamp: ts}},
		{"SyscallEvent", SyscallEvent{Syscall: "ptrace", Detail: "PTRACE_ATTACH", Timestamp: ts}},
		{"NetworkConnection", NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "1.2.3.4", Port: 443, FD: 5, Timestamp: ts, Hostname: "example.com"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.val)
			require.NoError(t, err)

			// Field MUST appear in JSON as the exact RFC3339Nano string.
			expected := `"timestamp":"` + want + `"`
			assert.True(t, strings.Contains(string(b), expected),
				"JSON %s missing %s", string(b), expected)

			// Parse back and confirm the timestamp value reads as a string
			// equal to what the old code path would have written. This is
			// the wire-format invariant external verifiers depend on.
			var generic map[string]interface{}
			require.NoError(t, json.Unmarshal(b, &generic))
			tsField, ok := generic["timestamp"].(string)
			require.True(t, ok, "timestamp field must be a JSON string, got %T", generic["timestamp"])
			parsed, err := time.Parse(time.RFC3339Nano, tsField)
			require.NoError(t, err)
			assert.Equal(t, ts.UTC(), parsed.UTC())
		})
	}
}

// TestLazyTimestamp_ZeroValueOmitted verifies the omitempty contract is
// preserved: an unset Timestamp (zero time.Time) is dropped from the
// JSON output rather than emitting "0001-01-01T00:00:00Z". This matters
// because the previous string-based field used the default omitempty
// behavior — a downstream parser that distinguishes "no timestamp" from
// "epoch timestamp" must keep working.
func TestLazyTimestamp_ZeroValueOmitted(t *testing.T) {
	cases := []struct {
		name string
		val  interface{}
	}{
		{"FileWrite", FileWrite{Path: "/x", Bytes: 1}},
		{"FileRename", FileRename{OldPath: "/a", NewPath: "/b"}},
		{"FileDelete", FileDelete{Path: "/x"}},
		{"FilePermChange", FilePermChange{Path: "/x", Mode: 0o755}},
		{"FileLink", FileLink{SourcePath: "/a", LinkPath: "/b"}},
		{"FileTruncate", FileTruncate{Path: "/x"}},
		{"DirOp", DirOp{Path: "/x", Op: "rmdir"}},
		{"SyscallEvent", SyscallEvent{Syscall: "ptrace"}},
		{"NetworkConnection", NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "1.2.3.4", FD: 5}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.val)
			require.NoError(t, err)
			assert.False(t, strings.Contains(string(b), "timestamp"),
				"JSON %s must omit timestamp for zero value", string(b))
		})
	}
}

// TestLazyTimestamp_NoSubSecondPrecision verifies the RFC3339Nano
// emitter prints whole-second timestamps without a fractional part —
// matching what `Format(time.RFC3339Nano)` produced. If Go ever
// changed the default time.Time.MarshalJSON to always print 9 digits
// of precision, this test would catch a wire-format regression.
func TestLazyTimestamp_NoSubSecondPrecision(t *testing.T) {
	ts := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	want := `"timestamp":"2026-05-23T12:00:00Z"`

	w := FileWrite{Path: "/x", Bytes: 1, Timestamp: ts}
	b, err := json.Marshal(w)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(b), want),
		"JSON %s missing expected zero-fractional timestamp %s", string(b), want)
}
