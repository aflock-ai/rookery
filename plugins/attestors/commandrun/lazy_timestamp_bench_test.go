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
	"testing"
	"time"
)

// These benchmarks compare the OLD hot-path (string-format the timestamp
// at capture time, ~500ns + ~42-byte alloc per event) against the NEW
// hot-path (store a time.Time, defer formatting to JSON marshal). They
// measure capture-time work only — JSON marshalling happens once per
// attestation, but capture happens once per syscall, so the per-event
// allocation is what dominates GC pressure on 100K+ syscall builds.

// oldFileWrite mirrors the pre-refactor FileWrite shape (Timestamp as
// a pre-formatted string). It exists only so the benchmark can replay
// the previous hot-path cost without resurrecting the old code.
type oldFileWrite struct {
	Path      string
	Bytes     int
	Timestamp string
}

// BenchmarkTimestamp_OldCapture measures the pre-refactor capture cost:
// time.Now().UTC().Format(time.RFC3339Nano) per event. This is the path
// we are replacing.
func BenchmarkTimestamp_OldCapture(b *testing.B) {
	b.ReportAllocs()
	sink := make([]oldFileWrite, 0, b.N)
	for i := 0; i < b.N; i++ {
		sink = append(sink, oldFileWrite{
			Path:      "/tmp/x",
			Bytes:     1024,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	// Reference sink so escape analysis cannot eliminate the append.
	if len(sink) != b.N {
		b.Fatalf("sink len mismatch: %d != %d", len(sink), b.N)
	}
}

// BenchmarkTimestamp_NewCapture measures the post-refactor capture cost:
// time.Now().UTC() per event. Formatting is deferred to JSON marshal.
func BenchmarkTimestamp_NewCapture(b *testing.B) {
	b.ReportAllocs()
	sink := make([]FileWrite, 0, b.N)
	for i := 0; i < b.N; i++ {
		sink = append(sink, FileWrite{
			Path:      "/tmp/x",
			Bytes:     1024,
			Timestamp: time.Now().UTC(),
		})
	}
	if len(sink) != b.N {
		b.Fatalf("sink len mismatch: %d != %d", len(sink), b.N)
	}
}

// BenchmarkTimestamp_Format isolates the cost of the string-format step
// alone (no struct construction, no slice append) so the per-call
// allocation/latency saved by the optimization is visible directly.
func BenchmarkTimestamp_Format(b *testing.B) {
	b.ReportAllocs()
	now := time.Now().UTC()
	var sink string
	for i := 0; i < b.N; i++ {
		sink = now.Format(time.RFC3339Nano)
	}
	if sink == "" {
		b.Fatal("sink unset")
	}
}

// BenchmarkTimestamp_Now isolates the cost of capturing the timestamp
// as a time.Time. This is what the new hot path pays. It should be
// strictly less than Format(time.RFC3339Nano).
func BenchmarkTimestamp_Now(b *testing.B) {
	b.ReportAllocs()
	var sink time.Time
	for i := 0; i < b.N; i++ {
		sink = time.Now().UTC()
	}
	if sink.IsZero() {
		b.Fatal("sink unset")
	}
}
