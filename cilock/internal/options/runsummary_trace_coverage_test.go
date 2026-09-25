// jade:ring local
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

package options

import (
	"bytes"
	"strings"
	"testing"
)

// A partial trace is stated on the operator's terminal, naming the gap kinds,
// so a degraded run (no fanotify, ptrace fallback, macOS) is never presented
// as if it were a complete one.
func TestRunSummary_TraceCoverageLine(t *testing.T) {
	s := sampleSummary()
	s.TraceCoverage = &TraceCoverageSummary{
		Tracer: "ptrace+seccomp",
		Gaps:   []string{"fanotify-unavailable", "syscalls-untraced"},
	}
	var buf bytes.Buffer
	s.WriteHuman(&buf)
	want := "trace:      ptrace+seccomp, PARTIAL (gaps: fanotify-unavailable, syscalls-untraced;"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("human summary missing %q:\n%s", want, buf.String())
	}

	s.TraceCoverage = &TraceCoverageSummary{Tracer: "ebpf", Complete: true}
	buf.Reset()
	s.WriteHuman(&buf)
	if !strings.Contains(buf.String(), "trace:      ebpf, complete") {
		t.Fatalf("human summary missing complete line:\n%s", buf.String())
	}

	s.TraceCoverage = nil
	buf.Reset()
	s.WriteHuman(&buf)
	if strings.Contains(buf.String(), "trace:      ") {
		t.Fatalf("untraced run must not print a trace line:\n%s", buf.String())
	}
}
