// Copyright 2026 TestifySec, Inc.
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
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// The v0.2 wire shape is hand-maintained, and the two existing guards do not
// reach this field. TestEverySignedFieldHasASection walks V02Predicate's
// TOP-LEVEL fields only, and TestEverySignedFieldSurvivesRoundTrip explicitly
// EXEMPTS "processes" — so a per-event digest, which lives two levels down
// inside processes → syscalls, is covered by neither.
//
// That matters more than an ordinary uncovered field. A digest silently
// dropped on the wire is the failure mode the section guard's own comment
// calls "strictly worse than never collecting it": the attestor measures the
// image, the operator believes the evidence exists, a digest-deny policy has
// nothing to match on, and nothing anywhere fails. So the claim is checked
// against the encoder rather than reasoned about from the struct tags.
func TestPerEventExecDigestSurvivesTheV02WireShape(t *testing.T) {
	const digestHex = "b1946ac92492d2347c6235b4d2611184f5c2bd1a1c0b1c2d3e4f5a6b7c8d9e0f"
	orig := &CommandRun{
		Cmd:      []string{"/bin/sh", "-c", "exit 0"},
		ExitCode: 0,
		Processes: []ProcessInfo{{
			ProcessID: 4242,
			Program:   "/bin/sh",
			SyscallEvents: []SyscallEvent{{
				Syscall:      "execve",
				Path:         "/bin/sh",
				DigestSource: "collector-open-path-hash",
				PathDigestAtCollectorOpen: cryptoutil.DigestSet{
					cryptoutil.DigestValue{Hash: crypto.SHA256}: digestHex,
				},
			}},
		}},
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The bytes themselves, before any decode: a decoder that reconstructs a
	// field the encoder never wrote would hide the drop.
	if !strings.Contains(string(raw), digestHex) {
		t.Fatalf("the per-event digest is not in the SIGNED bytes at all — a digest-deny policy has nothing "+
			"to match and the gap is invisible. wire=%s", truncateForMsg(string(raw)))
	}

	var back CommandRun
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Processes) != 1 || len(back.Processes[0].SyscallEvents) != 1 {
		t.Fatalf("processes/syscalls did not survive: %+v", back.Processes)
	}
	ev := back.Processes[0].SyscallEvents[0]
	if len(ev.PathDigestAtCollectorOpen) != 1 {
		t.Fatalf("per-event digest dropped by the round trip: %+v", ev)
	}
	for _, got := range ev.PathDigestAtCollectorOpen {
		if got != digestHex {
			t.Errorf("per-event digest = %q, want %q", got, digestHex)
		}
	}
	if ev.DigestSource != "collector-open-path-hash" {
		t.Errorf("digestSource = %q, want collector-open-path-hash — the digest without its provenance "+
			"label is an unqualified claim", ev.DigestSource)
	}
}

// The other half of the same contract question: the darwin diagnostics hang
// off summary.diagnostics.darwin. "summary" IS a top-level section, so the
// section guard sees it — but the guard only proves the section is emitted,
// never that a nested block inside it survives. These counters are what a
// verifier reads to decide whether the tree is a complete account or an
// incomplete one presented as complete, so losing them silently converts
// "this trace has stated gaps" into "this trace is clean".
func TestDarwinDiagnosticsSurviveTheV02WireShape(t *testing.T) {
	orig := &CommandRun{
		Cmd: []string{"/bin/sh", "-c", "exit 0"},
		Summary: &TraceSummary{
			CaptureMode: "sandbox-report",
			Diagnostics: TraceDiagnostics{
				Darwin: &DarwinTraceDiagnostics{
					// THE LITERAL, NOT execDigestBindingCollectorOpen. That
					// constant lives in tracing_darwin.go, so referencing it here
					// compiles on macOS and fails typecheck on LINUX, where this
					// untagged file still builds — which is exactly how it reached
					// CI green-on-my-machine and red on `lint rookery subtree`.
					// It is also the better assertion: this test pins the value
					// that goes ON THE WIRE, so it must fail if the constant's
					// value ever changes, which a reference to the constant could
					// never do.
					ExecDigestBinding:               "path-at-collector-open-time",
					NetworkReportsUnprovenOwnership: 7,
					UnprovenPIDs:                    3,
					ImagesUnhashed:                  1,
				},
			},
		},
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back CommandRun
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Summary == nil || back.Summary.Diagnostics.Darwin == nil {
		t.Fatalf("the darwin diagnostics block was dropped — a trace with stated gaps would read as clean; "+
			"summary=%+v", back.Summary)
	}
	d := back.Summary.Diagnostics.Darwin
	if d.ExecDigestBinding != "path-at-collector-open-time" {
		t.Errorf("execDigestBinding = %q, want %q — the label that tells a verifier what the digest binds",
			d.ExecDigestBinding, "path-at-collector-open-time")
	}
	if d.NetworkReportsUnprovenOwnership != 7 || d.UnprovenPIDs != 3 || d.ImagesUnhashed != 1 {
		t.Errorf("gap counters did not survive: unprovenOwnership=%d unprovenPIDs=%d imagesUnhashed=%d, want 7/3/1",
			d.NetworkReportsUnprovenOwnership, d.UnprovenPIDs, d.ImagesUnhashed)
	}
}

// The exec OUTCOME has to survive the wire too, and for the same reason the
// digest does: `syscall: "execve"` with a populated Program reads as "this
// image ran" to every consumer, and on this backend an allow report proves
// only that the sandbox PERMITTED the exec. execve's return value is not
// observable, so a permitted exec that then failed with ENOENT is
// indistinguishable from one that ran. Saying that only in a free-text note
// gives a policy no machine-readable way to tell the weaker semantics apart.
func TestExecOutcomeSurvivesTheV02WireShape(t *testing.T) {
	orig := &CommandRun{
		Cmd: []string{"/bin/sh"},
		Processes: []ProcessInfo{{
			ProcessID: 4242,
			Program:   "/bin/sh",
			SyscallEvents: []SyscallEvent{{
				Syscall: "execve",
				Path:    "/bin/sh",
				Outcome: "permitted-not-confirmed",
			}},
		}},
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), "permitted-not-confirmed") {
		t.Fatalf("the exec outcome is not in the SIGNED bytes — a policy has no way to tell an ATTEMPT from an "+
			"execution. wire=%s", truncateForMsg(string(raw)))
	}
	var back CommandRun
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Processes) != 1 || len(back.Processes[0].SyscallEvents) != 1 {
		t.Fatalf("processes/syscalls did not survive: %+v", back.Processes)
	}
	if got := back.Processes[0].SyscallEvents[0].Outcome; got != "permitted-not-confirmed" {
		t.Errorf("outcome = %q, want permitted-not-confirmed", got)
	}
}
