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

//go:build darwin

package commandrun

import (
	"encoding/json"
	"testing"
)

// The portable coverage model keys on this name; if the darwin backend is
// renamed without updating it, every macOS trace would read tracer-unknown.
func TestDarwinBackendNameMatchesCoverageModel(t *testing.T) {
	if darwinTraceBackend != TraceBackendDarwinSandbox {
		t.Fatalf("darwinTraceBackend %q != TraceBackendDarwinSandbox %q", darwinTraceBackend, TraceBackendDarwinSandbox)
	}
}

// A real, unprivileged macOS trace carries summary.coverage on the signed
// wire, names the sandbox tracer, and states that it is partial: the same
// field and meaning a Linux ptrace trace carries.
func TestDarwinTraceStatesItsCoverage(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\n/bin/cat /etc/hosts >/dev/null\n/bin/ls >/dev/null\n")
	rc, err := traceScript(t, []string{"/bin/sh", script})
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	b, err := json.Marshal(rc)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Summary struct {
			Coverage *TraceCoverage `json:"coverage"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	cov := body.Summary.Coverage
	if cov == nil {
		t.Fatal("signed macOS trace carries no summary.coverage")
	}
	if cov.Tracer != TraceBackendDarwinSandbox || cov.Complete {
		t.Fatalf("coverage = %+v; want tracer %q, complete=false", cov, TraceBackendDarwinSandbox)
	}
	kinds := map[string]bool{}
	for _, g := range cov.Gaps {
		kinds[g.Kind] = true
	}
	for _, want := range []string{GapExecSuccessUnconfirmed, GapExecDigestUnbound, GapFileReadsUnobserved} {
		if !kinds[want] {
			t.Errorf("coverage gaps %+v missing %q", cov.Gaps, want)
		}
	}
	for _, linuxOnly := range []string{GapFanotifyStateUnknown, GapFanotifyDisabled, GapSyscallsUntraced} {
		if kinds[linuxOnly] {
			t.Errorf("macOS coverage carries Linux gap %q", linuxOnly)
		}
	}
	// A short-lived child can exec and exit inside the report channel's
	// delivery latency, so its kernel facts are gone before the poll and it
	// is left out of the tree (measured here: 5 of 25 runs lost cat or ls).
	// That is the backend's documented limit. The property under test is
	// that the loss is STATED: every exec missing from the tree must be
	// accounted for by processes-unproven.
	imgs := execedImages(rc)
	if !imgs["/bin/sh"] {
		t.Errorf("process tree lacks the root /bin/sh: %v", imgs)
	}
	var missing uint64
	for _, want := range []string{"/bin/cat", "/bin/ls"} {
		if !imgs[want] {
			missing++
		}
	}
	var unproven uint64
	for _, g := range cov.Gaps {
		if g.Kind == GapProcessesUnproven {
			unproven = g.Count
		}
	}
	if unproven < missing {
		dd, _ := json.Marshal(rc.Summary.Diagnostics.Darwin)
		t.Errorf("%d exec(s) missing from the tree (%v) but coverage states only %d unproven process(es)\n"+
			"coverage gaps: %+v\ndarwin diagnostics: %s", missing, imgs, unproven, cov.Gaps, dd)
	}
}
