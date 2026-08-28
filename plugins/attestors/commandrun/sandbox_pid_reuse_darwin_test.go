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

//go:build darwin

package commandrun

import (
	"os"
	"testing"
)

// A pid is only a name: after the pid space wraps, a new process inherits an
// old pid, and facts cached at first sighting would hand it the dead
// process's proven ancestry — letting a pid-wrapping build put a stranger's
// execs and connections inside the signed tree, or hide its own under a
// retired canary pid. Incarnation is the kernel start time; when it moves,
// the pid's facts must be POISONED to unproven, never inherited.
func TestRecycledPidPoisonsItsFacts(t *testing.T) {
	t.Parallel()
	cached := procFacts{ppid: 10, pgid: 10, startSec: 1000, startUsec: 42, ok: true}

	t.Run("same incarnation keeps its facts", func(t *testing.T) {
		t.Parallel()
		got, recycled := reconcileFacts(cached, procFacts{ppid: 10, pgid: 10, startSec: 1000, startUsec: 42, ok: true})
		if recycled || !got.ok {
			t.Fatalf("an unchanged incarnation lost its facts: got=%+v recycled=%v", got, recycled)
		}
	})

	t.Run("exited process keeps its facts for late reports", func(t *testing.T) {
		t.Parallel()
		got, recycled := reconcileFacts(cached, procFacts{})
		if recycled || !got.ok {
			t.Fatalf("late reports for an exited process lost their facts: got=%+v recycled=%v", got, recycled)
		}
	})

	t.Run("new incarnation is poisoned to unproven", func(t *testing.T) {
		t.Parallel()
		got, recycled := reconcileFacts(cached, procFacts{ppid: 10, pgid: 10, startSec: 2000, startUsec: 7, ok: true})
		if !recycled {
			t.Fatal("a pid whose start time moved was not flagged as recycled")
		}
		if got.ok {
			t.Fatalf("a recycled pid kept proven facts %+v — the new process inherited a dead process's ancestry", got)
		}
	})
}

// Canary identity must not outlive the canary. The probes are excluded from
// the tree, so a pid the kernel recycles onto a build process after the probe
// died must STOP being a canary — otherwise every exec that process performs
// is skipped as "our probe", and a fork-heavy build gets a blessed pid to
// hide work under. The pid here is kernel-proven (facts chain to the root)
// and its report was NOT stamped canary-era at arrival, yet the pid is still
// listed in the snapshot's canary set: the exec must land in the signed tree.
func TestRecycledCanaryPidCannotHideExecs(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	const recycledPid = 555
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: recycledPid, op: opExecStar, detail: "/usr/bin/curl"},
		},
		members:  map[int]bool{rootPid: true, recycledPid: true},
		canaries: map[int]bool{recycledPid: true},
		facts: map[int]procFacts{
			rootPid:     {ppid: 1, pgid: rootPid, ok: true},
			recycledPid: {ppid: rootPid, pgid: rootPid, ok: true},
		},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	p := findProcess(procs, recycledPid)
	if p == nil {
		t.Fatalf("a kernel-proven tree pid's exec vanished because its pid was once a canary; diag=%+v", *diag)
	}
	if p.Program != "/usr/bin/curl" {
		t.Errorf("recycled-canary pid recorded program %q, want %q", p.Program, "/usr/bin/curl")
	}
	if diag.ExecReports != 2 {
		t.Errorf("ExecReports = %d, want 2 — the recycled pid's exec must be counted, not skipped as a probe", diag.ExecReports)
	}
}

// TestCanaryIdentityIsIncarnationNotPid drives the record-time decision that
// feeds the stamp above, against the real kernel: the canary's registration is
// its pid PLUS the start time read at publish, and a LIVE process with a
// different start time on that pid retires the registration on its very next
// report. The live process here is the test binary itself — a pid that is
// certainly alive and certainly pollable.
func TestCanaryIdentityIsIncarnationNotPid(t *testing.T) {
	self := os.Getpid()
	liveFacts := pollProcFacts(self)
	if !liveFacts.ok {
		t.Fatal("could not poll the test binary's own kernel facts")
	}

	t.Run("recycled canary pid is retired at its next report", func(t *testing.T) {
		s := &sandboxSession{
			facts:  map[int]procFacts{},
			pinned: map[imageIdentity]pinnedImage{},
			// A probe registered long ago: same pid, an incarnation the kernel
			// has since handed to the live process running this test.
			canaryPIDs: map[int]procFacts{self: {startSec: 1, startUsec: 1, ok: true}},
			ourPids:    map[int]bool{},
		}
		s.record(sandboxEvent{pid: self, op: opFork})

		if len(s.events) != 1 {
			t.Fatalf("events = %d, want 1", len(s.events))
		}
		if s.events[0].canary {
			t.Error("a report under a RECYCLED canary pid was stamped as the probe's — " +
				"the live owner's work would be skipped out of the signed tree")
		}
		if s.isCanaryPid(self) {
			t.Error("a canary pid disproven by incarnation stayed registered — the exclusion outlived the probe")
		}
		if s.pidReuse != 1 {
			t.Errorf("pidReuse = %d, want 1 — the recycle must be counted in the diagnostics", s.pidReuse)
		}
		if f := s.facts[self]; !f.ok {
			t.Error("the live owner's kernel facts were not cached at retirement; its ancestry could not be resolved")
		}
	})

	t.Run("live probe incarnation keeps its registration", func(t *testing.T) {
		s := &sandboxSession{
			facts:      map[int]procFacts{},
			pinned:     map[imageIdentity]pinnedImage{},
			canaryPIDs: map[int]procFacts{self: liveFacts},
			ourPids:    map[int]bool{},
		}
		s.record(sandboxEvent{pid: self, op: opFork})

		if !s.events[0].canary {
			t.Error("a report under a canary pid whose incarnation still matches was not stamped as the probe's")
		}
		if !s.isCanaryPid(self) {
			t.Error("a live probe's registration was retired — its late reports would join the tree as strangers")
		}
		if s.pidReuse != 0 {
			t.Errorf("pidReuse = %d, want 0", s.pidReuse)
		}
	})

	t.Run("unreadable publish incarnation cannot be disproven", func(t *testing.T) {
		s := &sandboxSession{
			facts:      map[int]procFacts{},
			pinned:     map[imageIdentity]pinnedImage{},
			canaryPIDs: map[int]procFacts{self: {}},
			ourPids:    map[int]bool{},
		}
		s.record(sandboxEvent{pid: self, op: opFork})

		if !s.events[0].canary {
			t.Error("with no publish incarnation to compare, the registration must stand (the probe-skip is the happy path)")
		}
	})
}
