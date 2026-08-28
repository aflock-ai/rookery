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
	"os/exec"
	"testing"
	"time"
)

func drainSession() *sandboxSession {
	return &sandboxSession{
		facts:      map[int]procFacts{},
		pinned:     map[imageIdentity]pinnedImage{},
		canaryPIDs: map[int]procFacts{},
		ourPids:    map[int]bool{},
	}
}

// Exhausting the drain deadline while possibly-ours reports keep arriving
// must FAIL the trace, not return success: killing the collector at an
// arbitrary moment of ongoing activity presents an incomplete tree as
// complete. (The earlier revision returned nil on exhaustion.)
func TestDrainDeadlineExhaustionFailsClosed(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.lastInTree = time.Now()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.mu.Lock()
			s.lastInTree = time.Now()
			s.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if err := s.awaitQuiet(time.Now().Add(300 * time.Millisecond)); err == nil {
		t.Fatal("awaitQuiet returned success while activity never went quiet — the trace would sign an incomplete tree as complete")
	}
}

// A stream that goes quiet drains normally.
func TestDrainQuietStreamSucceeds(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.lastInTree = time.Now().Add(-time.Second)
	if err := s.awaitQuiet(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("awaitQuiet failed on a quiet stream: %v", err)
	}
}

// The quiet clock must tick only for reports that COULD be this build's.
// Without the scope, any sandboxed app on the machine would hold the window
// open and the fail-closed drain would refuse honest builds on busy Macs.
func TestQuietClockIgnoresProvenForeignReports(t *testing.T) {
	t.Parallel()
	s := drainSession()
	rootPid := os.Getpid() // stand in as the traced root: a real, live process
	s.rootPid = rootPid

	// A real child of ours: kernel facts prove its chain to the root.
	child := exec.Command("/bin/sleep", "5")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()

	past := time.Now().Add(-time.Hour)

	// launchd: facts readable, provably NOT ours. Must not touch the clock.
	s.mu.Lock()
	s.lastInTree = past
	s.facts[1] = pollProcFacts(1)
	s.noteActivity(1)
	foreign := s.lastInTree
	s.mu.Unlock()
	if !foreign.Equal(past) {
		t.Error("a proven-foreign report refreshed the quiet clock; busy machines could never drain")
	}

	// Our child: chain reaches the root, must refresh the clock.
	s.mu.Lock()
	s.lastInTree = past
	s.facts[child.Process.Pid] = pollProcFacts(child.Process.Pid)
	s.noteActivity(child.Process.Pid)
	ours := s.lastInTree
	s.mu.Unlock()
	if ours.Equal(past) {
		t.Error("a report from the build's own descendant did not refresh the quiet clock")
	}

	// A pid nobody can read: not provably foreign, must refresh the clock.
	s.mu.Lock()
	s.lastInTree = past
	s.facts[99999999] = procFacts{}
	s.noteActivity(99999999)
	unknown := s.lastInTree
	s.mu.Unlock()
	if unknown.Equal(past) {
		t.Error("an unattributable report did not refresh the quiet clock; unknown is not provably foreign")
	}
}

// A kernel-proven descendant that is still RUNNING when the evidence is about
// to be signed detached itself from the reaped group on purpose; the trace
// must name it a survivor. A zombie is not a survivor (it cannot act), and a
// recycled pid (different start time) is not one either.
func TestSurvivingDetachedDescendantIsDetected(t *testing.T) {
	t.Parallel()
	rootPid := os.Getpid()

	live := exec.Command("/bin/sleep", "30")
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = live.Process.Kill()
		_ = live.Wait()
	}()
	livePid := live.Process.Pid

	members := map[int]bool{rootPid: true, livePid: true}
	facts := map[int]procFacts{
		rootPid: pollProcFacts(rootPid),
		livePid: pollProcFacts(livePid),
	}

	survivors, err := survivingDarwinMembers(rootPid, members, facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(survivors) != 1 || survivors[0] != livePid {
		t.Fatalf("survivingDarwinMembers = %v, want [%d] — a still-running proven descendant must fail the trace closed", survivors, livePid)
	}

	// Kill it and reap it fully: a process that no longer exists is no survivor.
	_ = live.Process.Kill()
	_ = live.Wait()
	survivors, err = survivingDarwinMembers(rootPid, members, facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(survivors) != 0 {
		t.Fatalf("survivingDarwinMembers = %v after the descendant was reaped, want none", survivors)
	}
}
