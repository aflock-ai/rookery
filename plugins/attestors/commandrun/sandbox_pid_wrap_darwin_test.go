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
	"errors"
	"strings"
	"testing"
)

var errTestProbe = errors.New("probe could not start")

// Every pid-keyed claim in a session — ancestry read at first sighting, probe
// exclusion, late-report attribution — assumes a pid names ONE process for the
// whole run. XNU allocates pids from a single counter that wraps at PID_MAX,
// so a pid can only be recycled after a wrap, and our own probes sample that
// counter: a probe pid below the previous probe's is the wrap, observed. A
// wrapped session must refuse to attest rather than sign a tree in which one
// pid may name two processes.
func TestPidCounterWrapFailsClosed(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.mu.Lock()
	s.noteProbePid(99_990) // readiness probe, near the top of the pid space
	s.noteProbePid(120)    // drain probe: the counter came back around
	s.mu.Unlock()

	_, err := s.harvest()
	if err == nil {
		t.Fatal("a session whose probe pids went backwards harvested a tree — pid identity was unprovable")
	}
	if !strings.Contains(err.Error(), "pid counter wrapped") {
		t.Fatalf("the refusal must name the wrap so the operator re-runs the step: %v", err)
	}
}

// Probes whose pids only ever advance are the normal shape and must not refuse.
func TestAdvancingProbePidsAreNotAWrap(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.mu.Lock()
	for _, pid := range []int{500, 501, 4_000, 99_999} {
		s.noteProbePid(pid)
	}
	s.mu.Unlock()
	if _, err := s.harvest(); err != nil {
		t.Fatalf("monotonic probe pids were refused: %v", err)
	}
}

// A probe the watch could not publish is not "no wrap": the counter went
// unsampled from that point on, and the session must say so instead of
// harvesting as if the watch had run.
func TestWrapWatchFailureFailsClosed(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.mu.Lock()
	s.wrapWatchErr = errTestProbe
	s.mu.Unlock()
	_, err := s.harvest()
	if err == nil || !strings.Contains(err.Error(), "pid-counter watch stopped") {
		t.Fatalf("a dead pid-counter watch did not refuse the harvest: %v", err)
	}
}

// stopWrapWatch runs from trace() and again from shutdown(); the second call
// must be a no-op, and a session that never started the watch must tolerate
// the stop.
func TestWrapWatchStopIsIdempotent(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.stopWrapWatch()
	s.startWrapWatch()
	s.stopWrapWatch()
	s.stopWrapWatch()

	// AND THE WATCHER IS ACTUALLY DEAD. The sequence above is the one that
	// used to leak: the first stop ran before any start and consumed the
	// sync.Once from inside, so the stop after startWrapWatch did nothing and
	// the ticker goroutine survived, publishing probes into the machine-wide
	// log stream for the life of the process — into whatever session read the
	// stream next. The old test asserted only that the calls did not panic,
	// which the leaking version satisfied perfectly.
	select {
	case <-s.wrapDone:
	default:
		t.Fatal("the pid-wrap watcher is still running after stopWrapWatch: a stop that preceded the start " +
			"consumed the once guard, so the real stop was a no-op and the probe goroutine leaked")
	}
}
