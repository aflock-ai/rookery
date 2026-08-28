//go:build darwin

package commandrun

import (
	"runtime"
	"sync"
	"testing"
)

// EVENTS AND FACTS MUST BE ONE CONSISTENT READING.
//
// The collector's reader goroutine runs until shutdown, and `log stream` is
// machine-wide, so reports keep arriving the entire time the evidence is being
// assembled. When the events copy and the facts copy were two separate
// acquisitions of s.mu, a report landing in the gap reached s.facts — so the
// snapshot HAD its pid — while the events copy taken a moment earlier did NOT
// have its exec or connect. The tree was then built with a process present and
// the thing it did missing: a gap that reads as an absence, which is the one
// shape of evidence this backend refuses everywhere else.
//
// The drain establishes quiet beforehand, but quiet is a heuristic about
// timing and this is a guarantee about ordering; they are not substitutes.
//
// This drives a writer that appends an event AND its facts on every iteration,
// exactly as record() does, and asserts the two halves never disagree about
// which pids exist.
func TestHarvestAndSnapshotAreOneReading(t *testing.T) {
	s := &sandboxSession{
		facts:      map[int]procFacts{},
		pinned:     map[imageIdentity]pinnedImage{},
		canaryPIDs: map[int]procFacts{},
		ourPids:    map[int]bool{},
		unobserved: map[int]procFacts{},
		rootPid:    100,
		rootFacts:  procFacts{ppid: 1, pgid: 100, startSec: 1000, ok: true},
	}
	s.facts[100] = s.rootFacts

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// STRICTLY INCREASING pids, so "newer" is expressible as "higher".
		// Each is parented to the root, which keeps them proven members and
		// so keeps snapshotLocked from polling the kernel for undecidable
		// ancestry — otherwise the test measures its own arithmetic.
		for pid := 1001; ; pid++ {
			select {
			case <-stop:
				return
			default:
			}
			s.mu.Lock()
			s.facts[pid] = procFacts{ppid: 100, pgid: 100, startSec: 1001, ok: true}
			s.events = append(s.events, sandboxEvent{pid: pid, op: opExecStar, detail: "/bin/true"})
			s.mu.Unlock()
			// Yield. An unthrottled writer starves the reader and the test
			// measures lock contention instead of consistency.
			runtime.Gosched()
		}
	}()

	for i := 0; i < 300; i++ {
		events, snap, err := s.harvestAndSnapshot(nil)
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("harvestAndSnapshot: %v", err)
		}
		// THE SIGNATURE OF A GAP IS FACTS NEWER THAN EVENTS. Because the
		// writer publishes a fact and its event together, "every event pid has
		// facts" holds even when the two copies come from different moments —
		// that invariant cannot see this bug, and an earlier version of this
		// test asserted exactly that and passed against the broken code.
		//
		// A pid present in facts but HIGHER than anything in the events copy
		// means the facts were read after an event the events copy missed:
		// the tree would carry that process with its work absent.
		maxEvent := 0
		for _, ev := range events {
			if ev.pid > maxEvent {
				maxEvent = ev.pid
			}
		}
		for pid := range snap.facts {
			if pid != s.rootPid && pid > maxEvent {
				close(stop)
				wg.Wait()
				t.Fatalf("facts carry pid %d but the events copy stops at %d — the two halves came from "+
					"different moments, so the tree can be built with a process present and the thing it "+
					"did missing", pid, maxEvent)
			}
		}
	}
	close(stop)
	wg.Wait()
}
