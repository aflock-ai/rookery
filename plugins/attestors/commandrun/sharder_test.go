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
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSharder_StickyAssignment(t *testing.T) {
	// A given pid is always routed to the same worker.
	s := newPIDSharder(4)
	for pid := 100; pid < 200; pid++ {
		first := s.WorkerFor(pid)
		for i := 0; i < 10; i++ {
			assert.Equal(t, first, s.WorkerFor(pid),
				"pid %d should consistently map to worker %d", pid, first)
		}
	}
}

func TestSharder_LeastLoadedAssignment(t *testing.T) {
	// Sequential new pids should spread across workers via least-loaded.
	s := newPIDSharder(4)
	for pid := 1; pid <= 4; pid++ {
		s.WorkerFor(pid)
	}
	load, total := s.stats()
	assert.Equal(t, 4, total)
	// Each worker should have exactly one assignment.
	for i, l := range load {
		assert.Equal(t, 1, l, "worker %d expected load 1, got %d", i, l)
	}
}

func TestSharder_LoadBalanceUnderManyPids(t *testing.T) {
	// 1000 pids across 4 workers — load should be near 250 each.
	s := newPIDSharder(4)
	for pid := 1; pid <= 1000; pid++ {
		s.WorkerFor(pid)
	}
	load, total := s.stats()
	assert.Equal(t, 1000, total)
	for i, l := range load {
		// With least-loaded picking, distribution must be exactly equal
		// (deterministic algorithm).
		assert.Equal(t, 250, l, "worker %d load expected 250, got %d", i, l)
	}
}

func TestSharder_ReleaseReclaimsSlot(t *testing.T) {
	s := newPIDSharder(2)
	// Assign 10 pids.
	for pid := 1; pid <= 10; pid++ {
		s.WorkerFor(pid)
	}
	loadBefore, _ := s.stats()
	require.Equal(t, []int{5, 5}, loadBefore)

	// Release all worker-0 assignments.
	for pid := 1; pid <= 10; pid++ {
		if s.WorkerFor(pid) == 0 {
			s.Release(pid)
		}
	}
	loadAfter, totalAfter := s.stats()
	assert.Equal(t, 5, totalAfter, "released pids removed")
	assert.Equal(t, 0, loadAfter[0])
	assert.Equal(t, 5, loadAfter[1])

	// A new pid should now go to worker 0 (least-loaded).
	pid := 999
	assert.Equal(t, 0, s.WorkerFor(pid))
}

func TestSharder_ReleaseUnknownPidIsNoop(t *testing.T) {
	s := newPIDSharder(2)
	s.WorkerFor(1)
	loadBefore, _ := s.stats()
	s.Release(9999) // never assigned
	loadAfter, _ := s.stats()
	assert.Equal(t, loadBefore, loadAfter)
}

func TestSharder_SingleWorkerDegenerate(t *testing.T) {
	// n=1 sends everything to worker 0.
	s := newPIDSharder(1)
	for pid := 1; pid <= 100; pid++ {
		assert.Equal(t, 0, s.WorkerFor(pid))
	}
}

func TestSharder_ZeroOrNegativeNDefaultsToOne(t *testing.T) {
	s := newPIDSharder(0)
	assert.Equal(t, 0, s.WorkerFor(42))
	s2 := newPIDSharder(-5)
	assert.Equal(t, 0, s2.WorkerFor(42))
}

func TestSharder_ConcurrentSafe(t *testing.T) {
	// Many goroutines hammering WorkerFor + Release. Race detector
	// + assertion: every pid's assignment is consistent across goroutines.
	s := newPIDSharder(4)
	const goroutines = 16
	const pidsPerGoroutine = 250
	var wg sync.WaitGroup
	results := make([][]int, goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		results[g] = make([]int, pidsPerGoroutine)
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Use overlapping pid ranges so the workers see contention.
			for i := 0; i < pidsPerGoroutine; i++ {
				pid := g*100 + i
				results[g][i] = s.WorkerFor(pid)
			}
		}()
	}
	wg.Wait()
	// Cross-check: same pid → same worker across goroutines.
	for g := 0; g < goroutines; g++ {
		for i := 0; i < pidsPerGoroutine; i++ {
			pid := g*100 + i
			want := results[g][i]
			got := s.WorkerFor(pid)
			require.Equal(t, want, got, "pid %d inconsistent across reads", pid)
		}
	}
}

// FuzzSharder_StickyAcrossArbitraryOps — given any sequence of
// (op, pid) tuples, the sharder must keep its sticky-assignment
// invariant. Op 0 = WorkerFor, Op 1 = Release.
func FuzzSharder_StickyAcrossArbitraryOps(f *testing.F) {
	// Seeds.
	f.Add(int8(4), []byte{0, 1, 0, 2, 0, 3, 0, 1, 1, 1, 0, 1})
	f.Add(int8(1), []byte{0, 7, 1, 7, 0, 7})
	f.Add(int8(8), []byte{}) // empty op sequence
	f.Add(int8(2), []byte{0, 0, 0, 0, 1, 0}) // pid 0 quirks

	f.Fuzz(func(t *testing.T, nWorkers int8, opStream []byte) {
		if nWorkers < 0 {
			nWorkers = -nWorkers
		}
		if nWorkers > 32 {
			nWorkers %= 32
		}
		s := newPIDSharder(int(nWorkers))
		seen := make(map[int]int) // pid -> expected worker

		for i := 0; i+1 < len(opStream); i += 2 {
			op := opStream[i] & 1
			pid := int(int8(opStream[i+1])) // signed pid for variety
			switch op {
			case 0: // WorkerFor
				w := s.WorkerFor(pid)
				if exp, ok := seen[pid]; ok && exp != w {
					t.Fatalf("sticky violated: pid %d was %d, now %d", pid, exp, w)
				}
				seen[pid] = w
			case 1: // Release
				s.Release(pid)
				delete(seen, pid)
			}
		}
		// After all ops: every still-assigned pid in `seen` must still
		// resolve to the recorded worker.
		for pid, exp := range seen {
			got := s.WorkerFor(pid)
			if got != exp {
				t.Fatalf("post-stream pid %d expected %d got %d", pid, exp, got)
			}
		}
	})
}

// FuzzSharder_NeverPanics — guarantee no out-of-range / divide-by-zero
// / negative-index panic for any nWorkers + pid combination.
func FuzzSharder_NeverPanics(f *testing.F) {
	f.Add(int8(0), 0)
	f.Add(int8(-1), -1)
	f.Add(int8(127), 999999)
	f.Add(int8(1), -42)
	f.Fuzz(func(t *testing.T, n int8, pid int) {
		s := newPIDSharder(int(n))
		_ = s.WorkerFor(pid)
		s.Release(pid)
	})
}

// BenchmarkSharder_WorkerFor measures the cost of the hot-path operation.
// Must be in the nanoseconds range — if it isn't, the sharder is itself
// the bottleneck.
func BenchmarkSharder_WorkerFor(b *testing.B) {
	s := newPIDSharder(8)
	// Pre-populate to avoid measuring the new-pid path.
	for pid := 1; pid <= 1024; pid++ {
		s.WorkerFor(pid)
	}
	r := rand.New(rand.NewSource(42))
	pids := make([]int, b.N)
	for i := range pids {
		pids[i] = r.Intn(1024) + 1
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.WorkerFor(pids[i])
	}
}

func BenchmarkSharder_WorkerForParallel(b *testing.B) {
	s := newPIDSharder(8)
	for pid := 1; pid <= 1024; pid++ {
		s.WorkerFor(pid)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(7))
		for pb.Next() {
			_ = s.WorkerFor(r.Intn(1024) + 1)
		}
	})
}
