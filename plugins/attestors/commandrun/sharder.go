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
	"sync"
)

// pidSharder routes a (pid → worker-index) mapping for the multi-tracer
// event distribution (#167).
//
// Contract:
//
//  1. Causal ordering: every event for a given pid is routed to the
//     same worker. The handler's per-pid ProcessInfo state is mutated
//     by only one goroutine, so no per-pid mutex is needed.
//
//  2. Deterministic assignment: a given pid is always assigned to the
//     same worker for the lifetime of this sharder. Re-assignment is
//     not supported (would break ordering).
//
//  3. Sticky on first observation: the first event for a new pid
//     decides the worker for that pid. The choice is load-balanced
//     against current per-worker counts (least-loaded wins; ties
//     broken by lowest-index).
//
//  4. Concurrent-safe: WorkerFor may be called from any goroutine.
//
// Used at the boundary of runTrace: each ptrace stop is keyed by pid;
// the sharder tells us which worker queue receives the event.
type pidSharder struct {
	mu       sync.Mutex
	n        int            // number of workers
	assigned map[int]int    // pid -> worker index
	load     []int          // load[i] = count of pids currently assigned to worker i
}

// newPIDSharder returns a sharder with n workers (n ≥ 1).
func newPIDSharder(n int) *pidSharder {
	if n < 1 {
		n = 1
	}
	return &pidSharder{
		n:        n,
		assigned: make(map[int]int, 64),
		load:     make([]int, n),
	}
}

// WorkerFor returns the worker index for pid. If pid hasn't been seen
// before, it's assigned to the least-loaded worker.
func (s *pidSharder) WorkerFor(pid int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.assigned[pid]; ok {
		return w
	}
	// Pick least-loaded worker, tiebreak by lowest index.
	w := 0
	for i := 1; i < s.n; i++ {
		if s.load[i] < s.load[w] {
			w = i
		}
	}
	s.assigned[pid] = w
	s.load[w]++
	return w
}

// Release frees a pid's assignment when the process exits, so its
// slot is reclaimed for future assignments. Calling Release on an
// unknown pid is a no-op.
func (s *pidSharder) Release(pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.assigned[pid]; ok {
		s.load[w]--
		if s.load[w] < 0 {
			s.load[w] = 0
		}
		delete(s.assigned, pid)
	}
}

// stats returns (per-worker assignment count, total assigned pids).
// Test/diagnostic use only.
func (s *pidSharder) stats() ([]int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, s.n)
	copy(out, s.load)
	return out, len(s.assigned)
}
