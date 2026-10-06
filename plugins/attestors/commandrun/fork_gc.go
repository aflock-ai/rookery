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
	"math"
	"os/exec"
	"runtime/debug"
	"sync"
)

// forkGCMu serialises the GC-off window: SetGCPercent is process-global, so
// two concurrent starts must not restore each other's saved value.
var forkGCMu sync.Mutex

// startWithoutCollector starts c, and when the fanotify gate is armed it does
// so with the garbage collector off for exactly the length of the fork.
//
// Go forks with clone(CLONE_VFORK|CLONE_VM) and the forking thread cannot be
// preempted until the child execs. The child's execve opens the binary and
// its ELF interpreter; under the gate each open is a FAN_OPEN_PERM event only
// this process's handler goroutines can answer. A GC stop-the-world that
// starts inside that window waits for the forking thread, the thread waits
// for the exec, and the exec waits for a handler the stop-the-world has
// frozen: the whole process stops for good, its own timers included
// (buildbox docker-runner-40, 94+ minutes, tracee in D in
// fanotify_get_response).
//
// SetGCPercent(-1) returns only after any in-flight mark phase has finished,
// and while it holds no allocation can start a cycle, so no stop-the-world
// begins between here and the restore. c.Start returns once the child has
// exec'd, which is when the vfork window closes.
func startWithoutCollector(c *exec.Cmd, fanotifyArmed bool) error {
	if !fanotifyArmed {
		return c.Start()
	}
	forkGCMu.Lock()
	defer forkGCMu.Unlock()
	// A GOMEMLIMIT still triggers collection with GC percent off, so the
	// limit is lifted for the same window.
	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(prevLimit)
	prev := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prev)
	return c.Start()
}
