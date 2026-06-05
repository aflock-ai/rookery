// Copyright 2021 The Witness Contributors
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

//go:build !windows

package commandrun

import (
	"os/exec"
	"syscall"
)

// configureProcessReaping puts the wrapped command in its OWN process
// group (Setpgid) and wires c.Cancel to signal that whole group, so a
// lingering descendant that inherited the stdout/stderr pipe write-end
// is actually killed — letting the pipes reach EOF naturally — rather
// than merely abandoned. This composes with c.WaitDelay (set by the
// caller): Cancel handles context-cancellation, WaitDelay handles the
// "process exited but a grandchild still holds the pipe" hang. Together
// they guarantee c.Wait() can never block forever on the copy goroutines.
//
// Invariants this MUST preserve:
//   - It runs BEFORE enableTracing / applyTraceePrivilegeDrop, which set
//     SysProcAttr.Ptrace and SysProcAttr.Credential on the SAME struct.
//     We only set Setpgid (allocating SysProcAttr if nil, mirroring the
//     existing nil-guard pattern), so those later writers are never
//     clobbered — and they in turn guard with `if c.SysProcAttr == nil`,
//     so they reuse the struct we allocate here.
//   - Setpgid is orthogonal to Ptrace: the child still stops at exec for
//     the tracer, and the ptrace loop's Wait4(-1, WALL) still reaps every
//     descendant regardless of process group. Setpgid only changes which
//     pgid those descendants share, which is precisely what lets Cancel
//     signal them as a group.
//
// Cancel is invoked by os/exec ONLY when the command's Context is done
// (e.g. operator Ctrl-C or an attestation timeout). On the normal,
// non-cancelled path it never runs. We signal the negative pgid
// (== the leader's pid, since Setpgid with Pgid==0 makes the child a
// group leader) so EVERY descendant in the group receives SIGKILL.
// Returning the kill error (or nil) lets os/exec proceed to its own
// WaitDelay-bounded pipe close, so this can never itself wedge Wait.
func configureProcessReaping(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Setpgid with Pgid==0 (the zero value) makes the child the leader of
	// a new process group whose pgid equals the child's pid.
	c.SysProcAttr.Setpgid = true

	c.Cancel = func() error {
		// c.Process is nil if Start() never succeeded; nothing to kill.
		if c.Process == nil {
			return nil
		}
		// Signal the whole group (negative pid == pgid). This reaps any
		// backgrounded / stranded descendant holding the inherited pipe
		// write-end, so the copy goroutines hit EOF and Wait returns.
		// ESRCH (group already gone) is benign.
		if err := syscall.Kill(-c.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
		return nil
	}
}
