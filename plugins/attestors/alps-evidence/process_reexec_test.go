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

//go:build linux || darwin

package alpsevidence

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reexecHelperEnv selects the helper role when the test binary re-invokes
// itself. Distinct from the ROOKERY_AGENT_CONTEXT_HELPER key used by the live
// suite so the two helper families can never trigger each other.
const reexecHelperEnv = "ROOKERY_AGENT_CONTEXT_REEXEC_HELPER"

// reexecProbeKey is the environment variable whose value changes across the
// helper's execve. Reading the post-exec value through a pre-exec instance is
// exactly the evidence corruption the regression pins.
const reexecProbeKey = "ROOKERY_AGENT_CONTEXT_REEXEC_PROBE"

const (
	reexecReadyMarker = "REEXEC_HELPER_READY"
	reexecDoneMarker  = "REEXEC_HELPER_REEXECED"
)

// TestReexecHelperProcess is not a test. It is the body of the child process
// TestReadEnvironmentRefusesSamePathReexec spawns.
//
// Phase 1 announces itself, waits for the parent to capture it, then calls
// execve on ITS OWN EXECUTABLE PATH — the same pathname it is already running.
// The kernel keeps the pid and the start time across that exec, and the image
// path is unchanged by construction, so every field the pre-fix instance check
// compared survives while argv and the environment are replaced. Phase 2 is
// the post-exec image: it announces the exec completed and parks until the
// parent kills it.
func TestReexecHelperProcess(t *testing.T) {
	switch os.Getenv(reexecHelperEnv) {
	case "1":
		fmt.Println(reexecReadyMarker)
		// Wait for the parent to capture the phase-1 instance.
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			fmt.Println("helper: stdin read failed:", err)
			os.Exit(1)
		}
		self, err := os.Executable()
		if err != nil {
			fmt.Println("helper: no executable path:", err)
			os.Exit(1)
		}
		env := []string{
			reexecHelperEnv + "=2",
			reexecProbeKey + "=post-exec-value",
		}
		// Keep the test-binary plumbing the harness needs.
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, reexecHelperEnv+"=") || strings.HasPrefix(kv, reexecProbeKey+"=") {
				continue
			}
			env = append(env, kv)
		}
		// Same pathname, different argv, different environment: the canonical
		// same-path re-exec.
		err = syscall.Exec(self, []string{self, "-test.run=TestReexecHelperProcess$", "reexec-phase2-argv-differs"}, env)
		fmt.Println("helper: exec failed:", err)
		os.Exit(1)
	case "2":
		fmt.Println(reexecDoneMarker)
		// Outlive the parent's assertions; the parent kills this process.
		time.Sleep(60 * time.Second)
	default:
		t.Skip("not the reexec helper child")
	}
}

// TestReadEnvironmentRefusesSamePathReexec is the same-path execve regression.
//
// The defect: pid and start time both survive execve, and a process can exec
// the SAME pathname it is already running — a self-update re-exec, or `exec
// "$0"` in a wrapper. An instance check built from pid, start time and image
// path alone therefore accepts the post-exec process image, and an environment
// read bound by that check returns the NEW image's values to be published
// beside the OLD image's argv, fingerprint and ancestry inside signed
// evidence.
//
// The child re-execs its own binary between capture and read, changing its
// argv and its environment while keeping pid, start time and executable path
// identical. The environment read through the pre-exec instance must refuse —
// ErrEnvironmentUnreadable, no values — because the captured instance's
// execution generation is gone.
func TestReadEnvironmentRefusesSamePathReexec(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	cmd := exec.Command(self, "-test.run=TestReexecHelperProcess$")
	cmd.Env = append(os.Environ(),
		reexecHelperEnv+"=1",
		reexecProbeKey+"=pre-exec-value",
	)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	scanner := bufio.NewScanner(stdout)
	waitForMarker := func(marker string) {
		t.Helper()
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), marker) {
				return
			}
		}
		t.Fatalf("helper never printed %q (scan err: %v)", marker, scanner.Err())
	}

	src := NewOSProcessSource()

	// Capture the phase-1 instance, exactly as the ancestry walk would.
	waitForMarker(reexecReadyMarker)
	captured, err := src.ReadProcess(cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, self, captured.Executable,
		"the captured image must be the test binary itself, or the same-path premise is broken")

	// Release the helper and wait until the execve has demonstrably completed:
	// the done marker is printed by the post-exec image.
	_, err = io.WriteString(stdin, "go\n")
	require.NoError(t, err)
	waitForMarker(reexecDoneMarker)

	// The post-exec process still matches every field the pre-fix check
	// compared: same pid, same start time, same executable path.
	current, err := src.ReadProcess(cmd.Process.Pid)
	require.NoError(t, err)
	assert.Equal(t, captured.PID, current.PID)
	assert.Equal(t, captured.StartTime, current.StartTime, "start time must survive execve for this regression to mean anything")
	assert.Equal(t, captured.Executable, current.Executable, "the image path must be unchanged for this regression to mean anything")

	// The environment read addressed by the PRE-exec instance must refuse:
	// returning values here pairs the post-exec environment with the pre-exec
	// argv, fingerprint and ancestry.
	values, err := src.ReadEnvironment(captured.instance(), []string{reexecProbeKey})
	require.Error(t, err,
		"a same-path re-exec'd process must not satisfy the captured instance: pid, start time and image path all survive execve")
	assert.ErrorIs(t, err, ErrEnvironmentUnreadable,
		"refusal must read as an unreadable environment, not as values or a walk failure")
	assert.Empty(t, values, "no environment values may escape a refused instance bind")
}

// TestValidateBindsExecutionGeneration pins the clause the live regression
// exercises, without a kernel: identical pid, start time and image path are
// NOT enough to satisfy an instance bind, because all three survive a
// same-path execve.
func TestValidateBindsExecutionGeneration(t *testing.T) {
	captured := ProcessInfo{
		PID:            4242,
		StartTime:      "1000.000001",
		Executable:     "/usr/local/bin/codex",
		execGeneration: "gen-a",
	}.instance()

	// The same execution still validates.
	assert.NoError(t, captured.validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex", execGeneration: "gen-a",
	}), "an unchanged instance must validate")

	// A same-path re-exec: every pre-fix field identical, generation changed.
	assert.Error(t, captured.validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex", execGeneration: "gen-b",
	}), "a changed execution generation must refuse the bind even when pid, start time and path all match")

	// No generation on the current side: the re-exec cannot be ruled out, so
	// the bind fails CLOSED — same polarity as the absent start time.
	assert.Error(t, captured.validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex",
	}), "an absent execution generation must fail closed, not pass as agreement")

	// No generation on the captured side either: still refused. "No evidence
	// of an exec" is not evidence of no exec.
	assert.Error(t, ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex",
	}.instance().validate(ProcessInfo{
		PID: 4242, StartTime: "1000.000001", Executable: "/usr/local/bin/codex",
	}), "two generation-less readings must not bind to each other")
}
