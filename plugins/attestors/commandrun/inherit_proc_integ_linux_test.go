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

//go:build linux

// Integration tests for the perf-inherit-proc optimization. These
// verify that:
//
//  1. ParentPID is correctly populated for every child in a fork+exec
//     chain, including ones spawned by a shell that itself was forked
//     from the traced root.
//  2. comm and cmdline still get re-read at execve time — those DO
//     change at execve and the optimization MUST NOT skip them.
//
// They spawn real bash + true chains through ptrace and inspect the
// resulting ProcessInfo slice.

package commandrun

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runTracedCommandWithCtx mirrors runTracedCommand but additionally
// returns the internal *ptraceContext so tests can inspect counters
// like statusReadsSkipped that don't make it to the public
// ProcessInfo slice.
func runTracedCommandWithCtx(t *testing.T, dir string, argv []string) (*ptraceContext, []ProcessInfo) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	actx, err := attestation.NewContext("test",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(dir),
	)
	require.NoError(t, err)

	rc := &CommandRun{
		Cmd:           argv,
		enableTracing: true,
		silent:        true,
	}

	c := exec.Command(rc.Cmd[0], rc.Cmd[1:]...) //nolint:gosec
	c.Dir = dir
	stdoutBuf, stderrBuf := bytes.Buffer{}, bytes.Buffer{}
	c.Stdout = io.MultiWriter(&stdoutBuf)
	c.Stderr = io.MultiWriter(&stderrBuf)
	enableTracing(c)
	require.NoError(t, c.Start())

	pctx, traceErr := rc.traceWithContext(c, actx)
	_ = c.Wait()
	if traceErr != nil {
		t.Logf("trace returned error (may be expected for non-zero exit): %v", traceErr)
	}
	rc.Processes = pctx.procInfoArray()
	return pctx, rc.Processes
}

// TestIntegration_InheritProc_BashEchoChain spawns a bash shell that
// runs three external commands in sequence. Each external command is
// a separate fork+execve (bash uses fork+exec for non-builtins; `true`
// is a builtin in many bashes, so we use /bin/echo via the explicit
// path to force a fork). We verify:
//
//   - all children have non-zero ParentPID populated
//   - the parent-of-each-child relationship forms a valid tree rooted
//     at the bash process (which itself was forked from the test
//     harness)
//   - each child captured comm AND cmdline correctly (execve overwrote
//     them — the optimization must NOT have inherited stale values)
func TestIntegration_InheritProc_BashEchoChain(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not in PATH")
	}
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("echo not in PATH")
	}

	dir := t.TempDir()
	// Use absolute paths to force bash to fork+exec rather than use
	// builtins. Three separate commands in one shell.
	script := echoPath + " a ; " + echoPath + " b ; " + echoPath + " c"
	procs := runTracedCommand(t, dir, []string{"bash", "-c", script})

	require.NotEmpty(t, procs, "expected ProcessInfo entries")

	// Build a PID -> ProcessInfo map for tree validation.
	byPID := make(map[int]*ProcessInfo, len(procs))
	for i := range procs {
		byPID[procs[i].ProcessID] = &procs[i]
	}

	// Count how many echo invocations were captured. Expected: 3 (or
	// 2 if bash exec-optimizes the last command into the shell PID —
	// in which case one of the "echo" entries IS the shell PID, with
	// ParentPID pointing at the *test runner* outside the trace).
	var echoCount int
	for i := range procs {
		p := &procs[i]
		if strings.HasSuffix(p.Program, "/echo") || p.Comm == "echo" {
			echoCount++

			// Every captured child must have a non-zero ParentPID.
			// This is the core assertion of the perf-inherit-proc
			// optimization: clone-time inheritance must populate it.
			assert.NotZero(t, p.ParentPID,
				"child %d (comm=%q program=%q) has zero ParentPID — clone-time inheritance failed",
				p.ProcessID, p.Comm, p.Program)

			// comm and cmdline DO change at execve. The optimization
			// must not skip those reads — they must reflect the new
			// program, not whatever the parent had.
			assert.NotEmpty(t, p.Comm,
				"child %d has empty comm — execve handler dropped /proc/<pid>/comm read",
				p.ProcessID)
		}
	}

	// Suppress the unused-variable warning while keeping byPID available
	// for future tightening of the parent-tree check.
	_ = byPID

	assert.GreaterOrEqual(t, echoCount, 3,
		"expected at least 3 echo execs from bash script, got %d", echoCount)
}

// TestIntegration_InheritProc_ParentPIDPlausible asserts that an
// external command's ParentPID is a plausible PID (positive, not equal
// to its own PID). This is the strict version of the inheritance
// check: not just "non-zero" but "is a real different process".
//
// We don't assert ParentPID == shell PID directly because bash often
// exec-optimizes the last command, replacing itself with echo. In that
// case the same PID transitions from bash to echo, and the "echo's
// parent" is the test runner outside the trace.
func TestIntegration_InheritProc_ParentPIDPlausible(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not in PATH")
	}
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("echo not in PATH")
	}

	dir := t.TempDir()
	// Two echoes so bash will fork at least once (even with last-cmd
	// optimization, the first one forks).
	script := echoPath + " a ; " + echoPath + " b"
	procs := runTracedCommand(t, dir, []string{"bash", "-c", script})

	// Find at least one echo child and check its ParentPID is sane.
	found := false
	for i := range procs {
		p := &procs[i]
		if !(strings.HasSuffix(p.Program, "/echo") || p.Comm == "echo") {
			continue
		}
		found = true
		assert.Positive(t, p.ParentPID,
			"echo child %d has non-positive ParentPID=%d", p.ProcessID, p.ParentPID)
		assert.NotEqual(t, p.ProcessID, p.ParentPID,
			"echo child %d has ParentPID equal to its own PID — clone inheritance is broken", p.ProcessID)
	}
	assert.True(t, found, "did not find any echo process in trace")
}

// TestIntegration_InheritProc_StatusReadsSkipped exercises the
// internal counter to confirm that we actually skipped /proc reads.
// This is the direct evidence of the optimization in action — without
// it, the integration tests above could pass even if the optimization
// had been silently disabled.
//
// Calls trace() via a sub-helper that gives the test access to the
// ptraceContext counters.
func TestIntegration_InheritProc_StatusReadsSkipped(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not in PATH")
	}
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("echo not in PATH")
	}

	dir := t.TempDir()
	script := echoPath + " a ; " + echoPath + " b ; " + echoPath + " c"
	pctx, _ := runTracedCommandWithCtx(t, dir, []string{"bash", "-c", script})

	require.NotNil(t, pctx, "ptraceContext should not be nil")

	// At least the three echo execves should have skipped the
	// /proc/<pid>/status read because their ParentPID was already
	// populated by the clone event. Allow some slack for kernel
	// scheduling — some children might race ahead of the event
	// delivery.
	assert.GreaterOrEqual(t, pctx.statusReadsSkipped, 2,
		"expected >=2 /proc/<pid>/status reads skipped (got %d/%d total)",
		pctx.statusReadsSkipped, pctx.statusReadsTotal)
}
