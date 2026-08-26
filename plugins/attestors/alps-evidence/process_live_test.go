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

package alpsevidence

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helperEnvKey marks the re-executed test binary as the child process.
const helperEnvKey = "ROOKERY_ALPS_EVIDENCE_HELPER"

// TestALPSEvidenceHelperProcess is not a test. It is the body of the child
// process the live tests spawn: the test binary re-executes itself so the test
// controls the child's argv and environment exactly, which is the only way to
// assert what the platform process source actually reads.
func TestALPSEvidenceHelperProcess(t *testing.T) {
	if os.Getenv(helperEnvKey) != "1" {
		t.Skip("not the helper child")
	}
	// Outlive the parent's assertions; the parent kills this process when done.
	time.Sleep(60 * time.Second)
}

func supportedLivePlatform(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("no process source implemented for %s", runtime.GOOS)
	}
}

// startHelperChild spawns the test binary as a child with a known argv and
// environment, and returns its PID.
func startHelperChild(t *testing.T, extraEnv ...string) int {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The selector is anchored so it names exactly the sleeping helper above:
	// -test.run is an unanchored regexp, and the unanchored spelling also
	// matches TestALPSEvidenceHelperProcessExitsImmediately by prefix.
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestALPSEvidenceHelperProcess$",
		"-test.timeout=120s",
	)
	cmd.Env = append(os.Environ(), helperEnvKey+"=1")
	cmd.Env = append(cmd.Env, extraEnv...)
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// TestOSProcessSourceReadsTheRealExecutablePath is the claim that justifies
// replacing the prototype's ps(1) fallback on macOS.
//
// ps prints argv, and an agent's argv[0] is a rewritten title, so ps can never
// report the image path — which on macOS is where Claude Code's version lives.
// This test asserts the source returns the actual binary path for a live child.
func TestOSProcessSourceReadsTheRealExecutablePath(t *testing.T) {
	supportedLivePlatform(t)
	pid := startHelperChild(t)
	src := NewOSProcessSource()

	var info ProcessInfo
	require.Eventually(t, func() bool {
		var err error
		info, err = src.ReadProcess(pid)
		return err == nil && info.Executable != ""
	}, 10*time.Second, 25*time.Millisecond, "child process never became readable")

	assert.Equal(t, pid, info.PID)
	assert.Equal(t, os.Getpid(), info.PPID, "the helper's parent is this test process")
	assert.NotEmpty(t, info.Executable)
	assert.NotEmpty(t, info.Comm)
	assert.NotEmpty(t, info.StartTime, "start time is what disambiguates a recycled PID")

	// The image path must be an absolute path to a real file, not an argv token.
	require.True(t, os.IsPathSeparator(info.Executable[0]), "executable %q must be absolute", info.Executable)
	_, statErr := os.Stat(info.Executable)
	assert.NoError(t, statErr, "executable %q must exist on disk", info.Executable)
}

func TestOSProcessSourceReadsArgv(t *testing.T) {
	supportedLivePlatform(t)
	pid := startHelperChild(t)
	src := NewOSProcessSource()

	var info ProcessInfo
	require.Eventually(t, func() bool {
		var err error
		info, err = src.ReadProcess(pid)
		return err == nil && len(info.Argv) > 1
	}, 10*time.Second, 25*time.Millisecond)

	assert.Contains(t, info.Argv, "-test.run=^TestALPSEvidenceHelperProcess$")
}

// TestOSProcessSourceReadsAnotherProcessEnvironment. The prototype's macOS
// fallback returned an empty map unconditionally, which silently lost every
// environment-sourced field on that platform.
func TestOSProcessSourceReadsAnotherProcessEnvironment(t *testing.T) {
	supportedLivePlatform(t)
	pid := startHelperChild(t,
		"AGENT_CONTEXT_LIVE_PROBE=live-value",
		"AGENT_CONTEXT_LIVE_TOKEN=must-not-be-read",
	)
	src := NewOSProcessSource()

	var env map[string]string
	require.Eventually(t, func() bool {
		// The environment read is addressed by the captured INSTANCE, so the
		// live test does what every real caller does: capture the process
		// first, then read its environment bound to that capture.
		info, rerr := src.ReadProcess(pid)
		if rerr != nil {
			return false
		}
		var err error
		env, err = src.ReadEnvironment(info.instance(), []string{"AGENT_CONTEXT_LIVE_PROBE"})
		return err == nil && env["AGENT_CONTEXT_LIVE_PROBE"] != ""
	}, 10*time.Second, 25*time.Millisecond, "child environment never became readable")

	assert.Equal(t, "live-value", env["AGENT_CONTEXT_LIVE_PROBE"])
	assert.NotContains(t, env, "AGENT_CONTEXT_LIVE_TOKEN",
		"only requested keys may be returned; the source must not hand back the whole environment")
}

// TestOSProcessSourceReportsMissingProcesses. A reaped child is the only PID a
// test can be certain does not exist; PID 0 is the kernel task and sysctl
// happily returns it on macOS.
func TestOSProcessSourceReportsMissingProcesses(t *testing.T) {
	supportedLivePlatform(t)
	src := NewOSProcessSource()

	cmd := exec.Command(os.Args[0], "-test.run=^TestALPSEvidenceHelperProcessExitsImmediately$")
	cmd.Env = append(os.Environ(), helperEnvKey+"=exit")
	require.NoError(t, cmd.Start())
	deadPID := cmd.Process.Pid
	_ = cmd.Wait()

	_, err := src.ReadProcess(deadPID)
	require.Error(t, err, "a reaped pid must not read as a live process")
	assert.ErrorIs(t, err, ErrProcessNotFound)
}

// TestALPSEvidenceHelperProcessExitsImmediately is the second helper body: a
// child that exits at once so the parent has a reaped PID to probe.
func TestALPSEvidenceHelperProcessExitsImmediately(t *testing.T) {
	if os.Getenv(helperEnvKey) != "exit" {
		t.Skip("not the exiting helper child")
	}
}

// TestLiveAncestryWalkTerminates runs the real detector against this machine's
// real process tree. It asserts termination and internal consistency rather than
// a particular agent, because the CI runner and a developer laptop legitimately
// disagree about what is running.
func TestLiveAncestryWalkTerminates(t *testing.T) {
	supportedLivePlatform(t)

	d := NewDetector(NewOSProcessSource(), DefaultProviders())
	got, err := d.Detect(context.Background(), os.Getpid(), t.TempDir())
	require.NoError(t, err, "reading our own process must work on a supported platform")

	// A live tree may legitimately end any of three ways: an agent found, a
	// clean walk to a root with nothing found, or a walk stopped short by an
	// ancestor this user cannot read (common in containers and CI). Only
	// unavailable would be wrong here — the platform is supported.
	assert.Contains(t, []ObservationStatus{StatusDetected, StatusNotDetected, StatusIncomplete}, got.Status)
	assert.LessOrEqual(t, len(got.Ancestry), DefaultMaxDepth)

	if got.Status == StatusDetected {
		require.NotNil(t, got.Provider)
		assert.NotEmpty(t, got.Match.Fingerprint)
		require.NotEmpty(t, got.Chain)
		assert.Equal(t, got.Process.PID, got.Chain[0].PID)
		t.Logf("live detection: %s/%s via %s",
			got.Provider.Vendor(), got.Provider.Product(), got.Match.Fingerprint)
	} else {
		t.Logf("live walk found no supported agent in %d ancestors", len(got.Ancestry))
	}

	// Whatever it found, the ancestry must never carry a path.
	for _, ancestor := range got.Ancestry {
		assert.NotContains(t, ancestor.Program, "/")
	}
}

// TestLiveAttestProducesAServializablePredicate runs the whole attestor against
// the real machine and checks the output is well formed either way.
func TestLiveAttestProducesASerializablePredicate(t *testing.T) {
	supportedLivePlatform(t)

	a := New()
	err := a.Attest(mustLiveContext(t, a))
	require.NoError(t, err)

	assert.False(t, a.Assurance.Enforcement)
	assert.NotZero(t, a.CapturedAt)
	assert.NotEmpty(t, a.Status)
}

// startZombieChild spawns a child, waits for it to EXIT, and deliberately does
// not reap it — so the PID still resolves but its identity files are gone.
//
// This is the real form of "a process that exits between enumeration and read".
// It is not simulated: the kernel really does still answer for the PID (it is a
// zombie until reaped) while the executable link, the command line and, on
// macOS, the process arguments have all ceased to exist. Measured on this
// machine, the pre-fix source answered err=nil with an empty executable and no
// argv — a failed read wearing the shape of a successful one.
func startZombieChild(t *testing.T) int {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^TestALPSEvidenceHelperProcessExitsImmediately$")
	cmd.Env = append(os.Environ(), helperEnvKey+"=exit")
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid

	// Reaping is what destroys the zombie, so Wait is deferred to cleanup and
	// never called before the assertions.
	t.Cleanup(func() { _ = cmd.Wait() })

	src := NewOSProcessSource()
	require.Eventually(t, func() bool {
		p, err := src.ReadProcess(pid)
		return err == nil && p.Executable == ""
	}, 10*time.Second, 20*time.Millisecond, "child never became a readable zombie")
	return pid
}

// TestExitedProcessIsReportedAsPartiallyReadNotAsEmpty is hazard 12, and the
// recurring class of this attestor one layer below where it kept being found:
// "could not look" rendered as "found nothing".
//
// A zombie's PID still resolves, so the source returns no error, but its
// executable link and command line are gone. The values that come back are
// EMPTY, and an empty executable is exactly what a process legitimately without
// one looks like. Nothing downstream could tell the two apart.
//
// Red against the pre-fix code: ReadProcess returns a ProcessInfo that claims
// to have been fully examined.
func TestExitedProcessIsReportedAsPartiallyReadNotAsEmpty(t *testing.T) {
	supportedLivePlatform(t)
	pid := startZombieChild(t)

	p, err := NewOSProcessSource().ReadProcess(pid)
	require.NoError(t, err, "the PID still resolves; this is a partial read, not a missing process")

	assert.False(t, p.fullyExamined(),
		"a ProcessInfo assembled from failed identity reads must not claim to have been examined")
	assert.NotEmpty(t, p.identityGaps(),
		"the sources that could not be read must be named")
	assert.Contains(t, p.identityGaps(), identityExecutable)
}

// TestWalkPastAnUnexaminedAncestorCannotClaimNotDetected is the verdict half.
//
// not-detected is a POSITIVE claim about the whole ancestry: every ancestor was
// examined and none was an agent. An ancestor whose identity could not be read
// cannot support it — a provider might have matched on exactly the source that
// was missing. The walk therefore continues (the agent may still be further
// out) but the verdict degrades to incomplete, which policies already treat the
// way they treat unavailable.
//
// The unreadable ancestor here is a real zombie, and it is spliced in as the
// walk's own parent so the walk genuinely passes through it.
//
// Red against the pre-fix code: status is not-detected.
func TestWalkPastAnUnexaminedAncestorCannotClaimNotDetected(t *testing.T) {
	supportedLivePlatform(t)
	zombie := startZombieChild(t)

	src := NewOSProcessSource()
	partial, err := src.ReadProcess(zombie)
	require.NoError(t, err)
	require.False(t, partial.fullyExamined(), "fixture precondition: the zombie read is partial")

	// The zombie is rooted so the walk COMPLETES. Without this it would report
	// incomplete for an unrelated reason — the zombie's real parent is not in
	// the fixture — and the test would pass without ever reaching its case.
	// Measured: with the walk completing, the pre-fix code signed not-detected.
	partial.PPID = 0

	// A two-node ancestry: a synthetic leaf whose parent is the real zombie.
	// Only the zombie's ProcessInfo is real, and it is the one the claim turns
	// on.
	fixture := newFixtureSource(
		ProcessInfo{PID: 100, PPID: zombie, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
	)
	fixture.procs[zombie] = partial

	got := detect(t, fixture, 100)

	assert.Equal(t, StatusIncomplete, got.Status,
		"an ancestor whose identity could not be read makes not-detected an unsupportable claim")
	assert.NotEqual(t, StatusNotDetected, got.Status)
	joined := strings.Join(got.Warnings, "\n")
	assert.Contains(t, joined, strconv.Itoa(zombie), "the warning must name the ancestor")
	assert.Contains(t, joined, string(identityExecutable))
}

// TestFullyReadAncestryStillReportsNotDetected guards the other direction, so
// the fix cannot be "achieved" by making every walk incomplete.
func TestFullyReadAncestryStillReportsNotDetected(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 90, PPID: 1, Executable: "/bin/bash", Comm: "bash", Argv: []string{"bash"}},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init", Comm: "init", Argv: []string{"init"}},
	)
	got := detect(t, src, 100)

	assert.Equal(t, StatusNotDetected, got.Status,
		"every ancestor was examined and none matched, which is exactly what not-detected claims")
}
