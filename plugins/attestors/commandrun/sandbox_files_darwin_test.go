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

// jade:ring local

package commandrun

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDarwinFileReadParsingIsOptIn(t *testing.T) {
	line := "Sandbox: sh(123) allow file-read-data /tmp/a file.mk"
	_, ok := parseSandboxReport(line)
	require.False(t, ok)
	ev, ok := parseSandboxReport(line, true)
	require.True(t, ok)
	require.Equal(t, opFileRead, ev.op)
	require.Equal(t, "/tmp/a file.mk", ev.detail)
	require.True(t, irrelevantReport(line))
	require.False(t, irrelevantReport(line, true))
}

func TestDarwinReadSnapshotBoundaries(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	s := &sandboxSession{}
	require.NoError(t, s.configureReadCapture([]darwinReadConfig{{enabled: true, workdir: dir}}))
	defer s.closeReadCapture()
	c := s.readCapture
	body := "echo synthetic\n"
	p := filepath.Join(dir, "input.sh")
	require.NoError(t, os.WriteFile(p, []byte(body), 0600))
	got := c.snapshot(p)
	require.Equal(t, "captured-at-collector-open", got.Status)
	require.Equal(t, body, got.Content)
	sum := sha256.Sum256([]byte(body))
	require.Equal(t, hex.EncodeToString(sum[:]), got.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}])
	require.Equal(t, "outside-workspace", c.snapshot(filepath.Join(dir, "..", "elsewhere")).Status)
	require.Equal(t, "missing-at-capture", c.snapshot(filepath.Join(dir, "absent")).Status)
	require.Equal(t, "not-regular", c.snapshot(dir).Status)
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("do not capture"), 0600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(outside, link))
	require.Equal(t, "scoped-open-failed", c.snapshot(link).Status)
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	require.Equal(t, "not-regular", c.snapshot(fifo).Status)
	require.NoError(t, os.WriteFile(p, []byte(strings.Repeat("x", maxReadSnapshotBytes+1)), 0600))
	require.Equal(t, "oversize", c.snapshot(p).Status)
	require.NoError(t, os.WriteFile(p, []byte{0, 255}, 0600))
	require.Equal(t, "binary", c.snapshot(p).Status)
	c.remaining = 1
	require.Equal(t, "size-or-budget-exceeded", c.snapshot(p).Status)
	require.Equal(t, "capture-budget-exceeded", c.snapshot(p).Status)
}

func TestDarwinFileReadDoesNotBecomeExecOrVerifiedInput(t *testing.T) {
	ev := sandboxEvent{pid: 10, op: opFileRead, detail: "/workspace/helper.sh", fileSnapshot: &FileSnapshot{Status: "captured-at-collector-open", Content: "echo x"}}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(darwinTreeInput{rootPid: 10, events: []sandboxEvent{ev}, members: map[int]bool{10: true}}, diag)
	require.Len(t, procs, 1)
	require.Zero(t, diag.ExecReports)
	require.EqualValues(t, 1, diag.FileReadReports)
	require.Empty(t, procs[0].OpenedFiles)
	require.Equal(t, execOutcomePermittedNotConfirmed, procs[0].SyscallEvents[0].Outcome)
	require.Nil(t, procs[0].SyscallEvents[0].PathDigestAtCollectorOpen)
	unproven := &DarwinTraceDiagnostics{}
	unknown := buildDarwinTree(darwinTreeInput{rootPid: 10, events: []sandboxEvent{ev}}, unproven)
	require.Empty(t, unknown, "unattributed paths must not be exposed")
	require.EqualValues(t, 1, unproven.UnprovenFileReadReports)
	// Compact encoding must preserve the new evidence, not silently drop it.
	rc := New()
	rc.Processes = procs
	encoded, err := json.Marshal(rc)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "fileAtCollectorOpen")
	var round CommandRun
	require.NoError(t, json.Unmarshal(encoded, &round))
	require.Equal(t, "echo x", round.Processes[0].SyscallEvents[0].FileAtCollectorOpen.Content)
}

func TestDarwinReadCaptureNeverOpensUnattributedFiles(t *testing.T) {
	s := &sandboxSession{rootPid: 10, facts: map[int]procFacts{}, ourPids: map[int]bool{}}
	got := s.captureReadEvent(sandboxEvent{pid: 11, detail: "/anything"})
	require.Equal(t, "attribution-unproven-at-capture", got.Status)
	require.Empty(t, got.Digest)
}

func TestDarwinReadCaptureLiveMakeAndHelpers(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	fixtures := map[string]string{
		"Makefile":    "include included.mk\nall:\n\t@/bin/sh child.sh\n",
		"included.mk": "$(info INCLUDED)\n",
		"child.sh":    ". ./helper.sh\nprintf 'echo GENERATED\\n/bin/sleep 0.1\\n' > generated.sh\n/bin/sh generated.sh\n/bin/sleep 0.1\nrm generated.sh\n",
		"helper.sh":   "echo SOURCED\n",
	}
	for name, body := range fixtures {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0600))
	}
	ctx, err := attestation.NewContext("read-capture", nil, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	rc := New(WithCommand([]string{"/usr/bin/make", "all"}), WithTracing(true), WithSilent(true), WithScriptCapture(ScriptCaptureContent), WithTraceFileContent(true))
	err = rc.Attest(ctx)
	skipIfUntestable(t, err)
	require.NoError(t, err)
	require.True(t, rc.darwinTraceDiag.FileReadsObserved)
	seen := map[string]bool{}
	captured := map[string]bool{}
	for _, p := range rc.Processes {
		for _, ev := range p.SyscallEvents {
			if ev.Syscall != opFileRead {
				continue
			}
			name := filepath.Base(ev.Path)
			seen[name] = true
			require.Equal(t, execOutcomePermittedNotConfirmed, ev.Outcome)
			if ev.FileAtCollectorOpen != nil && ev.FileAtCollectorOpen.Status == "captured-at-collector-open" {
				captured[name] = true
			}
		}
	}
	for name := range fixtures {
		require.True(t, seen[name], "missing read: %s", name)
		require.True(t, captured[name], "missing snapshot: %s", name)
	}
	require.True(t, seen["generated.sh"])
	require.True(t, captured["generated.sh"])
	require.NoFileExists(t, filepath.Join(dir, "generated.sh"))
	t.Logf("captured read-time observations for %v; all collector-time, not consumed-byte proof", captured)
}

func TestDarwinReadCaptureLiveReplacementNeverClaimsConsumedBytes(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	original := "echo ORIGINAL\n"
	target := filepath.Join(dir, "target.sh")
	require.NoError(t, os.WriteFile(target, []byte(original), 0600))
	body := "#!/bin/sh\ncp target.sh saved.sh\nprintf 'echo TRANSIENT\\n' > target.sh\n/bin/sh target.sh\nmv saved.sh target.sh\n"
	script := filepath.Join(dir, "run.sh")
	require.NoError(t, os.WriteFile(script, []byte(body), 0700))
	ctx, err := attestation.NewContext("read-replacement", nil, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	rc := New(WithCommand([]string{script}), WithTracing(true), WithSilent(true), WithTraceFileContent(true))
	err = rc.Attest(ctx)
	skipIfUntestable(t, err)
	require.NoError(t, err)
	require.Contains(t, rc.Stdout, "TRANSIENT")
	after, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, original, string(after))
	seen := false
	for _, p := range rc.Processes {
		for _, ev := range p.SyscallEvents {
			if ev.Syscall == opFileRead && ev.Path == target {
				seen = true
				require.Equal(t, execOutcomePermittedNotConfirmed, ev.Outcome)
				require.Empty(t, ev.PathDigestAtCollectorOpen)
				if ev.FileAtCollectorOpen != nil {
					require.NotEqual(t, "verified", ev.FileAtCollectorOpen.Status)
				}
			}
		}
	}
	require.True(t, seen || rc.darwinTraceDiag.UnprovenFileReadReports > 0,
		"a vanished process must leave either an attributed read or an explicit attribution gap")
	for _, s := range rc.Scripts {
		require.NotEqual(t, ScriptBindingVerified, s.ExecutionBinding)
	}
}

func TestDarwinReadCaptureRequiresTracingBeforeWorkload(t *testing.T) {
	dir := t.TempDir()
	ctx, err := attestation.NewContext("requires-trace", nil, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	rc := New(WithCommand([]string{"/usr/bin/touch", filepath.Join(dir, "must-not-run")}), WithTraceFileContent(true))
	err = rc.Attest(ctx)
	skipIfUntestable(t, err)
	require.ErrorContains(t, err, "requires --trace")
	require.NoFileExists(t, filepath.Join(dir, "must-not-run"))
}

func TestDarwinReadCaptureLiveProfileScope(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	// Quotes must remain data in the sandbox profile, not broaden its rules.
	dir := filepath.Join(parent, `workspace"quoted`)
	require.NoError(t, os.Mkdir(dir, 0700))
	inside := filepath.Join(dir, "inside.txt")
	outside := filepath.Join(parent, "outside.txt")
	require.NoError(t, os.WriteFile(inside, []byte("inside"), 0600))
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0600))
	ctx, err := attestation.NewContext("read-scope", nil, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	// The trailing sleep keeps the process attributable during log delivery.
	rc := New(WithCommand([]string{"/bin/sh", "-c", `read x < "$1"; read y < "$2"; /bin/sleep 0.1`, "scope", inside, outside}), WithTracing(true), WithSilent(true), WithTraceFileContent(true))
	err = rc.Attest(ctx)
	skipIfUntestable(t, err)
	require.NoError(t, err)
	seen := false
	for _, p := range rc.Processes {
		for _, ev := range p.SyscallEvents {
			if ev.Syscall != opFileRead {
				continue
			}
			require.NotEqual(t, outside, ev.Path, "outside reads must be excluded at profile level")
			if ev.Path == inside {
				seen = true
			}
		}
	}
	require.True(t, seen, "quoted workspace must remain observable")
}

func TestDarwinReadSnapshotOpenErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status string
	}{
		{os.ErrNotExist, "missing-at-capture"},
		{os.ErrPermission, "permission-denied"},
		{unix.ELOOP, "scoped-open-failed"},
		{unix.EMFILE, "scoped-open-failed"},
	} {
		require.Equal(t, tc.status, readSnapshotOpenStatus(&os.PathError{Op: "openat", Path: "input.sh", Err: tc.err}))
	}
}
