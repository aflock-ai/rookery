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

//go:build unix

package alpsevidence

// Hazard 9: an agent-influenced path opened without a bound.
//
// Every path this attestor opens that is not a fixed system location is
// influenced by the process being described — the executable path the kernel
// recorded (which the agent can replace on disk after exec), the package
// directory beside it, and $CODEX_HOME out of the agent's own environment.
// open(2) on a FIFO BLOCKS until a writer arrives, so a matched process could
// stop evidence collection dead by putting a named pipe where a file is
// expected. Not a wrong claim this time, but the same doctrine one step on:
// a path the agent controls is not a path this attestor may trust.
//
// These use a REAL FIFO. A mock would prove nothing here: the whole defect
// lives in the kernel's open(2) semantics, which is exactly what a fake would
// paper over. The build tag is because Mkfifo does not exist on Windows.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fifoRegressionsCompiled is set from this file's init so a PORTABLE test can
// assert these regressions are actually in the build.
//
// Review round 8 reported that "unix is not a standard automatically enabled Go
// build tag, so these FIFO regressions are skipped by ordinary go test runs".
// That was measured and is not so: `unix` has been a recognised build
// constraint since Go 1.19 (this module requires far newer), and on this
// machine `go list -f {{.TestGoFiles}}` includes this file for GOOS=darwin and
// GOOS=linux alike, with all three tests observed running in a plain `go test`.
//
// Rather than churn the constraint on a false premise — or leave the question
// to be re-litigated next round — the claim is now answered by a test. If the
// tag ever does stop including this file on a unix platform, the assertion in
// TestFifoRegressionsAreInTheBuild fails and says so.
func init() { fifoRegressionsCompiled = true }

// detectDeadline bounds how long a collection may take. The real hang is
// unbounded; anything in this neighbourhood means the open blocked.
const detectDeadline = 15 * time.Second

// mustMkfifo creates a real named pipe with no writer, which is what makes a
// plain open(2) for reading block.
func mustMkfifo(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, unix.Mkfifo(path, 0o600))
}

// detectWithin runs a detection and fails if it has not finished in time.
//
// The goroutine is deliberately abandoned on timeout rather than waited for: a
// blocking open cannot be interrupted from outside, so there is nothing to
// cancel. The claim under test is that the ATTESTOR returns, and a leaked
// goroutine inside an already-failing test is the cheapest honest way to show
// it did not.
func detectWithin(t *testing.T, src ProcessSource, selfPID int) Detection {
	t.Helper()

	type result struct {
		got Detection
		err error
	}
	done := make(chan result, 1)
	repoRoot := t.TempDir()
	go func() {
		d := NewDetector(src, DefaultProviders())
		got, err := d.Detect(t.Context(), selfPID, repoRoot)
		done <- result{got, err}
	}()

	select {
	case r := <-done:
		require.NoError(t, r.err)
		return r.got
	case <-time.After(detectDeadline):
		t.Fatalf("collection did not finish within %s: an agent-controlled path blocked the open", detectDeadline)
		return Detection{}
	}
}

// TestFifoAtTheNpmManifestDoesNotHangCollection is the cited critical.
//
// The manifest path is derived from the agent's own executable location, so
// the agent chooses what sits there. Red against the pre-fix code: os.ReadFile
// blocks in open(2) and the collection never returns.
func TestFifoAtTheNpmManifestDoesNotHangCollection(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64")
	binPath := filepath.Join(pkgDir, "vendor", "bin", "codex")
	writeExecutable(t, binPath)
	mustMkfifo(t, filepath.Join(pkgDir, "package.json"))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detectWithin(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Nil(t, got.Inspection.Version,
		"a named pipe where a package manifest belongs is not a package manifest")
}

// TestFifoAtTheAgentConfigDoesNotHangCollection is the sibling the review did
// not cite, and the reason this round fixed the opener rather than the line.
//
// $CODEX_HOME comes out of the AGENT'S OWN ENVIRONMENT, so the agent picks the
// directory the config is read from — a more direct handle on the path than
// the manifest case. Red against the pre-fix code: loadConfigSnapshot's
// os.Open blocks.
func TestFifoAtTheAgentConfigDoesNotHangCollection(t *testing.T) {
	codexHome := t.TempDir()
	mustMkfifo(t, filepath.Join(codexHome, "config.toml"))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{"codex"}, Env: map[string]string{"CODEX_HOME": codexHome}},
	)
	got := detectWithin(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	require.Len(t, got.Inspection.Configuration, 1,
		"the named pipe is a present but unresolved configuration tier")
	assert.Empty(t, got.Inspection.Configuration[0].SHA256,
		"a named pipe contributes no content evidence")
	assert.Contains(t, strings.Join(got.Inspection.Warnings, "\n"), "could not be read safely",
		"an unsupported higher-precedence entry must block lower resolution")
}

// TestFifoAtTheExecutableDoesNotHangCollection is the second sibling.
//
// The kernel records the path handed to execve, and nothing stops the agent
// replacing what lives at that path afterwards. Red against the pre-fix code:
// openExecutable's os.Open blocks before any fstat could reject it, which is
// why the regular-file check it already had did not save it.
func TestFifoAtTheExecutableDoesNotHangCollection(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "codex")
	mustMkfifo(t, binPath)

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)
	got := detectWithin(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Empty(t, got.Image.sha256, "a named pipe is not the process image and must not be digested")
	assert.Equal(t, digestSkipUnreadable, got.Image.digestSkipped)
	assert.Empty(t, got.Image.resolved(),
		"no path may be bound to a handle the snapshot refused")
}
