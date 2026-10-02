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

// jade:ring local

package cli

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// proveEnv prepares a real run: an isolated credential store with an enrolled
// agent, a git repository to record in, a private TMPDIR to check cleanup
// against, and this test binary standing in for cilock (TestMain).
type proveEnv struct {
	repo   string
	tmp    string
	draft  string
	stdout string
	stderr string
}

func newProveEnv(t *testing.T, enrolled bool) *proveEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("records POSIX shell commands")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	sandboxCredentials(t, enrolled)
	repo := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.email", "t@example.invalid"}, {"config", "user.name", "t"},
		{"config", "commit.gpgsign", "false"},
	} {
		c := exec.Command("git", args...)
		c.Dir = repo
		require.NoError(t, c.Run())
	}
	require.NoError(t, os.WriteFile(filepath.Join(repo, "main.txt"), []byte("source\n"), 0o600))
	for _, args := range [][]string{{"add", "."}, {"commit", "-q", "-m", "init"}} {
		c := exec.Command("git", args...)
		c.Dir = repo
		require.NoError(t, c.Run())
	}
	tmp := t.TempDir()
	t.Setenv(cliReexecEnv, "1")
	t.Setenv("TMPDIR", tmp)
	return &proveEnv{repo: repo, tmp: tmp, draft: filepath.Join(t.TempDir(), "policy.json")}
}

// newTestProver is a prover over a scratch key, this test binary as cilock,
// and the env's repository as the workdir.
func newTestProver(t *testing.T, e *proveEnv) (*prover, string, []byte) {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	scratch := t.TempDir()
	keyPath, pubPath, keyID, pubPEM, err := writeScratchKey(scratch)
	require.NoError(t, err)
	return &prover{ctx: context.Background(), self: self, workdir: e.repo, scratch: scratch, keyPath: keyPath, pubPath: pubPath,
		stderr: io.Discard, edges: map[string][]string{}}, keyID, pubPEM
}

// The engine on its own: record a step with cilock run, sign a scratch copy
// of the draft, verify the evidence against it, and name the rule that
// refuses evidence that does not match.
func TestProveEngineRecordsSignsAndVerifies(t *testing.T) {
	e := newProveEnv(t, true)
	_, err := templateCmd(t, "--goal", "app-build", "-o", e.draft,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf app > bin/app"]`)
	require.NoError(t, err)
	doc := readDraft(t, e.draft)
	step := asMap(draftSteps(doc)["app-build"])
	attestors, err := stepRunAttestors(step)
	require.NoError(t, err)
	require.NotEmpty(t, attestors)
	require.False(t, stepReadsTrace(step))

	p, keyID, pubPEM := newTestProver(t, e)
	signed, err := p.signScratch(doc, keyID, pubPEM)
	require.NoError(t, err)
	p.signed = signed

	good, reason := p.record("app-build", "good", attestors, false, []string{"sh", "-c", "mkdir -p bin && printf app > bin/app"})
	require.NotEmpty(t, good, reason)
	refused, err := p.verify([]string{good})
	require.NoError(t, err)
	require.Empty(t, refused, "the pinned command's own run passes")

	bad, reason := p.record("app-build", "bad", attestors, false, []string{"sh", "-c", "true"})
	require.NotEmpty(t, bad, reason)
	refused, err = p.verify([]string{bad})
	require.NoError(t, err)
	require.NotEmpty(t, refused["app-build"], "a run of another command is refused by name: %v", refused)
	require.Contains(t, refused["app-build"][0], "command must be")
}

func TestProveHelpers(t *testing.T) {
	t.Run("parseArgv", func(t *testing.T) {
		argv, err := parseArgv(`["sh","-c","go test ./..."]`)
		require.NoError(t, err)
		require.Equal(t, []string{"sh", "-c", "go test ./..."}, argv)
		argv, err = parseArgv("go test ./...")
		require.NoError(t, err)
		require.Equal(t, []string{"go", "test", "./..."}, argv)
		_, err = parseArgv(`sh -c "go test"`)
		require.ErrorContains(t, err, "contains quotes")
		_, err = parseArgv("  ")
		require.ErrorContains(t, err, "empty command")
	})
	t.Run("shellQuoteArgv", func(t *testing.T) {
		require.Equal(t, `sh -c 'printf app > bin/app'`, shellQuoteArgv([]string{"sh", "-c", "printf app > bin/app"}))
	})
	t.Run("stringList keeps the strings", func(t *testing.T) {
		require.Equal(t, []string{"a", "b"}, stringList([]any{"a", 1, "b", nil}))
	})
	t.Run("stepOrder records producers first and refuses a cycle or a missing step", func(t *testing.T) {
		doc := draftDoc{"steps": map[string]any{
			"publish": map[string]any{"artifactsFrom": []any{"build"}},
			"build":   map[string]any{},
			"tests":   map[string]any{"attestationsFrom": []any{"build"}},
		}}
		order, err := stepOrder(doc)
		require.NoError(t, err)
		require.Equal(t, []string{"build", "publish", "tests"}, order)
		_, err = stepOrder(draftDoc{"steps": map[string]any{"a": map[string]any{"artifactsFrom": []any{"b"}}}})
		require.ErrorContains(t, err, "has no step b")
		_, err = stepOrder(draftDoc{"steps": map[string]any{
			"a": map[string]any{"artifactsFrom": []any{"b"}}, "b": map[string]any{"attestationsFrom": []any{"a"}},
		}})
		require.ErrorContains(t, err, "cycle")
	})
	t.Run("stepReadsTrace sees a rule that reads processes", func(t *testing.T) {
		step := map[string]any{"attestations": []any{map[string]any{"type": typeCommandRun, "regopolicies": []any{
			map[string]any{"name": "t", "module": module(`package t
deny[m] { input.attestation.processes[_]; m := "x" }`)},
		}}}}
		require.True(t, stepReadsTrace(step))
		require.False(t, requiresType(step, typeProduct))
	})
}

func module(src string) string { return base64.StdEncoding.EncodeToString([]byte(src)) }

// The recorded command's stdout and stderr both land in the tail that a
// refusal quotes; os/exec copies them on separate goroutines unless both
// streams are the one writer, so the tail must take concurrent writes.
func TestTailBufferTakesConcurrentWriters(t *testing.T) {
	t.Parallel()
	tail := &tailBuffer{max: 64}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(b byte) {
			defer wg.Done()
			for n := 0; n < 1000; n++ {
				_, _ = tail.Write([]byte{b, '\n'})
			}
		}(byte('a' + i))
	}
	wg.Wait()
	require.Len(t, tail.String(), 64)
}
