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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestArgvProgramSplitsARewrittenProcessTitle. Agents publish a title like
// "claude bg-spare" in argv[0]. Treating the whole string as a path yields the
// basename "claude bg-spare", which matches nothing; only the first token is the
// product name.
func TestArgvProgramSplitsARewrittenProcessTitle(t *testing.T) {
	cases := []struct {
		argv0 string
		want  string
	}{
		{"claude bg-spare", "claude"},
		{"claude bg-pty-host", "claude"},
		{"codex tui", "codex"},
		{"/usr/local/bin/claude", "claude"},
		{"/usr/bin/claude-helper", "claude-helper"},
		{"claude", "claude"},
		{" leading", "leading"},
		{"   ", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := argvProgram(ProcessInfo{Argv: []string{tc.argv0}})
		assert.Equalf(t, tc.want, got, "argv0 %q", tc.argv0)
	}
	assert.Equal(t, "", argvProgram(ProcessInfo{}))
}

// TestExecutableBaseDoesNotFallBackToArgv pins the split that the prototype
// conflated. On the measured macOS layout the image basename is a version
// number while argv[0] is a title; a helper that silently substituted one for
// the other compared the wrong string and reported a confident wrong answer.
func TestExecutableBaseDoesNotFallBackToArgv(t *testing.T) {
	p := ProcessInfo{Argv: []string{"claude bg-spare"}}
	assert.Equal(t, "", executableBase(p))

	p.Executable = "/Users/dev/.local/share/claude/versions/2.1.234"
	assert.Equal(t, "2.1.234", executableBase(p))
}

// TestClaudeCodeMatchesByProcessTitleAlone covers the one fingerprint that rests
// entirely on agent-controlled data: an install whose path says nothing.
func TestClaudeCodeMatchesByProcessTitleAlone(t *testing.T) {
	p := ProcessInfo{
		Executable: "/tmp/build-a1b2c3/out",
		Comm:       "out",
		Argv:       []string{"claude bg-spare", "--bg-spare", "/tmp/x.sock"},
	}
	m := ClaudeCodeProvider{}.Match(p)

	require.True(t, m.Matched)
	assert.Equal(t, fpClaudeProcessTitle, m.Fingerprint,
		"the fingerprint must disclose that identity rested on a self-declared title")
}

func TestCodexMatchesByProcessTitleAlone(t *testing.T) {
	p := ProcessInfo{Executable: "/tmp/build/out", Comm: "out", Argv: []string{"codex exec"}}
	m := CodexProvider{}.Match(p)

	require.True(t, m.Matched)
	assert.Equal(t, fpCodexProcessTitle, m.Fingerprint)
}

func TestLooksLikeVersion(t *testing.T) {
	cases := map[string]bool{
		"2.1.234":      true,
		"0.143.0":      true,
		"1.0":          true,
		"1.2.3-beta.1": true,
		"1.2.3+build":  true,
		"nightly":      false,
		"v1.2.3":       false,
		"1":            false,
		"1..2":         false,
		"claude":       false,
		"":             false,
	}
	for input, want := range cases {
		assert.Equalf(t, want, looksLikeVersion(input), "input %q", input)
	}
}

func TestArgvValueHandlesBothFlagForms(t *testing.T) {
	argv := []string{"codex", "--model", "gpt-a", "--profile=work"}

	v, ok := argvValue(argv, "--model", "-m")
	require.True(t, ok)
	assert.Equal(t, "gpt-a", v)

	v, ok = argvValue(argv, "--profile")
	require.True(t, ok)
	assert.Equal(t, "work", v)

	_, ok = argvValue(argv, "--missing")
	assert.False(t, ok)

	// A trailing flag with no value must not read past the end of argv.
	_, ok = argvValue([]string{"codex", "--model"}, "--model")
	assert.False(t, ok)
}

func TestArgvKeyValueExtractsRepeatableOverrides(t *testing.T) {
	argv := []string{"codex", "-c", "model_reasoning_effort=xhigh", "-c", "model=gpt-5.6-sol"}

	v, ok := argvKeyValue(argv, []string{"-c", "--config"}, "model")
	require.True(t, ok)
	assert.Equal(t, "gpt-5.6-sol", v)

	v, ok = argvKeyValue(argv, []string{"-c", "--config"}, "model_reasoning_effort")
	require.True(t, ok)
	assert.Equal(t, "xhigh", v)

	_, ok = argvKeyValue(argv, []string{"-c"}, "sandbox_mode")
	assert.False(t, ok)
}

// TestArgvKeyValueDoesNotConfusePrefixedKeys. "model_reasoning_effort" starts
// with "model", so a naive prefix test would return "reasoning_effort=xhigh" as
// the model.
func TestArgvKeyValueDoesNotConfusePrefixedKeys(t *testing.T) {
	argv := []string{"codex", "-c", "model_reasoning_effort=xhigh"}
	v, ok := argvKeyValue(argv, []string{"-c"}, "model")
	assert.False(t, ok, "got %q", v)
}

func TestPathElementsLowercasesAndDropsEmpties(t *testing.T) {
	assert.Equal(t, []string{"opt", "claude", "versions", "2.1.234"},
		pathElements("/opt//Claude/versions/./2.1.234"))
	assert.Empty(t, pathElements(""))
}

// TestSplitNULTerminatedPreservesInternalEmptyArguments is the Codex round-3
// regression for the /proc cmdline parser. An empty Unix argument is valid —
// execve passes "" like any other string — and DROPPING it shifts every later
// entry one slot left, so `codex --model "" --sandbox read-only` read as
// [codex --model --sandbox read-only] and the flag scanner attested
// "--sandbox" as the model inside signed evidence. Only the buffer's single
// trailing NUL terminator may be removed.
func TestSplitNULTerminatedPreservesInternalEmptyArguments(t *testing.T) {
	argv := splitNULTerminated([]byte("codex\x00--model\x00\x00--sandbox\x00read-only\x00"))
	require.Equal(t, []string{"codex", "--model", "", "--sandbox", "read-only"}, argv)

	// The corruption this prevents: with the empty argument dropped,
	// argvValue paired --model with the NEXT FLAG.
	model, ok := argvValue(argv, "--model")
	require.True(t, ok)
	assert.Equal(t, "", model, "the model argument was empty and must be attested as empty")
	sandbox, ok := argvValue(argv, "--sandbox")
	require.True(t, ok)
	assert.Equal(t, "read-only", sandbox)
}

func TestSplitNULTerminatedEdges(t *testing.T) {
	assert.Nil(t, splitNULTerminated(nil))
	assert.Nil(t, splitNULTerminated([]byte{}))
	assert.Equal(t, []string{"only"}, splitNULTerminated([]byte("only\x00")))
	// A trailing empty ARGUMENT survives; only the terminator is dropped.
	assert.Equal(t, []string{"codex", "--model", ""}, splitNULTerminated([]byte("codex\x00--model\x00\x00")))
	// Defensive: a buffer without the trailing terminator still splits.
	assert.Equal(t, []string{"a", "b"}, splitNULTerminated([]byte("a\x00b")))
	// argv[0] can itself be the empty string; the buffer says so honestly.
	assert.Equal(t, []string{""}, splitNULTerminated([]byte{0}))
}

// TestArgvKeyValueKeepsTheLastAssignment is the Codex round-4 argv finding.
//
// The -c/--config flag is repeatable and Codex applies the overrides in
// order, so a later assignment replaces an earlier one. Returning the FIRST
// match attested "gpt-old" for `codex -c model=gpt-old -c model=gpt-new` — a
// model the run explicitly overrode — inside signed evidence.
func TestArgvKeyValueKeepsTheLastAssignment(t *testing.T) {
	v, ok := argvKeyValue([]string{"codex", "-c", "model=gpt-old", "-c", "model=gpt-new"},
		[]string{"-c", "--config"}, "model")
	require.True(t, ok)
	assert.Equal(t, "gpt-new", v, "the last -c assignment is the one Codex applied")

	// Both spellings of the flag, and both spellings of the payload, override
	// each other the same way.
	v, ok = argvKeyValue([]string{"codex", "-c=model=one", "--config", "model=two"},
		[]string{"-c", "--config"}, "model")
	require.True(t, ok)
	assert.Equal(t, "two", v)

	// Last-wins stops at the option terminator, so a duplicate typed into the
	// PROMPT cannot outrank the real one.
	v, ok = argvKeyValue([]string{"codex", "-c", "model=real", "--", "-c", "model=prompt"},
		[]string{"-c"}, "model")
	require.True(t, ok)
	assert.Equal(t, "real", v)

	// A later assignment to a DIFFERENT key leaves this one alone.
	v, ok = argvKeyValue([]string{"codex", "-c", "model=only", "-c", "sandbox_mode=read-only"},
		[]string{"-c"}, "model")
	require.True(t, ok)
	assert.Equal(t, "only", v)
}

// TestArgvValueKeepsTheLastOccurrence is the same last-wins rule for the
// dedicated flags, audited alongside the -c finding. Codex is clap v4, whose
// default ArgAction::Set overwrites on a repeat; Claude Code is commander.js,
// which likewise overwrites. A first-wins scan named a model that never
// served the run.
func TestArgvValueKeepsTheLastOccurrence(t *testing.T) {
	v, ok := argvValue([]string{"codex", "--model", "gpt-old", "--model", "gpt-new"}, "--model", "-m")
	require.True(t, ok)
	assert.Equal(t, "gpt-new", v)

	// Aliases of the same flag override each other too, in either form.
	v, ok = argvValue([]string{"codex", "-m", "short", "--model=long"}, "--model", "-m")
	require.True(t, ok)
	assert.Equal(t, "long", v)

	// The terminator still cuts the scan before the prompt.
	v, ok = argvValue([]string{"codex", "--model", "real", "--", "--model", "prompt"}, "--model")
	require.True(t, ok)
	assert.Equal(t, "real", v)
}

// TestArgvValueRefusesAFlagShapedValue. clap does not accept a hyphen-leading
// value for these flags (allow_hyphen_values is off by default, so it errors),
// and consuming one put "--sandbox" into signed evidence as the model. An
// unrecorded flag is an observation gap; a wrong value is a false claim, so
// the scan refuses rather than guesses.
func TestArgvValueRefusesAFlagShapedValue(t *testing.T) {
	_, ok := argvValue([]string{"codex", "--model", "--sandbox", "read-only"}, "--model")
	assert.False(t, ok, "a following flag must never be attested as the preceding flag's value")

	// The scan continues past the refusal, so a real later assignment wins.
	v, ok := argvValue([]string{"codex", "--model", "--sandbox", "--model", "gpt"}, "--model")
	require.True(t, ok)
	assert.Equal(t, "gpt", v)

	// A lone "-" is the conventional stdin placeholder and a legal value.
	v, ok = argvValue([]string{"codex", "--model", "-"}, "--model")
	require.True(t, ok)
	assert.Equal(t, "-", v)

	// An explicit "=" value is what the caller typed, hyphen or not.
	v, ok = argvValue([]string{"codex", "--model=-weird"}, "--model")
	require.True(t, ok)
	assert.Equal(t, "-weird", v)
}
