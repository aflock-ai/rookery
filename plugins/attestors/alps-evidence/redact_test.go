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
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPredicateNeverCarriesAnotherProjectsPaths is the privacy regression.
//
// The daemon-chain fixture is a transcription of a real machine. Its zsh
// ancestor's argv names a shell-snapshot file under the user's home and an
// unrelated customer repository; Claude Code's own daemon argv elsewhere carries
// a --spawned-by blob naming another checkout. None of it may appear in the
// serialized predicate.
func TestPredicateNeverCarriesAnotherProjectsPaths(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, claudeCodeMacOSDaemonChain(), pidCilock)

	body, err := json.Marshal(a)
	require.NoError(t, err)
	serialized := string(body)

	forbidden := []string{
		"other-customer-repo",
		"shell-snapshots",
		"snapshot-zsh-1787028458755-2dy6q7.sh",
		"/tmp/claude-e519-cwd",
		"claim.sock",
		"pty.sock",
		"tok-do-not-record",
		"messaging.sock",
		"/Users/dev/.claude/jobs/3b71492b",
	}
	for _, needle := range forbidden {
		assert.NotContainsf(t, serialized, needle,
			"predicate leaked %q; raw argv and unallowlisted environment must never be serialized", needle)
	}
}

// TestAncestryCarriesBasenamesOnly. The walk is auditable without disclosing
// where anything lives.
func TestAncestryCarriesBasenamesOnly(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, claudeCodeMacOSDaemonChain(), pidCilock)

	require.NotEmpty(t, a.Ancestry)
	for _, ancestor := range a.Ancestry {
		assert.NotContainsf(t, ancestor.Program, "/", "ancestry entry %q must be a basename", ancestor.Program)
	}
	assert.Equal(t, []string{"go", "zsh", "2.1.234"}, ancestryPrograms(a.Ancestry))
	assert.True(t, a.Ancestry[2].Matched)
	assert.Equal(t, fpClaudeInstallLayout, a.Ancestry[2].MatchedBy)
}

// TestUnallowlistedEnvironmentIsNeverRequestedFromTheSource.
//
// The allowlist is applied at the REQUEST, so an unlisted key is never asked
// for and never retained. Note precisely what this does and does not show: it
// pins the attestor's side of the ProcessSource boundary. It cannot pin the
// platform sources underneath, because a fixture source has no kernel — and
// those sources necessarily read the whole environment block, there being no
// per-key interface on either platform. The claim in the package doc is worded
// to match; overstating it here would be the same defect this predicate is
// about.
func TestUnallowlistedEnvironmentIsNeverRequestedFromTheSource(t *testing.T) {
	withHomeDir(t, t.TempDir())
	src := claudeCodeMacOSDaemonChain()
	attestFixture(t, src, pidCilock)

	requested := append(src.keysRequestedFor(pidCilock), src.keysRequestedFor(pidSpare)...)
	require.NotEmpty(t, requested)
	for _, key := range requested {
		assert.NotEqual(t, "CLAUDE_CODE_MESSAGING_TOKEN", key)
		assert.NotEqual(t, "CLAUDE_CODE_MESSAGING_SOCKET", key)
		assert.NotEqual(t, "CLAUDE_JOB_DIR", key)
	}
	assert.Contains(t, requested, "CLAUDE_CODE_SESSION_ID")
}

// TestCredentialShapedKeysAreDroppedEvenWhenAllowlisted is the backstop. A
// provider that mistakenly allowlists a token still cannot publish its value.
func TestCredentialShapedKeysAreDroppedEvenWhenAllowlisted(t *testing.T) {
	src := newFixtureSource(ProcessInfo{
		PID: 1, Env: map[string]string{
			"AGENT_API_TOKEN": "super-secret",
			"AGENT_MODEL":     "a-model",
		},
	})
	allow := []EnvKey{
		{Name: "AGENT_API_TOKEN", RecordValue: true},
		{Name: "AGENT_MODEL", RecordValue: true},
	}

	observations, scope := collectEnv(InspectRequest{Source: src, Process: src.procs[1], Self: src.procs[1]}, EnvScopeAgent, allow)

	assert.True(t, scope.read, "a readable environment reports that it was read")
	model, blocked := resolveEnvValue("AGENT_MODEL", scope)
	assert.False(t, blocked)
	assert.Equal(t, "a-model", model)
	token, _ := resolveEnvValue("AGENT_API_TOKEN", scope)
	assert.Empty(t, token, "a credential-shaped key must not yield a value")

	byKey := map[string]EnvObservation{}
	for _, obs := range observations {
		byKey[obs.Key] = obs
	}
	require.Contains(t, byKey, "AGENT_API_TOKEN")
	assert.True(t, byKey["AGENT_API_TOKEN"].Present, "presence is still recordable")
	assert.Empty(t, byKey["AGENT_API_TOKEN"].Value, "the value is not")
}

// TestIsCredentialShapedKeyTracksTheSharedSensitiveList pins the backstop to
// attestation.DefaultSensitiveEnvList. The private 10-word list it replaces
// missed whole classes the shared list names — a GH_PAT, a MY_JWT, a bearer or
// OAuth credential, a passphrase — so a provider typo could serialize a
// personal access token the sibling attestors already knew to obfuscate.
//
// The shared list's globs are substring-broad (*KEY*, *TOKEN*), so incidental
// containments like MONKEY_MODEL now lose their VALUE too. That is the traded
// cost and it is the safe direction: presence is still recorded, and every key
// a provider actually allowlists for value retention stays clean below.
func TestIsCredentialShapedKeyTracksTheSharedSensitiveList(t *testing.T) {
	flagged := []string{
		"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_CODE_MESSAGING_TOKEN",
		"GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "SSH_PRIVATE_KEY",
		"npm-auth-token", "service.credentials",
		// The classes the old 10-word list missed.
		"GH_PAT", "MY_JWT", "CI_BEARER", "OAUTH_CLIENT", "DB_PASSPHRASE",
	}
	for _, key := range flagged {
		assert.Truef(t, isCredentialShapedKey(key), "expected %q to be flagged", key)
	}

	// Every key any provider allowlists with RecordValue must stay clean, or
	// the backstop silently deletes the attestor's own evidence.
	clean := []string{
		"CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_CHILD_SESSION", "CLAUDECODE",
		"CLAUDE_CODE_EXECPATH", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_KIND",
		"ANTHROPIC_MODEL", "CODEX_HOME", "CODEX_SANDBOX",
		"CODEX_SANDBOX_NETWORK_DISABLED", "GEMINI_MODEL", "COPILOT_MODEL",
		"GOOSE_MODEL", "GOOSE_PROVIDER",
	}
	for _, key := range clean {
		assert.Falsef(t, isCredentialShapedKey(key), "expected %q not to be flagged", key)
	}
}

// TestEnvScopeIsHonoured. A key scoped to cilock's own environment must not be
// requested from the agent process, and vice versa.
func TestEnvScopeIsHonoured(t *testing.T) {
	src := newFixtureSource(ProcessInfo{PID: 1, Env: map[string]string{"ONLY_SELF": "x", "ONLY_AGENT": "y"}})
	allow := []EnvKey{
		{Name: "ONLY_SELF", RecordValue: true, Scopes: []EnvScope{EnvScopeSelf}},
		{Name: "ONLY_AGENT", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent}},
	}

	_, agentScope := collectEnv(InspectRequest{Source: src, Process: src.procs[1], Self: src.procs[1]}, EnvScopeAgent, allow)
	onlyAgent, _ := resolveEnvValue("ONLY_AGENT", agentScope)
	assert.NotEmpty(t, onlyAgent)
	onlySelf, _ := resolveEnvValue("ONLY_SELF", agentScope)
	assert.Empty(t, onlySelf)

	require.Len(t, src.envReads, 1)
	assert.Equal(t, []string{"ONLY_AGENT"}, src.envReads[0].keys)
}

// TestUnreadableEnvironmentIsNotAnError. macOS withholds the environment of
// SIP-protected binaries. Absence must read as "we could not look", never as
// "the variable was unset" — which is what the scope's read flag carries, so
// precedence chains know a higher-precedence override was never ruled out.
func TestUnreadableEnvironmentIsNotAnError(t *testing.T) {
	src := newFixtureSource(ProcessInfo{PID: 1, Env: map[string]string{"CODEX_HOME": "/x"}})
	src.unreadableEnv[1] = true

	observations, scope := collectEnv(InspectRequest{Source: src, Process: src.procs[1], Self: src.procs[1]}, EnvScopeAgent, CodexProvider{}.EnvAllowlist())
	assert.Empty(t, observations)
	assert.False(t, scope.read, "an unreadable environment must be distinguishable from an empty one")

	readable := newFixtureSource(ProcessInfo{PID: 2})
	_, readableScope := collectEnv(InspectRequest{Source: readable, Process: readable.procs[2], Self: readable.procs[2]}, EnvScopeAgent, CodexProvider{}.EnvAllowlist())
	assert.True(t, readableScope.read, "a readable environment with none of the keys set reports read")
}

// TestEnvironmentReadIsBoundToTheCapturedInstance is the regression for the
// execve/pid-reuse gap Codex flagged: pid and start time both survive execve,
// so an environment read addressed by number alone can return values from a
// program the captured executable, argv and ancestry do not describe. The
// read is addressed by the CAPTURED instance, and a process replaced between
// capture and read must report as unreadable — never as values.
func TestEnvironmentReadIsBoundToTheCapturedInstance(t *testing.T) {
	src := newFixtureSource(ProcessInfo{
		PID: 9, Executable: "/usr/local/bin/codex",
		Env: map[string]string{"CODEX_HOME": "/original"},
	})
	captured, err := src.ReadProcess(9)
	require.NoError(t, err)

	// The process execs a different image after capture: same pid, new image
	// and new environment.
	src.procs[9] = vouchedFixture(ProcessInfo{
		PID: 9, Executable: "/usr/local/bin/imposter",
		Env: map[string]string{"CODEX_HOME": "/imposter"},
	})

	observations, scope := collectEnv(InspectRequest{Source: src, Process: captured, Self: captured}, EnvScopeAgent, CodexProvider{}.EnvAllowlist())
	assert.Empty(t, observations)
	assert.False(t, scope.read,
		"the environment of a replaced process must read as unknown, not as the replacement's values")
}

// TestLowerPriorityScopeIsNeverConsultedAfterAFailedRead is the unit-level pin
// for hazard 16. A scope below an unreadable one is not evidence of anything:
// the unreadable one may hold an override, so the answer is "unknown", not the
// lower scope's value.
func TestLowerPriorityScopeIsNeverConsultedAfterAFailedRead(t *testing.T) {
	agent := envScope{}
	self := envScope{values: map[string]string{"MODEL": "cilocks-copy"}, present: map[string]struct{}{"MODEL": {}}, read: true}

	value, blocked := resolveEnvValue("MODEL", agent, self)
	assert.Empty(t, value, "a lower-priority scope must not answer for one that could not be read")
	assert.True(t, blocked)

	// The same chain with the higher scope actually read: absence there is
	// evidence, so the lower scope legitimately answers.
	readAgent := envScope{values: map[string]string{}, present: map[string]struct{}{}, read: true}
	value, blocked = resolveEnvValue("MODEL", readAgent, self)
	assert.Equal(t, "cilocks-copy", value)
	assert.False(t, blocked)

	// And the higher scope wins when it carries the key.
	loaded := envScope{values: map[string]string{"MODEL": "the-agents-own"}, present: map[string]struct{}{"MODEL": {}}, read: true}
	value, blocked = resolveEnvValue("MODEL", loaded, self)
	assert.Equal(t, "the-agents-own", value)
	assert.False(t, blocked)
}

// TestArgvFieldsAreAnAllowlistNotAPassthrough.
func TestArgvFieldsAreAnAllowlistNotAPassthrough(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex", Comm: "codex",
			Argv: []string{
				"codex", "exec", "--model", "gpt-a",
				"--cd", "/Users/dev/proj/unrelated-client-work",
				"--secret-internal-flag", "value-nobody-asked-for",
			}},
	)
	got := detect(t, src, 100)

	assert.Equal(t, "gpt-a", got.Inspection.ArgvFields["model"])
	for key, value := range got.Inspection.ArgvFields {
		assert.NotContainsf(t, value, "unrelated-client-work", "field %q leaked a path", key)
		assert.NotEqualf(t, "value-nobody-asked-for", value, "field %q passed through an unlisted flag", key)
	}
}

// TestProcessRefPublishesTheProgramTokenNotTheWholeTitle.
func TestProcessRefPublishesTheProgramTokenNotTheWholeTitle(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, claudeCodeMacOSDaemonChain(), pidCilock)

	require.NotNil(t, a.Invoker)
	assert.Equal(t, "claude", a.Invoker.Process.ArgvProgram)
	assert.Equal(t, 3, a.Invoker.Process.ArgvCount, "the count is published, the arguments are not")
	assert.NotContains(t, strings.Join(valuesOf(a.Invoker.Process.ArgvFields), " "), ".sock")
}

func ancestryPrograms(refs []AncestorRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.Program)
	}
	return out
}

func valuesOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
