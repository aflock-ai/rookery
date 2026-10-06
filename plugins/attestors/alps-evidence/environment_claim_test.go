// jade:ring local

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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The #9550 layout, transcribed from the detached mint's envelope: cilock
// launched by `nohup … &` from an agent session. The wrapper shell reparented
// to launchd, and launchd refuses to be read, so the walk ends incomplete
// with no agent in it. The agent's environment markers survived the reparent.
const (
	detachedCilock = 700
	detachedBash   = 690
)

var detachedClaudeEnv = map[string]string{
	"CLAUDECODE":             "1",
	"CLAUDE_CODE_ENTRYPOINT": "cli",
	"CLAUDE_CODE_SESSION_ID": "6f1c0f5e-6a1a-4a63-9f1e-2f2a4a0b1c33",
	"CLAUDE_CODE_EXECPATH":   "/Users/dev/.local/share/claude/versions/2.1.276",
	// A shell-profile export, the ordinary source. Never the model.
	"ANTHROPIC_MODEL": "claude-from-a-shell-profile",
	// Present in the real environment and never requested.
	"CLAUDE_CODE_MESSAGING_TOKEN": "tok-do-not-record",
}

func detachedMint(env map[string]string) *fixtureSource {
	src := newFixtureSource(
		ProcessInfo{PID: detachedCilock, PPID: detachedBash, Executable: "/usr/local/bin/cilock", Comm: "cilock", Env: env},
		ProcessInfo{PID: detachedBash, PPID: pidInit, Executable: "/bin/bash", Comm: "bash"},
	)
	// launchd: present, and not readable by the user's process.
	src.readErr[pidInit] = true
	return src
}

func withEnv(base map[string]string, set map[string]string, drop ...string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range set {
		out[k] = v
	}
	for _, k := range drop {
		delete(out, k)
	}
	return out
}

func TestDetachedMintRecordsTheEnvironmentClaim(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, detachedMint(detachedClaudeEnv), detachedCilock)

	require.Equal(t, StatusIncomplete, a.Status, "an environment variable never changes what the walk found")
	assert.Nil(t, a.Invoker, "invoker means a matched PROCESS; there is none")
	require.NotNil(t, a.EnvironmentClaim)
	c := a.EnvironmentClaim
	assert.Equal(t, "anthropic", c.Vendor)
	assert.Equal(t, "claude-code", c.Product)
	assert.Equal(t, "cilock-process.environment:CLAUDECODE", c.Fingerprint)
	assert.Equal(t, AssuranceEnvironmentObserved, c.Assurance)
	// The run-wide capture policy withholds CLAUDE_CODE_EXECPATH's value by
	// default, and a withheld value is unknown: no version is parsed from it.
	assert.Nil(t, c.Version)

	require.NotNil(t, a.Session)
	assert.Equal(t, "6f1c0f5e-6a1a-4a63-9f1e-2f2a4a0b1c33", a.Session.Value)
	assert.Equal(t, AssuranceEnvironmentObserved, a.Session.Assurance)

	assert.Nil(t, a.Model, "cilock's own ANTHROPIC_MODEL is never promoted to the model")
	assert.Contains(t, joinWarnings(a.Warnings), "environment_claim")
}

// Where the operator's policy retains CLAUDE_CODE_EXECPATH, the version is
// parsed from its layout and graded inferred, as on the detected path.
func TestEnvironmentClaimVersionFromARetainedExecPath(t *testing.T) {
	got := detect(t, detachedMint(detachedClaudeEnv), detachedCilock)
	require.NotNil(t, got.EnvironmentClaim)
	v := got.EnvironmentClaim.Version
	require.NotNil(t, v)
	assert.Equal(t, "2.1.276", v.Value)
	assert.Equal(t, "cilock-process.environment:CLAUDE_CODE_EXECPATH", v.Source)
	assert.Equal(t, AssuranceInferred, v.Assurance, "the version is parsed from a path layout")
}

func TestEnvironmentClaimOnACompletedWalkKeepsNotDetected(t *testing.T) {
	// Linux shape: the reparent lands on a readable init, so the walk COMPLETES.
	src := newFixtureSource(
		ProcessInfo{PID: detachedCilock, PPID: detachedBash, Executable: "/usr/local/bin/cilock", Env: detachedClaudeEnv},
		ProcessInfo{PID: detachedBash, PPID: 1, Executable: "/bin/bash"},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init"},
	)
	a := attestFixture(t, src, detachedCilock)

	assert.Equal(t, StatusNotDetected, a.Status)
	assert.Nil(t, a.Invoker)
	require.NotNil(t, a.EnvironmentClaim)
	assert.Equal(t, AssuranceEnvironmentObserved, a.EnvironmentClaim.Assurance)
}

// The marker is compared exactly. Every value that is not Claude Code's own
// "1" (absent, empty, a different word) claims nothing.
func TestEnvironmentClaimNeedsTheExactMarker(t *testing.T) {
	cases := map[string]map[string]string{
		"absent": withEnv(detachedClaudeEnv, nil, "CLAUDECODE"),
		"empty":  withEnv(detachedClaudeEnv, map[string]string{"CLAUDECODE": ""}),
		"zero":   withEnv(detachedClaudeEnv, map[string]string{"CLAUDECODE": "0"}),
		"true":   withEnv(detachedClaudeEnv, map[string]string{"CLAUDECODE": "true"}),
		"padded": withEnv(detachedClaudeEnv, map[string]string{"CLAUDECODE": " 1"}),
		// The other variables alone are not the marker.
		"session-only": withEnv(detachedClaudeEnv, nil, "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			a := attestFixture(t, detachedMint(env), detachedCilock)
			assert.Equal(t, StatusIncomplete, a.Status)
			assert.Nil(t, a.EnvironmentClaim)
		})
	}
}

// A value the operator's redaction policy withheld is unknown, not "1".
func TestEnvironmentClaimRespectsRedaction(t *testing.T) {
	a := newFixtureAttestor(t, detachedMint(detachedClaudeEnv), detachedCilock)
	ctx := mustLiveContext(t, a)
	detector := NewDetector(a.source, a.providers)
	detector.EnvValueKeep = func(key, _ string) bool { return key != "CLAUDECODE" }
	got, err := detector.Detect(ctx.Context(), detachedCilock, t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, StatusIncomplete, got.Status)
	assert.Nil(t, got.EnvironmentClaim)
}

func TestEnvironmentClaimNeedsAReadableSelfEnvironment(t *testing.T) {
	src := detachedMint(detachedClaudeEnv)
	src.unreadableEnv[detachedCilock] = true
	a := attestFixture(t, src, detachedCilock)
	assert.Equal(t, StatusIncomplete, a.Status)
	assert.Nil(t, a.EnvironmentClaim)
}

// A detected walk already names the agent with process evidence. The claim
// is never emitted beside it, so a reader never sees two answers.
func TestNoEnvironmentClaimWhenTheWalkDetected(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, claudeCodeMacOSDaemonChain(), pidCilock) // cilock carries CLAUDECODE=1
	require.Equal(t, StatusDetected, a.Status)
	assert.NotNil(t, a.Invoker)
	assert.Nil(t, a.EnvironmentClaim)
}

// Codex launched by Claude Code inherits CLAUDECODE=1. When the walk MATCHED
// Codex past an ancestor it could not examine, the verdict degrades to
// incomplete. Naming Claude Code from the inherited variable would then put
// the outer agent in place of the one the walk actually saw nearer.
func TestNoEnvironmentClaimWhenAnyProviderMatched(t *testing.T) {
	blind := newProcessInfo(90, 80, "").
		executable("", errors.New("kernel refused")).
		comm("", errors.New("kernel refused")).
		argv(nil, errors.New("kernel refused")).
		build()
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock", Comm: "cilock", Env: detachedClaudeEnv},
		ProcessInfo{PID: 80, PPID: 0, Executable: "/usr/local/bin/codex", Comm: "codex"},
	)
	src.procs[90] = blind

	got := detect(t, src, 100)
	require.NotNil(t, got.Provider, "fixture premise: codex matched past an unexamined ancestor")
	require.Equal(t, StatusIncomplete, got.Status, "fixture premise: the verdict degraded")
	assert.Nil(t, got.EnvironmentClaim)
}

// The claim's strings come from the environment, which the described party
// controls. They pass through the same per-value cap as every other field.
func TestEnvironmentClaimIsCapped(t *testing.T) {
	long := strings.Repeat("x", 2*maxPredicateString)
	a := attestFixture(t, detachedMint(withEnv(detachedClaudeEnv, map[string]string{"CLAUDE_CODE_SESSION_ID": long})), detachedCilock)
	require.NotNil(t, a.Session)
	assert.LessOrEqual(t, len(a.Session.Value), maxPredicateString+len(truncationMarker))
}

// The serialized field name is the contract both reducers read
// (agentcontext.go, evidence.js); renaming it silently would blank the chip.
func TestEnvironmentClaimWireShape(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, detachedMint(detachedClaudeEnv), detachedCilock)
	body, err := json.Marshal(a)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))

	assert.Equal(t, "incomplete", doc["status"])
	assert.NotContains(t, doc, "invoker")
	assert.NotContains(t, doc, "model")
	claim, ok := doc["environment_claim"].(map[string]any)
	require.True(t, ok, "environment_claim must serialize as an object")
	assert.Equal(t, "anthropic", claim["vendor"])
	assert.Equal(t, "claude-code", claim["product"])
	assert.Equal(t, "cilock-process.environment:CLAUDECODE", claim["fingerprint"])
	assert.Equal(t, "environment-observed", claim["assurance"])
	assert.NotContains(t, string(body), "tok-do-not-record")
}

func joinWarnings(ws []string) string {
	out := ""
	for _, w := range ws {
		out += w + "\n"
	}
	return out
}
