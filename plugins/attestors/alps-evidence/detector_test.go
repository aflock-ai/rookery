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
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func detect(t *testing.T, src ProcessSource, selfPID int) Detection {
	t.Helper()
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), selfPID, t.TempDir())
	require.NoError(t, err)
	return got
}

// TestFirstRecognizedAgentWins pins the central invariant. Codex is nearer than
// cursor-agent, so Codex is the invoker and the walk must not continue looking
// for an outer agent it might consider "better".
func TestFirstRecognizedAgentWins(t *testing.T) {
	got := detect(t, codexLinuxNested(), 100)

	require.Equal(t, StatusDetected, got.Status)
	require.NotNil(t, got.Provider)
	assert.Equal(t, "codex", got.Provider.Product())
	assert.Equal(t, "openai", got.Provider.Vendor())
	assert.Equal(t, 80, got.Process.PID)

	// bash and codex only. cursor-agent must never have been read.
	require.Len(t, got.Ancestry, 2, "walk must stop at the first match")
	assert.Equal(t, "bash", got.Ancestry[0].Program)
	assert.False(t, got.Ancestry[0].Matched)
	assert.Equal(t, "codex", got.Ancestry[1].Program)
	assert.True(t, got.Ancestry[1].Matched)
}

// TestVendorChainCannotReachAnotherVendor is the safety property that lets a
// provider read beyond its matched process without weakening first-agent-wins.
func TestVendorChainCannotReachAnotherVendor(t *testing.T) {
	got := detect(t, codexLinuxNested(), 100)

	require.Len(t, got.Chain, 1, "cursor-agent is not a Codex process, so the vendor chain stops immediately")
	assert.Equal(t, 80, got.Chain[0].PID)
}

func TestDirectAgentParent(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{
			PID: 80, PPID: 1,
			Executable: "/usr/local/bin/claude",
			Argv:       []string{"claude", "--model", "claude-opus-5"},
			Env:        map[string]string{"CLAUDE_CODE_SESSION_ID": "session-from-agent"},
		},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init"},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, "claude-code", got.Provider.Product())
	require.NotNil(t, got.Inspection.Model)
	assert.Equal(t, "claude-opus-5", got.Inspection.Model.Value)
	assert.Equal(t, AssuranceProcessObserved, got.Inspection.Model.Assurance)
}

// TestUnknownWrapperIsSkipped is the handoff's third acceptance case: an
// unrecognized process between cilock and the agent must not stop the walk.
func TestUnknownWrapperIsSkipped(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 90, PPID: 80, Executable: "/bin/sh"},
		ProcessInfo{PID: 80, PPID: 70, Executable: "/opt/corp/unknown-wrapper"},
		ProcessInfo{PID: 70, PPID: 1, Executable: "/usr/local/bin/gemini", Argv: []string{"gemini", "-m", "gemini-3-pro"}},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init"},
	)
	got := detect(t, src, 100)

	require.Equal(t, StatusDetected, got.Status)
	assert.Equal(t, "gemini-cli", got.Provider.Product())
	assert.Len(t, got.Ancestry, 3)
}

// TestNoAgentIsAnObservationNotAnError is the codebase rule that an attestor
// error means "couldn't look", never "found something bad".
func TestNoAgentIsAnObservationNotAnError(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 90, PPID: 1, Executable: "/bin/bash"},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init"},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), 100, t.TempDir())

	require.NoError(t, err, "an absent agent is a successful observation")
	assert.Equal(t, StatusNotDetected, got.Status)
	assert.Nil(t, got.Provider)
	assert.Contains(t, got.Warnings[0], "no supported coding agent found")
}

// TestUnreadableSelfIsTheOnlyError. Failing to read our own process is the one
// genuine "couldn't look" case.
func TestUnreadableSelfIsTheOnlyError(t *testing.T) {
	src := newFixtureSource()
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), 100, t.TempDir())

	require.Error(t, err)
	assert.Equal(t, StatusUnavailable, got.Status)
}

// TestUnreadableAncestorStopsTheWalkWithoutError. An ancestor owned by another
// user is an observation gap, not a failure — but it is also not a completed
// walk. The codex behind the unreadable ancestor was never examined, so
// claiming "not detected" here would sign an absence the walk cannot vouch
// for.
func TestUnreadableAncestorStopsTheWalkWithoutError(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 90, PPID: 80, Executable: "/bin/bash"},
		ProcessInfo{PID: 80, PPID: 1, Executable: "/usr/local/bin/codex"},
	)
	src.readErr[80] = true

	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), 100, t.TempDir())

	require.NoError(t, err)
	assert.Equal(t, StatusIncomplete, got.Status, "an unexamined ancestry must not read as a completed walk")
	assert.Contains(t, got.Warnings[0], "not readable")
}

// TestCancelledWalkIsIncompleteNotNotDetected. A cancelled walk examined
// nothing (or not everything); it must not produce the status documented as
// "the walk completed and found no agent".
func TestCancelledWalkIsIncompleteNotNotDetected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := NewDetector(codexLinuxNested(), DefaultProviders())
	got, err := d.Detect(ctx, 100, t.TempDir())

	require.NoError(t, err, "cancellation is an observation gap, not an attestor error")
	// The literal string, not the constant: the serialized status is the API
	// stored attestations and policies read, so the wire value is pinned here.
	assert.Equal(t, ObservationStatus("incomplete"), got.Status)
	assert.Contains(t, got.Warnings[0], "cancelled")
}

func TestAncestryLoopTerminates(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 90, PPID: 91, Executable: "/bin/bash"},
		ProcessInfo{PID: 91, PPID: 90, Executable: "/bin/sh"},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), 100, t.TempDir())

	require.NoError(t, err)
	// A PPID loop means the chain the kernel reported never reached a root;
	// whatever sits beyond the recycled PID was not examined.
	assert.Equal(t, StatusIncomplete, got.Status)
	assert.Contains(t, got.Warnings, "ancestry loop detected; walk stopped")
}

// TestSelfParentedProcessTerminates: a PID that names itself as its own
// parent is the degenerate PPID cycle, not a root. Real roots report PPID 0
// (and the kernel pid-1 case reaches 0 through its parent field), so a
// self-parent edge means the chain the kernel reported never reached a root
// and whatever sits beyond it was not examined. not-detected is a positive
// claim about the WHOLE ancestry; a looped walk cannot support it and must
// degrade to incomplete, exactly like the longer cycle above.
func TestSelfParentedProcessTerminates(t *testing.T) {
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 90, PPID: 90, Executable: "/bin/bash"},
	)
	d := NewDetector(src, DefaultProviders())
	got, err := d.Detect(context.Background(), 100, t.TempDir())

	require.NoError(t, err)
	assert.Equal(t, StatusIncomplete, got.Status,
		"a self-parented ancestor is an ancestry loop; the walk never reached a root and cannot sign an absence claim")
	assert.NotEqual(t, StatusNotDetected, got.Status)
	joined := strings.Join(got.Warnings, "\n")
	assert.Contains(t, joined, "own parent")
	assert.Contains(t, joined, "90", "the warning must name the looped pid")
}

func TestMaxDepthIsRespected(t *testing.T) {
	src := newFixtureSource(ProcessInfo{PID: 1000, PPID: 999, Executable: "/usr/local/bin/cilock"})
	for pid := 999; pid > 900; pid-- {
		src.procs[pid] = ProcessInfo{PID: pid, PPID: pid - 1, Executable: "/bin/bash"}
	}
	src.procs[900] = ProcessInfo{PID: 900, PPID: 1, Executable: "/usr/local/bin/codex"}

	d := NewDetector(src, DefaultProviders())
	d.MaxDepth = 4
	got, err := d.Detect(context.Background(), 1000, t.TempDir())

	require.NoError(t, err)
	// The codex beyond the bound was never looked at. A truncated walk must
	// say so rather than claim the completed-walk "not detected".
	assert.Equal(t, StatusIncomplete, got.Status, "codex is beyond the depth bound; the walk did not complete")
	assert.Contains(t, got.Warnings[0], "truncated")
	assert.Len(t, got.Ancestry, 4)
}

// TestExactMatchAvoidsSubstringFalsePositives is the regression the handoff
// called out by name, broadened to every near-miss shape that a substring
// matcher would wrongly claim.
func TestExactMatchAvoidsSubstringFalsePositives(t *testing.T) {
	nearMisses := []struct {
		name string
		proc ProcessInfo
	}{
		{"not-codex", ProcessInfo{Executable: "/tmp/not-codex", Comm: "not-codex", Argv: []string{"not-codex"}}},
		{"codex-evil", ProcessInfo{Executable: "/tmp/codex-evil", Comm: "codex-evil", Argv: []string{"codex-evil"}}},
		{"not-claude", ProcessInfo{Executable: "/tmp/not-claude", Comm: "not-claude", Argv: []string{"not-claude"}}},
		{"claudette", ProcessInfo{Executable: "/usr/bin/claudette", Comm: "claudette", Argv: []string{"claudette"}}},
		{"claude-helper", ProcessInfo{Executable: "/usr/bin/claude-helper", Comm: "claude-helper", Argv: []string{"/usr/bin/claude-helper"}}},
		{"my-cursor-agent", ProcessInfo{Executable: "/tmp/my-cursor-agent", Comm: "my-cursor-agen", Argv: []string{"my-cursor-agent"}}},
		{"dir named claude", ProcessInfo{Executable: "/opt/claude/bin/runner", Comm: "runner", Argv: []string{"runner"}}},
		{"fake versions dir", ProcessInfo{Executable: "/opt/notclaude/versions/9.9.9", Comm: "9.9.9", Argv: []string{"x"}}},
		{"fake @openai dir", ProcessInfo{Executable: "/usr/bin/node", Comm: "node", Argv: []string{"node", "/tmp/@openai-mirror/codex/bin/codex.js"}}},
	}

	for _, tc := range nearMisses {
		t.Run(tc.name, func(t *testing.T) {
			for _, provider := range DefaultProviders() {
				m := provider.Match(tc.proc)
				assert.Falsef(t, m.Matched, "%s must not match %s (fingerprint %q)", tc.name, provider.Product(), m.Fingerprint)
			}
		})
	}
}

// TestNoTwoProvidersClaimTheSameProcess guards the assumption that provider
// order is a tie-break that never fires. If two providers ever claim one
// process, that is a fingerprint bug and this test is where it surfaces.
func TestNoTwoProvidersClaimTheSameProcess(t *testing.T) {
	candidates := []ProcessInfo{
		{Executable: "/usr/local/bin/codex", Comm: "codex", Argv: []string{"codex"}},
		{Executable: "/usr/local/bin/claude", Comm: "claude", Argv: []string{"claude"}},
		{Executable: "/opt/cursor/cursor-agent", Comm: "cursor-agent"},
		{Executable: "/usr/local/bin/gemini", Comm: "gemini"},
		{Executable: "/usr/local/bin/copilot", Comm: "copilot"},
		{Executable: "/usr/local/bin/aider", Comm: "aider"},
		{Executable: "/usr/local/bin/goose", Comm: "goose"},
		{Executable: "/usr/local/bin/opencode", Comm: "opencode"},
		{Executable: "/Users/dev/.local/share/claude/versions/2.1.234", Comm: "2.1.234", Argv: []string{"claude bg-spare"}},
		{Executable: "/opt/homebrew/Caskroom/codex/0.143.0/codex-aarch64-apple-darwin", Comm: "codex-aarch64-a"},
	}
	for _, candidate := range candidates {
		var claimed []string
		for _, provider := range DefaultProviders() {
			if provider.Match(candidate).Matched {
				claimed = append(claimed, provider.Product())
			}
		}
		assert.LessOrEqualf(t, len(claimed), 1, "process %q claimed by %v", candidate.Executable, claimed)
	}
}

// TestInspectRunsOnlyForTheWinner. Inspection is the expensive, side-effecting
// half; it must never run for a provider that lost detection.
func TestInspectRunsOnlyForTheWinner(t *testing.T) {
	loser := &countingProvider{Provider: ClaudeCodeProvider{}}
	winner := &countingProvider{Provider: CodexProvider{}}

	d := NewDetector(codexLinuxNested(), []Provider{loser, winner})
	_, err := d.Detect(context.Background(), 100, t.TempDir())
	require.NoError(t, err)

	assert.Equal(t, 0, loser.inspects)
	assert.Equal(t, 1, winner.inspects)
}

type countingProvider struct {
	Provider
	inspects int
}

func (c *countingProvider) Inspect(ctx context.Context, r InspectRequest) Inspection {
	c.inspects++
	return c.Provider.Inspect(ctx, r)
}

// TestResolvedLinkMatchIsReboundToTheSnapshotResolution. A match established
// by resolving a symlink at MATCH time rests on a read the executable
// snapshot does not share. When the snapshot's own resolution — the one bound
// to the digested handle — still supports the provider's claim, the published
// fingerprint must be the snapshot-bound one, not the match-time one.
func TestResolvedLinkMatchIsReboundToTheSnapshotResolution(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".local", "share", "claude", "versions", "2.1.234")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
	require.NoError(t, os.WriteFile(target, []byte("binary"), 0o700))
	link := filepath.Join(dir, "claude-link")
	require.NoError(t, os.Symlink(target, link))

	src := newFixtureSource(ProcessInfo{PID: 7, PPID: 1, Executable: link, Comm: "sh", Argv: []string{"sh"}})
	p, err := src.ReadProcess(7)
	require.NoError(t, err)

	d := NewDetector(src, DefaultProviders())
	var out Detection
	unbound := d.observeMatch(context.Background(), &out, matchedProcess{
		provider: ClaudeCodeProvider{},
		process:  p,
		match:    matchedViaResolution(fpClaudeResolvedLink),
	}, t.TempDir(), ProcessInfo{})

	assert.Empty(t, unbound)
	assert.Equal(t, fpClaudeInstallLayout, out.Match.Fingerprint,
		"the published fingerprint must be the one the snapshot's own resolution supports")
}

// TestRetargetedLinkMatchDegradesToUnbound is the regression for the race
// Codex flagged: the symlink is retargeted between the match-time readlink
// and the snapshot's open, so the fingerprint would describe one binary while
// the digest describes another. The identity must not publish, nothing
// agent-specific may be inspected, and the walk verdict must degrade.
func TestRetargetedLinkMatchDegradesToUnbound(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "unrelated-binary")
	require.NoError(t, os.WriteFile(target, []byte("binary"), 0o700))
	link := filepath.Join(dir, "claude-link")
	require.NoError(t, os.Symlink(target, link))

	src := newFixtureSource(ProcessInfo{PID: 7, PPID: 1, Executable: link, Comm: "sh", Argv: []string{"sh"}})
	p, err := src.ReadProcess(7)
	require.NoError(t, err)

	d := NewDetector(src, DefaultProviders())
	var out Detection
	unbound := d.observeMatch(context.Background(), &out, matchedProcess{
		provider: ClaudeCodeProvider{},
		process:  p,
		match:    matchedViaResolution(fpClaudeResolvedLink),
	}, t.TempDir(), ProcessInfo{})

	assert.NotEmpty(t, unbound, "a match the digested image cannot confirm must be reported as unbound")
	assert.Nil(t, out.Chain, "no vendor chain may be recorded for an unbound match")
	assert.Nil(t, out.Inspection.Model, "no inspection may run for an unbound match")
	assert.Equal(t, StatusIncomplete, walkCoverage{matched: true, unbound: unbound}.verdict(),
		"an unbound match withholds every positive verdict")
}
