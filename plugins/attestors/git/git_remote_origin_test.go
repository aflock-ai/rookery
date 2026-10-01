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

package git

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/require"
)

// A judge mint recorded `anchor: git remote git@github.com:aflock-ai/cilock-action.git`
// because the worktree had a dozen remotes and the attestor emitted a remote:
// subject for every one (testifysec/judge#9233). Judge links a DSSE to every
// product whose repository matches ANY remote: subject, so the extra remotes
// attach the evidence to other organisations' products.
//
// When a remote named origin exists, it is the repository being attested, and
// it is the only one recorded.

// otherRemotes is a set of non-origin remotes including other organisations,
// named so that some sort before "origin" and some after.
var otherRemotes = map[string]string{
	"agentflow":     "https://github.com/aflock-ai/agentflow.git",
	"cilock-action": "git@github.com:aflock-ai/cilock-action.git",
	"rookery":       "https://github.com/aflock-ai/rookery.git",
	"upstream":      "https://github.com/testifysec/judge.git",
	"zz-fork":       "git@github.com:someone/judge.git",
}

func runWithNamedRemotes(t *testing.T, remotes map[string][]string) *Attestor {
	t.Helper()
	_, dir, cleanup := createTestRepo(t, true)
	t.Cleanup(cleanup)
	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)
	for name, urls := range remotes {
		_, err = repo.CreateRemote(&config.RemoteConfig{Name: name, URLs: urls})
		require.NoError(t, err)
	}
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	for _, c := range ctx.CompletedAttestors() {
		require.NoError(t, c.Error)
	}
	return a
}

func remoteSubjects(a *Attestor) []string {
	var out []string
	for name := range a.Subjects() {
		if strings.HasPrefix(name, "remote:") {
			out = append(out, strings.TrimPrefix(name, "remote:"))
		}
	}
	return out
}

// For every non-empty subset of the other remotes, origin is the only remote
// recorded and the only remote: subject, on every run (map iteration in go-git
// is randomised, so repeated runs are what catch an order dependence).
func TestOriginIsTheOnlyRecordedRemoteWhenPresent(t *testing.T) {
	names := make([]string, 0, len(otherRemotes))
	for n := range otherRemotes {
		names = append(names, n)
	}
	const origin = "https://github.com/testifysec/judge.git"
	for mask := 1; mask < 1<<len(names); mask++ {
		remotes := map[string][]string{"origin": {origin}}
		for i, n := range names {
			if mask&(1<<i) != 0 {
				remotes[n] = []string{otherRemotes[n]}
			}
		}
		for run := 0; run < 3; run++ {
			a := runWithNamedRemotes(t, remotes)
			require.Equal(t, []string{origin}, a.Remotes, "remotes %v", remotes)
			require.Equal(t, []string{origin}, remoteSubjects(a), "remotes %v", remotes)
		}
	}
}

// A refused origin is not replaced by another remote: falling back would be
// exactly the wrong-repository anchor this fixes.
func TestARefusedOriginDoesNotFallBackToAnotherRemote(t *testing.T) {
	a := runWithNamedRemotes(t, map[string][]string{
		"origin":        {"alice@example.com:tok@github.com:acme/api.git"},
		"cilock-action": {otherRemotes["cilock-action"]},
	})
	require.Empty(t, a.Remotes)
	require.Empty(t, remoteSubjects(a))
	require.Len(t, a.RemotesRefused, 1)
	require.Equal(t, 1, a.RemotesRefused[0].Count)
}

// Without origin there is no named subject, so every remote is still recorded,
// and in remote-name order so two reads of one repository sign the same bytes.
func TestWithoutOriginRemotesAreRecordedInNameOrder(t *testing.T) {
	remotes := map[string][]string{}
	for n, u := range otherRemotes {
		remotes[n] = []string{u}
	}
	want := []string{
		otherRemotes["agentflow"],
		otherRemotes["cilock-action"],
		otherRemotes["rookery"],
		otherRemotes["upstream"],
		otherRemotes["zz-fork"],
	}
	for run := 0; run < 5; run++ {
		require.Equal(t, want, runWithNamedRemotes(t, remotes).Remotes)
	}
}
