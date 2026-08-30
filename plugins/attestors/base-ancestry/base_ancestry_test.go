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

package baseancestry

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

// Every case below runs against a REAL repository built with go-git in a temp
// dir: real commits, real refs, a real merge-base. No fixture JSON stands in
// for the graph, because the graph is the thing under test.

type repoFixture struct {
	t    *testing.T
	dir  string
	repo *git.Repository
	n    int
}

func newRepo(t *testing.T) *repoFixture {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://x-access-token:SECRET@github.com/acme/api.git"},
	})
	require.NoError(t, err)
	return &repoFixture{t: t, dir: dir, repo: repo}
}

// commit writes a new file and commits it on the current HEAD.
func (f *repoFixture) commit(msg string) plumbing.Hash {
	f.t.Helper()
	f.n++
	name := strings.ReplaceAll(msg, " ", "-") + ".txt"
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, name), []byte(msg+"\n"), 0o600))
	wt, err := f.repo.Worktree()
	require.NoError(f.t, err)
	_, err = wt.Add(name)
	require.NoError(f.t, err)
	when := time.Date(2026, 8, 27, 12, 0, f.n, 0, time.UTC)
	h, err := wt.Commit(msg, &git.CommitOptions{
		Author:    &object.Signature{Name: "t", Email: "t@example.com", When: when},
		Committer: &object.Signature{Name: "t", Email: "t@example.com", When: when},
	})
	require.NoError(f.t, err)
	return h
}

// checkout moves HEAD (detached) to h so later commits branch from it.
func (f *repoFixture) checkout(h plumbing.Hash) {
	f.t.Helper()
	wt, err := f.repo.Worktree()
	require.NoError(f.t, err)
	require.NoError(f.t, wt.Checkout(&git.CheckoutOptions{Hash: h}))
}

func (f *repoFixture) setRef(name string, h plumbing.Hash) {
	f.t.Helper()
	require.NoError(f.t, f.repo.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(name), h)))
}

func (f *repoFixture) setSymbolic(name, target string) {
	f.t.Helper()
	require.NoError(f.t, f.repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.ReferenceName(name), plumbing.ReferenceName(target))))
}

func attest(t *testing.T, dir string, opts ...Option) *Attestor {
	t.Helper()
	fixed := time.Date(2026, 8, 27, 15, 0, 0, 0, time.UTC)
	opts = append([]Option{WithEnv(func(string) string { return "" }), WithClock(func() time.Time { return fixed })}, opts...)
	a := New(opts...)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))
	require.Equal(t, fixed, a.ObservedAt)
	return a
}

func TestNameTypeRunType(t *testing.T) {
	a := New()
	require.Equal(t, Name, a.Name())
	require.Equal(t, Type, a.Type())
	require.Equal(t, RunType, a.RunType())
	require.NotNil(t, a.Schema())
}

// CURRENT: head is a child of the base the clone fetched.
func TestCurrentWhenHeadIncludesBase(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	head := f.commit("feature one")
	f.setRef("refs/remotes/origin/main", base)

	a := attest(t, f.dir, WithBaseRef("main"))
	require.Equal(t, head.String(), a.Head)
	require.Equal(t, "main", a.BaseRef)
	require.Equal(t, BaseRefSourceFlag, a.BaseRefSource)
	require.Equal(t, "refs/remotes/origin/main", a.BaseResolvedFrom)
	require.Equal(t, base.String(), a.Base)
	require.Equal(t, base.String(), a.MergeBase)
	require.Equal(t, RelationshipCurrent, a.Relationship)
	require.False(t, a.Shallow)
	require.Empty(t, a.Warnings)
	// The remote URL is recorded with its credential REMOVED.
	require.Equal(t, []string{"https://github.com/acme/api.git"}, a.Remotes)
}

// A head that IS the base is current: it includes everything the base has.
func TestCurrentWhenHeadIsBase(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.setRef("refs/remotes/origin/main", base)

	a := attest(t, f.dir, WithBaseRef("main"))
	require.Equal(t, RelationshipCurrent, a.Relationship)
	require.Equal(t, base.String(), a.MergeBase)
}

// BEHIND: the base moved on and the head is one of its ancestors.
func TestBehindWhenHeadIsAncestorOfBase(t *testing.T) {
	f := newRepo(t)
	head := f.commit("base one")
	base := f.commit("base two")
	f.setRef("refs/remotes/origin/main", base)
	f.checkout(head)

	a := attest(t, f.dir, WithBaseRef("main"))
	require.Equal(t, head.String(), a.Head)
	require.Equal(t, base.String(), a.Base)
	require.Equal(t, head.String(), a.MergeBase)
	require.Equal(t, RelationshipBehind, a.Relationship)
}

// DIVERGED: the base advanced after the branch was cut, and the branch has
// its own commit. This is the shape "main advanced after this commit was
// tested" takes in a local graph.
func TestDivergedWhenBothSidesHaveCommits(t *testing.T) {
	f := newRepo(t)
	fork := f.commit("base one")
	f.commit("base two")
	newBase := f.commit("base three")
	f.setRef("refs/remotes/origin/main", newBase)
	f.checkout(fork)
	head := f.commit("feature one")

	a := attest(t, f.dir, WithBaseRef("main"))
	require.Equal(t, head.String(), a.Head)
	require.Equal(t, newBase.String(), a.Base)
	require.Equal(t, fork.String(), a.MergeBase)
	require.Equal(t, RelationshipDiverged, a.Relationship)
	require.Empty(t, a.Warnings)
}

// SHALLOW: the clone has a grafted boundary. The base is still recorded, the
// relationship is withheld, and the warning says why.
func TestShallowCloneReportsUnknown(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.commit("feature one")
	f.setRef("refs/remotes/origin/main", base)
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, ".git", "shallow"), []byte(base.String()+"\n"), 0o600))

	a := attest(t, f.dir, WithBaseRef("main"))
	require.True(t, a.Shallow)
	require.Equal(t, base.String(), a.Base, "the base the client saw is still worth recording")
	require.Empty(t, a.MergeBase, "a merge-base over grafted history must not be claimed")
	require.Equal(t, RelationshipUnknown, a.Relationship)
	require.Len(t, a.Warnings, 1)
	require.Contains(t, a.Warnings[0], "shallow")
}

// A shallow clone whose HEAD IS the base needs no walk: a commit includes
// itself, and saying so is not a claim about grafted history.
func TestShallowCloneAtTheBaseIsStillCurrent(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.setRef("refs/remotes/origin/main", base)
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, ".git", "shallow"), []byte(base.String()+"\n"), 0o600))

	a := attest(t, f.dir, WithBaseRef("main"))
	require.True(t, a.Shallow)
	require.Equal(t, RelationshipCurrent, a.Relationship)
	require.Equal(t, base.String(), a.MergeBase)
	require.Empty(t, a.Warnings)
}

// No base ref from anywhere: unknown, with a warning naming the three ways
// to supply one.
func TestNoBaseRefIsUnknownNotAnError(t *testing.T) {
	f := newRepo(t)
	head := f.commit("base one")

	a := attest(t, f.dir)
	require.Equal(t, head.String(), a.Head)
	require.Empty(t, a.BaseRef)
	require.Equal(t, RelationshipUnknown, a.Relationship)
	require.Len(t, a.Warnings, 1)
	require.Contains(t, a.Warnings[0], "--attestor-base-ancestry-base-ref")
	require.Contains(t, a.Warnings[0], EnvBaseRef)
}

func TestBaseRefFromEnvironment(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.commit("feature one")
	f.setRef("refs/remotes/origin/release", base)

	a := attest(t, f.dir, WithEnv(func(k string) string {
		if k == EnvBaseRef {
			return "release"
		}
		return ""
	}))
	require.Equal(t, "release", a.BaseRef)
	require.Equal(t, BaseRefSourceEnv, a.BaseRefSource)
	require.Equal(t, RelationshipCurrent, a.Relationship)
}

// The flag wins over the environment: an operator who named the base gets the
// base they named, even under a CI runner that exports something else.
func TestFlagOverridesEnvironment(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.commit("feature one")
	f.setRef("refs/remotes/origin/main", base)
	f.setRef("refs/remotes/origin/release", base)

	a := attest(t, f.dir, WithBaseRef("main"), WithEnv(func(string) string { return "release" }))
	require.Equal(t, "main", a.BaseRef)
	require.Equal(t, BaseRefSourceFlag, a.BaseRefSource)
}

// With nothing named, the remote's recorded default branch is used and the
// source says so.
func TestBaseRefFromRemoteHead(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.commit("feature one")
	f.setRef("refs/remotes/origin/main", base)
	f.setSymbolic("refs/remotes/origin/HEAD", "refs/remotes/origin/main")

	a := attest(t, f.dir)
	require.Equal(t, "main", a.BaseRef)
	require.Equal(t, BaseRefSourceRemoteHead, a.BaseRefSource)
	require.Equal(t, RelationshipCurrent, a.Relationship)
}

// A base ref the clone never fetched cannot be compared against, and the
// warning names the refs that were tried so the fix is obvious.
func TestUnfetchedBaseRefIsUnknown(t *testing.T) {
	f := newRepo(t)
	f.commit("base one")

	a := attest(t, f.dir, WithBaseRef("main"))
	require.Equal(t, "main", a.BaseRef)
	require.Empty(t, a.Base)
	require.Equal(t, RelationshipUnknown, a.Relationship)
	require.Len(t, a.Warnings, 1)
	require.Contains(t, a.Warnings[0], "refs/remotes/origin/main")
	require.Contains(t, a.Warnings[0], "refs/heads/main")
}

// The remote-tracking ref wins over a local branch of the same name: it is
// what was fetched, where the local branch is only what was checked out.
func TestRemoteTrackingRefPreferredOverLocalBranch(t *testing.T) {
	f := newRepo(t)
	fork := f.commit("base one")
	fetched := f.commit("base two")
	f.setRef("refs/remotes/origin/main", fetched)
	f.setRef("refs/heads/main", fork)
	f.checkout(fork)
	f.commit("feature one")

	a := attest(t, f.dir, WithBaseRef("main"))
	require.Equal(t, "refs/remotes/origin/main", a.BaseResolvedFrom)
	require.Equal(t, fetched.String(), a.Base)
	require.Equal(t, RelationshipDiverged, a.Relationship)
}

// A local branch is the fallback when nothing was fetched, and the predicate
// says that is what it read.
func TestLocalBranchFallbackIsNamed(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.setRef("refs/heads/main", base)
	f.commit("feature one")

	a := attest(t, f.dir, WithBaseRef("main"))
	require.Equal(t, "refs/heads/main", a.BaseResolvedFrom)
	require.Equal(t, RelationshipCurrent, a.Relationship)
}

func TestFullRefNameIsTakenAsGiven(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.commit("feature one")
	f.setRef("refs/remotes/upstream/trunk", base)

	a := attest(t, f.dir, WithBaseRef("refs/remotes/upstream/trunk"))
	require.Equal(t, "refs/remotes/upstream/trunk", a.BaseResolvedFrom)
	require.Equal(t, RelationshipCurrent, a.Relationship)
}

func TestConfiguredRemoteIsUsed(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.commit("feature one")
	f.setRef("refs/remotes/upstream/main", base)

	a := attest(t, f.dir, WithBaseRef("main"), WithRemote("upstream"))
	require.Equal(t, "refs/remotes/upstream/main", a.BaseResolvedFrom)
	require.Equal(t, RelationshipCurrent, a.Relationship)
}

func TestNotARepositoryIsAnError(t *testing.T) {
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.Error(t, err)
	require.True(t, IsNotARepository(err), "a missing repository must be distinguishable: %v", err)
}

// The predicate's JSON is what a verifier reads; pin the wire names so the
// platform's reducer (judge-api/pkg/pushpolicy/baseancestry.go) and this
// struct cannot drift silently.
func TestPredicateWireNames(t *testing.T) {
	f := newRepo(t)
	base := f.commit("base one")
	f.commit("feature one")
	f.setRef("refs/remotes/origin/main", base)

	a := attest(t, f.dir, WithBaseRef("main"))
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	for _, k := range []string{"head", "base_ref", "base_ref_source", "base_resolved_from", "base", "merge_base", "relationship", "shallow", "observed_at", "remotes"} {
		require.Contains(t, m, k)
	}
	require.NotContains(t, m, "warnings", "an empty warning list is omitted, so absence means nothing went wrong")
	require.Equal(t, "current", m["relationship"])
	require.Equal(t, "2026-08-27T15:00:00Z", m["observed_at"])
}

// --- credential stripping on recorded remotes -------------------------------
//
// Remotes travel inside SIGNED, UPLOADED evidence, so a credential that
// survives sanitisation is published, not merely logged. `url.User = nil`
// clears exactly one of the places a git remote can carry a secret, and each
// case below is a place it does not reach.

// oldStrip is the sanitisation this attestor shipped with, reproduced verbatim
// so every case can assert its OWN precondition: that the case is genuinely
// NOT about userinfo, and therefore cannot pass by accident on the one path
// `url.User = nil` does handle.
func oldStrip(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw // fail OPEN: the original behaviour
	}
	parsed.User = nil
	return parsed.String()
}

func TestRemoteCredentialsNeverReachTheEvidence(t *testing.T) {
	cases := []struct {
		name       string
		remote     string
		credential string
		why        string
	}{
		{
			name:       "token in query string",
			remote:     "https://github.com/org/repo.git?access_token=ghp_SECRET1",
			credential: "ghp_SECRET1",
			why:        "url.User only models userinfo; RawQuery is a separate field",
		},
		{
			name:       "token in fragment",
			remote:     "https://github.com/org/repo.git#token=SECRET2",
			credential: "SECRET2",
			why:        "fragments survive User=nil for the same reason",
		},
		{
			name:       "credential in an opaque (scp-like) url that still parses",
			remote:     "user:SECRET3@github.com:org/repo.git",
			credential: "SECRET3",
			why:        "parses as scheme=user + Opaque, so User is already nil and clearing it is a no-op",
		},
		{
			name:       "credential in a url that does not parse at all",
			remote:     "https://exa mple.com/repo.git?token=SECRET4",
			credential: "SECRET4",
			why:        "url.Parse errors, and the original code emitted the raw string",
		},
		{
			name:       "credential in a git remote-helper url",
			remote:     "ext::helper --token SECRET5",
			credential: "SECRET5",
			why:        "`transport::address` parses as an opaque URL, so User is nil and clearing it is a no-op",
		},
		{
			name:       "remote-helper url with no whitespace to give it away",
			remote:     "ext::send-pack-with-SECRET6",
			credential: "SECRET6",
			why:        "the same opaque shape, with nothing but the double colon to distinguish it from scp syntax",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// PRECONDITION. If clearing userinfo were enough for this case the
			// case would prove nothing about the fix, so assert up front that
			// the old sanitisation really does leak it.
			require.Contains(t, oldStrip(tc.remote), tc.credential,
				"precondition failed: %s — this case must NOT be reachable by User=nil (%s)",
				tc.name, tc.why)

			f := newRepo(t)
			base := f.commit("base one")
			f.setRef("refs/remotes/origin/main", base)
			require.NoError(t, f.repo.DeleteRemote("origin"))
			_, err := f.repo.CreateRemote(&config.RemoteConfig{
				Name: "origin",
				URLs: []string{tc.remote},
			})
			require.NoError(t, err)

			a := attest(t, f.dir, WithBaseRef("main"))

			// The predicate is what gets signed, so assert against its bytes
			// rather than the in-memory field: a leak that only shows up after
			// marshalling is still a published leak.
			encoded, err := json.Marshal(a)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), tc.credential,
				"credential reached the signed predicate via remotes: %v", a.Remotes)

			for _, got := range a.Remotes {
				require.NotContains(t, got, tc.credential)
			}
		})
	}
}

// The recorded remotes must be BYTE-STABLE across runs.
//
// go-git's Remotes() builds its slice by ranging a map, and Go randomises map
// iteration on every range. Two runs over an identical repository therefore
// emitted the same remotes in different orders — and this list goes into a
// predicate that gets SIGNED, so identical inputs produced different signed
// bytes. That defeats any consumer comparing evidence for the same commit, and
// it is invisible in a single-remote repository, which is every fixture here.
func TestRecordedRemotesAreDeterministic(t *testing.T) {
	f := newRepo(t)
	require.NoError(t, f.repo.DeleteRemote("origin"))
	for name, url := range map[string]string{
		"origin":   "https://github.com/acme/repo.git",
		"upstream": "https://github.com/upstream/repo.git",
		"fork":     "git@github.com:someone/repo.git",
		"mirror":   "ssh://git@git.example.com/acme/repo.git",
		"backup":   "https://backup.example.com/acme/repo.git",
	} {
		_, err := f.repo.CreateRemote(&config.RemoteConfig{Name: name, URLs: []string{url}})
		require.NoError(t, err)
	}

	want := remoteURLs(f.repo)
	require.Len(t, want, 5, "precondition: every remote survives sanitisation, so order is the only variable")
	require.True(t, sort.StringsAreSorted(want), "the recorded order must be a total order, not the map's")

	// Map iteration is randomised PER RANGE, so repeat enough that an unsorted
	// implementation cannot stay lucky.
	for i := 0; i < 64; i++ {
		require.Equal(t, want, remoteURLs(f.repo),
			"two reads of the same repository produced different signed bytes (run %d)", i)
	}
}

func TestSanitizeRemoteURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"plain https is untouched", "https://github.com/org/repo.git", "https://github.com/org/repo.git", true},
		{"userinfo removed", "https://user:tok@github.com/org/repo.git", "https://github.com/org/repo.git", true},
		{"query removed", "https://github.com/org/repo.git?access_token=tok", "https://github.com/org/repo.git", true},
		{"fragment removed", "https://github.com/org/repo.git#tok", "https://github.com/org/repo.git", true},
		{"ssh userinfo removed, port kept", "ssh://user:tok@github.com:22/org/repo.git", "ssh://github.com:22/org/repo.git", true},
		{"scp-like keeps host and path, drops user", "git@github.com:org/repo.git", "github.com:org/repo.git", true},
		{"scp-like with credential drops it", "user:tok@github.com:org/repo.git", "github.com:org/repo.git", true},
		{"scp-like query is dropped too", "git@github.com:org/repo.git?tok=x", "github.com:org/repo.git", true},
		{"local absolute path", "/srv/git/repo.git", "/srv/git/repo.git", true},
		{"local relative path", "../relative/repo.git", "../relative/repo.git", true},
		{"file url", "file:///srv/git/repo.git", "file:///srv/git/repo.git", true},
		{"ipv6 host and port", "http://[::1]:8080/repo.git", "http://[::1]:8080/repo.git", true},
		{"unparseable is omitted", "https://exa mple.com/repo.git", "", false},
		{"empty is omitted", "   ", "", false},
		// Git remote helpers use `transport::address`. The address is opaque,
		// arbitrary, and routinely carries credentials, so it is refused
		// outright rather than guessed at — scp syntax it is not.
		{"remote helper is refused", "ext::helper --token SECRET", "", false},
		{"remote helper without whitespace is refused", "ext::send-pack-SECRET", "", false},
		{"remote helper wrapping a url is refused", "ext::git-remote-https https://u:t@h/r.git", "", false},
		{"a host that is not host-shaped is refused", "not a host:path", "", false},
		// Each of the next two isolates ONE guard. Mutation testing showed the
		// whitespace and host-shape checks were both unfalsifiable, because every
		// case reaching them was already refused by the double-colon rule — which
		// made them read as coverage they were not providing.
		//
		// Whitespace in the PATH: the host is valid and there is one colon, so
		// only the whitespace rule refuses it.
		{"whitespace anywhere disqualifies", "github.com:path --upload-pack=SECRET", "", false},
		// A URL-unsafe host: no whitespace and one colon, so only the host-shape
		// rule refuses it.
		{"a host with url-unsafe characters is refused", "we<ird>host:path", "", false},
		{"an empty host is refused", ":path", "", false},
		// `github.com:` is NOT this case — it parses as a scheme with an empty
		// opaque and never reaches the scp path. This one does.
		{"an empty scp path is refused", "git@github.com:", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sanitizeRemoteURL(tc.in)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, got)
		})
	}
}
