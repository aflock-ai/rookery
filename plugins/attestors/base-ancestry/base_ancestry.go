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

// Package baseancestry implements an attestor that records where the commit
// under test sits relative to its base branch.
//
// # What it answers
//
// One question: does the tested commit include the base it claims to be built
// on? The predicate names the head commit, the base ref, the base commit the
// client could see for that ref, their merge-base, and the relationship those
// three hashes imply. A verifier that also knows the provider's CURRENT base
// commit — Pushgate reads it with its own repository-scoped identity — can
// then join the two and decide whether the base moved after the tests ran.
//
// # What it is worth
//
// This is a client-side observation of the LOCAL commit graph. It proves what
// the clone that ran the tests could see, signed and bound to the collection
// it travels in. It does not prove what the provider holds now: the base the
// client saw may be hours stale, and nothing here can tell. That is deliberate.
// The attestor never asks the provider, so it needs no credential and cannot
// be confused by one; the platform observes the provider independently and
// compares. Two observations from two principals is the design
// (docs/design/pushgate-current-with-base.md); this attestor is the client
// half only.
//
// # What it refuses to guess
//
// A shallow clone has holes in its graph, and a merge-base computed over holes
// is a number that looks like an answer. The attestor records `unknown` with a
// warning instead. The same goes for a base ref that cannot be resolved
// locally: no base, no relationship, said out loud rather than defaulted.
package baseancestry

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "base-ancestry"
	Type    = "https://aflock.ai/attestations/base-ancestry/v0.1"
	RunType = attestation.PreMaterialRunType

	// DefaultRemote is where the base ref is looked for first. A remote-tracking
	// ref is what the clone last FETCHED, which is the closest thing the client
	// has to the provider's opinion; a local branch of the same name is only
	// what the developer last checked out.
	DefaultRemote = "origin"

	// EnvBaseRef is the environment variable consulted when no --base-ref flag
	// is given. GitHub Actions sets it on pull_request events to the PR's
	// target branch name; other CI systems can export the same name.
	EnvBaseRef = "GITHUB_BASE_REF"
)

// Relationship is where the head sits relative to the base, in git's own
// vocabulary (`git status` uses the same words for a branch and its upstream).
type Relationship string

const (
	// RelationshipCurrent: the base commit is an ancestor of the head, so the
	// head includes everything the base had when it was observed. This is the
	// only value the current-with-base rule accepts.
	RelationshipCurrent Relationship = "current"
	// RelationshipBehind: the head is an ancestor of the base — the base has
	// commits the head lacks and the head has none of its own beyond it.
	RelationshipBehind Relationship = "behind"
	// RelationshipDiverged: each side has commits the other lacks. It says
	// nothing about conflicts; a clean merge and a conflicting one are both
	// diverged.
	RelationshipDiverged Relationship = "diverged"
	// RelationshipUnknown: the graph could not be read honestly — a shallow
	// clone, an unresolvable base ref, or no base ref at all. Every unknown
	// carries at least one warning saying which.
	RelationshipUnknown Relationship = "unknown"
)

// How the base ref was chosen, recorded so a verifier can tell a ref the
// operator named from one the attestor inferred.
const (
	BaseRefSourceFlag       = "flag"
	BaseRefSourceEnv        = "env:" + EnvBaseRef
	BaseRefSourceRemoteHead = "remote-head"
)

// The attestor is an Attestor and nothing else, on purpose.
//
// No Subjecter: the git attestor already binds the collection to the head
// commit with a VERIFIED commithash subject, and this predicate is meant to
// travel beside it. Declaring the same commit here would be a second, weaker
// binding for a verifier to be tempted by. No BackReffer for the same reason.
var _ attestation.Attestor = (*Attestor)(nil)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
		registry.StringConfigOption(
			"base-ref",
			"Base branch the tested commit should include, e.g. main. If empty: "+EnvBaseRef+", then the remote's HEAD.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithBaseRef(val)(att)
				return att, nil
			},
		),
		registry.StringConfigOption(
			"remote",
			"Remote whose tracking ref supplies the base commit.",
			DefaultRemote,
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithRemote(val)(att)
				return att, nil
			},
		),
	)
	detection.Register(Name, detectorYAML)
}

// Attestor is the base-ancestry predicate.
type Attestor struct {
	// Head is the commit under test: HEAD of the working directory.
	Head string `json:"head"`
	// BaseRef is the base branch as named — "main", not "refs/heads/main".
	// Empty when no base ref could be chosen; Relationship is then unknown.
	BaseRef string `json:"base_ref,omitempty"`
	// BaseRefSource says who chose BaseRef: flag, env:GITHUB_BASE_REF, or
	// remote-head (the remote's default branch as the clone recorded it).
	BaseRefSource string `json:"base_ref_source,omitempty"`
	// BaseResolvedFrom is the full local ref the base commit was read from,
	// normally refs/remotes/origin/<base>. A verifier comparing Base with the
	// provider's current commit should know whether the client read a
	// remote-tracking ref or a local branch that may never have been fetched.
	BaseResolvedFrom string `json:"base_resolved_from,omitempty"`
	// Base is the base commit AS THE CLIENT SAW IT. Not the provider's current
	// base: only the platform can say that, and the join between the two is
	// the whole rule.
	Base string `json:"base,omitempty"`
	// MergeBase is git merge-base of Head and Base. Equal to Base exactly when
	// the head includes the base.
	MergeBase string `json:"merge_base,omitempty"`
	// Relationship is what Head, Base and MergeBase imply; see the constants.
	Relationship Relationship `json:"relationship"`
	// Shallow reports a clone whose history has holes. A shallow clone always
	// yields Relationship unknown, because a merge-base computed across a
	// grafted boundary can name a commit that is not the real merge-base.
	Shallow bool `json:"shallow"`
	// ObservedAt is when the local graph was read.
	ObservedAt time.Time `json:"observed_at"`
	// Remotes are the configured remote URLs with credentials stripped — the
	// same repository identity the git attestor records — so a reader can
	// tell which repository's base this observation is about.
	Remotes []string `json:"remotes,omitempty"`
	// Warnings name everything that stopped the attestor from establishing a
	// relationship. Never empty when Relationship is unknown.
	Warnings []string `json:"warnings,omitempty"`

	baseRefFlag string
	remote      string
	getenv      func(string) string
	now         func() time.Time
}

// Option customizes the attestor.
type Option func(*Attestor)

// WithBaseRef names the base branch explicitly.
func WithBaseRef(ref string) Option { return func(a *Attestor) { a.baseRefFlag = ref } }

// WithRemote names the remote whose tracking refs supply the base commit.
func WithRemote(remote string) Option { return func(a *Attestor) { a.remote = remote } }

// WithEnv substitutes the environment reader. Tests use it; production reads
// the process environment.
func WithEnv(getenv func(string) string) Option { return func(a *Attestor) { a.getenv = getenv } }

// WithClock pins ObservedAt.
func WithClock(now func() time.Time) Option { return func(a *Attestor) { a.now = now } }

// New builds an attestor.
func New(opts ...Option) *Attestor {
	a := &Attestor{
		remote: DefaultRemote,
		getenv: os.Getenv,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(a) }

// Attest reads the local commit graph.
//
// It returns an error only when there is no repository to read. Everything
// else — no base ref, an unfetched base, a shallow clone — is a successful
// observation whose Relationship is unknown, because "could not establish"
// is itself the fact worth signing: a verifier in Enforce mode refuses it,
// one in Observe mode shows it, and neither mistakes it for "current".
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.ObservedAt = a.now().UTC()
	a.Relationship = RelationshipUnknown

	repo, err := git.PlainOpenWithOptions(ctx.WorkingDir(), &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if err != nil {
		return fmt.Errorf("base-ancestry: open repository at %s: %w", ctx.WorkingDir(), err)
	}

	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("base-ancestry: resolve HEAD: %w", err)
	}
	a.Head = head.Hash().String()
	a.Remotes = remoteURLs(repo)
	a.Shallow = isShallow(repo)

	ref, source := a.chooseBaseRef(repo)
	if ref == "" {
		a.warn("no base ref: pass --attestor-base-ancestry-base-ref, set " + EnvBaseRef +
			", or fetch the remote so refs/remotes/" + a.remote + "/HEAD names its default branch")
		return nil
	}
	a.BaseRef, a.BaseRefSource = ref, source

	baseRef, err := a.resolveBase(repo, ref)
	if err != nil {
		a.warn(err.Error())
		return nil
	}
	a.BaseResolvedFrom = baseRef.Name().String()
	a.Base = baseRef.Hash().String()

	return a.relate(repo, head.Hash(), baseRef.Hash())
}

// chooseBaseRef picks the base branch: the flag, then the environment, then
// the remote's recorded default branch. Returns the short name and its source.
func (a *Attestor) chooseBaseRef(repo *git.Repository) (string, string) {
	if v := strings.TrimSpace(a.baseRefFlag); v != "" {
		return v, BaseRefSourceFlag
	}
	if v := strings.TrimSpace(a.getenv(EnvBaseRef)); v != "" {
		return v, BaseRefSourceEnv
	}
	// refs/remotes/<remote>/HEAD is a symbolic ref git clone writes to point at
	// the remote's default branch. Resolved WITHOUT following it, so the
	// target's name is what is read, not the commit it happens to be at.
	remoteHead := plumbing.ReferenceName("refs/remotes/" + a.remote + "/HEAD")
	sym, err := repo.Reference(remoteHead, false)
	if err != nil || sym.Type() != plumbing.SymbolicReference {
		return "", ""
	}
	prefix := "refs/remotes/" + a.remote + "/"
	target := sym.Target().String()
	if !strings.HasPrefix(target, prefix) {
		return "", ""
	}
	return strings.TrimPrefix(target, prefix), BaseRefSourceRemoteHead
}

// resolveBase finds the commit the base ref names locally.
//
// Order matters and is the honest one: the remote-tracking ref is what the
// clone last fetched, the local branch is what the developer last had checked
// out, and a name already spelled as a full ref is taken as given.
func (a *Attestor) resolveBase(repo *git.Repository, ref string) (*plumbing.Reference, error) {
	var candidates []plumbing.ReferenceName
	if strings.HasPrefix(ref, "refs/") {
		candidates = []plumbing.ReferenceName{plumbing.ReferenceName(ref)}
	} else {
		candidates = []plumbing.ReferenceName{
			plumbing.NewRemoteReferenceName(a.remote, ref),
			plumbing.NewBranchReferenceName(ref),
		}
	}
	tried := make([]string, 0, len(candidates))
	for _, name := range candidates {
		r, err := repo.Reference(name, true)
		if err == nil && r.Hash() != plumbing.ZeroHash {
			return r, nil
		}
		tried = append(tried, name.String())
	}
	return nil, fmt.Errorf("base ref %q is not present locally as %s; fetch it before attesting",
		ref, strings.Join(tried, " or "))
}

// relate computes the merge-base and names the relationship.
func (a *Attestor) relate(repo *git.Repository, head, base plumbing.Hash) error {
	if head == base {
		// Trivially current: no walk is needed to know a commit includes
		// itself, so even a shallow clone may say so.
		a.MergeBase = base.String()
		a.Relationship = RelationshipCurrent
		return nil
	}
	if a.Shallow {
		// Recorded AFTER the base, so the predicate still says which commit
		// the client was working against; only the relationship is withheld.
		// A merge-base walked across a grafted boundary can name a commit
		// that is not the real merge-base, which would look exactly like an
		// answer.
		a.warn("repository is a shallow clone; the merge-base cannot be established over grafted history")
		return nil
	}
	headCommit, err := repo.CommitObject(head)
	if err != nil {
		return fmt.Errorf("base-ancestry: read head commit %s: %w", head, err)
	}
	baseCommit, err := repo.CommitObject(base)
	if err != nil {
		// The ref resolved but its object is missing: a partial clone, or a
		// ref written by hand. Not a relationship, and not an error either —
		// the observation is that the base could not be read, and the
		// predicate records exactly that with relationship unknown.
		a.warn(fmt.Sprintf("base commit %s is named by %s but its object is not in the repository", base, a.BaseResolvedFrom))
		return nil //nolint:nilerr // an unreadable base is a signed unknown, not an attestor failure
	}

	bases, err := headCommit.MergeBase(baseCommit)
	if err != nil {
		return fmt.Errorf("base-ancestry: merge-base of %s and %s: %w", head, base, err)
	}
	switch {
	case len(bases) == 0:
		a.Relationship = RelationshipDiverged
		a.warn("head and base share no common ancestor")
		return nil
	case len(bases) > 1:
		// A criss-cross merge has several merge-bases. git picks one for
		// display; the relationship does not depend on which, because the
		// question is whether BASE ITSELF is among them.
		a.warn(fmt.Sprintf("head and base have %d merge-bases (criss-cross history); the first is recorded", len(bases)))
	}
	a.MergeBase = bases[0].Hash.String()
	for _, mb := range bases {
		switch mb.Hash {
		case base:
			a.MergeBase = base.String()
			a.Relationship = RelationshipCurrent
			return nil
		case head:
			a.MergeBase = head.String()
			a.Relationship = RelationshipBehind
			return nil
		}
	}
	a.Relationship = RelationshipDiverged
	return nil
}

func (a *Attestor) warn(msg string) {
	log.Warnf("base-ancestry: %s", msg)
	a.Warnings = append(a.Warnings, msg)
}

// isShallow reports whether the object store has grafted boundaries.
func isShallow(repo *git.Repository) bool {
	ss, ok := repo.Storer.(storer.ShallowStorer)
	if !ok {
		return false
	}
	shallow, err := ss.Shallow()
	if err != nil {
		// Could not read .git/shallow at all. Treated as shallow: a graph
		// whose completeness cannot be established is not one to compute a
		// merge-base over.
		return true
	}
	return len(shallow) > 0
}

// sanitizeRemoteURL strips every credential-bearing component from a git remote
// URL. It reports false when the URL cannot be positively sanitized, and the
// caller must then OMIT it.
//
// Clearing url.User is not sufficient, and each of the three ways it falls
// short is a published-secret bug rather than a cosmetic one — a remote travels
// inside signed, uploaded evidence:
//
//   - `?access_token=…` and `#token=…` live in RawQuery and Fragment, which
//     url.User does not model at all.
//   - `user:tok@github.com:org/repo.git` PARSES, as scheme "user" with the rest
//     in Opaque. User is already nil there, so clearing it is a silent no-op
//     and String() reproduces the secret verbatim.
//   - a URL that fails to parse was previously appended RAW, so the one input
//     we understood least was the one we published unchanged.
//
// The rule is therefore: reconstruct from the components we recognise, and
// refuse anything we cannot. A remote is identified by its host and path; no
// git remote needs a query or a fragment to be understood, so both are dropped
// wholesale rather than filtered against a list of known token parameter names
// that the next provider will not be on.
//
// Parse FIRST and fall back, rather than sniffing for scp syntax up front: the
// opaque case below is only reachable this way, and a guard that cannot be
// reached is not a guard. Both fallbacks are covered by mutation tests.
func sanitizeRemoteURL(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}

	parsed, err := url.Parse(trimmed)
	switch {
	case err != nil:
		// Not a URL. It may still be scp syntax, which url.Parse does not
		// model; anything else is refused rather than published raw.
		return sanitizeSCPLike(trimmed)
	case parsed.Opaque != "":
		// Parsed, but into a shape with no host or path to rebuild from:
		// `user:tok@host:path` lands here as scheme "user" carrying the whole
		// secret in Opaque. Clearing User would be a no-op, so re-read it as
		// scp syntax instead of trusting String().
		return sanitizeSCPLike(trimmed)
	}

	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), true
}

// scpHost is the ONLY host shape sanitizeSCPLike will accept: a DNS label run,
// or a bracketed IPv6 literal. An allowlist rather than a denylist, because the
// thing being excluded is "every string a colon can appear in" and that set is
// not enumerable.
var scpHost = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])$`)

// sanitizeSCPLike rebuilds git's `[user@]host:path` remote syntax from its host
// and path alone, and accepts NOTHING else. Everything up to the last `@` is
// dropped unconditionally: the username is conventionally `git` and carries no
// information worth the risk of telling it apart from `user:token`.
//
// The strictness is the point. "Opaque, and contains a colon" is not scp
// syntax — it is also git's REMOTE HELPER syntax, `transport::address`, whose
// address is arbitrary and routinely carries credentials:
//
//	ext::helper --token SECRET
//	ext::git-remote-https https://user:tok@host/repo.git
//
// A first version of this function accepted any opaque string with a colon and
// returned those UNCHANGED, straight into signed evidence — the same fail-open
// it was written to remove, one shape further out. So the host must look like a
// host, the path must be non-empty, a second leading colon (the remote-helper
// signature) is refused, and whitespace disqualifies the whole string: no
// legitimate remote contains any, and a helper command line always does.
func sanitizeSCPLike(s string) (string, bool) {
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", false
	}
	if strings.Contains(s, "://") {
		return "", false
	}
	hostPath := s
	if at := strings.LastIndex(hostPath, "@"); at >= 0 {
		hostPath = hostPath[at+1:]
	}
	// A query or fragment has no meaning in scp syntax, so anything after `?`
	// or `#` is unexplained and is dropped with the rest.
	hostPath = strings.SplitN(hostPath, "?", 2)[0]
	hostPath = strings.SplitN(hostPath, "#", 2)[0]

	host, path, found := strings.Cut(hostPath, ":")
	if !found || host == "" || path == "" {
		return "", false
	}
	// `transport::address`. The second colon is what separates a remote helper
	// from a host, and there is no host to rebuild from on that side of it.
	if strings.HasPrefix(path, ":") {
		return "", false
	}
	if !scpHost.MatchString(host) {
		return "", false
	}
	return host + ":" + path, true
}

// remoteURLs lists the configured remotes with any embedded credentials
// removed. A remote that cannot be safely sanitized is omitted entirely rather
// than recorded, so the predicate under-reports instead of publishing a secret.
//
// SORTED, because this list is SIGNED. go-git builds Remotes() by ranging a
// map, and Go randomises map iteration on every range, so two reads of one
// unchanged repository emitted the same remotes in different orders and
// therefore different signed predicate bytes — which defeats any consumer
// comparing evidence for the same commit. Config order carries no meaning here
// (the field is a set of remotes; which one is "first" is not a claim the
// predicate makes), so a total order costs nothing and buys reproducibility.
// Invisible in a single-remote repository, which is why it took a review to
// find.
func remoteURLs(repo *git.Repository) []string {
	remotes, err := repo.Remotes()
	if err != nil {
		return nil
	}
	var out []string
	for _, remote := range remotes {
		for _, raw := range remote.Config().URLs {
			if clean, ok := sanitizeRemoteURL(raw); ok {
				out = append(out, clean)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ErrNotARepository is wrapped by Attest when the working directory holds no
// git repository. Exposed so a caller that auto-plans attestors can tell
// "nothing to observe" from a read failure.
var ErrNotARepository = git.ErrRepositoryNotExists

// IsNotARepository reports whether err means there was no repository to read.
func IsNotARepository(err error) bool { return errors.Is(err, ErrNotARepository) }

// unused guard so the object import stays meaningful when MergeBase's return
// type changes; object.Commit is what MergeBase yields.
var _ = (*object.Commit)(nil)
