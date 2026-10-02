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
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/gitremote"
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

	// EnvGitLabBaseRef is the same thing on GitLab CI: a merge request
	// pipeline sets it to the MR target branch. Read only in a GitLab job.
	EnvGitLabBaseRef = "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
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
	BaseRefSourceGitLabEnv  = "env:" + EnvGitLabBaseRef
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

	repo, err := openRepository(ctx.WorkingDir())
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
		a.warn("no base ref: pass --attestor-base-ancestry-base-ref, set " + EnvBaseRef + " (GitLab: run in a merge request pipeline, which sets " + EnvGitLabBaseRef + ")" +
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
	if a.getenv("GITLAB_CI") == "true" {
		if v := strings.TrimSpace(a.getenv(EnvGitLabBaseRef)); v != "" {
			return v, BaseRefSourceGitLabEnv
		}
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

// A git remote is written in one of a small number of forms, and which one it
// is decides where — or whether — a credential can be hiding in it.
//
// Deriving the form FIRST is the whole design, and it is a PORT of the
// decomposition PR #9177 arrived at for the sibling git attestor after three
// review rounds. The defect family is identical, and so is the cause:
// url.Parse was being asked a question about git's grammar.
//
// Go implements RFC 3986; git implements connect.c, and the two disagree.
// "user:tok@host:path" is an OPAQUE url.URL whose User is already nil.
// "https:/alice:tok@host/path" — ONE slash — is a hierarchical URL with a
// scheme and no authority, so clearing User is a no-op and String() hands the
// token straight back; that string was measured returning UNCHANGED from this
// function on origin/main (testifysec/judge#9181). Each disagreement was
// patched here in turn (`Opaque == ""`, then the scp fallback), and the
// function's own doc comment recorded that it had already been through one
// round of it. That is what a patch on a parser mismatch always looks like:
// another one arrives next round. There is no set of guards that makes an RFC
// 3986 parser answer a question about git's grammar, so url.Parse is REMOVED
// from this path rather than guarded, and the grammar is read directly.
type remoteForm int

const (
	// remoteFormLocal is a path. git reads a remote as a path when it holds no
	// colon, or when a slash arrives before the colon (connect.c
	// url_is_local_not_ssh). A path has no authority component at all.
	remoteFormLocal remoteForm = iota
	// remoteFormURL is scheme://[userinfo@]host[:port]/path. The authority is
	// unambiguous: it is everything between "://" and the next "/", "?" or "#".
	remoteFormURL
	// remoteFormSCP is git's scheme-less [user@]host:path. The path begins at
	// the first colon OUTSIDE any bracketed IPv6 literal, and everything before
	// it is the authority.
	remoteFormSCP
	// remoteFormHelper is git's REMOTE HELPER syntax, `transport::address`.
	//
	// It is a form the git attestor's version of this code does not model, and
	// it is modelled here because THIS package has already shipped a leak
	// through it: a first version of sanitizeSCPLike accepted any opaque string
	// with a colon and returned it UNCHANGED, so `ext::helper --token SECRET`
	// went straight into signed evidence. The address after `::` is an
	// arbitrary helper invocation — `ext::git-remote-https https://u:tok@h/r.git`
	// is a legal one — so there is no authority in it to find and nothing in it
	// that can be shown to be credential-free.
	remoteFormHelper
	// remoteFormUnclassifiable is a string whose boundary cannot be computed at
	// all — today, one with an unterminated '[', which leaves no defined place
	// for the delimiter search to resume.
	remoteFormUnclassifiable
)

// classifyRemote assigns raw to exactly one form. It is TOTAL: every string
// lands in exactly one branch, which is what stops the next spelling from
// falling through a gap between two heuristics.
//
// For remoteFormURL it also returns the scheme (including "://") and the rest;
// the other forms read raw directly.
func classifyRemote(raw string) (remoteForm, string, string) {
	if i := schemeSeparator(raw); i >= 0 {
		return remoteFormURL, raw[:i+3], raw[i+3:]
	}

	// LOCAL-PATH PRECEDENCE COMES FIRST, before any bracket verdict.
	//
	// git decides local-versus-scp on one question — does a slash arrive before
	// the colon (connect.c url_is_local_not_ssh) — and that question is answered
	// by the RAW colon, not by the delimiter search. A path has no authority, so
	// its brackets are filename bytes and there is no boundary to compute.
	//
	// Deciding it after the bracket check dropped `/srv/git/repo[1:2.git`: an
	// unterminated '[' swallowed the colon, the delimiter came back
	// uncomputable, and a local remote whose leading slash had already settled
	// the question was refused (#9186 review round 2). Precedence, not an extra
	// guard, is the fix — the same reason `/srv/git/a::b.git` is a filename and
	// not a remote helper.
	// A colonless string needs no clause of its own: the delimiter search can
	// only report "unterminated" when it actually swallowed a colon, so with no
	// colon anywhere it returns "no delimiter" and the check below sends the
	// string to remoteFormLocal regardless. A `firstColon < 0` arm here was
	// written first and mutation-tested as a NO-OP — unreachable, not untested.
	slash := strings.IndexByte(raw, '/')
	firstColon := strings.IndexByte(raw, ':')
	if slash >= 0 && firstColon >= 0 && slash < firstColon {
		return remoteFormLocal, "", raw
	}

	colon, bracketsClosed := colonOutsideBrackets(raw)
	if !bracketsClosed {
		return remoteFormUnclassifiable, "", raw
	}
	if colon < 0 {
		return remoteFormLocal, "", raw
	}
	// A SECOND colon immediately after the first is git's remote-helper
	// signature. This is the `strings.HasPrefix(path, ":")` rule the previous
	// implementation carried, preserved verbatim in effect: it refuses a little
	// more than git's own scheme-character test would (`git@host::path` is scp
	// syntax to git and a helper to this), and the extra refusals are strings
	// no clone uses, so the fail-CLOSED direction is the cheap one here.
	if colon+1 < len(raw) && raw[colon+1] == ':' {
		return remoteFormHelper, "", raw
	}
	return remoteFormSCP, "", raw
}

// sanitizeRemoteURL strips every credential-bearing component from a git remote
// URL. It reports false when the remote cannot be positively sanitized, and the
// caller must then OMIT it.
//
// The attestation is signed and uploaded, so every remote recorded here
// outlives the build and is readable by anything that can read the envelope. A
// CI checkout's remote routinely carries a live token — GitHub Actions writes
// https://x-access-token:ghs_TOKEN@github.com/owner/repo — so this is the field
// a secret escapes through if anything on the path can be talked into recording
// a string it did not understand.
//
// Dropping every remote would be fail-closed and WRONG in its own way: the
// predicate names these strings so a reader can tell which repository the
// observation is about, and a redactor that discards them takes that with it.
// Both failures are real, and where they cannot both be avoided the fail
// direction follows the worse one — recording an unredactable string is
// fail-OPEN, so a remote this cannot classify is dropped rather than passed
// through.
func sanitizeRemoteURL(rawWithQuery string) (string, bool) {
	raw := strings.TrimSpace(rawWithQuery)
	if raw == "" {
		return unclassifiableRemote(rawWithQuery)
	}

	// THE VERDICT IS TAKEN ON THE STRING AS WRITTEN. Nothing is removed before
	// classification, and that ordering is the whole point.
	//
	// The query and fragment used to be cut HERE, in front of the switch, so
	// that every form got the cut rather than only the branch with a parser
	// handy. The cut itself was right and still runs for every form — but doing
	// it first meant the redactor formed its opinion about a string the author
	// never wrote, and the span it discarded could carry the delimiter that made
	// the rest recognisable. Measured on head 89d7d81af1:
	//
	//   "alice:SECRETVALUE?q@github.com:acme/api.git" -> ok, "alice:SECRETVALUE"
	//   "/srv/alice:SECRETVALUE#q@repo.git"           -> ok, "/srv/alice:SECRETVALUE"
	//
	// Cutting at '?' takes the '@' with it, so what reached classifyRemote was
	// "alice:SECRETVALUE" — a host and a path, carrying no at-sign for any rule
	// to object to. Read as written, both strings are userinfo followed by a
	// host, and both are refused.
	form, scheme, rest := classifyRemote(raw)

	var clean string
	var ok bool
	switch form {
	case remoteFormURL:
		clean, ok = sanitizeURLRemote(scheme, rest)
	case remoteFormSCP:
		clean, ok = sanitizeSCPRemote(raw)
	case remoteFormLocal:
		clean, ok = sanitizeLocalRemote(raw)
	default:
		return unclassifiableRemote(raw)
	}
	if !ok {
		return "", false
	}

	// ONLY THE RECORDED VALUE IS CUT. A query or fragment is a credential in
	// the one part of the string userinfo redaction never reads
	// ("?access_token=…", "#token=…"), and every form drops it — the scp and
	// local branches hand their input back unmodified, so without this they
	// would carry one through. Doing it here rather than up front keeps that
	// property while leaving the verdict on the original.
	clean = cutRemoteQueryAndFragment(clean)
	if clean == "" {
		// The query was the whole remote. Nothing is left to name a repository.
		return unclassifiableRemote(raw)
	}
	// The token backstop the git attestor applies, on the value recorded: a
	// login or path segment the grammar admits as a name can still hold a
	// pasted token ("ghp_TOKEN@github.com:acme/api.git").
	if gitremote.CarriesTokenPrefix(clean) {
		return unclassifiableRemote(raw)
	}
	return clean, true
}

// unclassifiableRemote is the SINGLE decision point for a remote whose
// authority this could not identify, and it exists as a named function so that
// the decision is one edit rather than a sweep through every refusal site.
//
// POLICY: record nothing. The alternative under discussion is to record a
// MARKER — evidence that an unclassifiable remote was present, without its text
// — so the attestation stays honest about its own gaps instead of being silently
// short a remote. Silence is cheaper; a marker is more truthful. That is a
// provenance-product judgement, not an engineering one, and it is open. The
// same seam exists in the git attestor for the same reason, so ONE answer can
// be applied to both.
//
// Either answer is this function's body. remoteURLs already appends whatever
// comes back whenever ok is true and inspects nothing else, so returning
// ("<unclassifiable remote>", true) here is the entire change; no call site,
// and no other refusal in this file, needs to move. (Note that remoteURLs
// SORTS, so a marker would sort among the real remotes rather than trail them.)
func unclassifiableRemote(raw string) (string, bool) {
	_ = raw // named so a marker policy has the value it would need
	return "", false
}

// sanitizeURLRemote handles scheme://[userinfo@]host[:port]/path.
//
// The authority is bounded by the grammar rather than guessed, so the userinfo
// question has a definite answer: everything up to the LAST '@' inside the
// authority is userinfo and is removed. The last, not the first — an encoded or
// repeated at-sign inside the userinfo would otherwise leave half the credential
// behind.
func sanitizeURLRemote(scheme, rest string) (string, bool) {
	raw := scheme + rest

	authority, tail := cutRemoteAuthority(rest)
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}

	if strings.ContainsRune(percentDecodeOnce(tail), '@') {
		// AN AT-SIGN AFTER THE AUTHORITY. The string reads two ways that
		// disagree about whether its leading span is a credential:
		//
		//   https://ghp_CANARY?x@github.com/acme/api.git
		//     as RFC 3986 -> host "ghp_CANARY", path "?x@github.com/acme/api.git"
		//     as intent   -> userinfo "ghp_CANARY", host github.com
		//
		// An authority ends at the first '/', '?' or '#' (RFC 3986 §3.2), so
		// putting one of those three bytes in front of the '@' ends the
		// authority BEFORE the delimiter that would have marked the credential.
		// The userinfo cut above then finds nothing, and what is left is a bare
		// token sitting where a host belongs.
		//
		// authorityIsHostAndPort cannot separate the two readings, and no rule
		// of its kind can: a bare PAT has no colon and is shaped exactly like a
		// hostname, and "alice:12345" is shaped exactly like host:port. A
		// discriminator that is confidently wrong on its own target class is
		// the fail-OPEN shape, so the disagreement is treated as the answer —
		// the same move the scp branch already makes for
		// `github.com:repo@release.git`, and this is that rule ported rather
		// than a new one. Measured leaking before it existed, one row per
		// terminator (#9177 round 5, reproduced here):
		//
		//   "https://ghp_CANARY?x@github.com/acme/api.git" -> "https://ghp_CANARY"
		//   "https://ghp_CANARY#x@github.com/acme/api.git" -> "https://ghp_CANARY"
		//   "https://ghp_CANARY/x@github.com/acme/api.git" -> recorded VERBATIM
		//   "https://alice:12345?x@github.com/acme/api.git" -> "https://alice:12345"
		//   "https://alice:12345/x@github.com/acme/api.git" -> recorded VERBATIM
		//
		// THE CHECK IS NOT GATED ON "DID I ALREADY REMOVE A USERINFO", and that
		// gate is the round-4 finding. It read: having cut one prefix at the
		// last '@' of the authority, treat what remains as established-clean.
		// That is a single-pass assumption on an input that may hold several
		// at-signs, and it is false — measured leaking with the gate in place,
		// and identically on the parser this PR replaced, so the hole is
		// pre-existing rather than introduced:
		//
		//   "https://alice@ghs_TOKEN/part@github.com/acme/api.git"
		//     -> "https://ghs_TOKEN/part@github.com/acme/api.git", token kept
		//
		// Consuming a userinfo says something about the span that was removed
		// and nothing whatever about the span that was kept.
		//
		// The cost is stated and is the URL twin of one already accepted:
		// `https://github.com/acme/repo@release.git`, a repository whose NAME
		// holds an at-sign, is refused — with or without a login, because a
		// login no longer buys an exemption.
		//
		// THE TAIL IS PERCENT-DECODED ONCE BEFORE THE QUESTION IS ASKED, and
		// that decode is not a fourth guard bolted on: without it the rule
		// scans for a literal byte in a component whose bytes are escaped by
		// definition, so `ssh://git@example.com/%40acme/api.git` was recorded
		// while git handed the remote a path of `/@acme/api.git`. Found by the
		// git oracle in base_ancestry_remote_git_oracle_test.go on its first
		// run, not by a review round.
		//
		// ONCE IS THE WHOLE SEMANTICS, and this is where a decode differs from
		// the escape LIST that authorityIsHostAndPort's alphabet replaced. A
		// list loses to one more layer; a decode does not, because there is no
		// second layer to lose to — measured against git itself:
		//
		//   ssh://git@example.com/%40acme/api.git   -> git path "/@acme/api.git"
		//   ssh://git@example.com/%2540acme/api.git -> git path "/%40acme/api.git"
		//
		// git decodes a URL path exactly once, so `%2540` is a path holding the
		// literal text "%40" and is an at-sign to nobody.
		//
		// SCOPED TO THE URL FORM. sanitizeSCPRemote deliberately does NOT decode
		// its path, because git does not either: `git@example.com:%40acme/api.git`
		// reaches the remote as the literal path `%40acme/api.git` (measured the
		// same way). Decoding there would refuse a file whose name genuinely
		// contains a percent, which is the over-refusal `api%zz.git` exists to
		// prevent.
		return unclassifiableRemote(raw)
	}
	if authority == "" && !isLocalFileScheme(scheme) {
		// A network URL with no host names no repository, and a string whose
		// authority cannot be identified cannot be shown to be credential-free.
		// Two spellings reach this: "https://alice:TOKEN@/acme/api" clears to an
		// empty authority, and "https:///acme/api" never had one.
		return unclassifiableRemote(raw)
	}
	// A no-whitespace check and a no-percent check used to stand here, added a
	// round apart after a reviewer found each character. Both are subsumed by
	// the alphabet inside authorityIsHostAndPort and both mutation-tested as
	// NO-OP once it existed, so they are gone rather than left as guards that
	// cannot fail. That is the point of moving from prohibitions to an
	// alphabet: the list stops growing and starts shrinking.
	if !authorityIsHostAndPort(authority) {
		// WHAT IS LEFT AFTER USERINFO MUST BE host[:port], and checking only
		// that it is non-empty is not that check.
		//
		// "https://alice:SECRET/part@github.com/repo.git" has NO at-sign before
		// the first '/', so the authority is "alice:SECRET" and the userinfo cut
		// above removes nothing. It is not empty and holds no whitespace, so
		// every other rule passed it and the credential was recorded verbatim
		// (#9186 review round 1, measured). The only thing wrong with it is
		// structural: "SECRET" sits where a port belongs, and a port is digits.
		//
		// url.Parse rejected this before the rewrite — as an invalid-port error,
		// incidentally rather than deliberately. The rule is restored here as a
		// statement about the grammar instead of a parser side effect.
		return unclassifiableRemote(raw)
	}

	// A pathIsCredentialFree(tail) call used to stand here and it was DEAD: the
	// at-sign refusal above returns for every tail holding one, and that
	// function can only refuse a path that holds an at-sign. Mutating it to
	// return true unconditionally left the whole package green, which is the
	// same no-op verdict that retired the whitespace and percent guards. A
	// guard that cannot fail is worse than no guard, because it reads as
	// coverage.
	return scheme + authority + tail, true
}

// authorityIsHostAndPort reports whether a URL authority, with its userinfo
// already removed, is host[:port].
//
// It asks only about the PORT, and that narrowness is deliberate: the host half
// is left alone precisely because "is this text a hostname" is the unanswerable
// spelling question this whole file exists to stop asking. A port is not a
// spelling question — RFC 3986 says it is digits — so the one component that
// CAN be decided structurally is the one that gets decided.
//
// The delimiter is the colon outside brackets, so "[2001:db8::1]" has no port
// and "[::1]:8080" has one. An empty port ("github.com:") names no service and
// is refused with the rest.
func authorityIsHostAndPort(authority string) bool {
	if !bracketsAreAnIPLiteral(authority) {
		return false
	}
	// THE ALPHABET, and it is what closes the delimiter question for this
	// component. Everything outside it is refused without being enumerated:
	// every gen-delim of RFC 3986 §2.2 except the ':' a port needs and the
	// brackets an IP literal needs, every sub-delim, and the percent introducer
	// of §2.1. The clauses this replaced — no whitespace, no control, no
	// percent — were three prohibitions added in three separate rounds, each
	// after a reviewer found the character it names.
	if !urlAuthorityAlphabet.MatchString(authority) {
		return false
	}
	colon, ok := colonOutsideBrackets(authority)
	if !ok {
		return false
	}
	if colon < 0 {
		return true // no port at all
	}
	port := authority[colon+1:]
	if port == "" {
		return false
	}
	for i := range len(port) {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	return true
}

// bracketsAreAnIPLiteral reports whether the brackets in an authority component,
// if it has any, form a complete IP literal.
//
// THIS IS THE BRACKET INVARIANT, and it is one rule with two call sites rather
// than a guard per place a bracket has embarrassed us. RFC 3986 §3.2.2 gives a
// bracket exactly one job in an authority — IP-literal = "[" ( IPv6address /
// IPvFuture ) "]" — and it spans the WHOLE host. Anywhere else in an authority a
// bracket is an ordinary byte, and every finding in this file's history came
// from treating one as a delimiter anyway:
//
//	round 4  https://alice[realm:ghs_TOKEN]/part@github.com/repo.git
//	         the authority ends at the '/' before the at-sign, so nothing is
//	         cut; the colon hides inside the brackets, so the port check sees
//	         "no port" and passes; the credential is recorded verbatim.
//	round 4  [ghs_TOKEN]@github.com:acme/api.git
//	         an scp login is kept as routing information, and a bracketed one
//	         was kept too — but a bracket cannot open an ssh user any more than
//	         it can open a hostname.
//
// So the question asked is structural and closed: are there brackets, and if so
// do they start the component, close, contain only what an IP literal may
// contain, and end it apart from a port. It is NOT "does this look like an
// address" — the contents are checked against a character set, never a shape.
//
// Applied to the URL authority through authorityIsHostAndPort and to the scp
// login through loginIsRecordable; the scp HOST reaches the same answer through
// scpHost, whose bracketed alternative is the same character set. All three are
// pinned together by TestEveryAuthorityComponentAgreesOnBrackets.
func bracketsAreAnIPLiteral(component string) bool {
	open := strings.IndexByte(component, '[')
	if open < 0 && !strings.ContainsRune(component, ']') {
		return true // no brackets at all is the ordinary case
	}
	if open != 0 {
		// A stray ']', or a '[' that does not begin the component. Neither can
		// be a literal, and a literal is the only thing a bracket may be.
		//
		// Mutation-tested as BEHAVIOUR-PRESERVING rather than load-bearing: with
		// '[' at any index >= 1 that byte lands inside component[1:end] below,
		// and '[' is not a legal literal character, so the character loop
		// refuses the same strings on its own. It is kept because it is what
		// makes `component[1:end]` obviously correct — open == 0 means the slice
		// starts exactly after the opening bracket — and a reader should not
		// have to derive that from the character set.
		return false
	}
	end := strings.IndexByte(component, ']')
	if end < 0 {
		return false // unterminated
	}
	inner := component[1:end]
	if inner == "" {
		return false // "[]" addresses nothing
	}
	for i := range len(inner) {
		c := inner[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		case c == ':', c == '.':
		default:
			return false
		}
	}
	// Nothing may follow the literal except a port, whose digits are
	// authorityIsHostAndPort's business rather than this function's.
	rest := component[end+1:]
	return rest == "" || rest[0] == ':'
}

// urlAuthorityAlphabet admits exactly what a host, an IP literal and a numeric
// port are made of. The ':' and the brackets are constrained further by
// colonOutsideBrackets and bracketsAreAnIPLiteral; this only bounds the set of
// bytes those two are allowed to see.
//
// IT IS ALSO WHAT REFUSES PERCENT-ENCODING, and that is worth stating because a
// dedicated no-percent guard used to stand for it. Every other rule in this file
// scans for a literal byte, and percent-encoding is how a byte stops being
// literally present while still being there for anything that decodes the value:
// `https://alice%3Aghs_TOKEN%40github.com/…` holds no ':' and no '@', so the
// userinfo cut finds nothing, the port check sees a host with no port, and the
// credential is published. Measured against the parser this PR replaced
// (65c320c361ca), that exact input was REFUSED — a regression, not a gap.
//
// The rule is on the CHARACTER SET, never on a table of escapes. Percent-encoding
// does not terminate — %40, %2540, %252540 — so any list is beaten by one more
// layer, and lowercase hex beats a list holding only uppercase. Decoding first is
// worse still: it means choosing how many layers to peel, and it invents a value
// the author never wrote. An alphabet needs neither.
//
// Scoped to the AUTHORITY. A percent in a path or a query is ordinary —
// "https://github.com/acme/api%zz.git" is a real remote the old parser refused
// outright and this one keeps.
var urlAuthorityAlphabet = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]*$`)

// isLocalFileScheme reports whether an EMPTY authority is legitimate for this
// scheme. "file:///srv/git/repo.git" is a real remote whose authority is empty
// by definition — git reads it as PROTO_FILE, a local path, not as a network
// endpoint with a missing host — and it has nowhere to put a credential.
func isLocalFileScheme(scheme string) bool {
	return strings.EqualFold(scheme, "file://")
}

// sanitizeSCPRemote handles git's scheme-less [user@]host:path syntax.
//
// THE AUTHORITY BOUNDARY IS ESTABLISHED BEFORE ANY '@' IS READ. In scp syntax
// the path begins at the first colon outside brackets and everything before it
// is [user@]host, so an '@' after that colon belongs to the PATH and is not a
// delimiter at all. The previous implementation decided the delimiter first, by
// taking the LAST '@' in the whole string, so `git@example.com:repo@release.git`
// — where the second '@' is part of the repository NAME — was cut down to
// "release.git", which then failed the host check and vanished from the
// evidence entirely (#9181, measured).
func sanitizeSCPRemote(raw string) (string, bool) {
	colon, bracketsClosed := colonOutsideBrackets(raw)
	if !bracketsClosed || colon < 0 {
		// Unreachable via classifyRemote, which only routes here on a closed
		// bracket and a real colon. Kept because the invariant is cheap to
		// assert and expensive to lose.
		return unclassifiableRemote(raw)
	}

	authority, path := raw[:colon], raw[colon+1:]

	// A login lies wholly before the first colon, so it can never contain one:
	// scp syntax has no password field, which makes a login a routing value
	// rather than a credential. It has to survive — ssh dials on it, github and
	// gitlab both require git@, and a remote stripped of it can no longer clone.
	host, hasLogin := cutSCPAuthority(authority)

	if hasLogin && !loginIsRecordable(authority[:len(authority)-len(host)-1]) {
		// THE LOGIN IS HALF THE AUTHORITY AND WAS NEVER INSPECTED. Everything
		// here validated the HOST the authority resolved to and the PATH after
		// it, and simply preserved whatever sat in front of the last '@' —
		// which is the one span a credential can occupy while every other rule
		// passes. Two spellings reached signed evidence verbatim (#9186 review
		// round 2):
		//
		//   alice[realm:ghs_TOKEN]@github.com:org/repo.git
		//   git --token SECRET@github.com:org/repo.git
		//
		// The first hides its colon inside brackets, so the delimiter search
		// steps over it and the login keeps a full user:password pair. The
		// second is a command line: the whitespace rule was scoped to the host
		// and the path when it was narrowed from the previous implementation's
		// whole-string guard, and the login fell in the gap that scoping opened.
		return unclassifiableRemote(raw)
	}

	if strings.ContainsRune(path, '@') {
		// AN AT-SIGN AFTER THE AUTHORITY, and it is refused here on exactly the
		// terms sanitizeURLRemote already refuses one. THE TWO BRANCHES NOW
		// STATE ONE RULE: the authority is the only span of a remote a
		// credential can occupy, so once its boundary is established every
		// at-sign past it makes the string readable a second way, and a string
		// with two readings cannot be shown to be credential-free.
		//
		//   alice@example.com:SECRET@github.com:acme/api.git
		//     as scp       -> login "alice", host "example.com",
		//                     path "SECRET@github.com:acme/api.git"
		//     as authority -> user "alice@example.com", password SECRET,
		//                     host github.com
		//
		// THIS REPLACES TWO SHAPE PREDICATES, and the reason is the review
		// record rather than taste. pathReadsAsAnAuthority asked whether the
		// span in front of an at-sign looked like a userinfo AND the span
		// behind it looked like a host; those two lexical questions were
		// combined with an ordering that was found wrong in rounds 1, 5 and 6
		// of #9186, each time by a new spelling rather than a new mechanism:
		//
		//   r1  alice@example.com:SECRET@github.com:acme/api.git
		//   r5  alice@example.com:ghs_TOKEN/part@github.com:acme/api.git
		//   r6  alice@example.com:ghs_TOKEN/part@github.com/acme/api.git
		//
		// Two more of the same family were measured recorded verbatim on the
		// round-6 head and had not been reported at all — the predicate had a
		// hole per clause, not per round:
		//
		//       alice@example.com:ghs_TOKEN/part@github.com
		//       alice@example.com:ghs_TOKEN@github.com
		//
		// No ordering of those clauses closes the family, and that is provable
		// rather than a judgement: `git@example.com:repo@release.git` (which
		// #9181 asked be preserved) and `git@example.com:ghs_TOKEN@release.git`
		// differ only in how two identifier spans are SPELLED. Any rule that
		// keeps the first admits the second. Spelling is the question this file
		// exists to stop asking, so the family is closed from the other end.
		//
		// THE COST IS STATED, and it is the one #9181's acceptance list named:
		// a repository path containing an at-sign is dropped from the evidence
		// rather than recorded. `git@example.com:repo@release.git`,
		// `git@example.com:team/repo@release.git` and
		// `git@[2001:db8::1]:repo@release.git` are all refused. That cost is
		// already paid on the URL side of this same function — the comment in
		// sanitizeURLRemote states `https://github.com/acme/repo@release.git`
		// as an accepted loss — so the alternative was not "keep them" but
		// "keep them in one form and not the other", which is worse: it leaves
		// the attestor's fail direction depending on which spelling of the same
		// remote the operator happened to configure.
		//
		// Measured before taking it: of the 113 distinct remote URLs configured
		// across every repository on the machine this was written on, ZERO
		// contain an at-sign past the authority. GitHub, GitLab, Bitbucket and
		// Gitea all exclude '@' from owner and repository names, so the loss
		// falls only on self-hosted paths that put one in a directory name.
		// Dropping such a remote degrades the evidence; recording an
		// unredactable one is fail-OPEN, and the file's policy is to take the
		// first.
		return unclassifiableRemote(raw)
	}

	if !hostIsRecordable(host) {
		return unclassifiableRemote(raw)
	}
	if path == "" {
		// "git@github.com:" names a host and no repository. There is nothing to
		// record that a reader could act on.
		return unclassifiableRemote(raw)
	}
	if !noWhitespaceOrControl(path) {
		// PRESERVED FROM THE PREVIOUS IMPLEMENTATION, deliberately, and this is
		// the one rule here that the sibling git attestor does not have.
		//
		// It is what refuses `github.com:path --upload-pack=SECRET`: a single
		// colon, a host-shaped authority, no at-sign, so every other check in
		// this function passes it. Whitespace in a remote is where a helper
		// COMMAND LINE lives, and a command line is the shape this package has
		// already leaked through once. Dropping the rule to match the sibling
		// would loosen a credential refusal that is currently shipped and
		// pinned, and nothing here can show that loosening to be safe.
		//
		// Scoped to the scp path and the two authorities, NOT to local paths:
		// "/srv/git/My Repos/x.git" is an ordinary filename and is now recorded
		// as typed, where url.Parse used to percent-encode it into a spelling
		// git never wrote.
		return unclassifiableRemote(raw)
	}
	// Nothing in a credential-free scp remote is redactable, so it is recorded
	// exactly as typed — LOGIN INCLUDED. That is a change: this attestor used to
	// drop everything up to the last '@', rewriting git@github.com:org/repo.git
	// into github.com:org/repo.git. The rewrite invented a spelling git never
	// used, and the Remotes field documents itself as "the same repository
	// identity the git attestor records", which after #9177 is the string as
	// typed. The cost is stated out loud: a token pasted as a bare scp login is
	// lexically identical to an ssh user and is therefore recorded. Nothing in
	// the string can tell them apart, and the scheme'd spelling — which is what
	// tooling actually writes — is stripped by sanitizeURLRemote.
	return raw, true
}

// sanitizeLocalRemote handles the third form: a path.
//
// `git remote add origin /srv/git/repo.git` is a real remote and has no
// authority, so an at-sign in it belongs to the NAME (/srv/git/a@b.git) and a
// colon in it belongs to the name too (/srv/git/a:b.git). A path holding BOTH
// is the same ambiguity sanitizeSCPRemote refuses:
// "acme/alice:TOKEN@github.com:repo.git" is a relative path to git and an https
// authority to a human, and the two disagree about TOKEN.
func sanitizeLocalRemote(raw string) (string, bool) {
	if strings.ContainsRune(raw, ':') && strings.ContainsRune(raw, '@') {
		return unclassifiableRemote(raw)
	}
	// "TOKEN@github.com/acme/api.git" holds no colon, and reads as userinfo
	// in front of a host to every URL reader.
	if gitremote.FirstSegmentHoldsUserinfo(raw) {
		return unclassifiableRemote(raw)
	}
	return raw, true
}

// scpHost is the ONLY host shape sanitizeSCPRemote will accept: a DNS label run,
// or a bracketed IPv6 literal. An allowlist rather than a denylist, because the
// thing being excluded is "every string a colon can appear in" and that set is
// not enumerable.
//
// It is NOT the retired "does this look like a DNS name, i.e. does it have a
// DOT" heuristic, and the difference is the whole reason it survives the port:
// this pattern is blind to the host-versus-username question — "alice.smith"
// and "github.com" both match it, and "myserver" matches it too — so it can
// never be the thing that decides whether a prefix is a credential. That
// decision is made structurally, by hasLogin above. All this asks is whether
// the value could be a host at all.
var scpHost = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])$`)

// hostIsRecordable reports whether host could be a host at all. The whitespace
// and control-character cases are subsumed by scpHost, deliberately: a separate
// check for them here would be unfalsifiable, which is exactly the state
// mutation testing found the previous implementation's guards in.
func hostIsRecordable(host string) bool {
	return scpHost.MatchString(host)
}

// loginIsRecordable reports whether an scp login could be an ssh user.
//
// Two properties, and between them they are what makes keeping the login safe:
//
//   - NO COLON. This is the load-bearing one. scp syntax has no password field
//     because the first colon ends the authority — which is exactly why a login
//     is routing information rather than a credential, and the argument for
//     preserving it at all. A login that contains a colon has escaped that
//     guarantee, and the only way to do so is to hide it inside brackets, where
//     the delimiter search steps over it. The premise fails, so the conclusion
//     goes with it.
//   - NO WHITESPACE OR CONTROL CHARACTERS. ssh dials on this value; whitespace
//     makes it a command line rather than a user.
//
// A BRACKET IS THE THIRD QUESTION, and it was added in round 4 after
// `[ghs_TOKEN]@github.com:acme/api.git` came back recorded verbatim. An earlier
// version of this comment argued brackets should be left alone because
// `alice[realm]` carries no secret and refusing it would be a spelling test.
// That was wrong on the structure: a bracket in an AUTHORITY is an IP literal
// or it is nothing (RFC 3986 §3.2.2), and a login is not a host, so a login has
// no legitimate use for one at all. bracketsAreAnIPLiteral is asked here rather
// than a bespoke "no brackets" check so that the login and the URL authority
// answer to the same rule.
func loginIsRecordable(login string) bool {
	return scpLoginAlphabet.MatchString(login)
}

// scpLoginAlphabet is the WHITELIST that replaced this function's list of
// prohibitions, and the replacement is the round-5 closure.
//
// It used to read "no colon, and no whitespace or control, and no brackets, and
// no percent" — four clauses, each added the round after a reviewer found the
// delimiter it names. A list of prohibitions can only ever be as complete as
// the last thing someone thought of; a list of PERMISSIONS is complete by
// construction, and every gen-delim of RFC 3986 §2.2, every sub-delim, and the
// percent introducer of §2.1 are refused here without one of them being named.
//
// The at-sign is admitted because the login is the span before the LAST one, so
// "user@host@example.com" is a login ssh routes on. Everything admitted is a
// character an ssh username may actually hold.
var scpLoginAlphabet = regexp.MustCompile(`^[A-Za-z0-9._~@+_-]*$`)

// noWhitespaceOrControl reports whether v is free of the characters that no
// authority may contain and that no clone URL has any use for.
func noWhitespaceOrControl(v string) bool {
	for i := range len(v) {
		if v[i] <= ' ' || v[i] == 0x7f {
			return false
		}
	}
	return true
}

// cutSCPAuthority splits an scp authority into its host and reports whether a
// login preceded it. The split is at the LAST '@', which is where ssh splits:
// "user@host@example.com" logs in as "user@host" on "example.com". Splitting at
// the first would name the host "host@example.com", which is not a host.
//
// It is a named function rather than an inline LastIndexByte so that the choice
// is directly testable. A mutation flipping Last to Index changes nothing any
// end-to-end case observes — the scp branch records the string unmodified
// either way — so without a test on this boundary the choice would be pinned by
// nothing at all.
func cutSCPAuthority(authority string) (string, bool) {
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		return authority[at+1:], true
	}
	return authority, false
}

// colonOutsideBrackets returns the index of the DELIMITER — the first ':' that
// is not inside a bracketed IPv6 literal — and reports whether that answer could
// be established at all.
//
// git does exactly this, and for this reason: connect.c advances past the
// closing ']' before it looks for the delimiter, so `git@[2001:db8::1]:acme/api.git`
// splits at the colon AFTER the bracket. Taking the first colon instead — which
// is what strings.Cut did here — makes the host "[2001", which fails every check
// there is, and the remote disappears from the attestation. #9181 measured that
// exact string returning ok=false on origin/main: evidence lost to a delimiter
// chosen without regard to nesting.
//
// THE SCAN STOPS AT THE DELIMITER, and that bound is load-bearing. Bracket
// state belongs to the AUTHORITY; past the boundary every byte is path, where
// '[' is an ordinary filename character. Carrying the check to the end of the
// string made `git@github.com:repo[1.git` — a real remote whose authority was
// already unambiguous — unclassifiable, and dropped it (#9186 review round 1).
//
// The failure case is therefore narrow: a '[' that opens before any delimiter,
// never closes, AND swallows a ':'. Only then does the delimiter search have no
// defined place to resume. With no colon anywhere the string has no authority
// to find, so a stray '[' is just a filename byte — `/srv/git/a[1.git` is a
// local path and must survive, which the whole-string version also dropped.
func colonOutsideBrackets(v string) (int, bool) {
	depth := 0
	colonInsideBrackets := false
	for i := range len(v) {
		switch v[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				return i, true
			}
			colonInsideBrackets = true
		}
	}
	if depth != 0 && colonInsideBrackets {
		return -1, false
	}
	return -1, true
}

// schemeSeparator returns the index of the "://" that terminates a valid scheme,
// or -1 when the string does not begin with one. Hand-rolled rather than taken
// from url.Parse: git looks for a literal "://" (connect.c), which is why
// "https:/one/slash" is scp syntax to git and a scheme'd URL to RFC 3986.
func schemeSeparator(v string) int {
	i := strings.Index(v, "://")
	if i <= 0 {
		return -1
	}
	for j := range i {
		c := v[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return -1
		}
	}
	return i
}

// percentDecodeOnce applies RFC 3986 §2.1 percent-decoding a SINGLE time,
// leaving a malformed escape as the literal bytes it is written with.
//
// One pass, because one pass is what a URL path MEANS. It is not a conservative
// choice or a compromise with an unbounded problem: git decodes a URL path
// exactly once and stops, so "%2540" names a path containing the four
// characters "%40" and no amount of further decoding is anything a reader of
// that remote will do. Hand-rolled rather than taken from net/url because
// url.PathUnescape returns an error for "%zz" and this must leave it alone —
// "api%zz.git" is a real repository name the pre-PR parser refused and this one
// keeps.
//
// Used only on a URL tail. The scp path is not decoded, by git or by this,
// because an scp path is handed to the remote shell as typed.
func percentDecodeOnce(v string) string {
	if !strings.ContainsRune(v, '%') {
		return v
	}
	var out strings.Builder
	out.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) {
			hi, hiOK := hexNibble(v[i+1])
			lo, loOK := hexNibble(v[i+2])
			if hiOK && loOK {
				out.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		out.WriteByte(v[i])
	}
	return out.String()
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// cutRemoteQueryAndFragment drops everything from the first '?' or '#'.
//
// A clone URL identifies a repository by its host and path; no git remote needs
// a query or a fragment to be understood, so both are dropped wholesale rather
// than filtered against a list of known token parameter names that the next
// provider will not be on.
func cutRemoteQueryAndFragment(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// cutRemoteAuthority splits a URL's authority from the path, query or fragment
// that follows it.
func cutRemoteAuthority(v string) (string, string) {
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		return v[:i], v[i:]
	}
	return v, ""
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
