// Copyright 2023 The Witness Contributors
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
	"crypto"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
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
	Name    = "git"
	Type    = "https://aflock.ai/attestations/git/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ GitAttestor            = &Attestor{}
)

type GitAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *Attestor

	// Subjecter
	Subjects() map[string]cryptoutil.DigestSet

	// Backreffer
	BackRefs() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.BoolConfigOption(
			allowSubdirectoryOption,
			"Attest from a subdirectory of the worktree instead of failing; the non-empty workdirprefix is still signed and verifiers may refuse it",
			false,
			func(a attestation.Attestor, allow bool) (attestation.Attestor, error) {
				gitAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a git attestor", a)
				}
				WithAllowSubdirectory(allow)(gitAttestor)
				return gitAttestor, nil
			},
		),
	)
	detection.Register(Name, detectorYAML)
}

type Status struct {
	Staging  string `json:"staging,omitempty"`
	Worktree string `json:"worktree,omitempty"`
}

type Tag struct {
	Name         string `json:"name"`
	TaggerName   string `json:"taggername"`
	TaggerEmail  string `json:"taggeremail"`
	When         string `json:"when"`
	PGPSignature string `json:"pgpsignature"`
	Message      string `json:"message"`
}

type Attestor struct {
	GitTool    string               `json:"gittool"`
	GitBinPath string               `json:"gitbinpath,omitempty"`
	GitBinHash cryptoutil.DigestSet `json:"gitbinhash,omitempty"`
	CommitHash string               `json:"commithash"`
	// CommitHashVerified is the verified-commit-hash capability marker: it
	// records, inside the same signed predicate as CommitHash, that CommitHash
	// is the output of computeVerifiedCommitHash — the commit's canonical
	// object bytes re-hashed with the collision-detecting hasher, refused on a
	// claimed/computed mismatch or a detected collision — rather than a hash
	// the repository's storage merely claimed. The subject matcher grants the
	// SHA-1 commit-anchoring exception ONLY to collections whose git
	// attestation carries this marker (cryptoutil.HasGitCommitVerifiedMarker);
	// evidence signed before the hardening lacks it and stays unmatchable via
	// sha1. Because marker and hash travel in one signed unit, a marker cannot
	// be combined with an unverified hash without re-signing. Only Attest may
	// set it, and only at the same site that records the verified hash.
	CommitHashVerified bool                 `json:"commithashverified,omitempty"`
	Author             string               `json:"author"`
	AuthorEmail        string               `json:"authoremail"`
	CommitterName      string               `json:"committername"`
	CommitterEmail     string               `json:"committeremail"`
	CommitDate         string               `json:"commitdate"`
	CommitMessage      string               `json:"commitmessage"`
	Status             map[string]Status    `json:"status,omitempty"`
	CommitDigest       cryptoutil.DigestSet `json:"commitdigest,omitempty"`
	Signature          string               `json:"signature,omitempty"`
	ParentHashes       []string             `json:"parenthashes,omitempty"`
	TreeHash           string               `json:"treehash,omitempty"`
	Refs               []string             `json:"refs,omitempty"`
	// Remotes holds origin's URLs when a remote named origin exists, else
	// every remote's, in remote-name order (anchorRemotes).
	Remotes []string `json:"remotes,omitempty"`
	// RemotesRefused is the observable trace of every remote anchorRemotes
	// selected that this attestor declined to record, and it exists so that A REFUSAL CANNOT LOOK
	// LIKE AN ABSENCE.
	//
	// Remotes is the fail-CLOSED half of the contract: a remote whose authority
	// boundary cannot be established is omitted rather than recorded, because
	// recording an unredactable string is the fail-open direction (#8950).
	// Omission on its own, though, is a fail-open of a second kind — a reader
	// cannot tell "this repository has no remote" from "this attestor found a
	// remote and refused it", so the gap in the evidence is invisible in the
	// evidence. That is the shape that has bitten this repository before: an
	// attestor `error` meaning "could not look" read downstream as "looked and
	// found nothing".
	//
	// NO BYTE OF THE REFUSED REMOTE APPEARS HERE. The reason is a closed set of
	// constants chosen by the code path that refused (see the refusal*
	// constants), never anything derived from the input — the refused string is
	// exactly the one that may hold a live credential, and
	// docs/architecture/pushgate-agent-policy-contract.md requires free-form
	// predicate values to be bounded and to carry no secret. The count is the
	// only input-dependent number, and a count cannot spell a token.
	//
	// Sorted by reason, because this list is SIGNED and two reads of one
	// unchanged repository must produce the same predicate bytes.
	RemotesRefused []RefusedRemote `json:"remotesrefused,omitempty"`
	Tags           []Tag           `json:"tags,omitempty"`
	RefNameShort   string          `json:"branch,omitempty"`
	// WorkdirPrefix is the attestation working directory relative to the
	// worktree root, with forward slashes, and "" at the root
	// (testifysec/judge#9856).
	//
	// The repository open walks UP from the working directory, so a mint run
	// from a subdirectory still records the whole commit here, while the
	// material attestor walks only that subdirectory: one such mint bound the
	// right commit and attested 518 of 284,644 files. This field is the signed
	// statement of where the mint ran, in the same collection as the material
	// it qualifies, so a verifier can refuse a partial tree.
	//
	// NOT omitempty, on purpose: "" is the claim "minted at the root", and an
	// absent field means a producer too old to say.
	WorkdirPrefix string `json:"workdirprefix"`

	// allowSubdirectory lets a mint proceed from a subdirectory. The prefix is
	// still recorded, so the choice is visible to every verifier. Default
	// false: a subdirectory mint fails fast (the early check; verifiers stay
	// authoritative).
	allowSubdirectory bool
}

// allowSubdirectoryOption is the config option (flag
// --attestor-git-allow-subdirectory) that lets a mint run from a subdirectory
// of the worktree.
const allowSubdirectoryOption = "allow-subdirectory"

// Option configures the git attestor.
type Option func(*Attestor)

// WithAllowSubdirectory lets the attestor run from a subdirectory of the
// worktree instead of refusing. The non-empty WorkdirPrefix is still signed.
func WithAllowSubdirectory(allow bool) Option {
	return func(a *Attestor) {
		a.allowSubdirectory = allow
	}
}

func New() *Attestor {
	return &Attestor{
		Status: make(map[string]Status),
	}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

// collisionDetectingHash is the capability that separates collision-DETECTING
// SHA-1 (github.com/pjbgf/sha1cd, which go-git registers for object hashing)
// from plain crypto/sha1: sha1cd's digest reports whether the input carried
// the near-collision blocks a chosen-prefix attack requires. crypto/sha1 does
// not implement this method, so it is a precise discriminator. Production
// asserts it in computeVerifiedCommitHash; TestGitObjectHashIsCollisionDetecting
// pins that go-git's hasher keeps satisfying it.
//
// The plain hash.Hash Sum() is NOT enough: sha1cd's Sum returns the real
// SHA-1 digest even when a collision was detected — the detection flag is
// only exposed through CollisionResistantSum. A colliding object hashes to
// its "correct" id, so a mismatch check alone would never see it.
type collisionDetectingHash interface {
	CollisionResistantSum(in []byte) ([]byte, bool)
}

// computeVerifiedCommitHash recomputes the object id of a commit's canonical
// bytes — the standard git object header "commit <len>\x00" plus content —
// with go-git's collision-detecting hasher, and returns the computed id only
// when it equals the id the repository's storage claims for the object.
//
// This is the ONLY path by which a commit hash may reach the attested record.
// head.Hash() and ref hashes are the repository's CLAIM about what its
// storage contains; a crafted repository can store arbitrary bytes under any
// name. Attesting the claim would make every downstream protection —
// collision-detecting hashing, the verifier's SHA-1 commit-subject gates —
// a statement about an object nobody ever hashed.
//
// It fails, never falls back, in three cases:
//  1. the hasher is not collision-detecting (a go-git downgrade or hash
//     re-registration — the pin test catches this in CI; this check catches
//     it at runtime),
//  2. the collision detector reports the object carries near-collision
//     blocks (the object is an artifact of a chosen-prefix attack),
//  3. the computed id differs from the claimed id (storage lies about what
//     it holds).
func computeVerifiedCommitHash(claimed plumbing.Hash, content []byte) (string, error) {
	h := plumbing.NewHasher(plumbing.CommitObject, int64(len(content)))
	if _, err := h.Write(content); err != nil {
		return "", fmt.Errorf("hashing canonical bytes of commit %s: %w", claimed, err)
	}

	cd, ok := h.Hash.(collisionDetectingHash)
	if !ok {
		return "", fmt.Errorf("git object hasher %T is not collision-detecting; refusing to attest a SHA-1 commit id without collision detection", h.Hash)
	}

	sum, collision := cd.CollisionResistantSum(nil)
	if collision {
		return "", fmt.Errorf("commit object claimed as %s carries the near-collision blocks of a SHA-1 chosen-prefix attack; refusing to attest it", claimed)
	}

	var computed plumbing.Hash
	if len(sum) != len(computed) {
		return "", fmt.Errorf("git object hasher produced a %d-byte digest, want %d; refusing to attest", len(sum), len(computed))
	}
	copy(computed[:], sum)

	if computed != claimed {
		return "", fmt.Errorf("repository storage claims commit %s but its canonical object bytes hash to %s; refusing to attest the claimed id", claimed, computed)
	}

	return computed.String(), nil
}

// verifiedCommitObject reads the canonical bytes of the commit the repository
// claims as `claimed` ONCE, verifies them via computeVerifiedCommitHash, and
// decodes the commit FROM THOSE VERIFIED BYTES. Every attested field derived
// from the returned commit — tree hash, parent hashes, author, committer,
// message, signature — is therefore bound to the same bytes the verified id
// covers, not to a second, unverified read of storage.
func verifiedCommitObject(repo *git.Repository, claimed plumbing.Hash) (*object.Commit, string, error) {
	encoded, err := repo.Storer.EncodedObject(plumbing.CommitObject, claimed)
	if err != nil {
		return nil, "", err
	}

	reader, err := encoded.Reader()
	if err != nil {
		return nil, "", err
	}
	content, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, "", readErr
	}
	if closeErr != nil {
		return nil, "", closeErr
	}

	verifiedHash, err := computeVerifiedCommitHash(claimed, content)
	if err != nil {
		return nil, "", err
	}

	verified := &plumbing.MemoryObject{}
	verified.SetType(plumbing.CommitObject)
	if _, err := verified.Write(content); err != nil {
		return nil, "", err
	}

	commit, err := object.DecodeCommit(repo.Storer, verified)
	if err != nil {
		return nil, "", err
	}

	return commit, verifiedHash, nil
}

// repositoryIsProvablyUnborn reports whether the repository has genuinely never
// had a commit, as opposed to merely having a HEAD this attestor cannot resolve.
//
// The failure alone cannot tell those apart: go-git reports both as "reference
// not found", and `git rev-parse --verify --quiet HEAD` exits 1 for both. A
// repository whose .git/HEAD names a branch that does not exist produces the
// same signal as `git init` with no commits, while still holding every ref and
// object it ever had. Inferring "unborn" from that signal is how an attestor
// comes to report "I looked and found nothing" when the truth is "I could not
// look".
//
// So unborn is PROVEN here, never inferred: an unborn repository has no refs
// besides the symbolic HEAD, and no objects at all. Anything else — a surviving
// branch ref, a loose commit, even a blob staged by `git add` — means there is
// repository state that HEAD failed to name, and the attestation must fail
// closed rather than emit an empty one.
func repositoryIsProvablyUnborn(repo *git.Repository) (bool, error) {
	refs, err := repo.References()
	if err != nil {
		return false, fmt.Errorf("enumerate references: %w", err)
	}
	defer func() { refs.Close() }()

	hasRef := false
	if err := refs.ForEach(func(ref *plumbing.Reference) error {
		// HEAD itself is the reference that failed to resolve; a symbolic ref
		// carries no history on its own. Only a ref that names an object is
		// evidence that this repository has a commit.
		if ref.Name() == plumbing.HEAD || ref.Type() != plumbing.HashReference {
			return nil
		}
		hasRef = true
		return storer.ErrStop
	}); err != nil {
		return false, fmt.Errorf("enumerate references: %w", err)
	}
	if hasRef {
		return false, nil
	}

	objs, err := repo.Storer.IterEncodedObjects(plumbing.AnyObject)
	if err != nil {
		return false, fmt.Errorf("enumerate objects: %w", err)
	}
	defer func() { objs.Close() }()

	hasObject := false
	if err := objs.ForEach(func(plumbing.EncodedObject) error {
		hasObject = true
		return storer.ErrStop
	}); err != nil {
		return false, fmt.Errorf("enumerate objects: %w", err)
	}

	return !hasObject, nil
}

// A git remote is written in one of exactly three forms, and which one it is
// decides where — or whether — a credential can be hiding in it.
//
// Deriving the form FIRST is the whole design. Five review findings across two
// rounds of PR #9177 were one mistake repeated: a local lexical test standing in
// for a structural boundary. Which '@' delimits the credential, decided without
// computing the authority. Whether a prefix is a host, decided by looking for a
// dot. Where the path starts, decided by taking the first colon with no regard
// for bracket nesting. Every one of those questions has an answer in git's own
// grammar, and none of them has an answer in the characters alone.
//
// url.Parse is deliberately absent from all of this. Go implements RFC 3986;
// git implements connect.c, and the two disagree — an scp remote is not a URL
// at all, "alice:TOKEN@host:path" is an OPAQUE url.URL whose User is already
// nil, and "https:/alice:TOKEN@host/path" is a hierarchical URL with a scheme
// and no authority. Each disagreement was patched here in turn (`Opaque == ""`,
// then `bareColonPath`, then the review's third finding), which is what a patch
// on a parser mismatch always looks like: another one arrives next round. There
// is no set of guards that makes an RFC 3986 parser answer a question about
// git's grammar, so the grammar is read directly instead.
// RefusedRemote is one entry of the refusal trace: a reason from the closed set
// below, and how many configured remote URLs were refused for it.
type RefusedRemote struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// The closed set of refusal reasons. Each names a CODE PATH, not a property of
// the input, which is what keeps the trace free of the refused bytes. Adding a
// reason is a deliberate act: TestRefusalReasonsAreAClosedSet pins the set, so
// a new one cannot arrive unnoticed and a typo cannot invent a category.
const (
	// refusalAmbiguousAuthority is the general case: the string's authority
	// boundary could not be established, or what stands in an authority
	// position could not be shown to be credential-free. It covers the
	// unterminated bracket, the empty remote, and every rule in the URL, scp
	// and local branches that refuses on a disagreement between two readings.
	refusalAmbiguousAuthority = "ambiguous-authority"
	// refusalOpaqueTransport is git's remote-helper syntax, `transport::address`.
	// The address is an arbitrary helper INVOCATION rather than an endpoint, so
	// there is no authority in it to locate and no span of it that can be shown
	// to hold no credential.
	refusalOpaqueTransport = "opaque-transport"
	// refusalPathBytesNotRedactable is a '?' or '#' in a remote that git does
	// NOT hand to a query-parsing transport. Cutting there would rename the
	// repository inside signed evidence; recording it verbatim would publish
	// whatever the bytes hold. The two readings disagree about whether anything
	// in them is secret, so neither is taken — see recordRemote.
	refusalPathBytesNotRedactable = "path-bytes-not-redactable"
)

// remoteVerdict is the THREE-VALUED contract this attestor applies to every
// configured remote, and it replaces a two-valued one that could not express
// the case that mattered.
//
// The old shape was "always return a string". Under it, a remote whose
// authority boundary is unclear has only two moves — publish it, or rewrite it
// — and #9177 spent nine review rounds oscillating between them: tighten to
// kill a credential leak and a legitimate repository identity breaks; loosen to
// keep the identity and the leak reopens. The tension is not in any of the
// rules. It is in the requirement to emit SOMETHING.
//
//	remoteClean    the bytes carry no credential and the string is
//	               unambiguous: record it VERBATIM, byte for byte. '#', '?',
//	               '[' and '@' are ordinary path bytes here and survive.
//	remoteRedacted a credential is present AND the authority boundary is
//	               unambiguous: record the redacted form.
//	remoteRefused  neither of the above can be established: record NOTHING for
//	               this remote, and count the refusal in RemotesRefused.
//
// The third value is the whole point, and it is what the reviewer asked for in
// six of the nine rounds ("omit an ambiguous remote rather than record a
// different path"). A remote that is not recorded can neither leak a credential
// nor misname a repository.
//
// remoteRefused is the ZERO VALUE deliberately. A rule that forgets to set a
// verdict, or a future branch that falls through, refuses rather than records.
type remoteVerdict int

const (
	remoteRefused remoteVerdict = iota
	remoteClean
	remoteRedacted
)

// recordable is a CLOSED POSITIVE LIST, not `!= remoteRefused`. A verdict added
// later and not listed here is not recorded, which is the direction a mistake
// in this file should fail.
func (v remoteVerdict) recordable() bool {
	return v == remoteClean || v == remoteRedacted
}

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
	// Without this form the classifier could not reach the string at all: the
	// URL branch is claimed by schemeSeparator, which requires a literal "://",
	// and `ext::helper --token SECRET` carries "::" with no slashes. So it fell
	// through to scp, where "ext" reads as a host and `--token SECRET` is just
	// path text — no colon before an at-sign, nothing for pathIsCredentialFree
	// to object to. Measured on this branch before this form existed:
	// recordRemote("ext::helper --token SECRET") returned that string
	// verbatim with ok=true, i.e. the token went into signed evidence
	// (testifysec/judge#9188).
	//
	// It is REFUSED rather than redacted, and that is not caution — it is the
	// only defensible reading. The address after "::" is an arbitrary helper
	// INVOCATION, not an endpoint: `ext::git-remote-https https://u:tok@h/r.git`
	// and `ext::ssh -i /key %S repo` are both legal, so there is no authority
	// in it to locate and no part of it that can be shown to be
	// credential-free. A redactor that cannot name the credential's boundary
	// has nothing to strip, and recording the string anyway is the fail-OPEN
	// direction this whole function exists to close.
	//
	// The sibling base-ancestry attestor models the same form for the same
	// reason (testifysec/judge#9186) — that package had already SHIPPED this
	// leak. The two implementations deliberately diverge elsewhere and are not
	// merged; only the form is shared.
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

	// LOCAL-PATH PRECEDENCE COMES FIRST, BEFORE ANY BRACKET VERDICT.
	//
	// git decides local-versus-scp on one question — does a slash arrive before
	// the colon (connect.c url_is_local_not_ssh) — and that question is answered
	// by the RAW colon, not by the delimiter search. A path has no authority, so
	// its brackets are filename bytes and there is no boundary to compute.
	//
	// Deciding it after the bracket check dropped "/srv/git/repo[1:2.git": an
	// unterminated '[' swallowed the colon, the delimiter came back
	// uncomputable, and a local remote whose leading slash had already settled
	// the question was refused. Precedence, not an extra guard, is the fix —
	// the same reason "/srv/git/a::b.git" is a filename and not a remote helper.
	//
	// A colonless string needs no clause of its own: colonOutsideBrackets can
	// only report "unterminated" when it actually swallowed a colon, so with no
	// colon anywhere it returns "no delimiter" and the check below sends the
	// string to remoteFormLocal regardless.
	//
	// Ported from the sibling base-ancestry attestor, which reached this
	// ordering through its own review rounds (testifysec/judge#9186).
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
	// signature. It is tested here, AFTER the local-path rule, so that
	// "/srv/git/a::b.git" stays a filename rather than becoming a helper
	// invocation — a leading slash has already settled that question.
	//
	// This refuses slightly more than git's own scheme-character test would:
	// "git@host::path" is scp syntax to git and a helper to this. Those are
	// strings no clone uses, and where the two readings disagree the refusal is
	// the fail-CLOSED direction, so the over-refusal is the cheap error here.
	if colon+1 < len(raw) && raw[colon+1] == ':' {
		return remoteFormHelper, "", raw
	}
	return remoteFormSCP, "", raw
}

// recordRemote decides what a git remote contributes to the attestation, under
// the three-valued contract remoteVerdict describes.
//
// The attestation is signed and uploaded, so every remote recorded here
// outlives the build and is readable by anything that can read the envelope. A
// CI checkout's remote routinely carries a live token — GitHub Actions writes
// https://x-access-token:ghs_TOKEN@github.com/owner/repo — and this used to
// append the RAW string on any url.Parse error, that is, in exactly the cases
// where nobody had checked whether it held one. "Could not look" was recorded
// as "found nothing", so an UNPARSEABLE credential leaked while a parseable one
// was correctly stripped. (testifysec/judge#8950)
//
// Dropping every remote would be fail-closed and WRONG in its own way: judge
// links a DSSE to a product by these strings, so a redactor that discards them
// takes the attestation's whole discovery surface with it. Both failures are
// real, and where they cannot both be avoided the fail direction follows the
// worse one — recording an unredactable string is fail-OPEN, so a remote this
// cannot classify is dropped rather than passed through. What makes that drop
// acceptable rather than a third silent failure is RemotesRefused: the refusal
// is recorded, so the evidence is honest about its own gap.
func recordRemote(rawWithQuery string) (remoteVerdict, string, string) {
	if rawWithQuery == "" {
		return refuseRemote(refusalAmbiguousAuthority)
	}

	// THE VERDICT IS TAKEN ON THE STRING AS WRITTEN. ONLY THE RECORDED VALUE IS CUT.
	//
	// cutRemoteQueryAndFragment used to run FIRST, so every rule below judged a
	// string the user never wrote — and a truncated string can be credential-free
	// in a way the original is not. Measured on an earlier head of this branch:
	//
	//	"alice:SECRETVALUE?q@github.com:acme/api.git" -> ok=true "alice:SECRETVALUE"
	//	"/srv/alice:SECRETVALUE#q@repo.git"           -> ok=true "/srv/alice:SECRETVALUE"
	//
	// Both are authorities that lost their scheme, and both hold a credential the
	// '@' delimits. The cut removed the '@' — the ONE byte that made the string
	// recognisable as userinfo — and what was left read as an innocent
	// "host:path" scp remote and an innocent "dir:name" path. The check that
	// would have caught each of them (recordSCPRemote's login/at-sign
	// disagreement rule, recordLocalRemote's colon-and-at rule) never saw the
	// byte it keys on.
	//
	// Running the whole pipeline twice is the fix, and it is deliberately not a
	// new rule: the credential decision is taken on the bytes the user typed,
	// and the cut then applies only to the value that gets recorded.
	verdict, written, reason := recordRemoteAsWritten(rawWithQuery)
	if !verdict.recordable() {
		return refuseRemote(reason)
	}

	// The overwhelming majority of remotes carry neither byte and are done here.
	if !strings.ContainsAny(rawWithQuery, "?#") {
		return verdict, written, ""
	}

	// '?' AND '#' ARE A QUERY AND A FRAGMENT ONLY WHERE GIT HANDS THE REMOTE TO
	// A TRANSPORT THAT PARSES THEM. Everywhere else they are filename bytes, and
	// cutting there does not remove a credential — it renames the repository,
	// and the rename is then signed. Measured on earlier heads of this branch:
	//
	//	"git@example.com:repo#release.git" -> ok=true "git@example.com:repo"
	//	"/srv/git/repo#release.git"        -> ok=true "/srv/git/repo"
	//	"file:///srv/git/repo#release.git" -> ok=true "file:///srv/git/repo"
	//
	// None of those targets exists. recordSCPRemote states the principle this
	// broke — "rewriting it would invent a spelling git never used".
	//
	// THIS WAS NARROWED TWICE AND WAS STILL WRONG BOTH TIMES, which is the whole
	// lesson. Round 7 ran the cut before classifyRemote, so it renamed scp and
	// local repositories. Round 8 restricted it to remoteFormURL — and that was
	// still wrong, because CLASSIFYING A STRING AS A URL DOES NOT MEAN GIT HANDS
	// IT TO A PARSER THAT HAS A QUERY. git routes http/https/ftp/ftps through
	// curl, which parses both bytes; its own ssh, git and file transports take
	// the path verbatim, so "ssh://host/repo#release.git" and
	// "file:///srv/git/repo#release.git" are as much filename bytes as the scp
	// form is (testifysec/judge#9177).
	//
	// So the gate is the TRANSPORT, not the form, and it is written as a
	// closed positive list that fails CLOSED: a scheme nobody has classified is
	// refused rather than cut, so the next scheme cannot inherit this bug by
	// default. See schemeHasQueryGrammar.
	form, scheme, _ := classifyRemote(rawWithQuery)
	if form != remoteFormURL || !schemeHasQueryGrammar(scheme) {
		// REFUSED, NOT PASSED THROUGH. The review offered both remedies
		// ("preserve those path bytes or refuse the ambiguous remote") and only
		// one of them closes #8950 as well: recording the remote verbatim puts
		// "…/repo.git?token=ghs_TOKEN" straight into evidence, because no rule
		// in the scp or local branch keys on anything in it — there is no colon
		// before an at-sign and no at-sign at all. Telling that string apart
		// from the legitimate "…/repo#release.git" means asking whether the
		// bytes after the delimiter LOOK like a token, which is the spelling
		// question this file exists to stop asking. The two readings disagree
		// about whether anything is secret, so the disagreement is the answer.
		//
		// IT IS CASE 3, NOT CASE 1. The refusal is counted in RemotesRefused
		// under refusalPathBytesNotRedactable, so a legitimately-named
		// repository that disappears from the evidence for this reason leaves a
		// mark saying so. That is the difference between this and the silent
		// omission the same code performed before: the identity is still lost,
		// but the loss is no longer indistinguishable from having no remote.
		return refuseRemote(refusalPathBytesNotRedactable)
	}

	raw := cutRemoteQueryAndFragment(rawWithQuery)
	if raw == "" {
		// Unreachable from here: schemeHasQueryGrammar only accepts a scheme
		// that schemeSeparator already found, which needs at least one byte
		// before the "://", so the string cannot begin with the delimiter and
		// cannot cut down to nothing. Kept because the invariant is cheap to
		// assert and expensive to lose — a bare "?token=…" is remoteFormLocal
		// and is refused above, never here.
		return refuseRemote(refusalAmbiguousAuthority)
	}
	cutVerdict, cut, cutReason := recordRemoteAsWritten(raw)
	if !cutVerdict.recordable() {
		return refuseRemote(cutReason)
	}
	// BYTES WERE REMOVED, SO THIS IS NEVER CLEAN. The second pass judges `raw`,
	// which no longer carries the query or the fragment, and would happily call
	// it clean — but "clean" is this contract's promise that the recorded value
	// is the configured value byte for byte, and here it is not. The verdict is
	// taken from the operation, not from the second pass's opinion of its own
	// input.
	return remoteRedacted, cut, ""
}

// schemeHasQueryGrammar reports whether git hands a remote of this scheme to a
// transport that PARSES a query and a fragment, which is the only circumstance
// under which those bytes may be cut from a recorded remote.
//
// git's curl-family transports — http, https, ftp, ftps — pass the URL to
// libcurl, which splits the query and the fragment off before the request. Its
// NATIVE transports do not: ssh and git send the path to the remote end
// verbatim, and file resolves it on the filesystem, so a '?' or '#' in one of
// those is an ordinary byte of the repository's name.
//
// IT IS A CLOSED POSITIVE LIST AND IT FAILS CLOSED. An unrecognised scheme
// returns false, so a scheme this has never been taught about is refused rather
// than silently cut — the caller treats false as "cannot be represented
// safely". That direction matters: the alternative shape, a list of schemes to
// EXCLUDE, grows by one entry every time a reviewer finds another one, and each
// entry it is missing is a repository renamed inside signed evidence.
func schemeHasQueryGrammar(scheme string) bool {
	switch {
	case strings.EqualFold(scheme, "http://"),
		strings.EqualFold(scheme, "https://"),
		strings.EqualFold(scheme, "ftp://"),
		strings.EqualFold(scheme, "ftps://"):
		return true
	default:
		return false
	}
}

// recordRemoteAsWritten is recordRemote's body with no query/fragment cut in
// front of it: it classifies the bytes it is handed and routes them to the
// branch that owns that form.
func recordRemoteAsWritten(raw string) (remoteVerdict, string, string) {
	form, scheme, rest := classifyRemote(raw)
	switch form {
	case remoteFormURL:
		return recordURLRemote(scheme, rest)
	case remoteFormSCP:
		return recordSCPRemote(raw)
	case remoteFormLocal:
		return recordLocalRemote(raw)
	case remoteFormHelper:
		return refuseRemote(refusalOpaqueTransport)
	default:
		// remoteFormUnclassifiable lands here: it has no authority whose
		// boundary this can compute, so it cannot be shown to be
		// credential-free. So does any form added later and not routed above,
		// which is why the default refuses rather than falling through to a
		// branch.
		return refuseRemote(refusalAmbiguousAuthority)
	}
}

// refuseRemote is the SINGLE construction point for case 3, and it exists as a
// named function so the decision is one edit rather than a sweep through every
// refusal site.
//
// IT NEVER TAKES THE REMOTE. The signature is the enforcement: a reason
// constant is the only thing it can be handed, so no refusal site can
// accidentally carry a byte of the string it just refused into the trace, and a
// future edit cannot start doing so without changing this signature. The
// recorded value is always empty — refusing and then recording something are
// not two halves of one decision.
//
// The question this used to leave open — silence, or a marker — is now closed
// in favour of the marker, and the marker lives in RemotesRefused rather than
// in Remotes. Putting it in Remotes was the tempting shape and is the wrong
// one: every consumer of that list treats each entry as a repository identity
// (judge's archivista parser reads Remotes[0] as THE repository URL), so a
// marker string there would be parsed as the name of a repository.
func refuseRemote(reason string) (remoteVerdict, string, string) {
	return remoteRefused, "", reason
}

// recordURLRemote handles scheme://[userinfo@]host[:port]/path.
//
// The authority is bounded by the grammar rather than guessed, so the userinfo
// question has a definite answer: everything up to the LAST '@' inside the
// authority is userinfo and is removed. The last, not the first — an encoded or
// repeated at-sign inside the userinfo would otherwise leave half the credential
// behind.
func recordURLRemote(scheme, rest string) (remoteVerdict, string, string) {
	// userinfoRemoved is what separates verdict 1 from verdict 2, and it is
	// taken from the OPERATION rather than by comparing the result against the
	// input. A string comparison would be a proxy for the question, and it
	// answers wrong on the boundary case that matters: a URL whose userinfo is
	// the empty string ("https://@github.com/acme/api.git") has a credential
	// delimiter removed while its remaining bytes are unchanged in every other
	// position, and that is a rewrite, not a verbatim record.
	authority, tail := cutRemoteAuthority(rest)
	userinfoRemoved := false
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
		userinfoRemoved = true
	}

	if strings.ContainsRune(tail, '@') {
		// AN AT-SIGN DOWNSTREAM OF THE AUTHORITY, WHETHER OR NOT ONE WAS
		// ALREADY CONSUMED.
		//
		// Round 5 gated this on "no userinfo was found", and that gate was the
		// bug. CONSUMING ONE USERINFO TELLS YOU SOMETHING ABOUT THE SPAN YOU
		// REMOVED AND NOTHING ABOUT THE SPAN YOU KEPT. Measured on 8e1e8100:
		//
		//	"https://alice@ghs_TOKEN/part@github.com/acme/api.git"
		//	  -> ok=true "https://ghs_TOKEN/part@github.com/acme/api.git"
		//	"https://a@b@ghs_TOKEN/part@github.com/acme/api.git"
		//	  -> ok=true "https://ghs_TOKEN/part@github.com/acme/api.git"
		//
		// "alice@" was consumed and the gate then declared the rest
		// unambiguous, but "ghs_TOKEN" is still exactly as undecidable as it
		// was before: host, or the front of a userinfo whose delimiter lies
		// further right. A single-pass assumption on a multi-occurrence input
		// is the defect, and a SECOND pass is not the fix — the gate is deleted
		// rather than patched.
		//
		// The pre-PR parser leaked this identically (url.Parse consumed
		// "alice@" and recorded the rest), so unlike the percent hole below
		// this is a LONG-STANDING gap rather than anything this branch
		// introduced.
		//
		// THE COST WIDENED, DELIBERATELY: a URL whose PATH holds an at-sign is
		// now refused WITH a login as well as without, so
		// "ssh://git@github.com/acme/repo@release.git" no longer survives. The
		// scp form KEEPS its login exemption, because #9181 measured
		// "git@example.com:repo@release.git" as must-survive and scp settles
		// its authority boundary at the first colon BEFORE any at-sign is read.
		// The two grammars now differ on purpose, and both directions are
		// pinned by tests.
		//
		// Underneath the gate this is recordSCPRemote's disagreement rule: the
		// string reads two ways that DISAGREE about whether anything in it is
		// secret, and SHAPE CANNOT DECIDE BETWEEN THEM. "ghp_TOKEN" is spelled
		// exactly like the single-label host "myserver" and "alice:12345"
		// exactly like "github.com:8443", so any test asking what the text
		// LOOKS like is the unanswerable spelling question this file exists to
		// stop asking. The readings are not adjudicated; their disagreement is
		// the answer. It also refuses the login-less
		// "https://github.com/acme/repo@release.git" for the same reason, which
		// is the trade recordSCPRemote already makes and the one the sibling
		// base-ancestry attestor accepted (testifysec/judge#9186).
		return refuseRemote(refusalAmbiguousAuthority)
	}

	if authority == "" && !isLocalFileScheme(scheme) {
		// A network URL with no host names no repository, and a string whose
		// authority cannot be identified cannot be shown to be credential-free.
		// #9177 round 2 reached this two ways: "https://alice:TOKEN@/acme/api"
		// clears to an empty authority, and "https:///acme/api" never had one.
		return refuseRemote(refusalAmbiguousAuthority)
	}
	if !authorityAlphabetIsSafe(authority) {
		// A PERCENT IN WHAT IS LEFT AFTER USERINFO REMOVAL. See
		// authorityAlphabetIsSafe: the character is refused, nothing is
		// decoded. This is checked on the authority AFTER the userinfo cut, not
		// before, because the userinfo is being DELETED — whatever it encodes
		// never reaches evidence. That is what keeps
		// "https://alice%40corp:ghs_TOK@github.com/acme/api.git", a real
		// spelling of a GitHub login, working: its authority clears to
		// "github.com" and carries no percent at all.
		return refuseRemote(refusalAmbiguousAuthority)
	}
	if !bracketsAreAnIPLiteral(authority) {
		// Brackets belong to a host and only at its first byte, so a bracket
		// anywhere else in what is left after userinfo removal means this is not
		// a host. It is checked BEFORE the port test because the port test
		// cannot see it: colonOutsideBrackets skips a colon inside brackets, so
		// "alice[realm:ghs_TOKEN]" reports "no port" and reads as host-only.
		return refuseRemote(refusalAmbiguousAuthority)
	}
	if !authorityIsHostAndPort(authority) {
		// WHAT IS LEFT AFTER USERINFO MUST BE host[:port], and checking only
		// that it is non-empty is not that check.
		//
		// The authority ends at the next '/', '?' or '#' — RFC 3986 §3.2, and
		// the same three bytes cutRemoteAuthority splits on. Put one of them
		// between the credential and its '@' and the authority stops SHORT of
		// the delimiter, so the LastIndexByte('@') cut above removes nothing and
		// the password is what remains. Measured on the previous head of this
		// branch, one row per terminator:
		//
		//	"https://alice:SECRETVALUE/q@github.com/acme/api.git" -> ok=true, VERBATIM
		//	"https://alice:SECRETVALUE?q@github.com/acme/api.git" -> ok=true "https://alice:SECRETVALUE"
		//	"https://alice:SECRETVALUE#q@github.com/acme/api.git" -> ok=true "https://alice:SECRETVALUE"
		//
		// None is empty and none holds whitespace, so every other rule passed
		// them. The only thing wrong with them is structural: "SECRETVALUE" sits
		// where a port belongs, and a port is digits.
		//
		// url.Parse rejected these before the rewrite — as an invalid-port
		// error, incidentally rather than deliberately. The rule is restored
		// here as a statement about the grammar instead of a parser side effect,
		// and is ported from the sibling base-ancestry attestor, which had
		// already reached it (testifysec/judge#9186).
		return refuseRemote(refusalAmbiguousAuthority)
	}

	if !pathIsCredentialFree(tail) {
		// REACHABLE AS FALSE — and it was not, until the scheme-relative rule
		// landed in pathIsCredentialFree. The at-sign gate above refuses every
		// tail holding a LITERAL '@', so the only way here is a tail that opens
		// "//" onto a segment carrying a PERCENT, where "%40" is an at-sign the
		// gate above cannot see: "https://github.com//a%40b.git".
		//
		// That string is a URL path, not a network-path reference, so the
		// refusal is stricter than the grammar strictly requires. It is kept
		// deliberately. The alternative is a second, narrower copy of the rule
		// that runs only on a whole remote — and this file's ninth round was
		// spent on exactly that mistake: the scp branch and the local branch
		// each held their own spelling of the credential rule, and the leak
		// lived in the gap between them. One rule with a stated over-refusal
		// beats two rules that can drift, so a double-slashed URL path holding
		// a percent is dropped rather than published. TestAURLPathThatOpensA
		// DoubleSlashOntoAPercentIsRefused pins it so the cost is visible.
		return refuseRemote(refusalAmbiguousAuthority)
	}
	if userinfoRemoved {
		return remoteRedacted, scheme + authority + tail, ""
	}
	return remoteClean, scheme + authority + tail, ""
}

// authorityIsHostAndPort reports whether a URL authority, with its userinfo
// already removed, is host[:port].
//
// It asks only about the PORT, and that narrowness is deliberate: the host half
// is left alone precisely because "is this text a hostname" is the unanswerable
// spelling question this whole file exists to stop asking. A port is not a
// spelling question — RFC 3986 §3.2.3 says it is digits — so the one component
// that CAN be decided structurally is the one that gets decided.
//
// The delimiter is the colon outside brackets, so "[2001:db8::1]" has no port
// and "[::1]:8080" has one. An empty port ("github.com:") names no service and
// is refused with the rest.
func authorityIsHostAndPort(authority string) bool {
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

// isLocalFileScheme reports whether an EMPTY authority is legitimate for this
// scheme. "file:///srv/git/repo.git" is a real remote whose authority is empty
// by definition — git reads it as PROTO_FILE, a local path, not as a network
// endpoint with a missing host — and it has nowhere to put a credential.
func isLocalFileScheme(scheme string) bool {
	return strings.EqualFold(scheme, "file://")
}

// recordSCPRemote handles git's scheme-less [user@]host:path syntax.
//
// THE AUTHORITY BOUNDARY IS ESTABLISHED BEFORE ANY '@' IS READ. In scp syntax
// the path begins at the first colon outside brackets and everything before it
// is [user@]host, so an '@' after that colon belongs to the PATH and is not a
// delimiter at all. Deciding the delimiter first read the LAST '@' in the whole
// string, so git@example.com:repo@release.git — where the second '@' is part of
// the repository NAME — was cut down to "release.git", destroying the host and
// the repository identity inside evidence we then signed (#9177 round 1).
func recordSCPRemote(raw string) (remoteVerdict, string, string) {
	colon, bracketsClosed := colonOutsideBrackets(raw)
	if !bracketsClosed || colon < 0 {
		// Unreachable via classifyRemote, which only routes here on a closed
		// bracket and a real colon. Kept because the invariant is cheap to
		// assert and expensive to lose.
		return refuseRemote(refusalAmbiguousAuthority)
	}

	authority, path := raw[:colon], raw[colon+1:]

	// A login lies wholly before the first colon, so it can never contain one:
	// scp syntax has no password field, which makes a login a routing value
	// rather than a credential. It has to survive — ssh dials on it, github and
	// gitlab both require git@, and a remote stripped of it can no longer clone.
	login, host, hasLogin := cutSCPAuthority(authority)

	if !hasLogin && strings.ContainsRune(path, '@') {
		// No login, and an at-sign downstream. The string now reads two ways
		// that DISAGREE about whether anything in it is secret:
		//
		//   alice.smith:TOKEN@github.com:acme/api.git
		//     as scp     -> host "alice.smith", path "TOKEN@github.com:acme/api.git"
		//     as authority -> user "alice.smith", password TOKEN, host github.com
		//
		// An earlier pass tried to decide between them by asking whether the
		// text before the colon contained a DOT. That question is unanswerable
		// — a dotted username and a dotted host are the same characters — and it
		// was wrong in BOTH directions at once: it passed "alice.smith:TOKEN@…"
		// with the credential intact (#9177 round 2) while dropping
		// "git@myserver:repo.git", an ordinary internal remote carrying nothing.
		//
		// So the readings are not adjudicated; their disagreement IS the answer.
		// A login removes the ambiguity, which is why git@example.com:repo@release.git
		// survives and github.com:repo@release.git does not.
		return refuseRemote(refusalAmbiguousAuthority)
	}

	if !hostIsRecordable(host) {
		return refuseRemote(refusalAmbiguousAuthority)
	}
	// A login is not a host, so it may not wear a host's brackets. Measured on
	// 9a5d6966: "[ghs_TOKEN]@github.com:acme/api.git" recorded VERBATIM,
	// because the login survives by design (it is a routing value ssh dials on)
	// and nothing asked whether THIS login was spelled like one.
	//
	// login comes from cutSCPAuthority rather than a second LastIndexByte here,
	// so the login test and the host split cannot drift apart.
	//
	// The LOGIN is not asked WHERE its brackets are, the way the host is. It is
	// userinfo, and RFC 3986 §3.2.1 admits unreserved / pct-encoded /
	// sub-delims / ":" there and no brackets at all — brackets are the HOST's
	// IP-literal delimiters and nothing else. So any bracket in a login means
	// the component is not a login. A first attempt reused
	// bracketsAreAnIPLiteral here and let "[ghs_TOKEN]" straight through: it is
	// a perfectly well-formed single leading pair, which is exactly the wrong
	// question to ask about userinfo.
	if hasLogin && strings.ContainsAny(login, "[]") {
		return refuseRemote(refusalAmbiguousAuthority)
	}
	// THE LOGIN IS THE THIRD AUTHORITY POSITION, and it needs the percent guard
	// as much as the other two. An scp login is RECORDED, and a percent in it
	// moves the delimiter the same way it does in a URL:
	//
	//	"alice:TOKEN@github.com:repo"     -> refused (colon splits first, at-sign downstream)
	//	"alice%3ATOKEN@github.com:repo"   -> the colon is hidden, so the split
	//	                                     moves and the login is recorded whole
	//
	// The cost is a login that genuinely contains a percent
	// ("git%40corp@github.com:acme/api.git"), which is refused. ssh does not
	// percent-decode a login, so such a name would have to be literal, and none
	// is known.
	if hasLogin && !authorityAlphabetIsSafe(login) {
		return refuseRemote(refusalAmbiguousAuthority)
	}
	if !authorityAlphabetIsSafe(host) {
		return refuseRemote(refusalAmbiguousAuthority)
	}
	if !bracketsAreAnIPLiteral(host) {
		return refuseRemote(refusalAmbiguousAuthority)
	}
	if !pathIsCredentialFree(path) {
		return refuseRemote(refusalAmbiguousAuthority)
	}
	// Nothing in a credential-free scp remote is redactable, so it is recorded
	// exactly as typed. Rewriting it would invent a spelling git never used.
	return remoteClean, raw, ""
}

// recordLocalRemote handles the third form: a path.
//
// `git remote add origin /srv/git/repo.git` is a real remote and has no
// authority, so an at-sign in it belongs to the NAME (/srv/git/a@b.git) and a
// colon in it belongs to the name too (/srv/git/a:b.git). A path holding BOTH
// is the same ambiguity recordSCPRemote refuses: "acme/alice:TOKEN@github.com:repo.git"
// is a relative path to git and an https authority to a human, and the two
// disagree about TOKEN.
//
// A BRACKET IS THE SECOND WAY TO WRITE AN AUTHORITY, and it needs no colon.
// "[ghs_TOKEN]@github.com/acme/api.git" holds no colon at all, so the
// colon-and-at rule alone recorded it VERBATIM (measured on 9a5d6966) even
// though it reads as an IP-literal host followed by userinfo just as plainly as
// the colon form does. The at-sign is still the tell; what precedes it may be
// either delimiter.
//
// The cost is a local path that genuinely contains both a bracket and an
// at-sign ("/srv/git/user[1]@host.git"), which is now refused. A path with only
// one of them — "/srv/git/a@b.git", "/srv/git/a[1.git", "/srv/git/repo[1:2.git"
// — is untouched, and those are the shapes that actually occur.
//
// THE RULE IS pathIsCredentialFree, not a private copy of it. A local remote IS
// a path, so it takes the same test the scp path and the URL path take. This
// branch used to hold its own inline spelling of the rule, and the scp branch
// held a weaker one; the leak that round nine found lived exactly in the gap
// between the two. Calling the shared function is what makes that gap
// unopenable rather than merely closed.
func recordLocalRemote(raw string) (remoteVerdict, string, string) {
	if !pathIsCredentialFree(raw) {
		return refuseRemote(refusalAmbiguousAuthority)
	}
	return remoteClean, raw, ""
}

// pathIsCredentialFree reports whether a span of PATH bytes can be shown to
// hold no authority, and therefore no credential.
//
// A path is bytes git sends to the far end verbatim. It has no authority of its
// own, so an at-sign in it belongs to the repository's NAME
// ("/srv/git/a@b.git", "git@example.com:repo@release.git" — #9177 round 1 named
// that one as must-survive). What it must never do is read as an authority that
// lost its scheme, because that is the shape every credential leak in this PR
// wore.
//
// THE RULE IS "AN AT-SIGN TOGETHER WITH A DELIMITER", NOT "A COLON BEFORE AN
// AT-SIGN", and the difference is the whole of #9177's ninth round. The old
// rule scanned each slash-delimited segment for a ':' preceding an '@', which
// recognises "alice:TOKEN@github.com" — userinfo WITH a password — and nothing
// else. It has a blind spot the size of the commonest PAT spelling: a token is
// very often the entire username with no password at all, so the credential
// arrives as "ghp_TOKEN@github.com:acme/api.git", where the colon FOLLOWS the
// at-sign. Measured on the previous head of this branch:
//
//	"alice@example.com:ghp_SECRET@github.com:acme/api.git" -> ok=true, VERBATIM
//
// Both orderings are the same construct — a path that re-reads as
// "[userinfo@]host:path" — so the rule keys on the CO-OCCURRENCE and stops
// asking which byte came first. A bracket counts alongside the colon because it
// is the second way to write an authority and needs no colon at all:
// "[ghs_TOKEN]@github.com/acme/api.git" holds none.
//
// IT IS THE RULE redactLocalRemote ALREADY APPLIED, now applied to every path.
// That is the point of the unification rather than a side effect of it: the scp
// path and the local path are the same kind of thing — bytes with no authority
// — and they had drifted into two rules, so a leak closed in one stayed open in
// the other. One function means they cannot drift again.
//
// KNOWN COST, STATED: a repository whose name contains an at-sign AND a colon
// or bracket ("/srv/git/user[1]@host.git", "acme/my:repo@1.git") is refused
// rather than recorded. A name with only one of them — "/srv/git/a@b.git",
// "repo[legacy.git", "/srv/git/repo[1:2.git" — is untouched, and those are the
// shapes that actually occur.
//
// A LEADING "//" IS A THIRD WAY TO OPEN AN AUTHORITY, and it needs neither a
// colon nor a bracket. RFC 3986 §4.2 calls "//host/path" a NETWORK-PATH
// REFERENCE: every URL reader finds an authority in the bytes up to the next
// '/', so a token pasted in front of an '@' there is userinfo to all of them.
// git does not agree — connect.c sends the string to its local-path branch — and
// the at-sign-plus-delimiter rule above therefore saw an ordinary filename.
// Measured on the previous head of this branch:
//
//	"//ghp_SECRET@github.com/acme/api.git" -> verdict=clean, VERBATIM
//
// Before the parser was removed, url.Parse recognised exactly this form and
// clearing User stripped the PAT, so the rewrite lost a guard nobody had
// written down. It is restored here as a statement about the grammar rather
// than as a parser side effect (testifysec/judge#9177, Codex 2026-09-12).
//
// The question is asked of the WOULD-BE AUTHORITY and not of the whole string,
// which is what keeps "//fileserver/share/repo@release.git" recordable: the
// at-sign is past the first '/', so it is in the path under BOTH readings and
// neither calls it a credential. Only the first segment is contested.
//
// KNOWN COST, STATED: a "//" path whose FIRST segment holds an at-sign or a
// percent is refused rather than recorded, so a UNC share literally named
// "//srv@1/repo.git" is lost. A "//" path with a plain first segment —
// "//fileserver/share/repo.git", "//10.0.0.1/git/repo.git", "//host:8443/r.git"
// — is untouched, and those are the shapes that actually occur.
func pathIsCredentialFree(path string) bool {
	if authority, ok := schemeRelativeAuthority(path); ok {
		// AN AT-SIGN OR A PERCENT, and nothing else. A credential in an
		// authority always sits in front of an '@', so a span holding no
		// at-sign — literal, or encoded as "%40" — holds no userinfo under any
		// reading: "//fileserver/share/repo.git" and "//host:8443/repo.git" are
		// both recordable. The percent half is authorityAlphabetIsSafe, the
		// same function the URL branch uses, rather than a private copy: the
		// two authority readings must not drift apart, which is the failure
		// this whole file was rewritten to stop.
		if strings.ContainsRune(authority, '@') || !authorityAlphabetIsSafe(authority) {
			return false
		}
	}
	if !strings.ContainsRune(path, '@') {
		return true
	}
	return !strings.ContainsAny(path, ":[")
}

// schemeRelativeAuthority returns the span a URL reader would read as the
// AUTHORITY of a scheme-relative remote, and reports whether the string is one.
//
// The span ends where RFC 3986 §3.2 ends an authority — at the next '/', '?' or
// '#' — which is the same cut cutRemoteAuthority makes for a scheme'd URL. It is
// a named function rather than an inline prefix test so that the boundary is
// directly testable, and so that a future reader can see that "//" is being
// treated as an authority introducer on purpose.
//
// It deliberately does NOT extend to a backslash pair. "\\server\share" is a
// Windows UNC path, and UNC has no userinfo syntax at all, so git and every URL
// reader agree that an at-sign in it belongs to the name. Nothing disagrees
// there, so there is nothing to refuse.
func schemeRelativeAuthority(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "//")
	if !ok {
		return "", false
	}
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		return rest[:end], true
	}
	return rest, true
}

// hostIsRecordable rejects the host shapes that cannot be a host under ANY
// reading of the string.
//
// This is deliberately NOT the retired "is this a hostname" test. That one
// asked whether the text looked like a DNS name — a question about spelling
// that a dotted username answers just as well as a host does. This asks only
// whether the value is structurally impossible: empty, or carrying a space or
// control character that no host may contain. A single label ("myserver") and a
// bracketed literal ("[2001:db8::1]") both pass, because both are hosts.
func hostIsRecordable(host string) bool {
	if host == "" {
		return false
	}
	for i := range len(host) {
		if host[i] <= ' ' || host[i] == 0x7f {
			return false
		}
	}
	return true
}

// cutSCPAuthority splits an scp authority into its login and host, and reports
// whether a login was present. Both halves come from ONE split so that a caller
// testing the login and a caller testing the host cannot disagree about where
// the boundary was. The split is at the LAST '@', which is where ssh splits:
// "user@host@example.com" logs in as "user@host" on "example.com". Splitting at
// the first would name the host "host@example.com", which is not a host.
//
// It is a named function rather than an inline LastIndexByte so that the choice
// is directly testable. A mutation flipping Last to Index changes nothing any
// end-to-end case observes — the scp branch records the string unmodified
// either way — so without a test on this boundary the choice would be pinned by
// nothing at all.
func cutSCPAuthority(authority string) (login, host string, hasLogin bool) {
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		return authority[:at], authority[at+1:], true
	}
	return "", authority, false
}

// authorityAlphabetIsSafe reports whether an authority component is free of
// percent-encoding.
//
// THE CHARACTER IS GUARDED, NOTHING IS DECODED, AND THERE IS NO ESCAPE TABLE.
// Percent-encoding hides the very delimiters every rule in this file locates:
// "%3A" is a colon the port test never sees and "%40" is an at-sign the
// userinfo cut never finds, so the authority boundary moves and a credential
// rides through as a hostname. Measured on 8e1e8100:
//
//	"https://alice%3Aghs_TOKEN%40github.com/acme/api.git"     -> VERBATIM
//	"https://alice%3aghs_TOKEN%40github.com/acme/api.git"     -> VERBATIM
//	"https://alice%253Aghs_TOKEN%2540github.com/acme/api.git" -> VERBATIM
//	"git@%5Bghs_TOKEN%5D:acme/api.git"                        -> VERBATIM
//
// DECODING IS THE WRONG ANSWER, and the double-encoded row is why: decoding
// forces a choice of how many layers to peel, and any finite answer loses to
// one more layer — "%253A" survives a single decode as "%3A" and needs a
// second. It would also invent a value the author never wrote, and this
// function's whole job is to judge the bytes as typed. An escape TABLE fails
// the same way from the other end: it enumerates the encodings someone thought
// of, and the next spelling is the one that was not listed.
//
// IT IS AUTHORITY-SCOPED, WHICH IS THE OTHER HALF OF THE RULE. A percent
// outside an authority is an ordinary byte of a name and must survive:
// "https://github.com/acme/api%zz.git" and "/srv/git/repo%20one.git" are real
// remotes, and a whole-string percent rule would delete both.
//
// KNOWN COST, NOT SOLVED HERE: an IPv6 zone identifier is written with a
// percent ("[fe80::1%25eth0]"), so a link-local remote is refused. The claim
// that no DNS label, IP literal or port otherwise contains a percent comes from
// the GRAMMAR rather than from a survey of real remotes. If that has to change,
// the remedy is a carve-out inside bracketsAreAnIPLiteral, never a loosening of
// this character rule. Raised with the sibling attestor's lane rather than
// decided here.
func authorityAlphabetIsSafe(component string) bool {
	return !strings.ContainsRune(component, '%')
}

// bracketsAreAnIPLiteral reports whether every bracket in an authority
// component is part of a single leading IP literal.
//
// RFC 3986 §3.2.2 puts brackets in exactly one place: host = IP-literal /
// IPv4address / reg-name, and IP-literal = "[" ( IPv6address / IPvFuture ) "]".
// So a bracket may only open a host, at its first byte, and must close it. The
// userinfo production (§3.2.1) admits unreserved / pct-encoded / sub-delims /
// ":" and no brackets at all.
//
// That makes this a STRUCTURAL test, not a spelling one. It never asks whether
// the bytes inside look like an address — "[2001:db8::1]" and "[::1]" pass
// without being parsed — only whether the brackets sit where the grammar can
// put them. Two shapes measured leaking on 9a5d6966 fail it:
//
//	"https://alice[realm:ghs_TOKEN]/part@github.com/repo.git" -> VERBATIM
//	"[ghs_TOKEN]@github.com:acme/api.git"                     -> VERBATIM
//
// Both hide a colon inside brackets, which is what let them past
// colonOutsideBrackets: it correctly reports "no delimiter here", and
// authorityIsHostAndPort then reads "no port" as "host only" and passes a
// credential through.
func bracketsAreAnIPLiteral(component string) bool {
	open := strings.IndexByte(component, '[')
	close := strings.IndexByte(component, ']')
	if open < 0 && close < 0 {
		return true // no brackets at all is the common, legal case
	}
	if open != 0 || close < 0 {
		// A bracket that does not open the component cannot be an IP literal,
		// and one that never closes bounds nothing.
		return false
	}
	if strings.IndexByte(component[1:], '[') >= 0 || strings.IndexByte(component[close+1:], ']') >= 0 {
		return false // a second literal is not a host
	}
	// AN IP LITERAL ENDS THE HOST. authority = [userinfo@]host[":"port], so once
	// the ']' closes the host the only thing that may follow is a port. Without
	// this clause "[2001:db8::1]extra" passed — the port test cannot catch it
	// either, because the colons it would look at are inside the brackets and
	// "extra" contributes none. Caught by this file's own over-refusal control
	// rather than by a reviewer.
	rest := component[close+1:]
	return rest == "" || rest[0] == ':'
}

// colonOutsideBrackets returns the index of the DELIMITER — the first ':' that
// is not inside a bracketed IPv6 literal — and reports whether that answer could
// be established at all.
//
// git does exactly this, and for this reason: connect.c advances past the
// closing ']' before it looks for the delimiter, so `git@[2001:db8::1]:acme/api.git`
// splits at the colon AFTER the bracket. Taking the first colon instead makes
// the host "[2001", which fails every check there is, and the remote disappears
// from the attestation — evidence lost to a delimiter chosen without regard to
// nesting (#9177 round 2).
//
// THE SCAN STOPS AT THE DELIMITER, and that bound is load-bearing. Bracket
// state belongs to the AUTHORITY; past the boundary every byte is path, where
// '[' is an ordinary filename character. Carrying the check to the end of the
// string made `git@myserver:repo[legacy.git` — a real remote whose authority
// was already unambiguous, and which holds no credential — unclassifiable, and
// dropped it from the evidence (#9177 round 3, measured: ok=false).
//
// The failure case is therefore narrow: a '[' that opens before any delimiter,
// never closes, AND swallows a ':'. Only then does the delimiter search have no
// defined place to resume. With no colon anywhere the string has no authority
// to find, so a stray '[' is just a filename byte — `/srv/git/a[1.git` is a
// local path and must survive, which the whole-string version also dropped.
//
// Ported from the sibling base-ancestry attestor, which had already reached
// this bound (testifysec/judge#9186); it is not a new reading of the grammar.
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

// cutRemoteQueryAndFragment drops everything from the first '?' or '#'.
//
// A clone URL identifies a repository by its host and path; "?token=…" is a
// credential living in the one part of the string that userinfo redaction never
// reads, and testifysec/judge#8950 names it as one of the places a secret
// escapes.
//
// IT IS ONLY EVER CALLED BEHIND schemeHasQueryGrammar — that is, on a remote git
// actually hands to a query-parsing transport. On every other scheme and every
// other form those bytes belong to the repository's NAME, and calling this on
// one renames the repository instead of redacting it; redactRemoteURL refuses
// those rather than cutting them. Running it unconditionally, and then running
// it for every remoteFormURL, were #9177's last two criticals.
func cutRemoteQueryAndFragment(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// summarizeRefusedRemotes turns the per-reason tally into the sorted trace that
// goes into the predicate.
//
// SORTED, because this list is SIGNED. Go randomises map iteration on every
// range, so an unsorted projection of `refusals` would give two reads of one
// unchanged repository different predicate bytes — the same defect the sibling
// base-ancestry attestor found in its own remote list. Sorting by reason is a
// total order here because the reasons are a closed set of distinct constants
// and each appears at most once.
//
// Returns nil, not an empty slice, when nothing was refused: the field is
// `omitempty`, and an empty array in the JSON would be a third state between
// "no refusals" and "refusals" that nothing needs.
func summarizeRefusedRemotes(refusals map[string]int) []RefusedRemote {
	if len(refusals) == 0 {
		return nil
	}
	out := make([]RefusedRemote, 0, len(refusals))
	for reason, count := range refusals {
		out = append(out, RefusedRemote{Reason: reason, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Reason < out[j].Reason })
	return out
}

// cutRemoteAuthority splits a URL's authority from the path, query or fragment
// that follows it.
func cutRemoteAuthority(v string) (string, string) {
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		return v[:i], v[i:]
	}
	return v, ""
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error { //nolint:gocognit,gocyclo,funlen // git attestation involves multiple data sources
	repo, err := OpenRepository(ctx.WorkingDir())
	if err != nil {
		return err
	}

	// Where the mint ran, relative to the worktree the open just resolved
	// (#9856). Established before anything else is recorded: a mint from a
	// subdirectory fails here, before it has attested a partial tree.
	prefix, root, err := workdirPrefix(repo, ctx.WorkingDir())
	if err != nil {
		return fmt.Errorf("could not establish the working directory's position in the worktree (%w); refusing to attest a tree whose coverage cannot be stated", err)
	}
	if prefix != "" && !a.allowSubdirectory {
		return fmt.Errorf("the working directory %s is %q inside the worktree root %s, so the material attested here would cover only that subdirectory; run from the worktree root, or pass --%s to record the partial coverage (verifiers may refuse it)", ctx.WorkingDir(), prefix, root, registry.AttestorFlagName(Name, allowSubdirectoryOption))
	}
	a.WorkdirPrefix = prefix

	head, err := repo.Head()
	if err != nil {
		unborn, proveErr := repositoryIsProvablyUnborn(repo)
		if proveErr != nil {
			return fmt.Errorf("could not resolve HEAD (%v) and could not establish whether the repository is unborn (%v); refusing to attest a repository whose history could not be observed", err, proveErr)
		}
		if !unborn {
			return fmt.Errorf("could not resolve HEAD (%v) but the repository still holds refs or objects, so its HEAD is unresolvable rather than unborn; refusing to attest a repository whose history could not be observed", err)
		}

		// The one benign case: a repository that has genuinely never had a
		// commit. Nothing was observed because there is nothing to observe.
		return nil
	}

	// Re-hash the canonical commit object and refuse the attestation on any
	// mismatch or detected collision: only the COMPUTED, collision-checked id
	// may be attested, never the id storage merely claims. The commit fields
	// recorded below (tree, parents, author, message, signature) are decoded
	// from the same verified bytes.
	commit, verifiedHash, err := verifiedCommitObject(repo, head.Hash())
	if err != nil {
		return err
	}

	a.CommitDigest = cryptoutil.DigestSet{
		{
			Hash:   crypto.SHA1,
			GitOID: false,
		}: verifiedHash,
	}

	remotes, err := repo.Remotes()
	if err != nil {
		return err
	}
	remotes = anchorRemotes(remotes)

	// BOTH HALVES OF THE REMOTE RECORD ARE REBUILT FROM THIS OBSERVATION, not
	// added to whatever was there. RemotesRefused is assigned below, so leaving
	// Remotes to accumulate would make the two fields disagree about which run
	// they describe: a second Attest on one Attestor would double the remotes
	// while the refusal tally still reported one run's worth, and the pair
	// would then be signed together saying inconsistent things.
	a.Remotes = nil
	refusals := make(map[string]int)
	for _, remote := range remotes {
		for _, urlStr := range remote.Config().URLs {
			verdict, recorded, reason := recordRemote(urlStr)
			if !verdict.recordable() {
				// THE REFUSAL IS COUNTED, NOT DROPPED. `continue` alone was the
				// silent hole: it left an attestation that is short a remote
				// and says nothing about why, which reads downstream as a
				// repository that simply has no remote.
				refusals[reason]++
				continue
			}
			a.Remotes = append(a.Remotes, recorded)
		}
	}
	a.RemotesRefused = summarizeRefusedRemotes(refusals)
	for _, refused := range a.RemotesRefused {
		// The operator signal, separate from the signed one. It names the
		// reason and the count and NOTHING derived from the refused string —
		// judge already has a regression (TestLoggedRemotesAreSanitized) for a
		// sibling that logged a remote verbatim.
		log.Warnf("(attestation/git) refused to record %d remote url(s): %s", refused.Count, refused.Reason)
	}

	refs, err := repo.References()
	if err != nil {
		return err
	}

	// iterate over the refs and add them to the attestor
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		// only add the ref if it points to the head
		if ref.Hash() != head.Hash() {
			return nil
		}

		// add the ref name to the attestor
		a.Refs = append(a.Refs, ref.Name().String())

		return nil
	})
	if err != nil {
		return err
	}

	// The marker travels with the hash it vouches for: verifiedHash is the
	// output of computeVerifiedCommitHash (via verifiedCommitObject above), so
	// this is the ONE site allowed to assert the capability. Setting it
	// anywhere else — or from any hash that did not come through the verified
	// path — would let the SHA-1 matcher exception ride on an unverified claim.
	a.CommitHash = verifiedHash
	a.CommitHashVerified = true
	a.Author = commit.Author.Name
	a.AuthorEmail = commit.Author.Email
	a.CommitterName = commit.Committer.Name
	a.CommitterEmail = commit.Committer.Email
	a.CommitDate = commit.Author.When.String()
	a.CommitMessage = commit.Message
	a.Signature = commit.PGPSignature
	a.RefNameShort = head.Name().Short()

	for _, parent := range commit.ParentHashes {
		a.ParentHashes = append(a.ParentHashes, parent.String())
	}

	tags, err := repo.TagObjects()
	if err != nil {
		return fmt.Errorf("get tags error: %s", err)
	}

	var tagList []Tag

	err = tags.ForEach(func(t *object.Tag) error {
		// check if the tag points to the head
		if t.Target.String() != head.Hash().String() {
			return nil
		}

		tagList = append(tagList, Tag{
			Name:         t.Name,
			TaggerName:   t.Tagger.Name,
			TaggerEmail:  t.Tagger.Email,
			When:         t.Tagger.When.Format(time.RFC3339),
			PGPSignature: t.PGPSignature,
			Message:      t.Message,
		})
		return nil
	})
	if err != nil {
		return fmt.Errorf("iterate tags error: %s", err)
	}
	a.Tags = tagList

	a.TreeHash = commit.TreeHash.String()

	if GitExists() { //nolint:nestif // git binary detection requires nested checks
		a.GitTool = "go-git+git-bin"

		a.GitBinPath, err = GitGetBinPath()
		if err != nil {
			return err
		}

		a.GitBinHash, err = GitGetBinHash(ctx)
		if err != nil {
			return err
		}

		a.Status, err = GitGetStatus(ctx.WorkingDir())
		if err != nil {
			return err
		}
	} else {
		a.GitTool = "go-git"

		a.Status, err = GoGitGetStatus(repo)
		if err != nil {
			return err
		}
	}

	return nil
}

func GoGitGetStatus(repo *git.Repository) (map[string]Status, error) {
	gitStatuses := make(map[string]Status)

	worktree, err := repo.Worktree()
	if err != nil {
		return map[string]Status{}, err
	}

	status, err := worktree.Status()
	if err != nil {
		return map[string]Status{}, err
	}

	for file, status := range status {
		if status.Worktree == git.Unmodified && status.Staging == git.Unmodified {
			continue
		}

		attestStatus := Status{
			Worktree: statusCodeString(status.Worktree),
			Staging:  statusCodeString(status.Staging),
		}

		gitStatuses[file] = attestStatus
	}

	return gitStatuses, nil
}

func (a *Attestor) Data() *Attestor {
	return a
}

// addHashedSubject records "<prefix>:<value>" with a digest OF the value, and
// records NOTHING when value is empty.
//
// The guard is the point, and it lives here rather than at each call site so a
// subject added later cannot forget it. An empty component is not a fact about
// this repository — it is the absence of an observation — and emitting it
// produces a subject literally named e.g. "authoremail:" whose digest is
// SHA256(""), byte-identical in every attestation that ever failed to observe
// an author. A policy matching on that subject matches every such attestation
// from every repository, which is a cross-repository authorization collision.
func addHashedSubject(subjects map[string]cryptoutil.DigestSet, prefix, value string, hashes []cryptoutil.DigestValue) {
	if value == "" {
		return
	}

	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), hashes)
	if err != nil {
		log.Debugf("(attestation/git) failed to record %s subject: %v", prefix, err)
		return
	}

	subjects[fmt.Sprintf("%s:%v", prefix, value)] = ds
}

// addCommitSubject records "<prefix>:<sha>" with the raw sha1=<commit SHA>
// encoding shared by commithash and parenthash, and records NOTHING when sha
// is empty. Sharing one encoding is what lets a downstream collection's
// parenthash digest equal the upstream collection's commithash digest for the
// same commit, so subject-graph traversal can cross the parent linkage.
// See https://github.com/aflock-ai/rookery/issues/34.
func addCommitSubject(subjects map[string]cryptoutil.DigestSet, prefix, sha string) {
	if sha == "" {
		return
	}

	subjects[fmt.Sprintf("%s:%v", prefix, sha)] = cryptoutil.DigestSet{
		{
			Hash:   crypto.SHA1,
			GitOID: false,
		}: sha,
	}
}

// anchorRemotes picks the remotes whose URLs are recorded (testifysec/judge#9233).
//
// Every recorded URL becomes a remote: subject, and Judge links a collection to
// every product whose repository matches any of them. A developer worktree
// with a dozen remotes therefore anchored a judge commit to
// aflock-ai/cilock-action. When origin exists it is the repository being
// attested and the only one returned; a refused origin is NOT replaced by
// another remote, because that fallback is the wrong-repository anchor again.
// Without origin every remote is returned, sorted by name: go-git builds the
// list from a map, and the predicate is signed, so its order must not vary.
func anchorRemotes(remotes []*git.Remote) []*git.Remote {
	for _, r := range remotes {
		if r.Config().Name == "origin" {
			return []*git.Remote{r}
		}
	}
	sort.Slice(remotes, func(i, j int) bool { return remotes[i].Config().Name < remotes[j].Config().Name })
	return remotes
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	addCommitSubject(subjects, "commithash", a.CommitHash)
	addHashedSubject(subjects, "authoremail", a.AuthorEmail, hashes)
	addHashedSubject(subjects, "committeremail", a.CommitterEmail, hashes)

	for _, parentHash := range a.ParentHashes {
		addCommitSubject(subjects, "parenthash", parentHash)
	}

	addHashedSubject(subjects, "refnameshort", a.RefNameShort, hashes)

	// remote URLs — enables discovery of attestations by repository URL
	for _, remote := range a.Remotes {
		addHashedSubject(subjects, "remote", remote, hashes)
	}
	// NO SUBJECT IS EMITTED FOR A REFUSAL, and that is a decision rather than an
	// omission. A recorded remote becomes a "remote:" subject, which is what a
	// witness policy binds to, so refusing one removes a bindable subject — and
	// the tempting repair, a synthetic subject standing in for it, is strictly
	// worse: it swaps a subject naming a real repository for one naming
	// nothing, and a policy matching on it binds to a placeholder. The refusal
	// is a PREDICATE fact (RemotesRefused), not a subject.
	// TestTheRefusalTraceEmitsNoSubject pins this in both directions.

	return subjects
}

func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	backrefs := make(map[string]cryptoutil.DigestSet)

	addCommitSubject(backrefs, "commithash", a.CommitHash)

	// Include parenthash BackRefs with the same sha1 encoding as commithash.
	// This way, given a downstream collection, the reverse-lookup surface
	// exposes both "I am this commit" and "my parent is that commit" — so an
	// upstream collection whose commithash matches any of our parenthashes is
	// discoverable from the downstream side during BackRef expansion.
	for _, parentHash := range a.ParentHashes {
		addCommitSubject(backrefs, "parenthash", parentHash)
	}

	return backrefs
}

func statusCodeString(statusCode git.StatusCode) string {
	switch statusCode {
	case git.Unmodified:
		return "unmodified"
	case git.Untracked:
		return "untracked"
	case git.Modified:
		return "modified"
	case git.Added:
		return "added"
	case git.Deleted:
		return "deleted"
	case git.Renamed:
		return "renamed"
	case git.Copied:
		return "copied"
	case git.UpdatedButUnmerged:
		return "updated"
	default:
		return string(statusCode)
	}
}

// workdirPrefix returns the working directory's path relative to the root of
// the worktree repo was opened from, with forward slashes and "" at the root,
// plus that root (#9856).
//
// Both paths are made absolute and symlink-resolved before they are compared,
// so the same worktree reached through a link is still the root. A working
// directory that does not resolve INSIDE the worktree is an error, never a
// guess: the prefix is a signed claim about coverage.
func workdirPrefix(repo *git.Repository, workingDir string) (string, string, error) {
	wt, err := repo.Worktree()
	if err != nil {
		return "", "", fmt.Errorf("repository has no worktree: %w", err)
	}
	root, err := resolvedDir(wt.Filesystem.Root())
	if err != nil {
		return "", "", fmt.Errorf("worktree root: %w", err)
	}
	if workingDir == "" {
		workingDir = "."
	}
	dir, err := resolvedDir(workingDir)
	if err != nil {
		return "", root, fmt.Errorf("working directory: %w", err)
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "", root, err
	}
	if rel == "." {
		return "", root, nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", root, fmt.Errorf("working directory %s is outside the worktree root %s", dir, root)
	}
	return filepath.ToSlash(rel), root, nil
}

func resolvedDir(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return filepath.Dir(resolved), nil
	}
	return resolved, nil
}
