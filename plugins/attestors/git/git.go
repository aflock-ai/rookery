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
	"errors"
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

	// observedDir and observedHead are this process's own observation, kept
	// for CheckBeforeSigning and never serialized: a predicate decoded from a
	// signed envelope has no observation to re-check. observedHead is "" when
	// the repository was unborn at Attest.
	observedDir  string
	observedHead string
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

// RefusedRemote is one entry of the refusal trace: a reason from the closed set
// below, and how many configured remote URLs were refused for it.
type RefusedRemote struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
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
		a.observedDir, a.observedHead = ctx.WorkingDir(), ""
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
	a.observedDir, a.observedHead = ctx.WorkingDir(), verifiedHash

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
			verdict, recorded, reason := gitremote.Record(urlStr)
			if !verdict.Recordable() {
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

// CheckBeforeSigning re-reads HEAD and refuses if it is not the commit Attest
// recorded (attestation.SigningGuard, testifysec/judge#9359). The git
// attestor runs before the wrapped command, so a command that commits, or a
// second shell running `git checkout` in the same worktree, would otherwise
// get its tests signed against a commit whose tree they never ran on.
//
// A switch to another ref at the same commit passes: the attested tree still
// holds. Working-tree and index changes during the run are NOT checked here.
func (a *Attestor) CheckBeforeSigning() error {
	if a.observedDir == "" {
		return nil
	}
	now := ""
	repo, err := OpenRepository(a.observedDir)
	if err != nil {
		return fmt.Errorf("could not re-read HEAD before signing (%w); refusing to sign a commit that can no longer be confirmed", err)
	}
	head, err := repo.Head()
	switch {
	case err == nil:
		now = head.Hash().String()
	case errors.Is(err, plumbing.ErrReferenceNotFound) && a.observedHead == "":
		// Still unborn: nothing was attested and nothing moved.
	default:
		return fmt.Errorf("could not re-read HEAD before signing (%w); refusing to sign a commit that can no longer be confirmed", err)
	}
	if now != a.observedHead {
		return fmt.Errorf("the worktree %s moved during the run: HEAD was %s when the git attestor ran and is %s now, so the wrapped command did not run against the attested commit; refusing to sign. Was another process using this worktree?", a.observedDir, orUnborn(a.observedHead), orUnborn(now))
	}
	return nil
}

func orUnborn(hash string) string {
	if hash == "" {
		return "(unborn)"
	}
	return hash
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

// Anchors returns the collection's own measured commit as a git-commit anchor
// of role about (D15, docs/design/attestation-anchors.md 3.7): one anchor,
// only when Attest re-hashed the commit with the collision-detecting SHA-1
// and set CommitHashVerified, and never a parent (A6). The registry row is
// sha1, so a sha256 repository's commit has no anchor yet, and a value
// Canonical refuses is never repaired into one.
func (a *Attestor) Anchors(attestation.AnchorContext) []attestation.Anchor {
	if !a.CommitHashVerified {
		return nil
	}
	id, err := attestation.Canonical(attestation.KindGitCommit, a.CommitHash, attestation.NormalizationBareHex)
	if err != nil || id.Algorithm != attestation.AlgorithmSHA1 {
		return nil
	}
	return []attestation.Anchor{{
		Key:      "commithash:" + a.CommitHash,
		Identity: id,
		Role:     attestation.RoleAbout,
		Basis:    attestation.BasisMeasured,
	}}
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
