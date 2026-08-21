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
	"net/url"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
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
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
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
	Remotes            []string             `json:"remotes,omitempty"`
	Tags               []Tag                `json:"tags,omitempty"`
	RefNameShort       string               `json:"branch,omitempty"`
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

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error { //nolint:gocognit,gocyclo,funlen // git attestation involves multiple data sources
	repo, err := git.PlainOpenWithOptions(ctx.WorkingDir(), &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return err
	}

	head, err := repo.Head()
	if err != nil {
		if strings.Contains(err.Error(), "reference not found") {
			return nil
		}
		return err
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

	for _, remote := range remotes {
		for _, urlStr := range remote.Config().URLs {
			parsed, err := url.Parse(urlStr)
			if err != nil {
				// If parsing fails, fallback to the original URL
				a.Remotes = append(a.Remotes, urlStr)
				continue
			}
			// Remove any embedded user info (tokens, credentials, etc.)
			parsed.User = nil
			a.Remotes = append(a.Remotes, parsed.String())
		}
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

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	if a.CommitHash != "" {
		subjectName := fmt.Sprintf("commithash:%v", a.CommitHash)
		subjects[subjectName] = cryptoutil.DigestSet{
			{
				Hash:   crypto.SHA1,
				GitOID: false,
			}: a.CommitHash,
		}
	}

	// add author email
	subjectName := fmt.Sprintf("authoremail:%v", a.AuthorEmail)
	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.AuthorEmail), hashes)
	if err != nil {
		log.Debugf("(attestation/git) failed to record author email subject: %v", err)
	} else {
		subjects[subjectName] = ds
	}

	// add committer email
	subjectName = fmt.Sprintf("committeremail:%v", a.CommitterEmail)
	ds, err = cryptoutil.CalculateDigestSetFromBytes([]byte(a.CommitterEmail), hashes)
	if err != nil {
		log.Debugf("(attestation/git) failed to record committer email subject: %v", err)
	} else {
		subjects[subjectName] = ds
	}

	// add parent hashes
	// Use sha1=<raw parent commit SHA> — mirrors commithash encoding so that a
	// downstream collection's parenthash subject digest matches the upstream
	// collection's commithash subject digest for the same commit, enabling
	// subject-graph traversal across the parent-commit linkage.
	// See https://github.com/aflock-ai/rookery/issues/34.
	for _, parentHash := range a.ParentHashes {
		if parentHash == "" {
			continue
		}
		subjectName = fmt.Sprintf("parenthash:%v", parentHash)
		subjects[subjectName] = cryptoutil.DigestSet{
			{
				Hash:   crypto.SHA1,
				GitOID: false,
			}: parentHash,
		}
	}

	// add refname short
	subjectName = fmt.Sprintf("refnameshort:%v", a.RefNameShort)
	ds, err = cryptoutil.CalculateDigestSetFromBytes([]byte(a.RefNameShort), hashes)
	if err != nil {
		log.Debugf("(attestation/git) failed to record refname short subject: %v", err)
	} else {
		subjects[subjectName] = ds
	}

	// add remote URLs — enables discovery of attestations by repository URL
	for _, remote := range a.Remotes {
		subjectName = fmt.Sprintf("remote:%v", remote)
		ds, err = cryptoutil.CalculateDigestSetFromBytes([]byte(remote), hashes)
		if err != nil {
			log.Debugf("(attestation/git) failed to record remote subject: %v", err)
			continue
		}
		subjects[subjectName] = ds
	}

	return subjects
}

func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	backrefs := make(map[string]cryptoutil.DigestSet)
	if a.CommitHash != "" {
		subjectName := fmt.Sprintf("commithash:%v", a.CommitHash)
		backrefs[subjectName] = cryptoutil.DigestSet{
			{
				Hash:   crypto.SHA1,
				GitOID: false,
			}: a.CommitHash,
		}
	}
	// Include parenthash BackRefs with the same sha1 encoding as commithash.
	// This way, given a downstream collection, the reverse-lookup surface
	// exposes both "I am this commit" and "my parent is that commit" — so an
	// upstream collection whose commithash matches any of our parenthashes is
	// discoverable from the downstream side during BackRef expansion.
	for _, parentHash := range a.ParentHashes {
		if parentHash == "" {
			continue
		}
		subjectName := fmt.Sprintf("parenthash:%v", parentHash)
		backrefs[subjectName] = cryptoutil.DigestSet{
			{
				Hash:   crypto.SHA1,
				GitOID: false,
			}: parentHash,
		}
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
