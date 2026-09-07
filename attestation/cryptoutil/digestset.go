// Copyright 2022 The Witness Contributors
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

package cryptoutil

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/aflock-ai/rookery/attestation/gitoid"
)

// The canonical wire names for the digest algorithms a DigestSet can carry.
// These strings are part of the attestation format: they are the map keys in
// serialized DigestSets and the values `cilock run --hashes` accepts, so they
// are a stable vocabulary rather than incidental literals. Tests deliberately
// spell the literals out so a rename here cannot silently move the wire format.
const (
	digestNameSHA256       = "sha256"
	digestNameSHA1         = "sha1"
	digestNameGitOIDSHA256 = "gitoid:sha256"
	digestNameGitOIDSHA1   = "gitoid:sha1"
	digestNameDirHash      = "dirHash"
)

var (
	hashNames = map[DigestValue]string{
		{
			Hash:    crypto.SHA256,
			GitOID:  false,
			DirHash: false,
		}: digestNameSHA256,
		{
			Hash:    crypto.SHA1,
			GitOID:  false,
			DirHash: false,
		}: digestNameSHA1,
		{
			Hash:    crypto.SHA256,
			GitOID:  true,
			DirHash: false,
		}: digestNameGitOIDSHA256,
		{
			Hash:    crypto.SHA1,
			GitOID:  true,
			DirHash: false,
		}: digestNameGitOIDSHA1,
		{
			Hash:    crypto.SHA256,
			GitOID:  false,
			DirHash: true,
		}: digestNameDirHash,
	}

	hashesByName = map[string]DigestValue{
		digestNameSHA256: {
			crypto.SHA256,
			false,
			false,
		},
		digestNameSHA1: {
			crypto.SHA1,
			false,
			false,
		},
		digestNameGitOIDSHA256: {
			crypto.SHA256,
			true,
			false,
		},
		digestNameGitOIDSHA1: {
			crypto.SHA1,
			true,
			false,
		},
		digestNameDirHash: {
			crypto.SHA256,
			false,
			true,
		},
	}
)

type ErrUnsupportedHash string

func (e ErrUnsupportedHash) Error() string {
	return fmt.Sprintf("unsupported hash function: %v", string(e))
}

type DigestValue struct {
	crypto.Hash `jsonschema:"title=Hash Algorithm,description=Cryptographic hash function to use for digest calculation"`
	GitOID      bool `jsonschema:"title=Git OID,description=Whether to calculate Git Object ID format digest,default=false"`
	DirHash     bool `jsonschema:"title=Directory Hash,description=Whether to calculate directory hash using Go module dirhash format,default=false"`
}

func (dv DigestValue) New() hash.Hash {
	if dv.GitOID {
		return &gitoidHasher{hash: dv.Hash, buf: &bytes.Buffer{}}
	}

	return dv.Hash.New()
}

type DigestSet map[DigestValue]string

func HashToString(h crypto.Hash) (string, error) {
	if name, ok := hashNames[DigestValue{Hash: h}]; ok {
		return name, nil
	}

	return "", ErrUnsupportedHash(h.String())
}

func HashFromString(name string) (crypto.Hash, error) {
	if hash, ok := hashesByName[name]; ok {
		return hash.Hash, nil
	}

	return crypto.Hash(0), ErrUnsupportedHash(name)
}

// matchableSubjectAlgorithms is the allowlist of digest-algorithm names whose
// values are safe to use as a subject-match key when resolving "does this
// collection attest THIS artifact?".
//
// Two properties are required to be on this list:
//
//  1. Collision resistance. Subject matching is an equality check on the
//     digest value; if an attacker can craft two distinct artifacts that share
//     a digest, a collection legitimately signed over one can be replayed to
//     "verify" the other. SHA-1 is omitted for exactly this reason — it has
//     practical chosen-prefix collisions and must NOT anchor a subject match.
//     The single exception — a git commit id, carried by a statement whose
//     signed predicate holds a HARDENED git attestation (exact current type
//     plus the verified-commit-hash marker) — is handled outside this map by
//     isGitCommitSubject under a SubjectMatchScope, so that widening the map
//     can never accidentally admit generic SHA-1 artifact digests.
//
//     Be clear about what that exception is: a RISK ACCEPTANCE, not a preserved
//     control. It is NOT safe because "the repository produced the value rather
//     than the attestor choosing it" — a commit's tree, parents, message and
//     timestamps are entirely author-chosen.
//
//     What DOES bound it is not in this function: the git implementations
//     around it use collision-DETECTING SHA-1. go-git registers sha1cd as its
//     SHA-1 (plumbing/hash/hash.go: algos[crypto.SHA1] = sha1cd.New), and git
//     itself has shipped sha1dc since 2.13, so an object carrying the
//     near-collision blocks a chosen-prefix attack requires is rejected rather
//     than hashed. An attacker therefore has to land a colliding commit through
//     tooling that would detect it, which is a materially higher bar than "a
//     chosen-prefix collision is purchasable".
//
//     This matcher compares digest strings and never re-hashes a commit, so it
//     INHERITS that mitigation from the git attestor — and the mitigation is
//     EXERCISED there, not merely available: commithash subjects are no longer
//     copied from go-git's head.Hash() (the repository's storage CLAIM), they
//     are the output of computeVerifiedCommitHash
//     (plugins/attestors/git/git.go), which re-hashes the commit's canonical
//     object bytes with the collision-detecting hasher at attestation time and
//     FAILS the attestation on a claimed/computed mismatch or a detected
//     collision. A crafted repository whose storage carries a tampered or
//     colliding object under a benign id is refused, not attested. A PIN TEST
//     at that hashing site — TestGitObjectHashIsCollisionDetecting in
//     plugins/attestors/git/sha1cd_pin_test.go — asserts go-git's SHA-1 object
//     hasher is the collision-detecting sha1cd implementation, not plain
//     crypto/sha1 (a go-git downgrade or RegisterHash swap breaks it), and the
//     production code additionally type-asserts the same capability at
//     runtime. The reliance is therefore an ENFORCED AND EXERCISED invariant —
//     and the exception is BOUND to it: the hardened producer emits the
//     "commithashverified" marker in the same signed predicate, and the
//     matcher grants the SHA-1 arm only to evidence carrying that marker
//     under the exact current type (SubjectMatchScope.HardenedGitAttested).
//     Evidence signed before the hardening — which recorded head.Hash()
//     unverified — has no marker and stays unmatchable, so the invariant the
//     exception depends on cannot be presumed onto evidence that never had it.
//
//     What the exception actually buys is narrower and still worth having:
//     generic SHA-1 stays out. `cilock run --hashes` accepts "sha1", so a
//     wholesale widening would make every file: subject a match anchor, and
//     colliding two arbitrary files is far cheaper than colliding two git
//     commits. Binding the subject NAME to the VALUE, and the whole arm to a
//     statement that attests git (SubjectMatchScope), keeps that door shut
//     while opening the one commit-shaped case that has no alternative — on a
//     SHA-1 repository the commit id is the only identifier the evidence
//     carries, and already-signed collections can never be re-signed to add
//     another.
//
//     The controls that actually bound this are elsewhere: WHO may sign (the
//     policy's functionary) and whether the upstream host runs sha1dc.
//
//  2. A known fixed value length, so a malformed or wrong-length value can be
//     rejected before it is indexed. The value is the number of hex characters
//     a well-formed digest must have; 0 means the value is not a plain hex
//     digest (e.g. a gitoid URI or a dirhash "h1:..." string) and only the
//     algorithm allowlist applies.
var matchableSubjectAlgorithms = map[string]int{
	digestNameSHA256:       2 * (256 / 8), // 64 hex chars
	digestNameGitOIDSHA256: 0,             // gitoid URI string, not plain hex
	digestNameDirHash:      0,             // dirhash h1: string, not plain hex
}

// isHexString reports whether s is non-empty and composed solely of hex
// characters (0-9, a-f, A-F). Allocation-free; used to reject malformed digest
// values before they are indexed for subject matching.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// gitCommitSubjectInfix is the subject-name relation rookery's git attestor
// writes for "this collection is ABOUT this commit"
// (plugins/attestors/git/git.go Subjects()). It appears bare as
// "commithash:<sha>" and namespaced as
// ".../attestations/git/v0.1/commithash:<sha>" once Collection.Subjects()
// prefixes it with the attestation type, so it is matched as a SUFFIX.
//
// Deliberately NOT included: "parenthash:". A parenthash subject carries the
// sha1 of a DIFFERENT commit and exists only so collections can be chained
// along the commit graph; it is not a claim about that parent. Treating it as
// a match key is a policy bypass — commit X introduces a secret, commit Y
// removes it, the scan runs at Y and its collection carries {sha1: X} as a
// parenthash, so pushing X would be admitted on evidence that never examined
// X. jade/factory/edge/git/envelopecheck.go documents and denies exactly this
// at the edge; the matcher must not re-open it underneath.
const gitCommitSubjectInfix = "commithash:"

// sha1HexLen is the hex-character length of a well-formed SHA-1 digest.
const sha1HexLen = 2 * (160 / 8)

// gitNullOID is git's all-zero object id, written for the "no such commit"
// side of a branch create or delete. It is valid 40-char hex and would
// otherwise satisfy the commit-subject arm, so it is refused explicitly: a
// subject named "commithash:000…0" names no commit and must never anchor a
// match.
const gitNullOID = "0000000000000000000000000000000000000000"

// hardenedGitAttestationType is the ONE predicate type whose git attestations
// may open the SHA-1 commit exception: the type the CURRENT git attestor
// publishes (plugins/attestors/git/git.go Type) — the producer that computes
// its commithash via computeVerifiedCommitHash and emits the
// "commithashverified" capability marker in the same signed predicate.
//
// This is an exact string, not a namespace + version pattern, and that is the
// point of the fix it belongs to. The exception's justification is a
// PRODUCER-side invariant — the attested id is the canonical commit bytes
// re-hashed with a collision-detecting hasher at attestation time — so the
// exception may be granted only to evidence provably produced by that path.
// A namespace pattern granted it to every version that ever existed or will
// exist:
//
//   - legacy witness.dev evidence, which never received the verification;
//   - pre-hardening aflock.ai/v0.1 evidence, likewise (it SHARES this type
//     string, which is why type alone never grants anything — the in-payload
//     marker is the discriminator, see HasGitCommitVerifiedMarker);
//   - arbitrary FUTURE versions (".../git/v0.2"), whose producers have made
//     no promise at all yet.
//
// The trade this reverses was deliberate, so state the cost plainly: when the
// git attestor's version bumps, SHA-1 commit anchoring FAILS CLOSED for the
// new version until this constant and the marker contract are consciously
// carried forward. That failure is loud — verification stops finding evidence
// for commits on SHA-1 repositories — and it is the correct direction:
// granting the exception to formats that never promised the invariant is how
// the exception stops being an exception.
const hardenedGitAttestationType = "https://aflock.ai/attestations/git/v0.1"

// IsHardenedGitAttestationType reports whether uri is the exact predicate type
// of the hardened git attestor — the only type whose attestations may carry
// the verified-commit-hash capability marker legitimately.
//
// It is exported because the fact it establishes has to be derived from two
// different representations of the same bytes — the typed collection a source
// decoded, and a narrow decode of the signature-verified payload — and those
// two derivations must never disagree about what counts as hardened git
// evidence. One predicate, two readers.
//
// Comparison is case-exact: predicate-type URIs are identifiers, and
// ".../attestations/GIT/v0.1" is a DIFFERENT type nothing here vouches for.
//
// Type alone NEVER grants the SHA-1 arm — pre-hardening evidence shares this
// exact string. Scope derivation additionally requires the in-payload marker
// (HasGitCommitVerifiedMarker); this predicate is used on its own only where
// no attestation body exists to consult: the subject-name namespace binding
// in isGitCommitSubject, which the marker-gated scope still sits in front of.
func IsHardenedGitAttestationType(uri string) bool {
	return uri == hardenedGitAttestationType
}

// HasGitCommitVerifiedMarker reports whether a git attestation body — the JSON
// of one attestations[].attestation entry, read from the same bytes the
// subjects came from — carries the verified-commit-hash capability marker,
// "commithashverified": true.
//
// The marker is the discriminator between hardened and legacy evidence under
// the SAME predicate type. Only the hardened producer writes it, and it writes
// it in the same signed predicate as the CommitHash it vouches for
// (plugins/attestors/git/git.go: the field is set at the same site as the
// verified hash), so a marker cannot be paired with an unverified hash by
// recombining legacy parts — that would require re-signing. Already-signed
// legacy evidence lacks the key and fails closed here; a body that is absent
// or not a JSON object fails closed the same way — no marker, no exception.
func HasGitCommitVerifiedMarker(attestationBody []byte) bool {
	var att struct {
		CommitHashVerified bool `json:"commithashverified"`
	}
	if err := json.Unmarshal(attestationBody, &att); err != nil {
		return false
	}
	return att.CommitHashVerified
}

// SubjectMatchScope carries the one fact about the STATEMENT a subject was read
// from that the (name, algorithm, value) triple cannot carry itself.
//
// It exists because scoping the git-commit SHA-1 exception by subject name
// alone made the exception self-service. Subject names are producer-controlled,
// so anything able to write a statement could label an arbitrary SHA-1
// "commithash:<that same value>" and re-open collision-prone matching for a
// digest no repository ever produced. Binding name to value stops RELABELLING
// (naming one commit while carrying another's digest); it does nothing about
// MINTING, where the attacker simply makes both halves agree.
//
// Be precise about what the scope fixes, because it is not a cryptographic
// bind: the predicate is producer-controlled exactly like the subject name, so
// a producer that can sign a fake commithash subject can sign a fake git
// attestation next to it. What changes is where the arm can ride. Before, a
// collection presenting itself as an sbom, a scan, or anything else at all
// could carry a matchable SHA-1; now the collection has to CLAIM to be git
// evidence, which is a claim the policy already gates on per step
// (Step.Attestations) and rego can read. The exception therefore inherits the
// step's attestor scoping instead of sitting underneath it.
//
// The claim is deliberately NARROWER than "carries a git attestation". The
// SHA-1 exception's whole justification is a producer-side invariant — the
// attested commithash is the output of computeVerifiedCommitHash, which
// re-hashes the commit's canonical bytes with a collision-detecting hasher
// and fails on a mismatch or detected collision — and evidence signed BEFORE
// that hardening carries the same predicate type without the invariant.
// Deriving the scope from the type alone granted the exception RETROACTIVELY
// to that legacy evidence. So the scope is granted only to the hardened
// format: an attestation of the exact current type
// (IsHardenedGitAttestationType) whose signed body carries the
// verified-commit-hash capability marker (HasGitCommitVerifiedMarker).
// Legacy evidence — pre-hardening v0.1, witness.dev forms, and any unknown
// or future git type — derives the zero scope and keeps exactly the status
// it had before the exception existed: unmatchable via SHA-1. Fail-closed:
// unknown means no exception.
//
// The controls that actually bound this are unchanged and live elsewhere: WHO
// may sign for the step — every candidate clears checkFunctionaries before it
// can satisfy anything — and whether the upstream host runs sha1dc.
//
// NOT done, deliberately: requiring the git attestation's own commithash field
// to equal the subject value. It would add internal consistency but no new
// trust (same producer, same signature), and it is not derivable at all three
// call sites — two of them hold the predicate as a typed attestation.Attestor
// interface that neither cryptoutil nor source can introspect without importing
// the git plugin. A fact only two of three sites can compute is a fact the
// third silently disagrees with, which is the failure this whole type exists to
// avoid.
//
// The zero value is the STRICT scope. A caller that cannot establish the fact
// loses the git arm and never gains it by accident.
type SubjectMatchScope struct {
	// HardenedGitAttested reports that the statement's predicate carries a
	// HARDENED git attestation: an entry whose type is the exact current git
	// attestor type (IsHardenedGitAttestationType) AND whose attestation body
	// carries the verified-commit-hash capability marker
	// (HasGitCommitVerifiedMarker). A git attestation that fails either half —
	// legacy v0.1 without the marker, a witness.dev type, an unknown future
	// version — does NOT set it; that evidence never received the
	// verification the SHA-1 exception depends on, so it forfeits the arm.
	//
	// Derive both halves from the SAME bytes the subjects came from — never
	// from a field the caller could have populated independently of what was
	// signed, which is the mistake payloadMatchesSubjects documents for
	// subjects themselves.
	HardenedGitAttested bool
}

// isGitCommitSubject reports whether (name, algorithm, value) is a git COMMIT
// reference — the one narrowly-scoped case in which a SHA-1 digest may anchor
// a subject match.
//
// Why this exception exists. A git object id IS a digest, produced by the
// repository's object model, not chosen by the attestor. On a SHA-1
// repository the commit id is a SHA-1 and no sha256 restatement of it exists
// in already-signed evidence, which can never be re-signed. Refusing it did
// not make verification stronger — it made commit-anchored verification
// impossible, so every consumer silently fell back to matching on subjects
// that do not identify the commit at all (authoremail, refnameshort, remote —
// identical across every commit in the repo). The honest trade is therefore
// NOT "collision resistance vs. convenience"; it is "a chosen-prefix SHA-1
// collision on a git commit object" vs. "no commit scoping whatsoever". The
// first adversary must already have broken the repository's own object model,
// at which point the attestation layer cannot be stronger than the thing it
// names. The second is unconditional.
//
// This answers only the SUBJECT-shaped half of the question. The other half —
// does the statement carrying this subject actually carry a HARDENED git
// attestation (exact current type plus the verified-commit-hash marker) — is
// SubjectMatchScope.HardenedGitAttested, checked by the caller before this
// function is reached. Neither half is sufficient alone: without the scope,
// "commithash:" is a free label any producer can mint (and legacy evidence
// that never received the verification would regain the arm); without the
// name/value binding, a genuinely git-attested collection could relabel an
// unrelated SHA-1.
//
// Three conditions, all required:
//
//  1. Algorithm is exactly "sha1". Not "gitoid:sha1" — a gitoid addresses
//     blob/tree CONTENT, not a commit, so it keeps no exception.
//  2. The value is well-formed (40 hex) and is not the null object id.
//  3. The subject NAME is exactly "commithash:<that same value>" (the bare form
//     the attestor writes), or "<hardened-git-type>/commithash:<that same
//     value>" where the PREFIX is the exact hardened git attestation type. The
//     namespaced form is what a collection carries once Collection.Subjects()
//     prefixes each subject with the attestation type that produced it —
//     REQUIRING that prefix to be the hardened git type is what stops a mixed
//     collection substitution: a hardened git entry makes
//     SubjectMatchScope.HardenedGitAttested true, so without the namespace
//     check a NON-git attestor's subject, prefixed with e.g. the sbom type as
//     "<sbom-type>/commithash:<sha1>", would back into the SHA-1 arm and make
//     a collision-prone digest matchable. Binding the name to the VALUE stops
//     relabelling; binding the namespace to the hardened git type stops the
//     cross-attestor substitution. Requiring a segment boundary stops
//     "…notacommithash:<v>" from backing into the exception on a bare suffix.
//     The name is compared EXACTLY as attested — no folding, no trimming —
//     except the digest characters themselves, which are hex and so case-free.
//     Folding anything more than the digest would canonicalize a case-variant
//     attestation type (".../attestations/GIT/v0.1", a DIFFERENT type) into
//     the trusted git namespace.
func isGitCommitSubject(subjectName, algorithm, value string) bool {
	if algorithm != digestNameSHA1 {
		return false
	}
	if len(value) != sha1HexLen || !isHexString(value) {
		return false
	}
	v := strings.ToLower(value)
	if v == gitNullOID {
		return false
	}
	// Normalization is scoped PER COMPONENT, never applied to the whole name.
	// The trailing digest is hexadecimal, where case carries no meaning, so it
	// alone is compared folded ("…3D7B" names the same commit as "…3d7b").
	// Everything BEFORE it — the "commithash:" relation and, in the namespaced
	// form, the attestation-type URI — is an identifier the attestor writes
	// exactly, and predicate-type URIs are case-sensitive:
	// ".../attestations/GIT/v0.1" is a DIFFERENT type from the git attestor's
	// ".../attestations/git/v0.1", one nothing here vouches for. Folding (or
	// whitespace-trimming) the whole name would canonicalize such a name into
	// the trusted form and hand its SHA-1 subject the exception, so the name is
	// matched exactly as attested and only the digest characters are folded.
	if len(subjectName) < sha1HexLen {
		return false
	}
	digest := subjectName[len(subjectName)-sha1HexLen:]
	if strings.ToLower(digest) != v {
		// Includes the multibyte-tail case: a non-ASCII byte in the digest
		// position can change length under ToLower and simply never equals the
		// pure-hex v. Fail closed.
		return false
	}
	rest := subjectName[:len(subjectName)-sha1HexLen]
	if rest == gitCommitSubjectInfix {
		return true // bare form, straight from the git attestor
	}
	// Namespaced form: "<attestationType>/commithash:<value>". Accept ONLY when
	// the attestation-type prefix is the exact hardened git attestation type —
	// otherwise a non-git attestor's subject in a git-attested (mixed)
	// collection would gain the SHA-1 arm it must never have.
	// IsHardenedGitAttestationType is the SAME predicate the scope derivations
	// use for the type half of HardenedGitAttested — both case-exact — so the
	// namespace here and the scope there cannot disagree about what counts as
	// git. Legacy witness.dev prefixes and unknown future versions fail here by
	// construction, matching the scope side: evidence they came from cannot set
	// the scope either, so the exception is closed to them at both layers.
	sep := "/" + gitCommitSubjectInfix // "/commithash:"
	if !strings.HasSuffix(rest, sep) {
		return false
	}
	prefix := rest[:len(rest)-len(sep)]
	return IsHardenedGitAttestationType(prefix)
}

// IsMatchableSubjectDigest reports whether a subject digest — identified by
// its subject NAME, algorithm name and value — may be used as a subject-match
// key, for a caller that has established NOTHING about the statement the
// subject came from.
//
// That is the strict scope: the git-commit SHA-1 arm is unavailable here. A
// caller that holds the statement and wants that arm must say so explicitly
// via SubjectMatchScope, so a site that forgets fails CLOSED (evidence is not
// found) rather than open (a minted SHA-1 becomes matchable).
func IsMatchableSubjectDigest(subjectName, algorithm, value string) bool {
	return SubjectMatchScope{}.IsMatchableSubjectDigest(subjectName, algorithm, value)
}

// IsMatchableSubjectDigest reports whether a subject digest — identified by
// its subject NAME, algorithm name and value, read from a statement described
// by s — may be used as a subject-match key.
//
// The subject name is load-bearing, not decoration: matchability is a property
// of the whole (scope, name, algorithm, value) tuple, because one algorithm can
// be safe for a value the repository itself produced and unsafe for a value an
// attacker chose. Callers must pass the name from the SAME subject the digest
// came from, and a scope derived from the SAME statement; passing "" for the
// name, or the zero scope, is safe and simply forfeits the git arm.
//
// It returns false for:
//   - unknown algorithm names,
//   - non-collision-resistant algorithms (notably "sha1" / "gitoid:sha1"),
//     EXCEPT a git commit reference in a statement carrying a HARDENED git
//     attestation — see isGitCommitSubject and SubjectMatchScope,
//   - plain-hex algorithms whose value is not the exact expected hex length OR
//     contains non-hex characters (a 64-char string of "z" is the right length
//     but is not a real sha256 — it must not anchor a match).
//
// Callers that build a subject index (e.g. attestation/source) use this to keep
// SHA-1 and malformed digests out of the matchable set, closing a subject /
// artifact-substitution avenue. See finding S1.
func (s SubjectMatchScope) IsMatchableSubjectDigest(subjectName, algorithm, value string) bool {
	wantHexLen, ok := matchableSubjectAlgorithms[algorithm]
	if !ok {
		// Not on the value-blind allowlist. One narrowly-scoped arm remains:
		// a SHA-1 commit id, in a statement carrying a HARDENED git
		// attestation (exact current type + verified-commit-hash marker),
		// vouched for by its own subject name. Everything else — including
		// legacy git evidence that predates the marker — is unmatchable.
		return s.HardenedGitAttested && isGitCommitSubject(subjectName, algorithm, value)
	}
	if wantHexLen != 0 {
		// Plain-hex algorithm: enforce exact length AND hex-ness.
		return len(value) == wantHexLen && isHexString(value)
	}
	// Non-hex value (gitoid URI / dirhash string): the algorithm allowlist is
	// the gate; only require a non-empty value.
	return value != ""
}

// digestSize returns the digest length in bytes for a recognized DigestValue,
// and ok=false for any unknown or zero-value DigestValue. It gates calls to
// crypto.Hash.Size(), which panics for an unregistered/zero hash: only the
// algorithms in hashNames (sha256/sha1 and their gitoid/dirhash variants) reach
// Size(), and those are always registered.
func digestSize(dv DigestValue) (int, bool) {
	if _, ok := hashNames[dv]; !ok {
		return 0, false
	}
	return dv.Size(), true
}

// Equal returns true if every digest for hash functions both artifacts have in common are equal.
// If the two artifacts don't have any digests from common hash functions, equal will return false.
// If any digest from common hash functions differ between the two artifacts, equal will return false.
//
// Equality must not be allowed to silently downgrade to the weakest shared hash: an attacker who
// omits the strong digest could otherwise force a match on a weak one (GHSA-pgpm-j729-qcvh).
// Equality therefore additionally requires that the strongest algorithm present on either side is
// carried by both sides and agrees. If the strongest available algorithm is absent from one side,
// the sets are not equal.
func (ds *DigestSet) Equal(second DigestSet) bool {
	maxSize := strongestRecognizedSize(*ds, second)
	if maxSize < 0 {
		// Both sets are empty, or neither carries a recognized algorithm; there is
		// nothing we can compare strength on, so they are not equal.
		return false
	}
	if !strongestClassAgrees(*ds, second, maxSize) {
		return false
	}
	return noRecognizedSharedDisagrees(*ds, second)
}

// strongestRecognizedSize returns the largest digest size (larger size ==
// stronger) among recognized algorithms across either set, or -1 if neither has
// one. Unknown / zero-value keys are skipped, so crypto.Hash.Size() is never
// called on an unregistered hash, which would panic — a DoS vector for a caller
// that hand-builds a DigestSet with a zero-value key (GHSA-pgpm-j729-qcvh).
func strongestRecognizedSize(a, b DigestSet) int {
	maxSize := -1
	for _, set := range []DigestSet{a, b} {
		for dv := range set {
			if n, ok := digestSize(dv); ok && n > maxSize {
				maxSize = n
			}
		}
	}
	return maxSize
}

// strongestClassAgrees reports whether at least one algorithm in the
// strongest-size class is shared by both sides and every shared algorithm in
// that class agrees. This prevents one side from dropping the strong digest to
// force comparison onto a weaker shared algorithm (GHSA-pgpm-j729-qcvh).
//
// Tie semantics (intentional): when two algorithms tie at the strongest size, a
// match on EITHER satisfies equality, so Equal is not strictly transitive across
// the tie (e.g. {sha256:x} == {sha256:x, gitoid:sha256:y} and
// {sha256:x, gitoid:sha256:y} == {gitoid:sha256:y}, but
// {sha256:x} != {gitoid:sha256:y}). This leniency is deliberate and matches
// upstream go-witness: it lets attestors that record different strong-algorithm
// subsets still compare equal. It is not a downgrade vector — every
// strongest-size algorithm here is a 32-byte SHA-256 variant, so matching any
// one requires reproducing the actual content. Requiring ALL strongest-size
// algorithms on both sides would restore transitivity but reject legitimate
// cross-attestor comparisons, so it is intentionally not done.
func strongestClassAgrees(a, b DigestSet, maxSize int) bool {
	shared := false
	for hash, digest := range a {
		if n, ok := digestSize(hash); !ok || n != maxSize {
			continue
		}
		other, ok := b[hash]
		if !ok {
			continue
		}
		if digest != other {
			return false
		}
		shared = true
	}
	return shared
}

// noRecognizedSharedDisagrees reports whether no shared RECOGNIZED algorithm of
// any strength disagrees. Unknown keys are ignored so equality stays a proper
// equivalence relation over recognized algorithms: two sets that agree on every
// recognized algorithm are not made unequal by differing on an unrecognized key.
func noRecognizedSharedDisagrees(a, b DigestSet) bool {
	for hash, digest := range a {
		if _, ok := digestSize(hash); !ok {
			continue
		}
		if other, ok := b[hash]; ok && digest != other {
			return false
		}
	}
	return true
}

func (ds *DigestSet) ToNameMap() (map[string]string, error) {
	nameMap := make(map[string]string)
	for hash, digest := range *ds {
		name, ok := hashNames[hash]
		if !ok {
			return nameMap, ErrUnsupportedHash(hash.String())
		}

		nameMap[name] = digest
	}

	return nameMap, nil
}

func NewDigestSet(digestsByName map[string]string) (DigestSet, error) {
	ds := make(DigestSet)
	for hashName, digest := range digestsByName {
		hash, ok := hashesByName[hashName]
		if !ok {
			return ds, ErrUnsupportedHash(hashName)
		}

		ds[hash] = digest
	}

	return ds, nil
}

func CalculateDigestSet(r io.Reader, digestValues []DigestValue) (DigestSet, error) {
	digestSet := make(DigestSet)
	writers := make([]io.Writer, 0, len(digestValues))
	hashfuncs := map[DigestValue]hash.Hash{}
	for _, digestValue := range digestValues {
		hashfunc := digestValue.New()
		hashfuncs[digestValue] = hashfunc
		writers = append(writers, hashfunc)
	}

	multiwriter := io.MultiWriter(writers...)
	if _, err := io.Copy(multiwriter, r); err != nil {
		return digestSet, err
	}

	for digestValue, hashfunc := range hashfuncs {
		// gitoids are somewhat special... we're using a custom implementation of hash.Hash
		// to wrap the gitoid library. Sum will return a gitoid URI, so we don't want to hex
		// encode it as it's already a string with a hex encoded hash.
		if digestValue.GitOID {
			digestSet[digestValue] = string(hashfunc.Sum(nil))
			continue
		}

		digestSet[digestValue] = string(HexEncode(hashfunc.Sum(nil)))
	}

	return digestSet, nil
}

func CalculateDigestSetFromBytes(data []byte, hashes []DigestValue) (DigestSet, error) {
	// GitOID digests need the content length BEFORE hashing (git's header is
	// "blob <len>\0"), which forces the streaming path's gitoidHasher to
	// buffer the whole input. Here the input is already an in-memory slice
	// with a known length, so compute gitoids directly over it — zero
	// buffering, zero copies (#7572 wall-time follow-up). Non-gitoid hashes
	// take the streaming path unchanged. Values are byte-identical to the
	// streaming path for both kinds.
	digestSet := make(DigestSet)
	rest := make([]DigestValue, 0, len(hashes))
	for _, dv := range hashes {
		if !dv.GitOID {
			rest = append(rest, dv)
			continue
		}
		opts := []gitoid.Option{gitoid.WithContentLength(int64(len(data)))}
		if dv.Hash == crypto.SHA256 {
			opts = append(opts, gitoid.WithSha256())
		}
		g, err := gitoid.New(bytes.NewReader(data), opts...)
		if err != nil {
			return digestSet, err
		}
		digestSet[dv] = g.URI()
	}
	if len(rest) == 0 {
		return digestSet, nil
	}
	restSet, err := CalculateDigestSet(bytes.NewReader(data), rest)
	if err != nil {
		return digestSet, err
	}
	for dv, digest := range restSet {
		digestSet[dv] = digest
	}
	return digestSet, nil
}

func CalculateDigestSetFromFile(path string, hashes []DigestValue) (DigestSet, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is provided by the caller
	if err != nil {
		return DigestSet{}, err
	}
	defer func() { _ = file.Close() }()

	return calculateDigestSetFromOpenFile(file, path, hashes)
}

// CalculateDigestSetFromFileInRoot hashes the file named by name relative to
// root, refusing any symlink final component — escaping OR in-root.
//
// This closes the per-file symlink TOCTOU in attestation collection (#5994):
// the directory walk classifies entries with Lstat and only ever dispatches
// REGULAR files to a worker, but a worker opens them later. An attacker who
// swaps a regular file for a symlink between classification and open could
// otherwise have foreign content hashed and recorded under the original
// relPath, bypassing the walk's classification and filtering. The escaping
// case alone is not enough: a swap to a symlink pointing at an in-root target
// (or, for the single-file basePath recursion, any sibling under the parent
// root) is just as much an evidence-integrity break, and os.Root.Open would
// happily follow it because os.Root deliberately follows in-root symlinks.
//
// openRegularInRoot therefore refuses ANY symlink final component (see the
// unix build for the atomic O_NOFOLLOW openat). Legitimate in-tree symlinks are
// still handled by the walker itself, which resolves and recurses them before
// any worker open, so the only symlink a worker can encounter here is a
// malicious post-Lstat swap — which is exactly what this refuses.
func CalculateDigestSetFromFileInRoot(root *os.Root, name string, hashes []DigestValue) (DigestSet, error) {
	if root == nil {
		return DigestSet{}, fmt.Errorf("nil root")
	}

	file, err := openRegularInRoot(root, name)
	if err != nil {
		return DigestSet{}, err
	}
	defer func() { _ = file.Close() }()

	return calculateDigestSetFromOpenFile(file, name, hashes)
}

func calculateDigestSetFromOpenFile(file *os.File, name string, hashes []DigestValue) (DigestSet, error) {
	hashable, err := isHashableFile(file)
	if err != nil {
		return DigestSet{}, err
	}

	if !hashable {
		return DigestSet{}, fmt.Errorf("%s is not a hashable file", name)
	}

	return CalculateDigestSet(file, hashes)
}

func CalculateDigestSetFromDir(dir string, hashes []DigestValue) (DigestSet, error) {

	dirHash, err := dirhash.HashDir(dir, "", DirhHashSha256)
	if err != nil {
		return nil, err
	}

	digestSetByName := make(map[string]string)
	digestSetByName[digestNameDirHash] = dirHash

	return NewDigestSet(digestSetByName)
}

func (ds DigestSet) MarshalJSON() ([]byte, error) {
	nameMap, err := ds.ToNameMap()
	if err != nil {
		return nil, err
	}

	return json.Marshal(nameMap)
}

func (ds *DigestSet) UnmarshalJSON(data []byte) error {
	nameMap := make(map[string]string)
	err := json.Unmarshal(data, &nameMap)
	if err != nil {
		return err
	}

	newDs, err := NewDigestSet(nameMap)
	if err != nil {
		return err
	}

	*ds = newDs
	return nil
}

func isHashableFile(f *os.File) (bool, error) {
	stat, err := f.Stat()
	if err != nil {
		return false, err
	}

	mode := stat.Mode()

	isSpecial := stat.Mode()&os.ModeCharDevice != 0

	if isSpecial {
		return false, nil
	}

	if mode.IsRegular() {
		return true, nil
	}

	if mode.Perm().IsDir() {
		return true, nil
	}

	if mode&os.ModeSymlink != 0 {
		return true, nil
	}

	return false, nil
}
