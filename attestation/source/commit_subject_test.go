// Copyright 2025 The Aflock Authors
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

package source

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	intoto "github.com/aflock-ai/rookery/attestation/intoto"
)

// Finding a collection by the commit it attests, end to end through Search.
//
// The unit tests in cryptoutil pin the predicate; these pin the BEHAVIOUR that
// predicate exists to produce, because the matcher is reached from two places
// (this index build, and VerifiedSource's re-check of the signed payload) and a
// change that fixed one and not the other would leave the unit tests green
// while verification stayed broken.

const (
	csCommit  = "3d7b4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70"
	csParent  = "1111222233334444555566667777888899990000"
	csGitType = "https://aflock.ai/attestations/git/v0.1"
	csSBOMTyp = "https://aflock.ai/attestations/sbom/v0.1"
)

// gitAttestation is the HARDENED collection entry a matchable commithash
// subject can only legitimately come from: rookery's git attestor is the sole
// producer of that subject name (plugins/attestors/git/git.go Subjects()), and
// since the verified-commit-hash hardening it emits the "commithashverified"
// capability marker in the same signed predicate as the hash. Fixtures that
// omit the attestation are not "simpler" — they describe evidence no attestor
// emits, which is exactly the shape an attacker mints by hand — and fixtures
// that omit the MARKER describe legacy evidence, which forfeits the SHA-1 arm
// (see legacyGitAttestation).
func gitAttestation(t *testing.T, commit string) attestation.CollectionAttestation {
	t.Helper()
	body, err := json.Marshal(map[string]any{"commithash": commit, "commithashverified": true})
	if err != nil {
		t.Fatalf("marshal git attestation: %v", err)
	}
	return attestation.CollectionAttestation{
		Type:        csGitType,
		Attestation: attestation.NewRawAttestation(csGitType, body),
	}
}

// legacyGitAttestation is the git attestation every producer BEFORE the
// verified-commit-hash hardening wrote: the same predicate type, no capability
// marker. Its CommitHash was copied from head.Hash() — the repository's storage
// CLAIM — so it never carried the invariant the SHA-1 exception depends on
// (re-hashed canonical bytes, collision-detecting hasher). Already-signed
// evidence of this shape exists in every store and can never be re-signed;
// these fixtures pin that it stays UNMATCHABLE via sha1.
func legacyGitAttestation(t *testing.T, commit string) attestation.CollectionAttestation {
	t.Helper()
	body, err := json.Marshal(map[string]string{"commithash": commit})
	if err != nil {
		t.Fatalf("marshal legacy git attestation: %v", err)
	}
	return attestation.CollectionAttestation{
		Type:        csGitType,
		Attestation: attestation.NewRawAttestation(csGitType, body),
	}
}

// nonGitAttestation stands in for every producer that is NOT git: it can sign,
// it can name subjects, and it has no business making a SHA-1 matchable.
func nonGitAttestation(t *testing.T) attestation.CollectionAttestation {
	t.Helper()
	return attestation.CollectionAttestation{
		Type:        csSBOMTyp,
		Attestation: attestation.NewRawAttestation(csSBOMTyp, json.RawMessage(`{}`)),
	}
}

// csStatement builds the in-toto statement for a collection named "build"
// carrying one subject and the given attestations.
func csStatement(t *testing.T, subjectName string, digest map[string]string, atts ...attestation.CollectionAttestation) intoto.Statement {
	t.Helper()
	predicate, err := json.Marshal(attestation.Collection{Name: "build", Attestations: atts})
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	return intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: subjectName, Digest: digest}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
}

// loadNamedSubject loads a collection whose single subject has the given name
// and digest, under collection name "build", carrying the given attestations.
//
// Distinct from loadCollectionWithSubject, which hardcodes the subject name
// "artifact": the name is the whole point here, so it has to be a parameter.
// So are the attestations — whether the collection actually attests git is now
// half of the matchability decision.
func loadNamedSubject(t *testing.T, subjectName string, digest map[string]string, atts ...attestation.CollectionAttestation) *MemorySource {
	t.Helper()
	payload, err := json.Marshal(csStatement(t, subjectName, digest, atts...))
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	src := NewMemorySource()
	if err := src.LoadEnvelope("build.json", dsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
	}); err != nil {
		t.Fatalf("LoadEnvelope: %v", err)
	}
	return src
}

// TestSearch_CommitHashSubjectAnchorsMatch is the case the exception exists
// for: a collection recorded against a SHA-1 repository's commit must be
// findable by that commit.
//
// Before this, it was not. The verifier reported "not present in any subject"
// while printing that very value back, and because verification fails closed
// the result was indistinguishable from unattested code.
func TestSearch_CommitHashSubjectAnchorsMatch(t *testing.T) {
	for _, subjectName := range []string{
		"commithash:" + csCommit,
		"https://aflock.ai/attestations/git/v0.1/commithash:" + csCommit,
	} {
		src := loadNamedSubject(t, subjectName, map[string]string{"sha1": csCommit}, gitAttestation(t, csCommit))
		matches, err := src.Search(context.Background(), "build", []string{csCommit}, nil)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("subject %q: commit did not anchor a match (got %d, want 1)", subjectName, len(matches))
		}
	}
}

// TestSearch_CommitHashSubjectWithoutGitAttestationDoesNotAnchorMatch closes
// the hole that scoping by subject NAME alone left open.
//
// Subject names are producer-controlled. Anything able to write and sign a
// statement — an sbom step, a scan step, a hand-rolled producer that never
// touched a repository — could name a subject "commithash:<sha1>" over a SHA-1
// of its own choosing and re-enable collision-prone matching for it. Binding
// the name to the value stopped RELABELLING; it did nothing about MINTING,
// because the attacker controls both halves and making them agree is free.
//
// The exception now also requires the statement to actually attest git. That
// is not a cryptographic bind — the predicate is producer-controlled too — but
// it stops the SHA-1 arm riding on a collection that presents itself as
// something else, so the policy's own per-step attestor requirements scope the
// exception instead of sitting above it.
func TestSearch_CommitHashSubjectWithoutGitAttestationDoesNotAnchorMatch(t *testing.T) {
	for _, subjectName := range []string{
		"commithash:" + csCommit,
		"https://aflock.ai/attestations/git/v0.1/commithash:" + csCommit,
	} {
		src := loadNamedSubject(t, subjectName, map[string]string{"sha1": csCommit}, nonGitAttestation(t))
		matches, err := src.Search(context.Background(), "build", []string{csCommit}, nil)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("subject %q: a minted commithash subject on a collection that attests no git "+
				"anchored a match (got %d, want 0) — the SHA-1 exception is a free label again", subjectName, len(matches))
		}
	}
}

// TestSearch_LegacyGitCollectionDoesNotAnchorSha1Match pins the finding this
// round fixes: the SHA-1 exception's justification is the PRODUCER-side
// invariant (the attested commithash is the output of computeVerifiedCommitHash
// — canonical bytes re-hashed with a collision-detecting hasher), but evidence
// signed before that hardening carries the same predicate type without ever
// receiving the verification. Granting the exception on the type alone applies
// it RETROACTIVELY to evidence that lacks the invariant the exception depends
// on. A legacy (marker-less) git collection must therefore stay unmatchable via
// sha1 — exactly its status before the exception existed — on BOTH matcher
// paths (index build here, signed-payload guard below).
func TestSearch_LegacyGitCollectionDoesNotAnchorSha1Match(t *testing.T) {
	for _, subjectName := range []string{
		"commithash:" + csCommit,
		"https://aflock.ai/attestations/git/v0.1/commithash:" + csCommit,
	} {
		src := loadNamedSubject(t, subjectName, map[string]string{"sha1": csCommit}, legacyGitAttestation(t, csCommit))
		matches, err := src.Search(context.Background(), "build", []string{csCommit}, nil)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("subject %q: a LEGACY git collection (no verified-commit-hash marker) anchored a "+
				"SHA-1 match (got %d, want 0) — the exception applies retroactively to evidence that "+
				"never received the collision/storage verification", subjectName, len(matches))
		}
	}
}

// TestSearch_NonHardenedGitTypesDoNotAnchorSha1Match pins the fail-closed side
// of the grant: the SHA-1 exception keys on the exact hardened format, so a
// git-namespaced type that is not the current attestor's — the legacy
// witness.dev form, or an unknown FUTURE version like v0.2 — gets nothing,
// even when its body carries the capability marker. A future version's
// producer has made no promise yet; carrying the exception forward is a
// conscious edit to hardenedGitAttestationType, not an automatic inheritance.
// Unknown means no exception.
func TestSearch_NonHardenedGitTypesDoNotAnchorSha1Match(t *testing.T) {
	markedBody := func(typ string) attestation.CollectionAttestation {
		body, err := json.Marshal(map[string]any{"commithash": csCommit, "commithashverified": true})
		if err != nil {
			t.Fatalf("marshal git attestation: %v", err)
		}
		return attestation.CollectionAttestation{
			Type:        typ,
			Attestation: attestation.NewRawAttestation(typ, body),
		}
	}

	for name, typ := range map[string]string{
		"legacy witness.dev type": "https://witness.dev/attestations/git/v0.1",
		"unknown future version":  "https://aflock.ai/attestations/git/v0.2",
	} {
		t.Run(name, func(t *testing.T) {
			for _, subjectName := range []string{
				"commithash:" + csCommit,
				typ + "/commithash:" + csCommit,
			} {
				src := loadNamedSubject(t, subjectName, map[string]string{"sha1": csCommit}, markedBody(typ))
				matches, err := src.Search(context.Background(), "build", []string{csCommit}, nil)
				if err != nil {
					t.Fatalf("Search: %v", err)
				}
				if len(matches) != 0 {
					t.Fatalf("subject %q under type %q: a non-hardened git type anchored a SHA-1 match "+
						"(got %d, want 0) — the exception must be granted per hardened format, never per namespace", subjectName, typ, len(matches))
				}
			}
		})
	}
}

// TestSearch_ParentHashSubjectDoesNotAnchorMatch closes a policy bypass.
//
// A parenthash names a DIFFERENT commit and exists only to chain collections
// along the graph. If it anchored a match: commit X introduces a secret, commit
// Y removes it, the scan runs at Y, and Y's collection carries X as a
// parenthash — so a push of X would be cleared by evidence that never examined
// X.
func TestSearch_ParentHashSubjectDoesNotAnchorMatch(t *testing.T) {
	src := loadNamedSubject(t, "parenthash:"+csParent, map[string]string{"sha1": csParent}, gitAttestation(t, csCommit))

	matches, err := src.Search(context.Background(), "build", []string{csParent}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("a parenthash subject anchored a match (got %d, want 0) — evidence "+
			"gathered at a child commit must not satisfy a query for its parent", len(matches))
	}
}

// TestSearch_RelabelledCommitHashDoesNotAnchorMatch is the reason the exception
// binds the subject NAME to the VALUE.
//
// Were the name merely required to carry a "commithash:" prefix, anyone able to
// write a subject could label an arbitrary SHA-1 as a commit and make it
// matchable — turning the narrow exception into "SHA-1 is matchable whenever
// you say the magic word". The collection here DOES attest git, so this pins
// the name/value binding on its own, with the statement scope satisfied.
func TestSearch_RelabelledCommitHashDoesNotAnchorMatch(t *testing.T) {
	// The name claims csCommit; the digest actually carries csParent.
	src := loadNamedSubject(t, "commithash:"+csCommit, map[string]string{"sha1": csParent}, gitAttestation(t, csCommit))

	matches, err := src.Search(context.Background(), "build", []string{csParent}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("a subject naming one commit while carrying another's digest anchored "+
			"a match (got %d, want 0)", len(matches))
	}
}

// TestPayloadMatchesSubjects_CommitHash pins the SECOND call site.
//
// VerifiedSource re-checks subjects against the signature-verified payload (the
// artifact-substitution guard) after the source has already returned. That is a
// separate code path from the index build above, and it is the one that made a
// source-layer workaround impossible: a source matching on value alone had its
// candidates discarded here. Both must agree, or evidence is found and then
// silently thrown away.
//
// It goes through payloadMatchesSubjects rather than subjectsMatchDigests
// because the git claim has to be decoded out of the SIGNED BYTES here, not
// lifted off a struct field the untrusted source populated — so the decode is
// part of what is under test.
func TestPayloadMatchesSubjects_CommitHash(t *testing.T) {
	mustPayload := func(stmt intoto.Statement) []byte {
		t.Helper()
		b, err := json.Marshal(stmt)
		if err != nil {
			t.Fatalf("marshal statement: %v", err)
		}
		return b
	}

	commitSubject := "https://aflock.ai/attestations/git/v0.1/commithash:" + csCommit

	matched, err := payloadMatchesSubjects(
		mustPayload(csStatement(t, commitSubject, map[string]string{"sha1": csCommit}, gitAttestation(t, csCommit))),
		[]string{csCommit})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects: %v", err)
	}
	if !matched {
		t.Error("the substitution guard rejected a commit the index accepts — " +
			"evidence would be found and then discarded")
	}

	matched, err = payloadMatchesSubjects(
		mustPayload(csStatement(t, commitSubject, map[string]string{"sha1": csCommit}, nonGitAttestation(t))),
		[]string{csCommit})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects: %v", err)
	}
	if matched {
		t.Error("the substitution guard accepted a minted commithash subject from a collection " +
			"that attests no git — fixing only the index leaves this path as the bypass")
	}

	// The retroactivity finding, on THIS path: a legacy (marker-less) git
	// collection must not anchor a SHA-1 match here either, or evidence signed
	// before the producer verified commit hashes inherits an exception whose
	// justification it never carried. Both readers must refuse, or the index
	// and the substitution guard disagree.
	matched, err = payloadMatchesSubjects(
		mustPayload(csStatement(t, commitSubject, map[string]string{"sha1": csCommit}, legacyGitAttestation(t, csCommit))),
		[]string{csCommit})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects: %v", err)
	}
	if matched {
		t.Error("the substitution guard granted the SHA-1 arm to a LEGACY (marker-less) git collection — " +
			"the exception applies retroactively to evidence that never received the verification")
	}

	matched, err = payloadMatchesSubjects(
		mustPayload(csStatement(t, "parenthash:"+csParent, map[string]string{"sha1": csParent}, gitAttestation(t, csCommit))),
		[]string{csParent})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects: %v", err)
	}
	if matched {
		t.Error("the substitution guard accepted a parenthash — the bypass is open on this path")
	}
}

// TestPayloadMatchesSubjects_NonCollectionCannotClaimGitArm is the round-3
// rebuttal. The SHA-1 commit arm is claimable ONLY by a signed attestation
// COLLECTION. A bare external predicate (here SLSA provenance) whose predicate
// object is hand-shaped to carry an attestations[].type matching a git type,
// plus a minted commithash sha1 subject, must NOT get the arm — otherwise the
// SHA-1 restriction is bypassed by an object no git attestor ever produced.
func TestPayloadMatchesSubjects_NonCollectionCannotClaimGitArm(t *testing.T) {
	commitSubject := "https://aflock.ai/attestations/git/v0.1/commithash:" + csCommit
	// predicateType is NOT a collection; the predicate merely LOOKS like one —
	// fully hardened-shaped (type AND marker), so the refusal pinned here is
	// the collection gate specifically, not the marker gate saving it.
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1",` +
		`"subject":[{"name":"` + commitSubject + `","digest":{"sha1":"` + csCommit + `"}}],` +
		`"predicateType":"https://slsa.dev/provenance/v1",` +
		`"predicate":{"attestations":[{"type":"` + csGitType + `","attestation":{"commithashverified":true}}]}}`)

	matched, err := payloadMatchesSubjects(payload, []string{csCommit})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects: %v", err)
	}
	if matched {
		t.Error("a bare non-collection predicate claimed the git SHA-1 arm by hand-adding an attestations[].type — " +
			"the SHA-1 restriction is bypassable without an attestation collection")
	}
}

// TestPayloadMatchesSubjects_DuplicatePredicateKeysUseEffective is the round-7
// rebuttal. encoding/json calls gitAttestedClaim.UnmarshalJSON once per
// `predicate` key; a statement with DUPLICATE predicate keys — git-shaped first,
// non-git second — must be judged by the EFFECTIVE (last, non-git) predicate,
// the same one normal decoding keeps. Without a reset at method entry the flag
// latched true from the first key and granted the SHA-1 arm to a statement whose
// real predicate attests no git. predicateType is a collection here, so the R3
// gate does not save us — only the entry reset does.
func TestPayloadMatchesSubjects_DuplicatePredicateKeysUseEffective(t *testing.T) {
	commitSubject := "https://aflock.ai/attestations/git/v0.1/commithash:" + csCommit
	// Two predicate keys: a git-shaped collection FIRST (fully hardened-shaped,
	// type AND marker, so only the entry reset — not the marker gate — stands
	// between it and the arm), a non-git collection SECOND (the effective one).
	// Hand-built because a Go struct cannot carry duplicate keys.
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1",` +
		`"subject":[{"name":"` + commitSubject + `","digest":{"sha1":"` + csCommit + `"}}],` +
		`"predicateType":"https://aflock.ai/attestation-collection/v0.1",` +
		`"predicate":{"attestations":[{"type":"` + csGitType + `","attestation":{"commithashverified":true}}]},` +
		`"predicate":{"attestations":[{"type":"` + csSBOMTyp + `"}]}}`)

	matched, err := payloadMatchesSubjects(payload, []string{csCommit})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects: %v", err)
	}
	if matched {
		t.Error("duplicate predicate keys let a git-shaped FIRST predicate latch the SHA-1 arm even though " +
			"the effective (last) predicate attests no git — the matcher disagrees with normal decoding")
	}
}

// TestPayloadMatchesSubjects_MixedCollectionNonGitSubjectNotMatchable is the
// chunk-1 rebuttal at the VERIFIED path, end to end. A collection that carries
// BOTH a git attestation and a non-git (sbom) one is git-attested, so the scope
// grants the git arm — but a commithash subject NAMED UNDER THE SBOM TYPE (the
// shape Collection.Subjects() gives a subject the sbom attestor produced) must
// NOT ride that arm, or a non-git attestor's collision-prone SHA-1 becomes
// matchable (evidence substitution). The positive control proves the arm still
// works for a git-NAMESPACED commithash in the same collection.
func TestPayloadMatchesSubjects_MixedCollectionNonGitSubjectNotMatchable(t *testing.T) {
	mustPayload := func(stmt intoto.Statement) []byte {
		t.Helper()
		b, err := json.Marshal(stmt)
		if err != nil {
			t.Fatalf("marshal statement: %v", err)
		}
		return b
	}
	mixed := []attestation.CollectionAttestation{gitAttestation(t, csCommit), nonGitAttestation(t)}

	// The attack: commithash subject namespaced under the SBOM type.
	sbomNamed := csSBOMTyp + "/commithash:" + csCommit
	matched, err := payloadMatchesSubjects(
		mustPayload(csStatement(t, sbomNamed, map[string]string{"sha1": csCommit}, mixed...)),
		[]string{csCommit})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects: %v", err)
	}
	if matched {
		t.Error("a commithash subject namespaced under the SBOM type matched in a git-attested mixed " +
			"collection — a non-git attestor's SHA-1 rode the git exception (evidence substitution)")
	}

	// Positive control: the git-namespaced commithash in the same collection DOES
	// match, so the fix narrows the arm rather than removing it.
	gitNamed := csGitType + "/commithash:" + csCommit
	matched, err = payloadMatchesSubjects(
		mustPayload(csStatement(t, gitNamed, map[string]string{"sha1": csCommit}, mixed...)),
		[]string{csCommit})
	if err != nil {
		t.Fatalf("payloadMatchesSubjects (control): %v", err)
	}
	if !matched {
		t.Error("a git-namespaced commithash in a git-attested collection stopped matching — the fix " +
			"over-narrowed the exception")
	}
}

// TestPayloadMatchesSubjects_NonCollectionPredicateStillChecksSubjects guards
// the decode this fix added.
//
// SearchByPredicateType runs BARE predicates through the same guard — SLSA
// provenance, a VSA, a cosign attestation — and those predicates are not
// collections. Reading the git claim with an inline struct field would make
// any predicate of another JSON shape a decode error, and payloadMatchesSubjects
// fails CLOSED on a decode error: every external attestation would be rejected
// outright. A guard that widens into an outage is not a guard.
func TestPayloadMatchesSubjects_NonCollectionPredicateStillChecksSubjects(t *testing.T) {
	sha256Digest := "9f2c1e7a4b6d803f5c9e1a7b3d5f8092c4e6a1b3d5f7092c4e6a8b1d3f5709ac"

	for name, predicate := range map[string]string{
		"array predicate":  `[{"builder":"x"}]`,
		"string predicate": `"opaque"`,
		"null predicate":   `null`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1",` +
				`"subject":[{"name":"artifact","digest":{"sha256":"` + sha256Digest + `"}}],` +
				`"predicateType":"https://slsa.dev/provenance/v1",` +
				`"predicate":` + predicate + `}`)

			matched, err := payloadMatchesSubjects(payload, []string{sha256Digest})
			if err != nil {
				t.Fatalf("a non-collection predicate broke the subject check: %v", err)
			}
			if !matched {
				t.Error("a bare-predicate statement stopped matching its own sha256 subject")
			}
		})
	}
}
