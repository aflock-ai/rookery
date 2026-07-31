// Copyright 2026 The Archivista Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The verify walk is anchored to the subject set the workflow was dispatched
// for — the commit's own evidence closure, on the order of ten attestations.
// HUB digests (shared base-image layers, runner images, toolchain blobs) sit
// in that subject set too, and every other commit's collections carry them:
// without a guard, one hub admits the whole tenant corpus into a single
// verify (observed: 220 candidates for a commit whose closure is 2).
//
// These tests pin the guard: a closure digest matched by more candidates
// than the fan-out limit is a hub, and candidates whose ONLY connection to
// the closure is a hub digest are rejected before the step gate. Soundness
// direction: the guard can only REJECT (drop candidates); admitted
// candidates still pass per-envelope signature verification and the step
// gate, so the failure mode is a false reject, never a false pass.

const (
	fanoutCommitDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fanoutHubDigest    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fanoutStepName     = "build"
	fanoutAttestorType = "https://aflock.ai/attestations/git/v0.1"
)

type fanoutFixture struct {
	signer   cryptoutil.Signer
	verifier cryptoutil.Verifier
	keyID    string
	pubPEM   string
}

func newFanoutFixture(t *testing.T) *fanoutFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pemBytes, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)
	return &fanoutFixture{signer: signer, verifier: verifier, keyID: keyID, pubPEM: string(pemBytes)}
}

// collection builds a signed single-attestor collection whose statement
// attests the given subject digests.
func (f *fanoutFixture) collection(t *testing.T, ref string, digests ...string) source.CollectionEnvelope {
	t.Helper()
	gitPayload, err := json.Marshal(map[string]any{"commithash": ref})
	require.NoError(t, err)
	coll := attestation.Collection{
		Name: fanoutStepName,
		Attestations: []attestation.CollectionAttestation{{
			Type:        fanoutAttestorType,
			Attestation: attestation.NewRawAttestation(fanoutAttestorType, gitPayload),
		}},
	}
	predicate, err := json.Marshal(coll)
	require.NoError(t, err)

	subjects := make([]intoto.Subject, 0, len(digests))
	for i, d := range digests {
		subjects = append(subjects, intoto.Subject{Name: fmt.Sprintf("artifact-%d", i), Digest: map[string]string{"sha256": d}})
	}
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       subjects,
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(f.signer))
	require.NoError(t, err)
	return source.CollectionEnvelope{Envelope: env, Statement: stmt, Reference: ref}
}

// policy with one step requiring the git attestor, trusting the fixture key.
func (f *fanoutFixture) policy(t *testing.T) Policy {
	t.Helper()
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: map[string]PublicKey{
			f.keyID: {KeyID: f.keyID, Key: []byte(f.pubPEM)},
		},
		Steps: map[string]Step{
			fanoutStepName: {
				Name:          fanoutStepName,
				Attestations:  []Attestation{{Type: fanoutAttestorType}},
				Functionaries: []Functionary{{Type: "publickey", PublicKeyID: f.keyID}},
			},
		},
	}
}

// fanoutCorpus: commit A's own evidence (2 collections carrying the commit
// digest AND the hub digest — a real build attests its base image too) plus
// hubOnly collections from OTHER commits that share ONLY the hub digest.
func fanoutCorpus(t *testing.T, f *fanoutFixture, hubOnly int) []source.CollectionEnvelope {
	t.Helper()
	envs := []source.CollectionEnvelope{
		f.collection(t, "commit-a-build", fanoutCommitDigest, fanoutHubDigest),
		f.collection(t, "commit-a-test", fanoutCommitDigest, fanoutHubDigest),
	}
	for i := 0; i < hubOnly; i++ {
		envs = append(envs, f.collection(t, fmt.Sprintf("other-commit-%d", i), fanoutHubDigest))
	}
	return envs
}

func fanoutVerify(t *testing.T, f *fanoutFixture, corpus []source.CollectionEnvelope, extraOpts ...VerifyOption) (bool, map[string]StepResult) {
	t.Helper()
	mem := source.NewMemorySource()
	for _, e := range corpus {
		require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
	opts := append([]VerifyOption{
		WithVerifiedSource(vs),
		WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}),
	}, extraOpts...)
	accepted, results, err := f.policy(t).Verify(context.Background(), opts...)
	require.NoError(t, err)
	return accepted, results
}

// RED-pin: without the guard, the hub admits every other commit's evidence
// into this commit's verify — candidate count scales with the corpus, not
// with the commit's closure. (This is the defect, kept as documentation of
// the unguarded behavior.)
func TestSubjectFanout_UnguardedAdmitsTheWholeHubCorpus(t *testing.T) {
	f := newFanoutFixture(t)
	accepted, results := fanoutVerify(t, f, fanoutCorpus(t, f, 20))
	require.True(t, accepted)
	assert.Equal(t, 22, len(results[fanoutStepName].Passed),
		"unguarded: every hub-connected collection is admitted and gate-processed")
}

// The guard: with a fan-out limit, hub-only candidates are rejected before
// the gate. Commit A's verdict is unchanged and its OWN evidence — which
// also carries the hub digest — is still admitted via the commit digest.
func TestSubjectFanout_GuardConfinesTheWalkToTheCommitClosure(t *testing.T) {
	f := newFanoutFixture(t)
	accepted, results := fanoutVerify(t, f, fanoutCorpus(t, f, 20),
		WithMaxSubjectFanout(8))

	require.True(t, accepted, "commit A's own evidence must still satisfy the policy — the guard may only drop hub-only candidates")
	sr := results[fanoutStepName]
	assert.Equal(t, 2, len(sr.Passed),
		"guarded: only the commit's own evidence closure is admitted (expected ~10 per commit, got the corpus without the guard)")
	for _, pc := range sr.Passed {
		assert.Contains(t, []string{"commit-a-build", "commit-a-test"}, pc.Collection.Reference,
			"no other commit's evidence may enter this commit's walk")
	}
	// Hub-suppressed candidates are visible as rejections, not silently gone —
	// and COMPACT: rejected results are write-only downstream (judge reads
	// Reference/Reason, the VSA reads PayloadDigests), so retaining parsed
	// bodies would keep per-turn memory proportional to the corpus the guard
	// just excluded.
	var hubRejected int
	for _, rc := range sr.Rejected {
		if rc.Reason == nil || rc.Collection.Reference == "" {
			continue
		}
		hubRejected++
		assert.Empty(t, rc.Collection.Envelope.Payload, "hub-rejected results must not retain payload bytes")
		assert.Empty(t, rc.Collection.Statement.Predicate, "hub-rejected results must not retain the parsed statement predicate")
		assert.Empty(t, rc.Collection.Collection.Attestations, "hub-rejected results must not retain parsed collection attestations")
	}
	assert.GreaterOrEqual(t, hubRejected, 20, "hub-suppressed candidates must be reported as rejected with a reason")
}

// SOUNDNESS: the guard must never turn a rejection into an acceptance. A
// candidate inside the admitted closure with a BAD signature still rejects —
// crypto checks are per-envelope and run regardless of the guard.
func TestSubjectFanout_GuardNeverAcceptsBadCrypto(t *testing.T) {
	f := newFanoutFixture(t)
	evil := newFanoutFixture(t) // different key — untrusted by the policy
	corpus := fanoutCorpus(t, f, 20)
	corpus = append(corpus, evil.collection(t, "commit-a-forged", fanoutCommitDigest))

	accepted, results := fanoutVerify(t, f, corpus, WithMaxSubjectFanout(8))
	require.True(t, accepted)
	sr := results[fanoutStepName]
	assert.Equal(t, 2, len(sr.Passed), "the forged collection must not be admitted to Passed despite being inside the closure")
	for _, pc := range sr.Passed {
		assert.NotEqual(t, "commit-a-forged", pc.Collection.Reference)
	}
}

// CLOSURE GROWTH: evidence the seed digests do not name directly enters the
// closure via trust-gated BackRef expansion (verifySteps appends discovered
// digests to vo.subjectDigests for the next depth). The guard must admit a
// candidate through any non-hub CLOSURE digest — not only the original seed —
// or depth expansion would be dead. Pinned at the filter level: the same
// candidate is rejected against the bare seed and admitted once the closure
// contains the digest a passed collection's BackRefs discovered.
func TestSubjectFanout_ExpandedClosureAdmitsBackRefEvidence(t *testing.T) {
	f := newFanoutFixture(t)
	upstream := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" + "cc"
	candidate := f.collection(t, "upstream-build", upstream)

	// The filter operates on the step's functionary-authorized set.
	authorized := []PassedCollection{{Collection: source.CollectionVerificationResult{CollectionEnvelope: candidate}}}

	// Before expansion: seed closure only — the candidate is outside it.
	admitted, rejected := filterHubOnlyPassed(authorized, []string{fanoutCommitDigest}, 8)
	assert.Empty(t, admitted, "a candidate outside the closure must not be admitted")
	require.Len(t, rejected, 1)

	// After expansion: the upstream digest joined the closure (as BackRef
	// discovery does) — the candidate is admitted through it.
	admitted, rejected = filterHubOnlyPassed(authorized, []string{fanoutCommitDigest, upstream}, 8)
	assert.Len(t, admitted, 1, "closure-expanded digests must admit evidence exactly like seed digests")
	assert.Empty(t, rejected)
}

// DENIAL-OF-VERIFICATION resistance: fan-out must be computed ONLY from
// cryptographically valid candidates. Anyone can upload envelopes naming a
// legitimate digest; if unverified candidates counted toward fan-out, an
// attacker could add maxFanout+1 wrong-key envelopes for the victim's commit
// digest, classify it as a hub, and suppress the victim's VALID evidence —
// unauthenticated data steering which authenticated evidence is admitted.
func TestSubjectFanout_UnverifiedFloodCannotHubTheVictimDigest(t *testing.T) {
	f := newFanoutFixture(t)
	attacker := newFanoutFixture(t) // key the policy does not trust

	const limit = 8
	corpus := []source.CollectionEnvelope{
		f.collection(t, "victim-build", fanoutCommitDigest),
		f.collection(t, "victim-test", fanoutCommitDigest),
	}
	// Flood: limit+1 wrong-key envelopes all naming the victim's digest.
	for i := 0; i < limit+1; i++ {
		corpus = append(corpus, attacker.collection(t, fmt.Sprintf("flood-%d", i), fanoutCommitDigest))
	}

	accepted, results := fanoutVerify(t, f, corpus, WithMaxSubjectFanout(limit))

	require.True(t, accepted, "an unauthenticated flood must not be able to fail a valid verification")
	sr := results[fanoutStepName]
	require.Len(t, sr.Passed, 2, "the victim's validly-signed evidence must still be admitted — wrong-key envelopes must not count toward the digest's fan-out")
	for _, pc := range sr.Passed {
		assert.Contains(t, []string{"victim-build", "victim-test"}, pc.Collection.Reference)
	}
}

// When the guard rejects EVERY candidate, the step's collection set is empty
// and verifySteps injects a diagnostic placeholder. The hub rejections must
// still reach the step result — they are the operator's only explanation for
// why their evidence vanished, and (when the policy is not accepted) their
// evidence descriptors are what the signed failure VSA records.
func TestSubjectFanout_AllRejectedStillReportsHubRejections(t *testing.T) {
	f := newFanoutFixture(t)
	const limit = 4
	// Every candidate connects ONLY through the hub digest, so none survive.
	var corpus []source.CollectionEnvelope
	for i := 0; i < limit+3; i++ {
		corpus = append(corpus, f.collection(t, fmt.Sprintf("hub-only-%d", i), fanoutHubDigest))
	}

	mem := source.NewMemorySource()
	for _, e := range corpus {
		require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
	accepted, results, err := f.policy(t).Verify(context.Background(),
		WithVerifiedSource(vs),
		// Closure names the commit AND the hub; no candidate carries the commit.
		WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}),
		WithMaxSubjectFanout(limit),
	)
	require.NoError(t, err)
	require.False(t, accepted, "no admissible evidence must not accept the policy")

	sr := results[fanoutStepName]
	assert.Empty(t, sr.Passed, "no candidate should be admitted")
	var hubReasons int
	for _, rc := range sr.Rejected {
		if rc.Reason != nil && strings.Contains(rc.Reason.Error(), "subject fan-out guard") {
			hubReasons++
		}
	}
	assert.Equal(t, limit+3, hubReasons,
		"every hub-suppressed candidate must be reported even when the guard empties the step — otherwise the failure VSA and the operator lose the reason the evidence disappeared")
}

// TRUSTED-BUT-UNAUTHORIZED signer: crypto-validity is NOT sufficient to let a
// candidate classify a hub. A policy commonly trusts different keys for
// different steps; a key the policy trusts for step B is fully
// cryptographically valid, yet has no authority over step A. If such a signer
// could contribute to step A's fan-out, a functionary for ANY step could
// publish maxFanout+1 envelopes naming the victim digest and suppress step
// A's legitimate evidence — privilege escalation across steps, and a
// denial-of-verification. Fan-out must be counted only from candidates
// authorized as functionaries for the step being verified.
func TestSubjectFanout_TrustedButUnauthorizedSignerCannotHub(t *testing.T) {
	f := newFanoutFixture(t)     // authorized for the step under test
	other := newFanoutFixture(t) // trusted by the policy, but for a DIFFERENT step

	const limit = 4
	corpus := []source.CollectionEnvelope{
		f.collection(t, "victim-build", fanoutCommitDigest),
		f.collection(t, "victim-test", fanoutCommitDigest),
	}
	for i := 0; i < limit+1; i++ {
		corpus = append(corpus, other.collection(t, fmt.Sprintf("otherstep-%d", i), fanoutCommitDigest))
	}

	mem := source.NewMemorySource()
	for _, e := range corpus {
		require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
	}
	// BOTH keys verify cryptographically (both are policy public keys), but
	// only f is a functionary of the step under test.
	// One call with BOTH: VerifyWithVerifiers assigns (does not append), so
	// two separate calls would silently drop the first verifier.
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier, other.verifier))

	pol := f.policy(t)
	pol.PublicKeys[other.keyID] = PublicKey{KeyID: other.keyID, Key: []byte(other.pubPEM)}
	// other is declared as a functionary of a SEPARATE step only.
	pol.Steps["unrelated"] = Step{
		Name:          "unrelated",
		Attestations:  []Attestation{{Type: fanoutAttestorType}},
		Functionaries: []Functionary{{Type: "publickey", PublicKeyID: other.keyID}},
	}

	accepted, results, err := pol.Verify(context.Background(),
		WithVerifiedSource(vs),
		WithSubjectDigests([]string{fanoutCommitDigest}),
		WithMaxSubjectFanout(limit),
	)
	require.NoError(t, err)

	// The property under test is per-step admission. Overall acceptance is
	// deliberately NOT asserted: the extra "unrelated" step exists only to
	// make `other` a policy-trusted functionary somewhere, and this corpus
	// carries no collection named for it, so the policy cannot accept.
	_ = accepted
	sr := results[fanoutStepName]
	require.Len(t, sr.Passed, 2,
		"a signer trusted for a different step must not be able to hub-classify this step's digest and suppress its authorized evidence")
	for _, pc := range sr.Passed {
		assert.Contains(t, []string{"victim-build", "victim-test"}, pc.Collection.Reference)
	}
}

// A fan-out limit of 0 (unset) must behave exactly like the unguarded path —
// the guard ships opt-in.
func TestSubjectFanout_ZeroLimitIsUnguarded(t *testing.T) {
	f := newFanoutFixture(t)
	_, results := fanoutVerify(t, f, fanoutCorpus(t, f, 20), WithMaxSubjectFanout(0))
	assert.Equal(t, 22, len(results[fanoutStepName].Passed))
}
