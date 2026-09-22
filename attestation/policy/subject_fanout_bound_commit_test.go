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

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With relationship edges no longer followed, a commit-seeded verify reaches
// its evidence only through the commit digest itself. A commit released or
// re-run many times carries many collections per step for that ONE digest
// (measured on prod, all time: up to 37 source-git collections for one
// commit), so with the fan-out limit at 32 the guard would classify the
// commit as a hub and reject every one of them. There is no longer a depth-1
// edge to rescue the step.
//
// The bound commit is exempt from hub classification. It is sound because
// every candidate admitted through it still faces the commit binding at the
// step gate: a collection whose git commithash is not the bound commit is
// rejected there, so the exemption cannot admit another build's evidence.
// Every other digest is still classified exactly as before.

// boundCommitCollection is fanoutFixture.collection with the git commithash
// set to commit instead of the reference.
func (f *fanoutFixture) boundCommitCollection(t *testing.T, ref, commit string, digests ...string) source.CollectionEnvelope {
	t.Helper()
	gitPayload, err := json.Marshal(map[string]any{"commithash": commit})
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
	payload, err := json.Marshal(intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       subjects,
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	})
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(f.signer))
	require.NoError(t, err)
	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(payload, &stmt))
	return source.CollectionEnvelope{Envelope: env, Statement: stmt, Reference: ref}
}

const fanoutOtherCommit = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// 40 re-runs of the same commit, above the production limit of 32.
func boundCommitCorpus(t *testing.T, f *fanoutFixture, n int) []source.CollectionEnvelope {
	t.Helper()
	envs := make([]source.CollectionEnvelope, 0, n)
	for i := 0; i < n; i++ {
		envs = append(envs, f.boundCommitCollection(t, fmt.Sprintf("rerun-%d", i), fanoutCommitDigest, fanoutCommitDigest))
	}
	return envs
}

func boundCommitVerify(t *testing.T, f *fanoutFixture, corpus []source.CollectionEnvelope, extraOpts ...VerifyOption) (bool, map[string]StepResult) {
	t.Helper()
	mem := source.NewMemorySource()
	for _, e := range corpus {
		require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
	opts := append([]VerifyOption{
		WithVerifiedSource(vs),
		WithSubjectDigests([]string{fanoutCommitDigest}),
		WithMaxSubjectFanout(32),
	}, extraOpts...)
	accepted, results, err := f.policy(t).Verify(t.Context(), opts...)
	require.NoError(t, err)
	return accepted, results
}

func TestSubjectFanout_BoundCommitSeedIsNeverAHub(t *testing.T) {
	f := newFanoutFixture(t)
	accepted, results := boundCommitVerify(t, f, boundCommitCorpus(t, f, 40), WithCommitBinding(fanoutCommitDigest))
	assert.True(t, accepted, "40 collections bound to the evaluated commit are its own evidence, not a hub")
	assert.Len(t, results[fanoutStepName].Passed, 40)
}

// The exemption is keyed on the binding. Without one, the same digest is an
// ordinary closure digest and the guard classifies it exactly as before.
func TestSubjectFanout_UnboundCommitDigestIsStillClassified(t *testing.T) {
	f := newFanoutFixture(t)
	accepted, results := boundCommitVerify(t, f, boundCommitCorpus(t, f, 40))
	assert.False(t, accepted, "without a commit binding the 40-way digest is a hub")
	assert.Empty(t, results[fanoutStepName].Passed)
}

// The exemption admits candidates to the gate; it does not pass them. A
// collection that names the bound commit as a subject but whose git
// commithash is another commit is still rejected by the binding.
func TestSubjectFanout_BoundCommitExemptionStillFacesTheBinding(t *testing.T) {
	f := newFanoutFixture(t)
	corpus := make([]source.CollectionEnvelope, 0, 40)
	for i := 0; i < 40; i++ {
		corpus = append(corpus, f.boundCommitCollection(t, fmt.Sprintf("other-%d", i), fanoutOtherCommit, fanoutCommitDigest))
	}
	accepted, results := boundCommitVerify(t, f, corpus, WithCommitBinding(fanoutCommitDigest))
	assert.False(t, accepted)
	assert.Empty(t, results[fanoutStepName].Passed)
	var notBound int
	for _, rc := range results[fanoutStepName].Rejected {
		var e ErrWitnessNotBoundToCommit
		if rc.Reason != nil && errors.As(rc.Reason, &e) {
			notBound++
		}
	}
	assert.Equal(t, 40, notBound, "every candidate reaches the gate through the exemption and is rejected by the binding there")
}

// Only the bound commit is exempt: a second seed digest shared by more than
// the limit is still a hub, and a candidate connected only through it is
// still rejected.
func TestSubjectFanout_BoundCommitExemptionIsOnlyTheCommit(t *testing.T) {
	f := newFanoutFixture(t)
	authorized := make([]PassedCollection, 0, 40)
	for i := 0; i < 40; i++ {
		ce := f.boundCommitCollection(t, fmt.Sprintf("hub-%d", i), fanoutCommitDigest, fanoutHubDigest)
		authorized = append(authorized, PassedCollection{Collection: source.CollectionVerificationResult{CollectionEnvelope: ce}})
	}
	admitted, rejected := filterHubOnlyPassed(authorized, []string{fanoutCommitDigest, fanoutHubDigest}, 32, fanoutCommitDigest)
	assert.Empty(t, admitted, "a hub digest other than the bound commit is still a hub")
	assert.Len(t, rejected, 40)

	tracker := newFanoutTracker([]string{fanoutHubDigest}, 32, fanoutCommitDigest)
	var provable int
	for _, pc := range authorized {
		if _, rej := tracker.add(pc.Collection.CollectionEnvelope); rej {
			provable++
		}
	}
	assert.Equal(t, 8, provable, "the streamed tracker classifies the non-exempt hub exactly as the batch guard")
}
