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
	"runtime"
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

// These tests pin the INTERLEAVED per-candidate step pipeline (#7572):
//
//   - TestInterleave_PeakStaysBoundedPerCandidate is the mechanical
//     revert gate for the memory property itself. It fails if the policy
//     engine goes back to materializing every candidate's decoded body
//     before evaluation — whether by calling the slice Search again or by
//     accumulating uncompacted results inside the streamed consumer.
//   - TestInterleave_StreamedAndBatchStepResultsAreEquivalent pins verdict
//     equivalence between the streamed path and the batch path, with the
//     subject fan-out guard ACTIVE, so the fanoutTracker's end-of-stream
//     classification can never drift from filterHubOnlyPassed.

const (
	interleaveStep     = "bulk-step"
	interleaveAttType  = "https://aflock.ai/attestations/git/v0.1"
	interleaveBulkType = "https://example.com/attestations/bulk/v0.1"
	interleaveDigest   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

type interleaveFixture struct {
	signer   cryptoutil.Signer
	verifier cryptoutil.Verifier
	keyID    string
	pubPEM   string
}

func newInterleaveFixture(t *testing.T) *interleaveFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pemBytes, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)
	return &interleaveFixture{
		signer:   cryptoutil.NewRSASigner(priv, crypto.SHA256),
		verifier: verifier,
		keyID:    keyID,
		pubPEM:   string(pemBytes),
	}
}

// policy requires the git attestor type; bulk collections carry ONLY the bulk
// type, so every candidate is functionary-AUTHORIZED but gate-REJECTED
// (missing required attestation) — rejection compaction retains almost
// nothing, which is what makes the per-candidate release measurable.
func (f *interleaveFixture) policy() Policy {
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: map[string]PublicKey{
			f.keyID: {KeyID: f.keyID, Key: []byte(f.pubPEM)},
		},
		Steps: map[string]Step{
			interleaveStep: {
				Name:          interleaveStep,
				Attestations:  []Attestation{{Type: interleaveAttType}},
				Functionaries: []Functionary{{Type: "publickey", PublicKeyID: f.keyID}},
			},
		},
	}
}

// bulkEnvelopeJSON builds one signed collection envelope whose predicate
// carries a bulkBytes-sized raw attestation, returned as MARSHALED JSON so
// the source can decode it freshly per search — the analogue of a remote
// store download, and the reason decoded-body lifetime is observable.
func (f *interleaveFixture) bulkEnvelopeJSON(t *testing.T, ref string, bulkBytes int) []byte {
	t.Helper()
	bulk, err := json.Marshal(map[string]string{"data": strings.Repeat("a", bulkBytes)})
	require.NoError(t, err)
	coll := attestation.Collection{
		Name: interleaveStep,
		Attestations: []attestation.CollectionAttestation{{
			Type:        interleaveBulkType,
			Attestation: attestation.NewRawAttestation(interleaveBulkType, bulk),
		}},
	}
	predicate, err := json.Marshal(coll)
	require.NoError(t, err)
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       []intoto.Subject{{Name: "artifact", Digest: map[string]string{"sha256": interleaveDigest}}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(f.signer))
	require.NoError(t, err)
	raw, err := json.Marshal(env)
	require.NoError(t, err)
	return raw
}

// gcMeasuringStreamSourcer decodes each candidate FRESH from raw JSON at
// yield time, and at every yield boundary forces a GC and records the peak
// LIVE heap (HeapAlloc). With per-candidate consumption, each decoded body is
// unreachable by the time the next boundary runs, so live heap stays at
// O(one candidate). If the engine (or a revert) holds every decoded result
// until the stream completes, live heap at the boundaries grows by
// O(candidate) each yield and the peak scales with the corpus.
type gcMeasuringStreamSourcer struct {
	rawEnvelopes [][]byte
	yields       int
	peakLiveHeap uint64
}

func (s *gcMeasuringStreamSourcer) measure() {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if ms.HeapAlloc > s.peakLiveHeap {
		s.peakLiveHeap = ms.HeapAlloc
	}
}

func (s *gcMeasuringStreamSourcer) decodeOne(i int) (source.CollectionEnvelope, error) {
	var env dsse.Envelope
	if err := json.Unmarshal(s.rawEnvelopes[i], &env); err != nil {
		return source.CollectionEnvelope{}, err
	}
	stmt := intoto.Statement{}
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return source.CollectionEnvelope{}, err
	}
	coll := attestation.Collection{}
	if err := json.Unmarshal(stmt.Predicate, &coll); err != nil {
		return source.CollectionEnvelope{}, err
	}
	return source.CollectionEnvelope{
		Reference:  fmt.Sprintf("bulk-%d", i),
		Envelope:   env,
		Statement:  stmt,
		Collection: coll,
	}, nil
}

func (s *gcMeasuringStreamSourcer) SearchStream(_ context.Context, collectionName string, _, _ []string, yield func(source.CollectionEnvelope) error) error {
	if collectionName != interleaveStep {
		return nil
	}
	for i := range s.rawEnvelopes {
		s.measure()
		ce, err := s.decodeOne(i)
		if err != nil {
			return err
		}
		s.yields++
		if err := yield(ce); err != nil {
			return err
		}
	}
	s.measure()
	return nil
}

func (s *gcMeasuringStreamSourcer) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]source.CollectionEnvelope, error) {
	out := make([]source.CollectionEnvelope, 0, len(s.rawEnvelopes))
	err := s.SearchStream(ctx, collectionName, subjectDigests, attestations, func(ce source.CollectionEnvelope) error {
		out = append(out, ce)
		return nil
	})
	return out, err
}

func (s *gcMeasuringStreamSourcer) SearchByPredicateType(context.Context, []string, []string) ([]source.StatementEnvelope, error) {
	return []source.StatementEnvelope{}, nil
}

// REVERT GATE (#7572): with candidates consumed one at a time, the live heap
// observed at yield boundaries must stay O(one candidate), not O(corpus).
// Reverting the interleave — policy materializing the Search slice again, or
// the streamed consumer retaining uncompacted results — pushes the measured
// peak to ~(candidates × per-candidate retention) and fails the bound.
func TestInterleave_PeakStaysBoundedPerCandidate(t *testing.T) {
	const (
		candidates = 16
		bulkBytes  = 3 << 20 // 3 MiB predicate per candidate; ≥6 MiB retained each when materialized (payload + decoded collection)
	)
	f := newInterleaveFixture(t)
	src := &gcMeasuringStreamSourcer{}
	for i := 0; i < candidates; i++ {
		src.rawEnvelopes = append(src.rawEnvelopes, f.bulkEnvelopeJSON(t, fmt.Sprintf("bulk-%d", i), bulkBytes))
	}

	vs := source.NewVerifiedSource(src, dsse.VerifyWithVerifiers(f.verifier))

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	accepted, results, err := f.policy().Verify(context.Background(),
		WithVerifiedSource(vs),
		WithSubjectDigests([]string{interleaveDigest}),
	)
	require.NoError(t, err)
	assert.False(t, accepted, "every bulk collection lacks the required attestation type")
	require.Equal(t, candidates, src.yields, "the streaming path must actually have been taken")
	// candidates gate rejections + verifyArtifacts' no-passed-collections
	// rejection (appended after the step loop on every all-rejected verify).
	require.Len(t, results[interleaveStep].Rejected, candidates+1)

	growth := int64(src.peakLiveHeap) - int64(base.HeapAlloc)
	growthMiB := float64(growth) / (1 << 20)
	perCandidateMiB := float64(bulkBytes) / (1 << 20)
	// Bound: a handful of candidates' worth of transient state. Materializing
	// all 16 retains ≥ 16 × ~6 MiB ≈ 96 MiB at the final boundaries; the
	// interleaved pipeline stays at ~1 candidate (~6-12 MiB) + compact
	// results. 40 MiB splits the two regimes with wide margin both ways.
	assert.Lessf(t, growthMiB, 4*perCandidateMiB+8,
		"live heap at yield boundaries grew %.1f MiB for %d × %.1f MiB candidates — decoded bodies are being retained across candidates (interleave reverted?)",
		growthMiB, candidates, perCandidateMiB)
	t.Logf("STAT interleave peak_live_heap_growth_mib=%.1f candidates=%d per_candidate_mib=%.1f", growthMiB, candidates, perCandidateMiB)
}

// batchOnlyVerifiedSourcer hides VerifiedSource's SearchStream so the policy
// engine takes the BATCH path (checkFunctionaries → filterHubOnlyPassed →
// validateAttestations) for the equivalence comparison.
type batchOnlyVerifiedSourcer struct{ inner *source.VerifiedSource }

func (b batchOnlyVerifiedSourcer) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]source.CollectionVerificationResult, error) {
	return b.inner.Search(ctx, collectionName, subjectDigests, attestations)
}

func (b batchOnlyVerifiedSourcer) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]source.StatementEnvelope, error) {
	return b.inner.SearchByPredicateType(ctx, predicateTypes, subjectDigests)
}

// stepResultDigest flattens a StepResult into comparable (reference, reason)
// tuples, preserving order.
func stepResultDigest(sr StepResult) (passed []string, rejected []string) {
	for _, pc := range sr.Passed {
		passed = append(passed, pc.Collection.Reference)
	}
	for _, rc := range sr.Rejected {
		reason := ""
		if rc.Reason != nil {
			reason = rc.Reason.Error()
		}
		rejected = append(rejected, rc.Collection.Reference+" | "+reason)
	}
	return passed, rejected
}

// VERDICT EQUIVALENCE with the fan-out guard ACTIVE: the streamed pipeline
// (fanoutTracker + end-of-stream classification, provisional gate verdicts
// discarded on hub demotion) must produce the same StepResult — same passed
// references, same rejection reasons, same entry order — as the batch
// pipeline (filterHubOnlyPassed before the gate) over a corpus that
// exercises every candidate class: closure evidence, hub-only flood
// candidates, a wrong-key signature, and a gate rejection.
func TestInterleave_StreamedAndBatchStepResultsAreEquivalent(t *testing.T) {
	f := newFanoutFixture(t)
	corpus := fanoutCorpus(t, f, 12)
	// One candidate signed by a DIFFERENT key: functionary rejection.
	other := newFanoutFixture(t)
	corpus = append(corpus, other.collection(t, "wrong-key", fanoutCommitDigest))

	mem := source.NewMemorySource()
	for _, e := range corpus {
		require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))

	opts := func(v VerifyOption) []VerifyOption {
		return []VerifyOption{
			v,
			WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}),
			WithMaxSubjectFanout(4),
		}
	}

	// Streamed (interleaved) path: *VerifiedSource implements SearchStream.
	streamAccepted, streamResults, err := f.policy(t).Verify(context.Background(), opts(WithVerifiedSource(vs))...)
	require.NoError(t, err)

	// Batch path: same source, SearchStream hidden.
	batchAccepted, batchResults, err := f.policy(t).Verify(context.Background(), opts(WithVerifiedSource(batchOnlyVerifiedSourcer{inner: vs}))...)
	require.NoError(t, err)

	assert.Equal(t, batchAccepted, streamAccepted)
	require.Equal(t, len(batchResults), len(streamResults))
	for name, batchSR := range batchResults {
		streamSR, ok := streamResults[name]
		require.Truef(t, ok, "step %s missing from streamed results", name)
		batchPassed, batchRejected := stepResultDigest(batchSR)
		streamPassed, streamRejected := stepResultDigest(streamSR)
		assert.Equalf(t, batchPassed, streamPassed, "step %s: passed sets diverge", name)
		assert.Equalf(t, batchRejected, streamRejected, "step %s: rejected sets diverge", name)
	}
}
