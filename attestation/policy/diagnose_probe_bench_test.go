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
	"context"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
)

// ---------------------------------------------------------------------------
// Cost of the empty-collection diagnostic re-probe, at the prod corpus size.
//
// Prod measurement that motivated the bound: "[verified-source] verified 806
// candidate envelope(s)" four times in one 30-minute window, 1,088
// verifications over 643 distinct gitoids.
//
// The legacy (unbounded) implementation is benchmarked alongside the bounded
// one IN THE SAME BINARY against the SAME fixture, so the before/after numbers
// differ only by the code under test — no cross-run, cross-tree comparison.
//
// The per-candidate cost of a remote source (one round trip plus a decoded
// body) is modelled as ONE allocation of probeBenchBodyBytes per DELIVERED
// candidate, materialized at delivery time so an abort genuinely skips the
// remainder — ArchivistaSource.SearchStream behaves exactly this way (its
// `aborted` flag short-circuits the outstanding downloads). Read B/op and
// candidates/op as "corpus fetched", not as absolute prod bytes.
// ---------------------------------------------------------------------------

const (
	probeBenchCorpus    = 806
	probeBenchBodyBytes = 16 << 10
)

// dsseEnvelopeOfSize stands in for the decoded body a real candidate carries
// once it has been downloaded — the allocation the probe pays per candidate it
// pulls.
func dsseEnvelopeOfSize(n int) dsse.Envelope {
	return dsse.Envelope{Payload: make([]byte, n), PayloadType: intoto.PayloadType}
}

// benchProbeSource hands back candidates whose bodies are materialized at
// delivery time. Subject metadata is prepared once, at construction, so the
// benchmark loop times the probe rather than the fixture.
type benchProbeSource struct {
	subjects [][]intoto.Subject
	// delivered counts candidates whose body was materialized.
	delivered int
}

func newBenchProbeSource(n int) *benchProbeSource {
	s := &benchProbeSource{subjects: make([][]intoto.Subject, n)}
	for i := range s.subjects {
		s.subjects[i] = []intoto.Subject{
			{Name: fmt.Sprintf("file:dist/app-%d", i), Digest: map[string]string{"sha256": fmt.Sprintf("%064x", i)}},
			{Name: "commit", Digest: map[string]string{"sha1": fmt.Sprintf("%040x", i)}},
		}
	}
	return s
}

func (s *benchProbeSource) materialize(i int) source.CollectionVerificationResult {
	s.delivered++
	return source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Reference: fmt.Sprintf("gitoid-%d", i),
			Envelope:  dsseEnvelopeOfSize(probeBenchBodyBytes),
			Statement: intoto.Statement{
				PredicateType: attestation.CollectionType,
				Subject:       s.subjects[i],
			},
		},
	}
}

func (s *benchProbeSource) Search(_ context.Context, _ string, subjectDigests, _ []string) ([]source.CollectionVerificationResult, error) {
	if len(subjectDigests) > 0 {
		return nil, nil
	}
	out := make([]source.CollectionVerificationResult, 0, len(s.subjects))
	for i := range s.subjects {
		out = append(out, s.materialize(i))
	}
	return out, nil
}

func (s *benchProbeSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// benchProbeStreamSource is the same corpus behind the streaming surface —
// the arm production takes, since *source.VerifiedSource always implements
// StreamingVerifiedSourcer.
type benchProbeStreamSource struct{ *benchProbeSource }

func (s benchProbeStreamSource) SearchStream(_ context.Context, _ string, subjectDigests, _ []string, yield func(source.CollectionVerificationResult) error) error {
	if len(subjectDigests) > 0 {
		return nil
	}
	for i := range s.subjects {
		if err := yield(s.materialize(i)); err != nil {
			return err
		}
	}
	return nil
}

type diagnoseFn func(context.Context, source.VerifiedSourcer, string, []string, []string) error

func benchDiagnose(b *testing.B, src *benchProbeSource, probed source.VerifiedSourcer, fn diagnoseFn) {
	b.Helper()
	ctx := context.Background()
	total := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.delivered = 0
		if err := fn(ctx, probed, "build", []string{"deadbeef"}, nil); err == nil {
			b.Fatal("diagnostic must return an error")
		}
		total += src.delivered
	}
	b.StopTimer()
	b.ReportMetric(float64(total)/float64(b.N), "candidates/op")
}

func BenchmarkDiagnoseProbe_Legacy_Streamed(b *testing.B) {
	src := newBenchProbeSource(probeBenchCorpus)
	benchDiagnose(b, src, benchProbeStreamSource{src}, legacyDiagnoseEmptyCollectionResult)
}

func BenchmarkDiagnoseProbe_Bounded_Streamed(b *testing.B) {
	src := newBenchProbeSource(probeBenchCorpus)
	benchDiagnose(b, src, benchProbeStreamSource{src}, diagnoseEmptyCollectionResult)
}

func BenchmarkDiagnoseProbe_Legacy_Batch(b *testing.B) {
	src := newBenchProbeSource(probeBenchCorpus)
	benchDiagnose(b, src, src, legacyDiagnoseEmptyCollectionResult)
}

func BenchmarkDiagnoseProbe_Bounded_Batch(b *testing.B) {
	src := newBenchProbeSource(probeBenchCorpus)
	benchDiagnose(b, src, src, diagnoseEmptyCollectionResult)
}
