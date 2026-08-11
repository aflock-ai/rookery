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

	"github.com/aflock-ai/rookery/attestation/source"
)

// lazyBenchCorpus is the size of the prod incident that opened #7572 and is
// quoted in the minimum-witness design doc §2: "[verified-source] verified 806
// candidate envelope(s) (streamed, interleaved)", four times in one 30-minute
// window.
const lazyBenchCorpus = 806

// benchmarkLazySatisfiedStep runs ONE verify of a single satisfied step over
// the 806-candidate corpus, with the option on or off, and reports
// candidates/verify alongside the standard ns/op and B/op.
//
// candidates/verify is the number the design cares about: on a prod source
// each one is an Archivista download plus a DSSE verification plus the
// archivista_subjects / archivista_dsses EXISTS queries that measure at 43% of
// prod DB load.
func benchmarkLazySatisfiedStep(b *testing.B, lazy bool) {
	verifier, keyID := earlyExitVerifierB(b)

	corpus := make([]source.CollectionVerificationResult, 0, lazyBenchCorpus)
	for i := 0; i < lazyBenchCorpus; i++ {
		corpus = append(corpus, lazyPlain(verifier, fmt.Sprintf("build-hist-%04d", i), "build", ""))
	}
	pol := lazyPolicy(keyID, lazyStep("build", keyID))

	totalCandidates := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": corpus})
		opts := []VerifyOption{
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:seed"}),
			WithSearchDepth(3),
		}
		if lazy {
			opts = append(opts, WithLazyStepSatisfaction(true))
		}
		pass, _, err := pol.Verify(context.Background(), opts...)
		if err != nil || !pass {
			b.Fatalf("expected a clean PASS verdict, got pass=%v err=%v", pass, err)
		}
		totalCandidates += src.yielded
	}
	b.StopTimer()
	b.ReportMetric(float64(totalCandidates)/float64(b.N), "candidates/verify")
}

// BenchmarkLazyWitness_SatisfiedStep_Eager is the baseline: every candidate in
// the corpus is fetched, verified and gated even though the first one already
// satisfies the step.
func BenchmarkLazyWitness_SatisfiedStep_Eager(b *testing.B) {
	benchmarkLazySatisfiedStep(b, false)
}

// BenchmarkLazyWitness_SatisfiedStep_Lazy is the same verify with the
// minimum-witness option on: the stream aborts at the first gate pass.
func BenchmarkLazyWitness_SatisfiedStep_Lazy(b *testing.B) {
	benchmarkLazySatisfiedStep(b, true)
}

// BenchmarkLazyWitness_ValveRescan is the pessimistic case, and it is here so
// the win above is never quoted without it: an artifactsFrom edge that the
// first witness does not satisfy forces the demand valve to re-run the
// upstream step exhaustively, so the truncated pass is paid for twice.
func BenchmarkLazyWitness_ValveRescan(b *testing.B) {
	verifier, keyID := earlyExitVerifierB(b)

	totalCandidates := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pol, src := lazyArtifactsFromDepth1(b, verifier, keyID)
		pass, _, err := pol.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:seed"}),
			WithSearchDepth(3),
			WithLazyStepSatisfaction(true),
		)
		if err != nil || !pass {
			b.Fatalf("expected a clean PASS verdict, got pass=%v err=%v", pass, err)
		}
		totalCandidates += src.yielded
	}
	b.StopTimer()
	b.ReportMetric(float64(totalCandidates)/float64(b.N), "candidates/verify")
}
