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
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubVerifiedSourcer is a minimal in-memory VerifiedSourcer that lets the
// diagnostic helper distinguish the two failure modes finding #2 calls out:
//
//   - Search(name, subjects=[<digest-not-in-envelope>], _) → []
//   - Search(name, subjects=nil,                       _) → [collection]
//
// When the diagnostic re-probes with subjects=nil and gets a non-empty
// result, it MUST surface ErrSubjectDigestMismatch, not ErrNoCollections.
type stubVerifiedSourcer struct {
	// allByStep is the population of collections per step regardless of
	// subject filter — i.e. what an "empty-subject-filter" probe returns.
	allByStep map[string][]source.CollectionVerificationResult
	// matchByStepDigest is the (step, supplied-digest) → match list, the
	// filtered-search behaviour. Anything not in this map returns empty.
	matchByStepDigest map[string]map[string][]source.CollectionVerificationResult
	// searchErr forces Search() to return this error on every call.
	searchErr error
}

func (s *stubVerifiedSourcer) Search(_ context.Context, stepName string, subjectDigests, _ []string) ([]source.CollectionVerificationResult, error) {
	if s.searchErr != nil {
		return nil, s.searchErr
	}
	if len(subjectDigests) == 0 {
		return s.allByStep[stepName], nil
	}
	stepMatches := s.matchByStepDigest[stepName]
	for _, d := range subjectDigests {
		if hit, ok := stepMatches[d]; ok {
			return hit, nil
		}
	}
	return nil, nil
}

func (s *stubVerifiedSourcer) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// TestDiagnose_NoCollectionsLoaded asserts that when the empty-subject-filter
// probe also returns zero, the diagnostic surfaces ErrNoCollections (i.e. no
// envelope was loaded for this step). This pins the "phantom did-I-load-my-
// attestation?" question only fires when it's genuinely true.
func TestDiagnose_NoCollectionsLoaded(t *testing.T) {
	src := &stubVerifiedSourcer{
		allByStep:         map[string][]source.CollectionVerificationResult{},
		matchByStepDigest: map[string]map[string][]source.CollectionVerificationResult{},
	}

	got := diagnoseEmptyCollectionResult(context.Background(), src, "build", []string{"deadbeef"}, nil)

	var nc ErrNoCollections
	require.True(t, errors.As(got, &nc), "with no envelope loaded the diagnostic must return ErrNoCollections, got %T: %v", got, got)
	assert.Equal(t, "build", nc.Step)
}

// TestVerify_DigestMismatch_NamesObservedSubjects is the headline regression
// test for blind Linux UX test Bug 2. When the collection IS loaded but the
// supplied artifact digest isn't a subject, the error names the observed
// subjects so the operator can see what they ARE asked to verify against.
func TestVerify_DigestMismatch_NamesObservedSubjects(t *testing.T) {
	loaded := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{
				Subject: []intoto.Subject{
					{Name: "binary:dist/argocd", Digest: map[string]string{"sha256": "ghi789"}},
					{Name: "commit", Digest: map[string]string{"sha1": "def456"}},
					{Name: "file:dist/argocd", Digest: map[string]string{"sha256": "ghi789"}},
				},
			},
		},
	}

	src := &stubVerifiedSourcer{
		allByStep: map[string][]source.CollectionVerificationResult{
			"build": {loaded},
		},
		matchByStepDigest: map[string]map[string][]source.CollectionVerificationResult{
			"build": {}, // supplied digest never matches → empty
		},
	}

	got := diagnoseEmptyCollectionResult(context.Background(), src, "build", []string{"abc123notinenvelope"}, nil)

	var mm ErrSubjectDigestMismatch
	require.True(t, errors.As(got, &mm), "envelope-present case must yield ErrSubjectDigestMismatch, got %T: %v", got, got)
	assert.Equal(t, "build", mm.Step)
	assert.Contains(t, mm.SuppliedDigests, "abc123notinenvelope")

	msg := got.Error()
	assert.Contains(t, msg, "not present in any subject", "error must explain the real problem")
	assert.Contains(t, msg, "binary:dist/argocd", "error must name the observed binary subject")
	assert.Contains(t, msg, "commit", "error must name the observed commit subject")
	assert.Contains(t, msg, "file:dist/argocd", "error must name the observed file subject")
	assert.NotContains(t, msg, "no collections found",
		"must not regress to the misleading no-collections phrasing")
}

// TestDiagnose_ProbeErrorFallsBackToNoCollections asserts that if the empty-
// subject probe itself fails (corrupt source, etc.), the diagnostic returns
// ErrNoCollections rather than surfacing a confusing probe-internal error.
// The contract: a diagnostic helper must NOT introduce a new error class
// that the original code path wouldn't have surfaced.
func TestDiagnose_ProbeErrorFallsBackToNoCollections(t *testing.T) {
	src := &stubVerifiedSourcer{searchErr: errors.New("source corrupted")}

	got := diagnoseEmptyCollectionResult(context.Background(), src, "build", []string{"x"}, nil)
	var nc ErrNoCollections
	assert.True(t, errors.As(got, &nc), "probe error path must collapse to ErrNoCollections")
}
