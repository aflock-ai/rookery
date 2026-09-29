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
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// Every deny of every attestor in a rejected collection, in order, including
// messages that themselves contain ", ": the reason errors.As (first match
// only) and splitting the rendered text on ", " both got wrong.
func TestDenyReasonsCollectsEveryDenial(t *testing.T) {
	reason := ErrCollectionValidationFailed{Reasons: []error{
		fmt.Errorf("rego policy evaluation failed for attestor type a: %w", ErrPolicyDenied{Reasons: []string{"check:x, want y", "check:z"}}),
		errors.New("unrelated"),
		fmt.Errorf("wrapped: %w", &ErrPolicyDenied{Reasons: []string{"check:w"}}),
	}}
	require.Equal(t, []string{"check:x, want y", "check:z", "check:w"}, DenyReasons(fmt.Errorf("step: %w", reason)))
	require.Empty(t, DenyReasons(errors.New("policy was denied due to: a, b")), "rendered text is not a denial")
	require.Empty(t, DenyReasons(nil))
}

// A verification that reached no verdict: unreadable evidence, a refusal, the
// assignment bound. A denial is none of them.
func TestNoVerdict(t *testing.T) {
	require.True(t, NoVerdict(fmt.Errorf("x: %w", fmt.Errorf("%w: searching step %q: %w", ErrEvidenceUnavailable, "s", errors.New("401")))))
	require.True(t, NoVerdict(fmt.Errorf("x: %w", ErrAIEvaluationRefused{Code: "provider"})))
	require.True(t, NoVerdict(errors.Join(errors.New("a"), ErrRegoEvaluationRefused{Code: "deadline"})))
	require.True(t, NoVerdict(fmt.Errorf("x: %w", ErrExternalAssignmentsExceedBound{Externals: []string{"e"}})))
	require.False(t, NoVerdict(ErrMissingExternalAttestation{Name: "e"}))
	require.False(t, NoVerdict(fmt.Errorf("x: %w", ErrPolicyDenied{Reasons: []string{"no"}})))
	require.False(t, NoVerdict(nil))
}

// failingStream is a streaming source whose store is down.
type failingStream struct{}

func (failingStream) Search(context.Context, string, []string, []string) ([]source.CollectionVerificationResult, error) {
	return nil, errors.New("archivista graphql returned 401: Authentication required")
}

func (failingStream) SearchByPredicateType(context.Context, []string, []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

func (failingStream) SearchStream(context.Context, string, []string, []string, func(source.CollectionVerificationResult) error) error {
	return errors.New("archivista graphql returned 401: Authentication required")
}

// The streamed step path reads the same store as the batch path; an outage
// there is unreadable evidence too, not a denial.
func TestStreamedSearchFailureIsEvidenceUnavailable(t *testing.T) {
	p := Policy{Expires: futureExpiry(), Steps: map[string]Step{
		"build": {Name: "build", Functionaries: []Functionary{{PublicKeyID: "k"}}, Attestations: []Attestation{{Type: "https://example.com/a/v1"}}},
	}}
	_, _, err := p.Verify(context.Background(), WithVerifiedSource(failingStream{}), WithSubjectDigests([]string{"sha256:abc"}))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEvidenceUnavailable, "a store outage on the streamed path read as a denial: %v", err)
	require.True(t, NoVerdict(err))
}
