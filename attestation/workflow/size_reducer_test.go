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

package workflow

import (
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

// shrinkingAttestor is a bulkAttestor that can bound itself to shrinkTo bytes
// of body, and counts how often it was asked.
type shrinkingAttestor struct {
	bulkAttestor
	shrinkTo int
	calls    int
}

func (s *shrinkingAttestor) ReduceForSize() bool {
	s.calls++
	if len(s.body) <= s.shrinkTo {
		return false
	}
	s.body = s.body[:s.shrinkTo]
	return true
}

func newShrinking(body, shrinkTo int) *shrinkingAttestor {
	return &shrinkingAttestor{
		bulkAttestor: bulkAttestor{name: "shrink", typeURI: "https://example.test/attestations/shrink/v0.1", body: strings.Repeat("x", body)},
		shrinkTo:     shrinkTo,
	}
}

func TestSizeReducerIsNotAskedWhenTheStatementFits(t *testing.T) {
	a := newShrinking(4096, 16)
	_, err := Run("fits", RunWithSigners(sizeTestSigner(t)), RunWithAttestors([]attestation.Attestor{a}), RunWithMaxStatementBytes(64<<10))
	require.NoError(t, err)
	require.Zero(t, a.calls, "a statement that fits must never be reduced")
	require.Len(t, a.body, 4096)
}

func TestSizeReducerTurnsARefusalIntoABoundedSignature(t *testing.T) {
	a := newShrinking(64<<10, 1024)
	result, err := Run("reduce", RunWithSigners(sizeTestSigner(t)), RunWithAttestors([]attestation.Attestor{a}), RunWithMaxStatementBytes(16<<10))
	require.NoError(t, err, "a reducer that brings the statement under the limit must let it sign")
	require.Equal(t, 1, a.calls)
	require.LessOrEqual(t, len(result.SignedEnvelope.Payload), 16<<10)
	require.Contains(t, string(result.SignedEnvelope.Payload), strings.Repeat("x", 1024))
	require.NotContains(t, string(result.SignedEnvelope.Payload), strings.Repeat("x", 1025))
}

func TestSizeReducerThatCannotFitIsStillRefused(t *testing.T) {
	a := newShrinking(64<<10, 32<<10)
	result, err := Run("still-big", RunWithSigners(sizeTestSigner(t)), RunWithAttestors([]attestation.Attestor{a}), RunWithMaxStatementBytes(16<<10))
	var tooLarge *StatementTooLargeError
	require.True(t, errors.As(err, &tooLarge), "still over the limit after reducing must refuse exactly as before: %v", err)
	require.Equal(t, 1, a.calls, "one reduction per statement, no loop")
	require.Empty(t, result.SignedEnvelope.Signatures)
}

// An attestor exported as its own envelope is the predicate itself, not a
// collection entry; it gets the same one chance.
func TestSizeReducerOnAnExportedPredicate(t *testing.T) {
	a := newShrinking(64<<10, 1024)
	env, err := createAndSignEnvelope(a, a.Type(), nil, nil, 16<<10, dsse.SignWithSigners(sizeTestSigner(t)))
	require.NoError(t, err)
	require.Equal(t, 1, a.calls)
	require.LessOrEqual(t, len(env.Payload), 16<<10)
}
