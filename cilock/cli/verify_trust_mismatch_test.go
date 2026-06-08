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

package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrapLikeEngine reproduces the exact error-wrapping chain the verify pipeline
// builds around a dsse trust-mismatch diagnostic, so this test fails if any
// layer flattens the typed error (the historical bug this guards against):
//
//	dsse.ErrNoMatchingSigs{TrustMismatch}                 (dsse.Envelope.Verify)
//	-> "failed to verify envelope: %w"                    (source.VerifiedSource)
//	-> errors.Join(genericReason, joinedCollectionErrors) (policy.checkFunctionaries)
func wrapLikeEngine(tm *dsse.TrustNameKeyMismatchError) error {
	dsseErr := dsse.ErrNoMatchingSigs{TrustMismatch: tm}
	collErr := fmt.Errorf("failed to verify envelope: %w", dsseErr)
	generic := fmt.Errorf("no verifiers present to validate against collection verifiers")
	return errors.Join(generic, errors.Join(collErr))
}

func TestFindTrustMismatch_ReachesThroughEngineWrapping(t *testing.T) {
	want := &dsse.TrustNameKeyMismatchError{
		CommonName:    "TestifySec Platform Root CA",
		ArtifactKeyID: "29d022f5",
		PolicyKeyID:   "9fed6167",
	}
	stepResults := map[string]policy.StepResult{
		"source-git": {
			Step: "source-git",
			Rejected: []policy.RejectedCollection{
				{Reason: wrapLikeEngine(want)},
			},
		},
	}

	// The generic workflow error carries no diagnostic; the reason chain does.
	got := findTrustMismatch(fmt.Errorf("policy verification failed"), stepResults)
	require.NotNil(t, got, "trust mismatch must be reachable through the engine wrapping")
	assert.Equal(t, want.CommonName, got.CommonName)
	assert.Equal(t, want.ArtifactKeyID, got.ArtifactKeyID)
	assert.Equal(t, want.PolicyKeyID, got.PolicyKeyID)
	assert.Contains(t, got.Error(), "TRUST MISMATCH")
}

func TestFindTrustMismatch_FromTopLevelError(t *testing.T) {
	want := &dsse.TrustNameKeyMismatchError{CommonName: "TestifySec Platform TSA", ArtifactKeyID: "aaaa", PolicyKeyID: "bbbb", IsTimestamp: true}
	top := fmt.Errorf("failed to verify policy: %w", errors.Join(want, fmt.Errorf("policy verification failed")))
	got := findTrustMismatch(top, nil)
	require.NotNil(t, got)
	assert.True(t, got.IsTimestamp)
}

func TestFindTrustMismatch_NilWhenAbsent(t *testing.T) {
	stepResults := map[string]policy.StepResult{
		"source-git": {
			Step: "source-git",
			Rejected: []policy.RejectedCollection{
				{Reason: fmt.Errorf("no verifiers matched the allowed functionaries for step source-git")},
				{Reason: nil},
			},
		},
	}
	got := findTrustMismatch(fmt.Errorf("policy verification failed"), stepResults)
	assert.Nil(t, got, "an unrelated failure must not yield a trust mismatch")
}
