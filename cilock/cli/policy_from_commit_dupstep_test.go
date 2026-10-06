// jade:ring local

// Copyright 2026 The Aflock Authors
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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Re-attesting a step (a CI retry, or running twice) leaves two collections for
// one commit under one step name. from-commit has no --step-prefix, so the
// from-bundles remediation is unreachable: it must derive one step, keep a
// single signer identity, and say which collections it dropped.
func TestFromCommit_TwoCollectionsForOneStepDeriveOneStep(t *testing.T) {
	types := []string{"https://aflock.ai/attestations/command-run/v0.1"}
	first, _ := keylessCollectionEnvelope(t, "build", "first@example.com", types)
	second, _ := keylessCollectionEnvelope(t, "build", "second@example.com", types)
	installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{
		"gitoid-a": first,
		"gitoid-b": second,
	}})

	var errOut bytes.Buffer
	pol, count, err := derivePolicyFromCommit(context.Background(), &errOut,
		policyFromCommitOpts{expiresIn: 365 * 24 * time.Hour},
		testCommitSHA, "https://archivista.example", "bearer-token")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	require.Contains(t, pol.Steps, "build")
	// One identity only: a union would admit every signer who ever attested the step.
	require.Len(t, pol.Steps["build"].Functionaries, 1)
	assert.Contains(t, errOut.String(), `step "build"`)
	assert.Contains(t, errOut.String(), "gitoid-")
}

// The choice must not depend on Archivista's (map-order) result order.
func TestFromCommit_DuplicateStepChoiceIsDeterministic(t *testing.T) {
	types := []string{"https://aflock.ai/attestations/command-run/v0.1"}
	first, _ := keylessCollectionEnvelope(t, "build", "first@example.com", types)
	second, _ := keylessCollectionEnvelope(t, "build", "second@example.com", types)
	var chosen []string
	for i := 0; i < 8; i++ {
		installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{
			"gitoid-a": first,
			"gitoid-b": second,
		}})
		pol, _, err := derivePolicyFromCommit(context.Background(), &bytes.Buffer{},
			policyFromCommitOpts{expiresIn: time.Hour}, testCommitSHA, "https://archivista.example", "t")
		require.NoError(t, err)
		chosen = append(chosen, pol.Steps["build"].Functionaries[0].CertConstraint.Emails...)
	}
	for _, e := range chosen {
		assert.Equal(t, chosen[0], e)
	}
}
