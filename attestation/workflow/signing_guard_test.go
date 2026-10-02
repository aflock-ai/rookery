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

package workflow

import (
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// guardedAttestor is an attestor whose measurement can go stale before
// signing (testifysec/judge#9359: the git attestor reads HEAD before the
// wrapped command, and the command can move it).
type guardedAttestor struct {
	dummySubjectAttestor
	stale error
}

func (a *guardedAttestor) CheckBeforeSigning() error { return a.stale }

// A stale measurement refuses the whole run: no collection envelope and no
// exported sidecar is signed, and the guard's reason reaches the caller.
func TestRun_SigningGuardRefusesStaleMeasurement(t *testing.T) {
	stale := errors.New("HEAD moved from aaaa to bbbb during the run")
	results, err := RunWithExports("guard-step",
		RunWithSigners(newTestSigner(t)),
		RunWithAttestors([]attestation.Attestor{&guardedAttestor{stale: stale}}),
	)
	require.ErrorIs(t, err, stale)
	for _, r := range results {
		require.Empty(t, r.SignedEnvelope.Signatures, "nothing may be signed once a measurement is stale")
	}
}

// The insecure path produces an unsigned collection that still names the
// stale commit, so the guard applies there too.
func TestRun_SigningGuardAppliesWhenInsecure(t *testing.T) {
	stale := errors.New("moved")
	results, err := RunWithExports("guard-step",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{&guardedAttestor{stale: stale}}),
	)
	require.ErrorIs(t, err, stale)
	require.Empty(t, results)
}

func TestRun_SigningGuardPassesFreshMeasurement(t *testing.T) {
	results, err := RunWithExports("guard-step",
		RunWithSigners(newTestSigner(t)),
		RunWithAttestors([]attestation.Attestor{&guardedAttestor{}}),
	)
	require.NoError(t, err)
	require.NotEmpty(t, results[len(results)-1].SignedEnvelope.Signatures)
}
