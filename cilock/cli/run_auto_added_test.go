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

package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `cilock run -- node --test` with no -a list auto-attaches test-results
// because the node-test catalog entry emits it. node --test without a JUnit
// reporter writes no report, test-results fails with "no products to
// attest", and a run whose tests passed exited 1. An attestor the operator
// never asked for must not fail the run: its failure is a warning, and the
// verifier still refuses any policy that requires the missing evidence.
func TestSoftenAutoAddedLegs_AutoAddedFailureIsAWarning(t *testing.T) {
	agg := &workflow.AttestorRunErrors{Legs: []workflow.AttestorErrorLeg{
		{Attestor: "test-results", Err: fmt.Errorf("attestor test-results failed: %w", errors.New("no products to attest"))},
	}}

	got := classifyAttestorRunError(softenAutoAddedLegs(agg, []string{"test-results"}))
	assert.NoError(t, got, "an auto-attached attestor finding nothing must not fail the run")
	require.Len(t, agg.SoftLegs(), 1)
	assert.Contains(t, agg.SoftLegs()[0].Err.Error(), "no products to attest", "the warning keeps the attestor's reason")
	assert.Contains(t, agg.SoftLegs()[0].Err.Error(), "-a test-results", "the warning says how to require it")
}

// The operator's own list is a contract: -a test-results with no report
// stays fatal, and so does a default attestor. Only the auto-added names are
// softened, and only when auto-detection added them.
func TestSoftenAutoAddedLegs_OperatorAndDefaultAttestorsStayFatal(t *testing.T) {
	cases := []struct {
		name      string
		autoAdded []string
	}{
		{"operator named it with -a", nil},
		{"a different attestor was auto-added", []string{"sarif"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agg := &workflow.AttestorRunErrors{Legs: []workflow.AttestorErrorLeg{
				{Attestor: "test-results", Err: errors.New("attestor test-results failed: no products to attest")},
				{Attestor: "git", Err: errors.New("attestor git failed: repository does not exist")},
			}}
			got := classifyAttestorRunError(softenAutoAddedLegs(agg, c.autoAdded))
			require.Error(t, got)
			assert.Len(t, agg.FatalLegs(), 2)
		})
	}
}

// A run can fail for an auto-added attestor and a requested one at once;
// the requested one still decides the exit code.
func TestSoftenAutoAddedLegs_MixedLegsKeepTheFatalOne(t *testing.T) {
	agg := &workflow.AttestorRunErrors{Legs: []workflow.AttestorErrorLeg{
		{Attestor: "sarif", Err: errors.New("attestor sarif failed: no sarif file found")},
		{Attestor: "command-run", Err: errors.New("attestor command-run failed: exit status 1")},
		{Attestor: "sbom", Err: fmt.Errorf("attestor sbom failed: %w", attestation.NewSoftError("no SBOM file found"))},
	}}
	got := classifyAttestorRunError(softenAutoAddedLegs(agg, []string{"sarif", "sbom"}))
	require.Error(t, got)
	fatal := agg.FatalLegs()
	require.Len(t, fatal, 1)
	assert.Equal(t, "command-run", fatal[0].Attestor)
	assert.Len(t, agg.SoftLegs(), 2)
}

// Errors that are not an attestor aggregate (signer, storage) pass through.
func TestSoftenAutoAddedLegs_NonAggregatePassesThrough(t *testing.T) {
	raw := errors.New("failed to load signer")
	assert.Same(t, raw, softenAutoAddedLegs(raw, []string{"test-results"}))
	assert.NoError(t, softenAutoAddedLegs(nil, []string{"test-results"}))
}
