// Copyright 2025 The Witness Contributors
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
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detectorAttestor mimics the shape of a scanning attestor (secretscan and
// friends): it records what it observed in a serializable payload field, and
// — when the operator opted into a run-time guard — reports a verdict on that
// observation.
//
// The two error classes it can produce are the whole point of these tests:
//
//	detection  -> attestation.NewDetectionError: "I looked, and I found
//	              something you told me to reject." Observation SUCCEEDED, so
//	              the payload is trustworthy and MUST reach the collection.
//	blind      -> a plain error: "I could not look." Observation FAILED, so
//	              the payload is partial/meaningless and must NOT be recorded
//	              as if it were a clean result.
type detectorAttestor struct {
	name     string
	typeName string

	// Findings is the observation, carried as DATA in the signed payload.
	Findings []string `json:"findings"`

	// detect makes Attest report an operator-configured verdict.
	detect bool
	// blind makes Attest report a failure to observe.
	blind bool
}

func (a *detectorAttestor) Name() string                 { return a.name }
func (a *detectorAttestor) Type() string                 { return a.typeName }
func (a *detectorAttestor) RunType() attestation.RunType { return attestation.PostProductRunType }
func (a *detectorAttestor) Schema() *jsonschema.Schema   { return nil }

func (a *detectorAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{}
}

func (a *detectorAttestor) Attest(_ *attestation.AttestationContext) error {
	if a.blind {
		// Failure to observe: the scanner never ran to completion, so we have
		// nothing trustworthy to say.
		return errors.New("scanner crashed: could not observe")
	}
	if a.detect && len(a.Findings) > 0 {
		return attestation.NewDetectionError("found 1 secret")
	}
	return nil
}

// TestDetectionErrorKeepsEvidenceInCollection is the regression test for the
// secretscan error-contract defect.
//
// An attestor that FINDS something and reports it via DetectionError observed
// successfully. Its payload is the evidence of the finding, and it is the only
// record that the finding ever happened. Before the fix, workflow.run()
// filtered the collection on `completed.Error != nil`, so "I found secrets"
// deleted its own evidence: a findings-positive scan and a scan that never ran
// were indistinguishable downstream. The run failed OPEN, in the direction of
// silence.
func TestDetectionErrorKeepsEvidenceInCollection(t *testing.T) {
	att := &detectorAttestor{
		name:     "scanner",
		typeName: "https://aflock.ai/attestations/scanner/v0.1",
		Findings: []string{"aws-key at product:/bin/app"},
		detect:   true,
	}

	result, runErr := Run(
		"build",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)

	// The guard still fails the build: an operator who asked to fail closed
	// must still get a non-zero exit. Preserving evidence must not silently
	// downgrade the gate.
	require.Error(t, runErr, "a detection must still surface as a run error so --fail-on-detection keeps gating")

	var runErrs *AttestorRunErrors
	require.True(t, errors.As(runErr, &runErrs), "run error should be a typed AttestorRunErrors")
	assert.NotEmpty(t, runErrs.FatalLegs(), "a detection is fatal, not soft — the CLI must exit non-zero")
	assert.Empty(t, runErrs.SoftLegs(), "a detection is not a 'nothing to do' outcome")

	// ...and the evidence survives.
	var found *attestation.CollectionAttestation
	for i := range result.Collection.Attestations {
		if result.Collection.Attestations[i].Type == att.typeName {
			found = &result.Collection.Attestations[i]
			break
		}
	}
	require.NotNil(t, found,
		"attestor that FOUND something must still appear in the collection — "+
			"dropping it makes a findings-positive scan indistinguishable from a scan that never ran")

	// Presence is not enough: the findings themselves must be recorded as data
	// in the signed payload, so a verify-time policy can gate on them.
	encoded, err := json.Marshal(result.Collection)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), "aws-key at product:/bin/app",
		"the finding must be carried as data in the attestation payload")
}

// TestFailureToObserveIsExcludedFromCollection is the other half of the
// contract. A plain error means the attestor COULD NOT LOOK, so whatever is in
// its payload is partial at best. Recording it would assert a clean result
// that was never actually established, which is the exact fail-open the
// DetectionError path exists to prevent. It must stay out.
func TestFailureToObserveIsExcludedFromCollection(t *testing.T) {
	att := &detectorAttestor{
		name:     "scanner",
		typeName: "https://aflock.ai/attestations/scanner/v0.1",
		blind:    true,
	}

	result, runErr := Run(
		"build",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.Error(t, runErr, "failure to observe must surface as a run error")

	for _, ca := range result.Collection.Attestations {
		assert.NotEqual(t, att.typeName, ca.Type,
			"an attestor that could not observe must NOT be recorded as evidence")
	}
}

// TestCleanScanIsRecordedInCollection pins the baseline: no findings, no
// errors, and the attestor is recorded normally.
func TestCleanScanIsRecordedInCollection(t *testing.T) {
	att := &detectorAttestor{
		name:     "scanner",
		typeName: "https://aflock.ai/attestations/scanner/v0.1",
		detect:   true,
	}

	result, runErr := Run(
		"build",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, runErr, "a clean scan is not an error")

	types := make([]string, 0, len(result.Collection.Attestations))
	for _, ca := range result.Collection.Attestations {
		types = append(types, ca.Type)
	}
	assert.Contains(t, types, att.typeName,
		"a clean scan must be recorded (got: %s)", strings.Join(types, ","))
}
