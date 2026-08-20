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

// This file pins secretscan's ERROR CONTRACT.
//
// An attestor observes and records; it does not gate. So a plain error from
// Attest() means exactly one thing: "I COULD NOT OBSERVE." A finding is a
// RESULT and belongs in the attestation payload — never in the error return,
// because the workflow drops errored attestors from the signed collection and
// a finding reported as a plain error therefore deletes its own evidence.
//
// The opt-in --attestor-secretscan-fail-on-detection guard still has to fail
// the build, so a detected finding is reported as an attestation.DetectionError:
// fatal (non-zero exit preserved) but explicitly classified as a successful
// observation, so the workflow keeps the findings in the collection.
package secretscan

import (
	"crypto"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedFinding returns an attestor pre-loaded with one finding, standing in for
// a scan that actually hit a secret.
func seedFinding(t *testing.T, opts ...Option) *Attestor {
	t.Helper()
	a := New(opts...)
	digest := make(cryptoutil.DigestSet)
	digest[cryptoutil.DigestValue{Hash: crypto.SHA256}] = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	a.Findings = []Finding{{
		RuleID:      "aws-access-key",
		Description: "AWS Access Key",
		Location:    "product:/bin/app",
		Line:        1,
		Secret:      digest,
	}}
	return a
}

// TestDetectedSecretIsNotAFailureToObserve is the core contract test. Finding a
// secret means the scan WORKED. Classifying it as an ordinary error tells every
// downstream consumer the opposite — that secretscan could not be trusted to
// have looked — and costs the collection the only record of the finding.
func TestDetectedSecretIsNotAFailureToObserve(t *testing.T) {
	a := seedFinding(t, WithFailOnDetection(true))

	err := a.Attest(&attestation.AttestationContext{})

	require.Error(t, err, "fail-on-detection must still fail the build")
	assert.True(t, attestation.IsDetectionError(err),
		"a detected secret is a VERDICT on a successful observation, not a failure to observe; "+
			"classifying it as a plain error drops the findings from the collection")
	assert.False(t, attestation.IsSoftError(err),
		"a detection is fatal — the operator asked to fail closed, so the CLI must exit non-zero")

	// The legacy message is preserved so existing string-matching consumers
	// (and the CLI's operator-facing output) don't regress.
	assert.Contains(t, err.Error(), "secret scanning failed")
}

// TestDetectedSecretKeepsFindingsInPayload proves the findings survive as DATA
// on the attestor after Attest reports the detection — that payload is exactly
// what the collection serializes and what a verify-time rego policy reads.
func TestDetectedSecretKeepsFindingsInPayload(t *testing.T) {
	a := seedFinding(t, WithFailOnDetection(true))

	err := a.Attest(&attestation.AttestationContext{})
	require.Error(t, err)

	require.Len(t, a.Findings, 1, "Attest must not discard the findings it reported on")

	encoded, marshalErr := json.Marshal(a)
	require.NoError(t, marshalErr)
	assert.Contains(t, string(encoded), "aws-access-key",
		"the finding must be carried as data in the attestation payload")
}

// TestScanErrorIsAFailureToObserve is the other half. A crashed or unreadable
// scan is a genuine "I could not look" — it must stay a plain error, because
// the payload cannot be trusted and must NOT be recorded as a clean result.
func TestScanErrorIsAFailureToObserve(t *testing.T) {
	a := New(WithFailOnDetection(true))
	a.scanErrors = append(a.scanErrors, errors.New("simulated gitleaks crash on product X"))

	err := a.Attest(&attestation.AttestationContext{})

	require.Error(t, err)
	assert.False(t, attestation.IsDetectionError(err),
		"a scan that could not run is a failure to OBSERVE, not a detection — "+
			"its payload is partial and must not be recorded as evidence")
	assert.Contains(t, err.Error(), "scan error")
	assert.Contains(t, err.Error(), "gitleaks crash")
}

// TestScanErrorTakesPrecedenceOverFindings keeps the fail-closed ordering: if
// any scan errored, the findings list is incomplete by definition, so the
// stricter "could not observe" classification wins.
func TestScanErrorTakesPrecedenceOverFindings(t *testing.T) {
	a := seedFinding(t, WithFailOnDetection(true))
	a.scanErrors = append(a.scanErrors, errors.New("simulated gitleaks crash on product X"))

	err := a.Attest(&attestation.AttestationContext{})

	require.Error(t, err)
	assert.False(t, attestation.IsDetectionError(err),
		"an incomplete scan cannot be reported as a trustworthy verdict")
}

// TestFindingsAloneDoNotError pins the DEFAULT contract: without the opt-in
// guard, observing a secret is not an error at all. The finding is recorded and
// policy decides at verify time. This is the behaviour the fail-on-detection
// path must not be allowed to silently diverge from.
func TestFindingsAloneDoNotError(t *testing.T) {
	a := seedFinding(t) // defaultFailOnDetection == false

	err := a.Attest(&attestation.AttestationContext{})

	assert.NoError(t, err,
		"attestors observe and record; gating is policy's job, so a finding alone is never an error")
	assert.Len(t, a.Findings, 1, "the finding is still recorded as evidence")
}
