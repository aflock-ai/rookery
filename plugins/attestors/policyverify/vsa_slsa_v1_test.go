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

package policyverify

import (
	"crypto"
	"net/url"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/stretchr/testify/require"
)

// #9836: the policy-verification VSA carries the SLSA VSA v1 REQUIRED fields.
// verifier.id is a URI, resourceUri names the ARTIFACT verified, and
// verifiedLevels says no SLSA Build level was assessed (UNEVALUATED), or
// FAILED.
func TestVerificationSummaryIsSLSAVSAv1(t *testing.T) {
	actx, err := attestation.NewContext("vsa-test", nil)
	require.NoError(t, err)
	policyEnv := dsse.Envelope{Payload: []byte(`{"fake":"policy"}`), PayloadType: "application/vnd.in-toto+json"}
	artifact := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA1}:   "1111111111111111111111111111111111111111",
		cryptoutil.DigestValue{Hash: crypto.SHA256}: vsaTestDigest,
	}
	for accepted, level := range map[bool]string{true: slsa.BuildLevelUnevaluated, false: slsa.LevelFailed} {
		summary, err := verificationSummaryFromResults(actx, policyEnv, map[string]policy.StepResult{}, accepted, []cryptoutil.DigestSet{artifact})
		require.NoError(t, err)
		_, err = url.ParseRequestURI(summary.Verifier.ID)
		require.NoError(t, err, "verifier.id must be a URI")
		require.Equal(t, "sha256:"+vsaTestDigest, summary.ResourceURI, "resourceUri names the artifact by its sha256")
		require.Equal(t, []string{level}, summary.VerifiedLevels)
	}
}
