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
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// End to end through the attestor every cilock verify runs: a policy with NO
// steps whose one required external is a Pushgate VSA, admitted through its
// declared commitSubject, seeded and bound by the commit as `cilock verify
// --subjects sha1:<commit>` and `--commit <commit>` would.

const (
	vsaBindingE2EPredicate = "https://pushgate.dev/verification_summary/v0.5"
	vsaBindingE2EPrefix    = "https://pushgate.dev/v0.1/commithash:"
)

func vsaBindingE2EPolicy(t *testing.T, k abKey, commitSubject string) []byte {
	t.Helper()
	pol := policy.Policy{
		PublicKeys: map[string]policy.PublicKey{k.keyID: {KeyID: k.keyID, Key: k.pem}},
		ExternalAttestations: map[string]policy.ExternalAttestation{
			"pushgate-vsa": {
				Name:          "pushgate-vsa",
				PredicateType: vsaBindingE2EPredicate,
				Functionaries: []policy.Functionary{{Type: "publickey", PublicKeyID: k.keyID}},
				Required:      true,
				CommitSubject: commitSubject,
				RegoPolicies: []policy.RegoPolicy{{Name: "passed", Module: []byte(`package vsabindinge2e

deny[msg] {
	input.verificationResult != "PASSED"
	msg := "verdict is not PASSED"
}
`)}},
			},
		},
	}
	pol.Expires.Time = time.Now().Add(time.Hour)
	raw, err := json.Marshal(pol)
	require.NoError(t, err)
	return raw
}

func vsaBindingE2EVSA(t *testing.T, k abKey, commit, verdict string) dsse.Envelope {
	t.Helper()
	payload, err := json.Marshal(intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: vsaBindingE2EPredicate,
		Subject:       []intoto.Subject{{Name: vsaBindingE2EPrefix + commit, Digest: map[string]string{"sha1": commit}}},
		Predicate:     json.RawMessage(fmt.Sprintf(`{"verificationResult":%q}`, verdict)),
	})
	require.NoError(t, err)
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(k.signer))
	require.NoError(t, err)
	return env
}

func vsaBindingE2EAttest(t *testing.T, k abKey, policyJSON []byte, vsa dsse.Envelope, commit, binding string) (*Attestor, error) {
	t.Helper()
	polEnv, err := dsse.Sign(uriPolicyV01, bytes.NewReader(policyJSON), dsse.SignWithSigners(k.signer))
	require.NoError(t, err)
	mem := source.NewMemorySource()
	require.NoError(t, mem.LoadEnvelope("vsa", vsa))
	a := New()
	a.SetPolicyEnvelope(polEnv)
	a.SetPolicyVerificationOptions(policysig.NewVerifyPolicySignatureOptions(
		policysig.VerifyWithPolicyVerifiers([]cryptoutil.Verifier{k.verifier})))
	a.SetSubjectDigests([]cryptoutil.DigestSet{sha1Seed(commit)})
	a.SetCollectionSource(mem)
	a.SetCommitBinding(binding)
	actx, err := attestation.NewContext("vsa-commit-subject", nil)
	require.NoError(t, err)
	return a, a.Attest(actx)
}

func TestVsaBindingE2EZeroStepVSAPolicy(t *testing.T) {
	k := newABKey(t)
	for _, binding := range []string{"", pvC} {
		t.Run("binding="+binding, func(t *testing.T) {
			a, err := vsaBindingE2EAttest(t, k, vsaBindingE2EPolicy(t, k, vsaBindingE2EPrefix), vsaBindingE2EVSA(t, k, pvC, "PASSED"), pvC, binding)
			require.NoError(t, err)
			require.Equal(t, slsa.PassedVerificationResult, a.VerificationResult)
		})
	}

	t.Run("a FAILED verdict fails", func(t *testing.T) {
		a, _ := vsaBindingE2EAttest(t, k, vsaBindingE2EPolicy(t, k, vsaBindingE2EPrefix), vsaBindingE2EVSA(t, k, pvC, "FAILED"), pvC, pvC)
		require.NotEqual(t, slsa.PassedVerificationResult, a.VerificationResult)
	})
	t.Run("another commit's VSA does not pass", func(t *testing.T) {
		a, _ := vsaBindingE2EAttest(t, k, vsaBindingE2EPolicy(t, k, vsaBindingE2EPrefix), vsaBindingE2EVSA(t, k, pvP, "PASSED"), pvC, pvC)
		require.NotEqual(t, slsa.PassedVerificationResult, a.VerificationResult)
	})
	t.Run("without commitSubject the VSA does not pass", func(t *testing.T) {
		a, _ := vsaBindingE2EAttest(t, k, vsaBindingE2EPolicy(t, k, ""), vsaBindingE2EVSA(t, k, pvC, "PASSED"), pvC, "")
		require.NotEqual(t, slsa.PassedVerificationResult, a.VerificationResult)
	})
}
