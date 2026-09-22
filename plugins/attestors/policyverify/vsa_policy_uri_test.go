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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// The policy predicate types, spelled literally so a test cannot pass by
// comparing a constant with itself.
const (
	uriPolicyV01       = "https://aflock.ai/policy/v0.1"
	uriPolicyV02       = "https://aflock.ai/policy/v0.2"
	uriPolicyLegacyV01 = "https://witness.testifysec.com/policy/v0.1"
)

// uriAttest runs the real attestor over a signed corpus whose policy envelope
// has the given payload type. aboutOn names the steps whose JSON gets
// "about": "source" written into the signed policy bytes, the way an author's
// file carries it. The corpus is the commit-binding one: C's secrets scan has
// findings, its parent's is clean.
func uriAttest(t *testing.T, payloadType string, binding string, aboutOn ...string) *Attestor {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := cryptoutil.NewECDSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pem, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)

	fn := []policy.Functionary{{Type: "publickey", PublicKeyID: keyID}}
	pol := policy.Policy{
		PublicKeys: map[string]policy.PublicKey{keyID: {KeyID: keyID, Key: pem}},
		Steps: map[string]policy.Step{
			"build": {Name: "build", Functionaries: fn, Attestations: []policy.Attestation{{Type: pvBuildType}}},
			"secrets": {Name: "secrets", Functionaries: fn, Attestations: []policy.Attestation{{
				Type: pvScanType,
				RegoPolicies: []policy.RegoPolicy{{Name: "no-findings", Module: []byte(`package pvsecrets

deny[msg] {
	count(input.findings) > 0
	msg := "secretscan findings"
}
`)}},
			}}},
		},
	}
	pol.Expires.Time = time.Now().Add(time.Hour)
	polBytes, err := json.Marshal(pol)
	require.NoError(t, err)
	if len(aboutOn) > 0 {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(polBytes, &doc))
		steps := doc["steps"].(map[string]any)
		for _, name := range aboutOn {
			steps[name].(map[string]any)["about"] = "source"
		}
		polBytes, err = json.Marshal(doc)
		require.NoError(t, err)
		require.Contains(t, string(polBytes), `"about":"source"`, "fixture must carry the declaration in the signed bytes")
	}
	polEnv, err := dsse.Sign(payloadType, bytes.NewReader(polBytes), dsse.SignWithSigners(signer))
	require.NoError(t, err)

	mem := source.NewMemorySource()
	require.NoError(t, mem.LoadEnvelope("C-build", pvSigned(t, signer, "build", pvC, pvP, 0)))
	require.NoError(t, mem.LoadEnvelope("C-secrets-dirty", pvSigned(t, signer, "secrets", pvC, pvP, 2)))
	require.NoError(t, mem.LoadEnvelope("P-build", pvSigned(t, signer, "build", pvP, pvG, 0)))
	require.NoError(t, mem.LoadEnvelope("P-secrets-clean", pvSigned(t, signer, "secrets", pvP, pvG, 0)))

	a := New()
	a.SetPolicyEnvelope(polEnv)
	a.SetPolicyVerificationOptions(policysig.NewVerifyPolicySignatureOptions(
		policysig.VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier})))
	a.SetSubjectDigests([]cryptoutil.DigestSet{{cryptoutil.DigestValue{Hash: crypto.SHA1}: pvC}})
	a.SetCollectionSource(mem)
	a.SetCommitBinding(binding)

	actx, err := attestation.NewContext("vsa-policy-uri", nil)
	require.NoError(t, err)
	require.NoError(t, a.Attest(actx))
	return a
}

// PV6: the VSA names the policy's own type, read from the signed envelope. A
// v0.2 policy verified by this attestor must not be reported as v0.1: a
// consumer of the VSA reads Policy.URI to learn which predicate, and so which
// step semantics, the verdict was reached under.
func TestVSAPolicyURIIsTheEnvelopePayloadType(t *testing.T) {
	a := uriAttest(t, uriPolicyV02, "", "secrets")
	require.Equal(t, uriPolicyV02, a.Policy.URI,
		"the VSA's Policy.URI must be the policy envelope's PayloadType")
	require.Contains(t, a.Subjects(), "policy:"+uriPolicyV02,
		"the VSA's policy subject follows the URI")
	require.NotContains(t, a.Subjects(), "policy:"+uriPolicyV01)
}

// v0.1 policies are unchanged, byte for byte: an aflock v0.1 envelope and a
// legacy witness v0.1 envelope both name aflock v0.1, exactly as every VSA
// written before this change did. The legacy type is an alias of the aflock
// one (policy.LegacyPolicyPredicate), not a different predicate.
func TestVSAPolicyURIForV01PoliciesIsUnchanged(t *testing.T) {
	for _, pt := range []string{uriPolicyV01, uriPolicyLegacyV01} {
		t.Run(pt, func(t *testing.T) {
			a := uriAttest(t, pt, "")
			require.Equal(t, uriPolicyV01, a.Policy.URI)
			require.Contains(t, a.Subjects(), "policy:"+uriPolicyV01)
		})
	}
}

// What this verify path does with a v0.2 policy today, stated as a test so a
// change to it is a visible decision. A v0.2 policy decodes through
// policy.DecodePolicyEnvelope (strictly, with the v0.2 stamp) and is verified
// with the same walk as v0.1; "about" grants reach, and until the declared
// source link lands it grants nothing beyond the depth-0 witnesses, so it
// changes no verdict and no step result. The only difference is the type the
// VSA names (PV6). The refusals (about on v0.1, an unknown about value, an
// unknown policy type) are pinned by TestR27f_PolicyVersionRefusalsThroughTheAttestor.
func TestV02PolicyAboutDoesNotChangeTheVerdictYet(t *testing.T) {
	for _, binding := range []string{"", pvC} {
		t.Run("binding="+binding, func(t *testing.T) {
			withAbout := uriAttest(t, uriPolicyV02, binding, "secrets")
			without := uriAttest(t, uriPolicyV01, binding)
			require.Equal(t, without.VerificationResult, withAbout.VerificationResult,
				"a declared about must not change the verdict before the engine reads it")
			require.Equal(t, stepVerdicts(without), stepVerdicts(withAbout))
			require.Equal(t, uriPolicyV02, withAbout.Policy.URI)
			require.Equal(t, uriPolicyV01, without.Policy.URI)
		})
	}
}

func stepVerdicts(a *Attestor) map[string][2]int {
	out := map[string][2]int{}
	for name, r := range a.StepResults() {
		out[name] = [2]int{len(r.Passed), len(r.Rejected)}
	}
	return out
}

// The mapping on its own: every type is named as signed, except the legacy
// alias and an envelope with no type, which name aflock v0.1.
func TestVSAPolicyURIMapping(t *testing.T) {
	for in, want := range map[string]string{
		uriPolicyV02:                    uriPolicyV02,
		uriPolicyV01:                    uriPolicyV01,
		uriPolicyLegacyV01:              uriPolicyV01,
		"":                              uriPolicyV01,
		"https://aflock.ai/policy/v0.3": "https://aflock.ai/policy/v0.3",
	} {
		require.Equal(t, want, vsaPolicyURI(in), "payload type %q", in)
	}
}
