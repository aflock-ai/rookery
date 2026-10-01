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
	"context"
	"encoding/json"
	"errors"
	"testing"

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

// #8121: a required external that is missing, or whose every candidate the
// policy rejected, is a policy verdict. The engine returns it as an error
// (ErrMissingExternalAttestation, ErrExternalAttestationRejected), and the
// attestor used to pass that error straight up. The workflow drops an attestor
// whose error is not recordable, so the verdict left no FAILED VSA: a denial
// erased its own evidence. Missing required STEP evidence has always produced
// a FAILED VSA; a missing required external must too.

const evChildType = "https://example.com/child-vsa/v1"

// evChild signs a bare statement of evChildType about abImage.
func evChild(t *testing.T, signer cryptoutil.Signer) dsse.Envelope {
	t.Helper()
	payload, err := json.Marshal(intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: abImageSubject + abImage, Digest: map[string]string{"sha256": abImage}}},
		PredicateType: evChildType,
		Predicate:     json.RawMessage(`{"verificationResult":"PASSED"}`),
	})
	require.NoError(t, err)
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	return env
}

// evRequireChild adds a required external of evChildType signed by k.
func evRequireChild(k abKey) func(doc map[string]any) {
	return func(doc map[string]any) {
		doc["externalAttestations"] = map[string]any{
			"child": map[string]any{
				"name":          "child",
				"predicateType": evChildType,
				"functionaries": []any{map[string]any{"type": "publickey", "publickeyid": k.keyID}},
				"required":      true,
			},
		}
	}
}

func requireFailedVerdictRecorded(t *testing.T, r abRun) {
	t.Helper()
	require.Error(t, r.err, "a denial still fails the run")
	require.True(t, attestation.EvidenceIsRecordable(r.err),
		"a verdict must keep its evidence in the collection, got unrecordable error: %v", r.err)
	require.Equal(t, slsa.FailedVerificationResult, r.att.VerificationResult)
	require.NotEmpty(t, r.att.Policy.Digest, "the FAILED VSA names the policy that decided it")
}

func TestRequiredExternalVerdictRecordsFailedVSA(t *testing.T) {
	k := newABKey(t)
	corpus := map[string]dsse.Envelope{
		"C-build":         abBuild(t, k, pvC, pvP),
		"C-secrets-clean": pvSigned(t, k.signer, "secrets", pvC, pvP, 0),
	}
	seeds := []cryptoutil.DigestSet{sha1Seed(pvC), imageSeed()}

	t.Run("control: a child signed by the functionary passes", func(t *testing.T) {
		envs := map[string]dsse.Envelope{"child.json": evChild(t, k.signer)}
		for ref, env := range corpus {
			envs[ref] = env
		}
		r := abAttest(t, k, uriPolicyV02, abPolicy(t, k, evRequireChild(k)), envs, seeds, "")
		require.NoError(t, r.err)
		require.Equal(t, slsa.PassedVerificationResult, r.att.VerificationResult)
	})

	t.Run("missing required external is a FAILED verdict", func(t *testing.T) {
		r := abAttest(t, k, uriPolicyV02, abPolicy(t, k, evRequireChild(k)), corpus, seeds, "")
		requireFailedVerdictRecorded(t, r)
		var missing policy.ErrMissingExternalAttestation
		require.True(t, errors.As(r.err, &missing), "the typed cause survives: %v", r.err)
		require.Equal(t, "child", missing.Name)
		require.False(t, policy.NoVerdict(r.err))
	})

	t.Run("every candidate rejected is a FAILED verdict naming the rejected child", func(t *testing.T) {
		stranger := newABKey(t)
		child := evChild(t, stranger.signer)
		envs := map[string]dsse.Envelope{"child.json": child}
		for ref, env := range corpus {
			envs[ref] = env
		}
		r := abAttest(t, k, uriPolicyV02, abPolicy(t, k, evRequireChild(k)), envs, seeds, "")
		requireFailedVerdictRecorded(t, r)
		var rejected policy.ErrExternalAttestationRejected
		require.True(t, errors.As(r.err, &rejected), "the typed cause survives: %v", r.err)
		actx, err := attestation.NewContext("digest", nil)
		require.NoError(t, err)
		want, err := cryptoutil.CalculateDigestSetFromBytes(child.Payload, actx.Hashes())
		require.NoError(t, err)
		named := false
		for _, in := range r.att.InputAttestations {
			named = named || in.Digest.Equal(want)
		}
		require.True(t, named, "the FAILED VSA names the child it rejected: %+v", r.att.InputAttestations)
	})

	t.Run("an unreadable source reaches no verdict and records nothing", func(t *testing.T) {
		polEnv, err := dsse.Sign(uriPolicyV02, bytes.NewReader(abPolicy(t, k, evRequireChild(k))), dsse.SignWithSigners(k.signer))
		require.NoError(t, err)
		r := abAttestEnvelope(t, k, polEnv, evFailingSource{}, seeds)
		require.Error(t, r.err)
		require.True(t, policy.NoVerdict(r.err), "%v", r.err)
		require.False(t, attestation.EvidenceIsRecordable(r.err), "no verdict must never be signed")
		require.Empty(t, r.att.VerificationResult)
	})
}

// abAttestEnvelope is abAttest over an arbitrary source.
func abAttestEnvelope(t *testing.T, k abKey, polEnv dsse.Envelope, src source.Sourcer, seeds []cryptoutil.DigestSet) abRun {
	t.Helper()
	a := New()
	a.SetPolicyEnvelope(polEnv)
	a.SetPolicyVerificationOptions(policysig.NewVerifyPolicySignatureOptions(
		policysig.VerifyWithPolicyVerifiers([]cryptoutil.Verifier{k.verifier})))
	a.SetSubjectDigests(seeds)
	a.SetCollectionSource(src)
	actx, err := attestation.NewContext("external-verdict", nil)
	require.NoError(t, err)
	return abRun{att: a, err: a.Attest(actx)}
}

type evFailingSource struct{}

func (evFailingSource) Search(context.Context, string, []string, []string) ([]source.CollectionEnvelope, error) {
	return nil, errors.New("archivista graphql returned 503")
}

func (evFailingSource) SearchByPredicateType(context.Context, []string, []string) ([]source.StatementEnvelope, error) {
	return nil, errors.New("archivista graphql returned 503")
}
