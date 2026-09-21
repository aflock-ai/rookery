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
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// The commit binding reaches this attestor through the same anonymous
// interface assertion as the other knobs (attestation/workflow/verify.go).
// For this knob a silent miss is a security hole, not a slow verify: the
// caller believes the gate is bound to its commit and the engine never hears
// about it. The workflow refuses when the assertion does not match; this pins
// that the real attestor matches it.
func TestAttestor_SatisfiesTheCommitBindingConfigurerAssertion(t *testing.T) {
	var att any = New()
	cb, ok := att.(interface{ SetCommitBinding(string) })
	if !ok {
		t.Fatal("*Attestor does not satisfy interface{ SetCommitBinding(string) }; " +
			"attestation/workflow/verify.go asserts exactly this shape, so VerifyWithCommitBinding would be refused")
	}
	cb.SetCommitBinding(pvC)
}

const (
	pvGitType   = "https://aflock.ai/attestations/git/v0.1"
	pvBuildType = "https://example.com/hsec1-build/v1"
	pvScanType  = "https://example.com/hsec1-secretscan/v1"
	pvG         = "1111111111111111111111111111111111111111"
	pvP         = "2222222222222222222222222222222222222222"
	pvC         = "3333333333333333333333333333333333333333"
)

// pvSigned signs one synthetic collection in the git attestor's JSON shape:
// commithash and parenthash subjects (sha1) and the matching signed backrefs.
func pvSigned(t *testing.T, signer cryptoutil.Signer, step, commit, parent string, findings int) dsse.Envelope {
	t.Helper()
	gitBody, err := json.Marshal(map[string]any{"commithash": commit, "commithashverified": true, "parenthashes": []string{parent}})
	require.NoError(t, err)
	attType := pvBuildType
	body := []byte(`{}`)
	if step == "secrets" {
		attType = pvScanType
		f := make([]string, findings)
		for i := range f {
			f[i] = "synthetic-finding"
		}
		body, err = json.Marshal(map[string]any{"findings": f})
		require.NoError(t, err)
	}
	sha1 := func(v string) cryptoutil.DigestSet {
		return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA1}: v}
	}
	coll := attestation.Collection{
		Name: step,
		Attestations: []attestation.CollectionAttestation{
			{Type: pvGitType, Attestation: attestation.NewRawAttestation(pvGitType, gitBody)},
			{Type: attType, Attestation: attestation.NewRawAttestation(attType, body)},
		},
		RecordedBackRefs: map[string]cryptoutil.DigestSet{
			pvGitType + "/commithash:" + commit: sha1(commit),
			pvGitType + "/parenthash:" + parent: sha1(parent),
		},
	}
	predicate, err := json.Marshal(coll)
	require.NoError(t, err)
	payload, err := json.Marshal(intoto.Statement{
		Type: intoto.StatementType,
		Subject: []intoto.Subject{
			{Name: pvGitType + "/commithash:" + commit, Digest: map[string]string{"sha1": commit}},
			{Name: pvGitType + "/parenthash:" + parent, Digest: map[string]string{"sha1": parent}},
		},
		PredicateType: attestation.CollectionType,
		Predicate:     predicate,
	})
	require.NoError(t, err)
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	return env
}

// pvAttest runs the real attestor over a signed corpus in which C's own
// secrets scan has findings and its parent's scan is clean.
func pvAttest(t *testing.T, binding *string) slsa.VerificationResult {
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
	polEnv, err := dsse.Sign("https://witness.testifysec.com/policy/v0.1", bytes.NewReader(polBytes), dsse.SignWithSigners(signer))
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
	if binding != nil {
		a.SetCommitBinding(*binding)
	}

	actx, err := attestation.NewContext("commit-binding-plumbing", nil)
	require.NoError(t, err)
	require.NoError(t, a.Attest(actx))
	return a.VerificationResult
}

// End to end through the real attestor: unbound, C passes on its parent's
// clean scan (the characterized HSEC1 behaviour); bound to C, it fails on
// its own findings. A setter that latches but never reaches the engine
// passes the interface test above and fails here.
func TestAttestor_CommitBindingReachesTheEngine(t *testing.T) {
	require.Equal(t, slsa.PassedVerificationResult, pvAttest(t, nil),
		"characterization: unbound, the parent's clean scan satisfies C")

	c := pvC
	require.Equal(t, slsa.FailedVerificationResult, pvAttest(t, &c),
		"bound to C, the parent's scan must not satisfy C's secrets step")

	empty := ""
	require.Equal(t, slsa.PassedVerificationResult, pvAttest(t, &empty),
		"an empty binding is the unbound zero value")
}
