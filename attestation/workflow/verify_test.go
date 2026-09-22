// Copyright 2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workflow

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Inline attestor types to avoid importing plugin modules into core
	commandrunType           = "https://aflock.ai/attestations/command-run/v0.1"
	dummySubjectAttestorName = "subject attestor"
	dummySubjectAttestorType = "test/subjectattestor"
	dummyBackrefAttestorName = "backref attestor"
	dummyBackrefAttestorType = "test/backrefattestor"
	matchSubjectName         = "matchSubject"

	// Valid 64-char hex sha256 stand-ins for the operator seed digest and the
	// back-reference digest. They must be real hex: S1's IsMatchableSubjectDigest
	// drops malformed sha256 values from the matchable set, so the earlier
	// placeholders (seedDigestHex / backrefDigestHex) are no longer matchable and
	// would fail the subject-match these tests assert.
	seedDigestHex    = "5eed000000000000000000000000000000000000000000000000000000000000"
	backrefDigestHex = "bac4ef0000000000000000000000000000000000000000000000000000000000"
)

// dummyCommandRunAttestor is a minimal attestor that simulates commandrun for testing.
type dummyCommandRunAttestor struct {
	Cmd []string `json:"cmd"`
}

func (a *dummyCommandRunAttestor) Name() string                                     { return "command-run" }
func (a *dummyCommandRunAttestor) Type() string                                     { return commandrunType }
func (a *dummyCommandRunAttestor) RunType() attestation.RunType                     { return attestation.ExecuteRunType }
func (a *dummyCommandRunAttestor) Attest(ctx *attestation.AttestationContext) error { return nil }
func (a *dummyCommandRunAttestor) Schema() *jsonschema.Schema                       { return nil }

// dummyMaterialAttestor simulates material attestor for testing.
type dummyMaterialAttestor struct{}

func (a *dummyMaterialAttestor) Name() string                                     { return "material" }
func (a *dummyMaterialAttestor) Type() string                                     { return "https://aflock.ai/attestations/material/v0.1" }
func (a *dummyMaterialAttestor) RunType() attestation.RunType                     { return attestation.PreMaterialRunType }
func (a *dummyMaterialAttestor) Attest(ctx *attestation.AttestationContext) error { return nil }
func (a *dummyMaterialAttestor) Schema() *jsonschema.Schema                       { return nil }

// dummyProductAttestor simulates product attestor for testing.
type dummyProductAttestor struct{}

func (a *dummyProductAttestor) Name() string                                     { return "product" }
func (a *dummyProductAttestor) Type() string                                     { return "https://aflock.ai/attestations/product/v0.1" }
func (a *dummyProductAttestor) RunType() attestation.RunType                     { return attestation.PostProductRunType }
func (a *dummyProductAttestor) Attest(ctx *attestation.AttestationContext) error { return nil }
func (a *dummyProductAttestor) Schema() *jsonschema.Schema                       { return nil }
func (a *dummyProductAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{}
}

func TestVerify(t *testing.T) {
	// This test requires real attestor plugins (commandrun, material, product) to produce
	// valid attestation collections. With stub attestors, the policy engine cannot verify
	// because the collections lack proper predicate types. Run these tests from the
	// integration test suite with real plugin imports instead.
	t.Skip("requires real attestor plugins; run integration tests instead")
	registerDummyAttestors()
	testPolicy, functionarySigner := makePolicyWithPublicKeyFunctionary(t)
	policyEnvelope, _, policyVerifier := signPolicyRSA(t, testPolicy)

	step1Result, err := Run(
		"step01",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			&dummyMaterialAttestor{},
			&dummyCommandRunAttestor{Cmd: []string{"bash", "-c", "echo test"}},
			&dummyProductAttestor{},
		}),
	)
	require.NoError(t, err)

	step2Result, err := Run(
		"step02",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			&dummyMaterialAttestor{},
			&dummyCommandRunAttestor{Cmd: []string{"bash", "-c", "echo test"}},
			&dummyProductAttestor{},
		}),
	)
	require.NoError(t, err)

	// Create a dummy subject digest for policy verification
	dummySubjects := []cryptoutil.DigestSet{
		{
			{Hash: crypto.SHA256}: seedDigestHex,
		},
	}

	t.Run("Pass", func(t *testing.T) {
		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
		require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			policyEnvelope,
			[]cryptoutil.Verifier{policyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(dummySubjects),
		)

		require.NoError(t, err, fmt.Sprintf("failed with results: %+v", results))
	})

	t.Run("Fail with missing collection", func(t *testing.T) {
		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			policyEnvelope,
			[]cryptoutil.Verifier{policyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(dummySubjects),
		)

		require.Error(t, err, fmt.Sprintf("passed with results: %+v", results))
	})

	t.Run("Fail with missing attestation", func(t *testing.T) {
		functionaryVerifier, err := functionarySigner.Verifier()
		require.NoError(t, err)
		policyFunctionary, policyPk := functionaryFromVerifier(t, functionaryVerifier)
		failPolicy := makePolicy(policyFunctionary, policyPk, map[string]policy.Root{})

		step1 := failPolicy.Steps["step01"]
		step1.Attestations = append(step1.Attestations, policy.Attestation{Type: "nonexistent atttestation"})
		failPolicy.Steps["step01"] = step1
		failPolicyEnvelope, _, failPolicyVerifier := signPolicyRSA(t, failPolicy)

		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
		require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			failPolicyEnvelope,
			[]cryptoutil.Verifier{failPolicyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(dummySubjects),
		)

		require.Error(t, err, fmt.Sprintf("passed with results: %+v", results))
	})

	t.Run("Fail with incorrect signer", func(t *testing.T) {
		functionaryVerifier, err := functionarySigner.Verifier()
		require.NoError(t, err)
		policyFunctionary, policyPk := functionaryFromVerifier(t, functionaryVerifier)
		failPolicy := makePolicy(policyFunctionary, policyPk, map[string]policy.Root{})

		newSigner := createTestRSAKey(t)
		newVerifier, err := newSigner.Verifier()
		require.NoError(t, err)
		failPolicyFunctionary, failPolicyPk := functionaryFromVerifier(t, newVerifier)
		failPolicy.PublicKeys[failPolicyPk.KeyID] = failPolicyPk
		step1 := failPolicy.Steps["step01"]
		step1.Functionaries = []policy.Functionary{failPolicyFunctionary}
		failPolicy.Steps["step01"] = step1
		failPolicyEnvelope, _, failPolicyVerifier := signPolicyRSA(t, failPolicy)

		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
		require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			failPolicyEnvelope,
			[]cryptoutil.Verifier{failPolicyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(dummySubjects),
		)

		require.Error(t, err, fmt.Sprintf("passed with results: %+v", results))
	})
}

// TestBackRefs pins that the policy engine no longer follows BackRefs:
// verification follows only what the seed matches. The verifier starts with a
// "seed" subject that step02's collection carries; step02's collection also
// exposes a BackRef digest that covers step01's subject. That edge used to be
// followed at depth 1, which found step01 and passed the policy. Now step01 is
// never found from the seed alone and the policy FAILS; seeding step01's
// digest as well finds it directly and the policy passes.
//
// The test drives policy.Verify() directly (rather than workflow.Verify) to
// avoid a circular module dependency with the policyverify plugin — the
// attestation module is a leaf module and cannot import its own plugins.
func TestBackRefs(t *testing.T) {
	registerDummyAttestors()
	testPolicy, functionarySigner := makePolicyWithPublicKeyFunctionary(t)
	functionaryVerifier, err := functionarySigner.Verifier()
	require.NoError(t, err)

	step1Result, err := Run(
		"step01",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			&dummyMaterialAttestor{},
			&dummySubjectAttestor{Data: "test"},
			&dummyCommandRunAttestor{Cmd: []string{"bash", "-c", "echo test"}},
			&dummyProductAttestor{},
		}),
	)
	require.NoError(t, err)

	step2Result, err := Run(
		"step02",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			&dummyMaterialAttestor{},
			&dummyBackrefAttestor{},
			&dummyCommandRunAttestor{Cmd: []string{"bash", "-c", "echo test"}},
			&dummyProductAttestor{},
		}),
	)
	require.NoError(t, err)

	verify := func(seeds ...string) (bool, map[string]policy.StepResult) {
		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
		require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))
		// Wrap the raw memory source with the DSSE-verifying source that
		// policy.Verify expects. The functionary signer is also the envelope
		// signer for these synthetic collections.
		verifiedSource := source.NewVerifiedSource(
			memorySource,
			dsse.VerifyWithVerifiers(functionaryVerifier),
		)
		pass, stepResults, err := testPolicy.Verify(
			context.Background(),
			policy.WithVerifiedSource(verifiedSource),
			policy.WithSubjectDigests(seeds),
		)
		require.NoError(t, err, fmt.Sprintf("policy.Verify returned error: results=%+v", stepResults))
		return pass, stepResults
	}

	// Seed alone: step02 matches the seed; step01 is reachable only through
	// step02's BackRef, which is not followed.
	pass, stepResults := verify(seedDigestHex)
	require.False(t, pass, "step01 is reachable only through step02's back-reference, which is no longer followed")
	require.Empty(t, stepResults["step01"].Passed, "step01 must not be found through a BackRef")
	step2ResultEntry, ok := stepResults["step02"]
	require.True(t, ok, "step02 missing from results")
	require.NotEmpty(t, step2ResultEntry.Passed, "step02 must have passed collections: the seed names it")

	// Non-vacuity: step02's collection really does emit the BackRef that
	// covers step01, so the FAIL above is about the edge not being followed,
	// not about a missing edge.
	backRefs := step2ResultEntry.Passed[0].Collection.Collection.BackRefs()
	require.NotEmpty(t, backRefs, "step02 collection must expose BackRefs, or this test proves nothing")

	// Seeding step01's digest finds it directly.
	pass, stepResults = verify(seedDigestHex, backrefDigestHex)
	require.True(t, pass, fmt.Sprintf("policy did not pass with both digests seeded: results=%+v", stepResults))
	require.NotEmpty(t, stepResults["step01"].Passed, "step01 must be found through its seeded digest")
}

func makePolicy(functionary policy.Functionary, publicKey policy.PublicKey, roots map[string]policy.Root) policy.Policy {
	step01 := policy.Step{
		Name:          "step01",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrunType}},
	}

	step02 := policy.Step{
		Name:          "step02",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrunType}},
		// NOTE: no ArtifactsFrom here. This fixture exercises BackRef SUBJECT
		// expansion (the depth-iteration search graph), not artifactsFrom
		// artifact comparison. Under v0.3, inline leaves are the sole trust path
		// and a leaf-less collection (these dummy attestors carry no inline
		// materials) fails the artifactsFrom chain closed — which is correct, but
		// orthogonal to what this test asserts. The chain-comparison path is
		// covered by inline_leaves_adversarial_test.go and the policy package's
		// verifyCollectionArtifacts tests.
	}

	p := policy.Policy{
		Expires:    metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		PublicKeys: map[string]policy.PublicKey{},
		Steps:      map[string]policy.Step{},
	}

	if functionary.CertConstraint.Roots != nil {
		p.Roots = roots
	}

	p.Steps = make(map[string]policy.Step)
	p.Steps[step01.Name] = step01
	p.Steps[step02.Name] = step02

	if publicKey.KeyID != "" {
		p.PublicKeys[publicKey.KeyID] = publicKey
	}

	return p
}

func makePolicyWithPublicKeyFunctionary(t *testing.T) (policy.Policy, cryptoutil.Signer) {
	signer := createTestRSAKey(t)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	functionary, pk := functionaryFromVerifier(t, verifier)
	p := makePolicy(functionary, pk, nil)
	return p, signer
}

func functionaryFromVerifier(t *testing.T, v cryptoutil.Verifier) (policy.Functionary, policy.PublicKey) {
	keyID, err := v.KeyID()
	require.NoError(t, err)
	keyBytes, err := v.Bytes()
	require.NoError(t, err)
	return policy.Functionary{
			Type:        "PublicKey",
			PublicKeyID: keyID,
		},
		policy.PublicKey{
			KeyID: keyID,
			Key:   keyBytes,
		}
}

func signPolicyRSA(t *testing.T, p policy.Policy) (dsse.Envelope, cryptoutil.Signer, cryptoutil.Verifier) {
	signer := createTestRSAKey(t)
	env := signPolicy(t, p, signer)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	return env, signer, verifier
}

func signPolicy(t *testing.T, p policy.Policy, signer cryptoutil.Signer) dsse.Envelope {
	pBytes, err := json.Marshal(p)
	require.NoError(t, err)
	reader := bytes.NewReader(pBytes)
	outBytes := []byte{}
	writer := bytes.NewBuffer(outBytes)
	require.NoError(t, Sign(reader, policy.PolicyPredicate, writer, dsse.SignWithSigners(signer)))
	env := dsse.Envelope{}
	require.NoError(t, json.Unmarshal(writer.Bytes(), &env))
	return env
}

func createTestRSAKey(t *testing.T) cryptoutil.Signer {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	return signer
}

// policy verification currently needs attestors to be registered to properly validate them
func registerDummyAttestors() {
	attestation.RegisterAttestation("material", "https://aflock.ai/attestations/material/v0.1", attestation.PreMaterialRunType, func() attestation.Attestor { return &dummyMaterialAttestor{} })
	attestation.RegisterAttestation("command-run", commandrunType, attestation.ExecuteRunType, func() attestation.Attestor { return &dummyCommandRunAttestor{} })
	attestation.RegisterAttestation("product", "https://aflock.ai/attestations/product/v0.1", attestation.PostProductRunType, func() attestation.Attestor { return &dummyProductAttestor{} })
	attestation.RegisterAttestation(dummyBackrefAttestorName, dummyBackrefAttestorType, attestation.PreMaterialRunType, func() attestation.Attestor { return &dummyBackrefAttestor{} })
	attestation.RegisterAttestation(dummySubjectAttestorName, dummySubjectAttestorType, attestation.PreMaterialRunType, func() attestation.Attestor { return &dummySubjectAttestor{} })
}

// dummySubjectAttestor is a test attestor used to create a subject on an attestation.
type dummySubjectAttestor struct {
	Data string
}

func (a *dummySubjectAttestor) Name() string                                     { return dummySubjectAttestorName }
func (a *dummySubjectAttestor) Type() string                                     { return dummySubjectAttestorType }
func (a *dummySubjectAttestor) RunType() attestation.RunType                     { return attestation.PreMaterialRunType }
func (a *dummySubjectAttestor) Attest(ctx *attestation.AttestationContext) error { return nil }
func (a *dummySubjectAttestor) Schema() *jsonschema.Schema                       { return nil }
func (a *dummySubjectAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		matchSubjectName: {
			{Hash: crypto.SHA256}: backrefDigestHex,
		},
	}
}

// dummyBackrefAttestor is a test attestor used to expose a back ref subject.
//
// It exposes TWO subjects: the operator's seed digest (seedDigestHex),
// so step02's collection is found legitimately at depth 0 by a real
// subject-digest match (NOT by subjectless fail-open matching), and the
// back-reference digest (backrefDigestHex), which step01 carries as its subject. This
// honors the BackReffer contract (factory.go / detection contract.go): an
// attestor's BackRefs MUST be a subset of its own Subjects — the canonical
// example being the git attestor publishing its commit hash as both a subject
// and a back-reference. Without seedDigestHex as a real subject here,
// step02 could only be matched via the subjectless fail-open that
// memory_subjectless_test.go closes.
type dummyBackrefAttestor struct{}

func (a *dummyBackrefAttestor) Name() string                                     { return dummyBackrefAttestorName }
func (a *dummyBackrefAttestor) Type() string                                     { return dummyBackrefAttestorType }
func (a *dummyBackrefAttestor) RunType() attestation.RunType                     { return attestation.PreMaterialRunType }
func (a *dummyBackrefAttestor) Attest(ctx *attestation.AttestationContext) error { return nil }
func (a *dummyBackrefAttestor) Schema() *jsonschema.Schema                       { return nil }
func (a *dummyBackrefAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		"seed": {
			{Hash: crypto.SHA256}: seedDigestHex,
		},
		matchSubjectName: {
			{Hash: crypto.SHA256}: backrefDigestHex,
		},
	}
}
func (a *dummyBackrefAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		matchSubjectName: {
			{Hash: crypto.SHA256}: backrefDigestHex,
		},
	}
}
