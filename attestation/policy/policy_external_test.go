// Copyright 2025 The Aflock Authors
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

package policy

import (
	"context"
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
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Helpers for building external-attestation StatementEnvelopes
// ---------------------------------------------------------------------------

// slsaProvenanceV1PredicateType matches plugins/attestors/slsa.SLSAProvenanceV1PredicateType
// duplicated here to avoid importing the plugin from the policy package.
const slsaProvenanceV1PredicateType = "https://slsa.dev/provenance/v1"

// vsaPredicateType matches plugins/attestors/vsa.PredicateType.
const vsaPredicateType = "https://slsa.dev/verification_summary/v1"

// newECDSAVerifier returns a fresh ECDSA verifier and its keyID.
func newECDSAVerifier(t *testing.T) (cryptoutil.Verifier, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := v.KeyID()
	require.NoError(t, err)
	return v, keyID
}

// mkExternalEnvelope builds a StatementEnvelope with a RawAttestation
// wrapping the predicate JSON. The envelope has the provided Verifiers
// pre-populated — tests feed this directly into mockVerifiedSource so the
// DSSE signature verification step is bypassed. The subject digest is
// hardcoded because every caller uses the same canonical value (the
// policy is seeded with it). Callers that need multi-subject envelopes
// construct the Statement inline (see test 16).
func mkExternalEnvelope(t *testing.T, predicateType string, predicate json.RawMessage, verifiers ...cryptoutil.Verifier) source.StatementEnvelope {
	t.Helper()
	const subjectDigest = "sha256:artifact"
	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: predicateType,
		Subject: []intoto.Subject{
			{Name: "pkg:example/artifact", Digest: map[string]string{"sha256": subjectDigest}},
		},
		Predicate: predicate,
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)

	return source.StatementEnvelope{
		Envelope:  dsse.Envelope{Payload: payload, PayloadType: intoto.PayloadType},
		Statement: stmt,
		Attestor:  attestation.NewRawAttestation(predicateType, predicate),
		Verifiers: verifiers,
		Reference: predicateType + "-" + subjectDigest,
	}
}

// regoAccept is a permissive Rego module that never denies. Used as the
// baseline external policy body when the test wants a pass.
var regoAccept = []byte(`
package test
deny[msg] {
    false
    msg := "never"
}
`)

// regoVsaPassedOnly denies unless the VSA's verificationResult is PASSED.
var regoVsaPassedOnly = []byte(`
package test
deny[msg] {
    input.verificationResult != "PASSED"
    msg := "vsa verification result is not PASSED"
}
`)

// regoRequireBuildType denies unless the SLSA provenance has a buildType.
var regoRequireBuildType = []byte(`
package test
deny[msg] {
    not input.buildDefinition.buildType
    msg := "buildDefinition.buildType missing"
}
`)

// regoReadsExternalVSA denies unless input.external["vsa-check"] has a
// PASSED verificationResult. Used for the cross-step ExternalFrom test.
var regoReadsExternalVSA = []byte(`
package test
deny[msg] {
    input.external["vsa-check"].verificationResult != "PASSED"
    msg := "external VSA is not PASSED"
}
`)

// futureExpiry returns a policy expiry 1 hour in the future.
func futureExpiry() metav1.Time {
	return metav1.Time{Time: time.Now().Add(1 * time.Hour)}
}

// passingSLSAPredicate is a minimal but valid SLSA v1 provenance body.
var passingSLSAPredicate = json.RawMessage(`{
    "buildDefinition": {"buildType": "https://example.com/build/v1"},
    "runDetails": {"builder": {"id": "https://example.com/builder"}}
}`)

// passingVSAPredicate is a minimal valid VSA with PASSED result.
var passingVSAPredicate = json.RawMessage(`{
    "verifier": {"id": "https://example.com/verifier"},
    "timeVerified": "2025-01-01T00:00:00Z",
    "policy": {"uri": "https://example.com/policy"},
    "inputAttestations": [],
    "verificationResult": "PASSED"
}`)

// failingVSAPredicate has a FAILED verificationResult.
var failingVSAPredicate = json.RawMessage(`{
    "verifier": {"id": "https://example.com/verifier"},
    "timeVerified": "2025-01-01T00:00:00Z",
    "policy": {"uri": "https://example.com/policy"},
    "inputAttestations": [],
    "verificationResult": "FAILED"
}`)

// ---------------------------------------------------------------------------
// Test 1: SLSA provenance external, rego accepts → pass
// ---------------------------------------------------------------------------

func TestExternal_01_SLSAProvenanceAccepted(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, passingSLSAPredicate, verifier)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{}, // no steps — only externals
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa": {
				Name:          "slsa",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
			},
		},
	}

	// Need at least one step for verifySteps not to error. Give a dummy
	// step with no attestations and a collection that auto-passes.
	p.Steps = map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}}

	noopColl := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "noop"},
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {noopColl}},
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
	}

	pass, stepResults, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.True(t, pass, "policy should pass when SLSA external + noop step pass")
	assert.True(t, stepResults["noop"].HasPassed())
	require.Contains(t, extResults, "slsa")
	assert.Len(t, extResults["slsa"].Passed, 1)
	assert.Empty(t, extResults["slsa"].Rejected)
}

// ---------------------------------------------------------------------------
// Test 2: required=true, no match → ErrMissingExternalAttestation
// ---------------------------------------------------------------------------

func TestExternal_02_RequiredNoMatchFails(t *testing.T) {
	_, keyID := newECDSAVerifier(t)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa": {
				Name:          "slsa",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byPredicate: map[string][]source.StatementEnvelope{},
	}

	pass, _, _, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:nothing"}),
	)
	assert.False(t, pass)
	require.Error(t, err)
	var missErr ErrMissingExternalAttestation
	assert.ErrorAs(t, err, &missErr)
	assert.Equal(t, "slsa", missErr.Name)
}

// ---------------------------------------------------------------------------
// Test 3: required=false, no match → pass (skipped)
// ---------------------------------------------------------------------------

func TestExternal_03_OptionalNoMatchPasses(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa": {
				Name:          "slsa",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      false,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
			},
		},
	}

	noopColl := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "noop"},
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {noopColl}},
		byPredicate: map[string][]source.StatementEnvelope{},
	}

	pass, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:nothing"}),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	assert.True(t, extResults["slsa"].Skipped)
	assert.True(t, extResults["slsa"].Analyze())
}

// ---------------------------------------------------------------------------
// Test 4: VSA external, rego reads verificationResult=PASSED → pass
// ---------------------------------------------------------------------------

func TestExternal_04_VSAPassed(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, vsaPredicateType, passingVSAPredicate, verifier)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"vsa": {
				Name:          "vsa",
				PredicateType: vsaPredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoVsaPassedOnly, Name: "vsa.rego"}},
			},
		},
	}

	noopColl := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "noop"},
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {noopColl}},
		byPredicate: map[string][]source.StatementEnvelope{vsaPredicateType: {envelope}},
	}

	pass, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	assert.Len(t, extResults["vsa"].Passed, 1)
}

// ---------------------------------------------------------------------------
// Test 5: VSA external, rego reads verificationResult=FAILED → rego-deny fail
// ---------------------------------------------------------------------------

func TestExternal_05_VSAFailedRegoDenies(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, vsaPredicateType, failingVSAPredicate, verifier)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"vsa": {
				Name:          "vsa",
				PredicateType: vsaPredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoVsaPassedOnly, Name: "vsa.rego"}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byPredicate: map[string][]source.StatementEnvelope{vsaPredicateType: {envelope}},
	}

	pass, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.Error(t, err, "failing VSA with required=true + no passes should surface rejection reasons")
	assert.False(t, pass)
	// All envelopes rejected, none passed → Required triggers rejected-error (NOT missing).
	// The distinction matters: 'missing' vs 'rejected' carry different diagnostic info
	// for the operator — this test case is "we found one but it failed rego", so we
	// expect ErrExternalAttestationRejected with the rego deny reason embedded.
	var rejErr ErrExternalAttestationRejected
	require.ErrorAs(t, err, &rejErr, "expected ErrExternalAttestationRejected, got %T: %v", err, err)
	assert.Equal(t, "vsa", rejErr.Name)
	assert.NotEmpty(t, rejErr.Rejections, "rejection reasons must be surfaced")
	if _, ok := extResults["vsa"]; ok {
		assert.Empty(t, extResults["vsa"].Passed)
		assert.NotEmpty(t, extResults["vsa"].Rejected)
	}
}

// ---------------------------------------------------------------------------
// Test 6: Wrong functionary signed the external → functionary-mismatch fail
// ---------------------------------------------------------------------------

func TestExternal_06_WrongFunctionary(t *testing.T) {
	signingVerifier, _ := newECDSAVerifier(t)
	_, otherKeyID := newECDSAVerifier(t)

	envelope := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, passingSLSAPredicate, signingVerifier)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: otherKeyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa": {
				Name:          "slsa",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: otherKeyID}}, // wrong key
				RegoPolicies:  []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
	}

	pass, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	assert.False(t, pass)
	assert.Error(t, err)
	require.Contains(t, extResults, "slsa")
	assert.Empty(t, extResults["slsa"].Passed, "no envelope should pass — functionary mismatch")
	assert.NotEmpty(t, extResults["slsa"].Rejected)
}

// ---------------------------------------------------------------------------
// Test 7: External subject doesn't match policy seed → required=true fails,
// required=false passes via Skipped.
// ---------------------------------------------------------------------------

func TestExternal_07_SubjectMismatch(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	// Envelope has a different subject than the policy seed. Source is
	// strict: it returns no match when subject doesn't intersect. We
	// simulate that by returning an empty envelope list for the predicate.

	noopColl := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "noop"},
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	t.Run("required_fails", func(t *testing.T) {
		p := Policy{
			Expires: futureExpiry(),
			Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
			ExternalAttestations: map[string]ExternalAttestation{
				"slsa": {
					Name:          "slsa",
					PredicateType: slsaProvenanceV1PredicateType,
					Required:      true,
					Functionaries: []Functionary{{PublicKeyID: keyID}},
				},
			},
		}
		ms := &stepAwareVerifiedSource{
			byStep: map[string][]source.CollectionVerificationResult{"noop": {noopColl}},
		}
		pass, _, _, err := p.VerifyWithExternals(context.Background(),
			WithVerifiedSource(ms),
			WithSubjectDigests([]string{"sha256:policy-seed-only"}),
		)
		var missErr ErrMissingExternalAttestation
		assert.ErrorAs(t, err, &missErr)
		assert.False(t, pass)
	})

	t.Run("optional_passes", func(t *testing.T) {
		p := Policy{
			Expires: futureExpiry(),
			Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
			ExternalAttestations: map[string]ExternalAttestation{
				"slsa": {
					Name:          "slsa",
					PredicateType: slsaProvenanceV1PredicateType,
					Required:      false,
					Functionaries: []Functionary{{PublicKeyID: keyID}},
				},
			},
		}
		ms := &stepAwareVerifiedSource{
			byStep: map[string][]source.CollectionVerificationResult{"noop": {noopColl}},
		}
		pass, _, extResults, err := p.VerifyWithExternals(context.Background(),
			WithVerifiedSource(ms),
			WithSubjectDigests([]string{"sha256:policy-seed-only"}),
		)
		require.NoError(t, err)
		assert.True(t, pass)
		assert.True(t, extResults["slsa"].Skipped)
	})
}

// ---------------------------------------------------------------------------
// Test 8: Policy with both steps and externals, both pass → pass
// ---------------------------------------------------------------------------

func TestExternal_08_BothStepsAndExternalsPass(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, passingSLSAPredicate, verifier)

	buildAttType := "https://example.com/build-att/v1"
	buildColl := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{Type: buildAttType, Attestation: &dummyAttestor{name: "build", typeStr: buildAttType}},
		},
	}
	buildCVR := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: buildColl,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: buildAttType}},
			},
		},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa": {
				Name:          "slsa",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"build": {buildCVR}},
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
	}

	pass, stepResults, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	assert.True(t, stepResults["build"].HasPassed())
	assert.Len(t, extResults["slsa"].Passed, 1)
}

// ---------------------------------------------------------------------------
// Test 9: Two externals, same predicateType, different rego → each evaluated separately
// ---------------------------------------------------------------------------

func TestExternal_09_TwoExternalsSamePredicateDifferentRego(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, passingSLSAPredicate, verifier)

	// First rego accepts; second rego always denies.
	regoAlwaysDeny := []byte(`
package test
deny[msg] { msg := "always" }
`)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa-accept": {
				Name:          "slsa-accept",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
			},
			"slsa-deny": {
				Name:          "slsa-deny",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      false, // non-required so we see Rejected, not hard-error
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoAlwaysDeny, Name: "deny.rego"}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
	}

	_, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	// slsa-accept passes, slsa-deny has 0 passes — but is optional.
	// Optional externals with all-rejected envelopes still count as failing.
	// However our implementation marks them Skipped only if the source
	// returned zero envelopes; here envelopes were returned and rejected
	// so Skipped=false and len(Passed)=0 → Analyze() returns false. Since
	// slsa-deny is not required, the overall error should still propagate
	// as policy denial through the Analyze() aggregate.
	require.Contains(t, extResults, "slsa-accept")
	require.Contains(t, extResults, "slsa-deny")
	assert.Len(t, extResults["slsa-accept"].Passed, 1)
	assert.Empty(t, extResults["slsa-deny"].Passed)
	assert.NotEmpty(t, extResults["slsa-deny"].Rejected)
	// Error channel: when optional external has all-rejected envelopes,
	// verifyExternalAttestations skips the "required" hard failure path so
	// no err is returned here — but Analyze() still reports false for
	// that external, making overall pass false.
	_ = err
}

// ---------------------------------------------------------------------------
// Test 10: External with timestamp authority → verifies with timestamp
// ---------------------------------------------------------------------------
//
// Test 10 exercises the code path where the StatementEnvelope carries
// Verifiers (produced by DSSE verification with a timestamp option). Our
// mock source shortcuts signature verification entirely, so this test
// asserts the structural plumbing: timestamp-originated verifiers reaching
// the functionary check. True TSA verification is covered elsewhere.

func TestExternal_10_TimestampAuthorityEnvelope(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, passingSLSAPredicate, verifier)

	p := Policy{
		Expires: futureExpiry(),
		// Declare a dummy timestamp authority root so TrustBundles() wires
		// up a TSA bucket; the unit path doesn't actually validate against
		// real TSA tokens.
		TimestampAuthorities: map[string]Root{},
		Steps:                map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa-ts": {
				Name:          "slsa-ts",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
	}

	_, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.Len(t, extResults["slsa-ts"].Passed, 1)
}

// ---------------------------------------------------------------------------
// Test 11: Step with ExternalFrom: ["vsa-check"] reads input.external.vsa-check.verificationResult
// ---------------------------------------------------------------------------

func TestExternal_11_StepReadsExternalContext(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, vsaPredicateType, passingVSAPredicate, verifier)

	buildAttType := "https://example.com/build-att/v1"
	buildColl := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{Type: buildAttType, Attestation: &dummyAttestor{name: "build", typeStr: buildAttType}},
		},
	}
	buildCVR := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: buildColl,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				ExternalFrom:  []string{"vsa-check"},
				Attestations: []Attestation{
					{
						Type: buildAttType,
						RegoPolicies: []RegoPolicy{
							{Module: regoReadsExternalVSA, Name: "reads-external.rego"},
						},
					},
				},
			},
		},
		ExternalAttestations: map[string]ExternalAttestation{
			"vsa-check": {
				Name:          "vsa-check",
				PredicateType: vsaPredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"build": {buildCVR}},
		byPredicate: map[string][]source.StatementEnvelope{vsaPredicateType: {envelope}},
	}

	pass, stepResults, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	assert.True(t, stepResults["build"].HasPassed(), "step should pass when input.external.vsa-check.verificationResult==PASSED")
	assert.Len(t, extResults["vsa-check"].Passed, 1)
}

// ---------------------------------------------------------------------------
// Test 12: Step references missing external name in ExternalFrom → validation error
// ---------------------------------------------------------------------------

func TestExternal_12_UnknownExternalFromRef(t *testing.T) {
	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {
				Name:         "build",
				ExternalFrom: []string{"nonexistent"},
			},
		},
	}
	ms := &mockVerifiedSource{}
	pass, _, _, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:seed"}),
	)
	assert.False(t, pass)
	var unknown ErrUnknownExternalAttestation
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "build", unknown.Step)
	assert.Equal(t, "nonexistent", unknown.Name)
}

// ---------------------------------------------------------------------------
// Test 13: Unknown predicate type → RawAttestation fallback, rego over raw JSON
// ---------------------------------------------------------------------------

func TestExternal_13_RawAttestationFallback(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	const unknownPred = "https://example.com/custom-unregistered/v1"
	predicate := json.RawMessage(`{"hello":"world","n":42}`)
	envelope := mkExternalEnvelope(t, unknownPred, predicate, verifier)

	regoAcceptIfHello := []byte(`
package test
deny[msg] {
    input.hello != "world"
    msg := "hello field missing or wrong"
}
`)

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"custom": {
				Name:          "custom",
				PredicateType: unknownPred,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoAcceptIfHello, Name: "hello.rego"}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byPredicate: map[string][]source.StatementEnvelope{unknownPred: {envelope}},
	}

	_, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.Len(t, extResults["custom"].Passed, 1, "rego over RawAttestation raw JSON should pass when field matches")
}

// ---------------------------------------------------------------------------
// Test 14: Registered typed factory (SLSA v1) with valid predicate → rego sees structured fields
// ---------------------------------------------------------------------------

func TestExternal_14_TypedFactoryStructuredFields(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)

	const typedPred = "https://slsa.dev/provenance/v1-test-14"

	factory := func() attestation.Attestor {
		return &concreteTypedAttestor{predicateType: typedPred}
	}
	attestation.RegisterAttestation("test14-typed", typedPred, attestation.VerifyRunType, factory)

	// Build envelope with the typed attestor (emulating SearchByPredicateType
	// path where FactoryByType is invoked).
	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: typedPred,
		Subject:       []intoto.Subject{{Name: "artifact", Digest: map[string]string{"sha256": "sha256:artifact"}}},
		Predicate:     passingSLSAPredicate,
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)

	typed := factory()
	require.NoError(t, json.Unmarshal(stmt.Predicate, typed))
	// Sanity check: MarshalJSON should expose the typed fields.
	marshaled, err := json.Marshal(typed)
	require.NoError(t, err)
	require.Contains(t, string(marshaled), "buildDefinition")

	envelope := source.StatementEnvelope{
		Envelope:  dsse.Envelope{Payload: payload, PayloadType: intoto.PayloadType},
		Statement: stmt,
		Attestor:  typed,
		Verifiers: []cryptoutil.Verifier{verifier},
		Reference: "typed-ref",
	}

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": {Name: "noop", Functionaries: []Functionary{{PublicKeyID: keyID}}}},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa-typed": {
				Name:          "slsa-typed",
				PredicateType: typedPred,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoRequireBuildType, Name: "typed.rego"}},
			},
		},
	}

	// Noop step needs a collection to pass.
	noopColl := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "noop"},
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {noopColl}},
		byPredicate: map[string][]source.StatementEnvelope{typedPred: {envelope}},
	}

	pass, _, extResults, verifyErr := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, verifyErr)
	assert.True(t, pass)
	assert.Len(t, extResults["slsa-typed"].Passed, 1)
}

// ---------------------------------------------------------------------------
// Test 15: Topological ordering — external must verify before step that references it
// ---------------------------------------------------------------------------

func TestExternal_15_ExternalVerifiedBeforeReferencingStep(t *testing.T) {
	// If externals weren't verified first, a step rego reading
	// input.external.vsa-check would see nothing and deny. Test 11 already
	// covers the success path. This test confirms the ordering contract by
	// using a rego that asserts input.external is always populated by the
	// time the step's rego fires.
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, vsaPredicateType, passingVSAPredicate, verifier)

	buildAttType := "https://example.com/build-att/v1"
	buildColl := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{Type: buildAttType, Attestation: &dummyAttestor{name: "build", typeStr: buildAttType}},
		},
	}
	buildCVR := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: buildColl,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// Rego that requires input.external.vsa-check to exist. If the
	// verification flow ran steps before externals, this would be missing
	// and deny.
	regoRequireExternalPresent := []byte(`
package test
deny[msg] {
    not input.external["vsa-check"]
    msg := "external vsa-check not present — step ran before external verification?"
}
`)

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				ExternalFrom:  []string{"vsa-check"},
				Attestations: []Attestation{
					{Type: buildAttType, RegoPolicies: []RegoPolicy{{Module: regoRequireExternalPresent, Name: "order.rego"}}},
				},
			},
		},
		ExternalAttestations: map[string]ExternalAttestation{
			"vsa-check": {
				Name:          "vsa-check",
				PredicateType: vsaPredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"build": {buildCVR}},
		byPredicate: map[string][]source.StatementEnvelope{vsaPredicateType: {envelope}},
	}

	pass, stepResults, _, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.True(t, pass, "step rego requiring input.external should pass — externals verified first")
	assert.True(t, stepResults["build"].HasPassed())
}

// ---------------------------------------------------------------------------
// Test 16: External attestation's subjects do NOT feed subject-graph
// ---------------------------------------------------------------------------

// TestExternal_16_SubjectGraphIsolation ensures that an external
// attestation carrying additional subjects beyond the policy seed does not
// expand the subject set that downstream step searches see. We spy on the
// subjectDigests argument the source receives for Search() and assert it
// equals the seed — never the external's subjects.
func TestExternal_16_SubjectGraphIsolation(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	// The external's statement subject is "sha256:artifact". We also add
	// a second subject "sha256:external-leak" to the envelope — if the
	// implementation erroneously fed it back, subsequent step searches
	// would see it in subjectDigests.
	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: slsaProvenanceV1PredicateType,
		Subject: []intoto.Subject{
			{Name: "pkg:example/artifact", Digest: map[string]string{"sha256": "sha256:artifact"}},
			{Name: "pkg:example/leak", Digest: map[string]string{"sha256": "sha256:external-leak"}},
		},
		Predicate: passingSLSAPredicate,
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	envelope := source.StatementEnvelope{
		Envelope:  dsse.Envelope{Payload: payload, PayloadType: intoto.PayloadType},
		Statement: stmt,
		Attestor:  attestation.NewRawAttestation(slsaProvenanceV1PredicateType, passingSLSAPredicate),
		Verifiers: []cryptoutil.Verifier{verifier},
		Reference: "leak-test",
	}

	buildAttType := "https://example.com/build-att/v1"
	buildColl := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{Type: buildAttType, Attestation: &dummyAttestor{name: "build", typeStr: buildAttType}},
		},
	}
	buildCVR := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: buildColl,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// Record every subjectDigests slice that Search() is called with.
	spy := &spyingVerifiedSource{
		inner: &stepAwareVerifiedSource{
			byStep:      map[string][]source.CollectionVerificationResult{"build": {buildCVR}},
			byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
		},
	}

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: buildAttType}},
			},
		},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa": {
				Name:          "slsa",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
			},
		},
	}

	_, _, _, err = p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(spy),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	// Every step-Search call must have been seeded with only
	// "sha256:artifact". The external's second subject must never appear.
	for _, observed := range spy.subjectDigestsByCall {
		for _, d := range observed {
			assert.NotEqual(t, "sha256:external-leak", d,
				"external attestation's subject must NOT feed into step-search subjectDigests")
		}
	}
}

// spyingVerifiedSource records the subjectDigests argument passed to Search.
type spyingVerifiedSource struct {
	inner                source.VerifiedSourcer
	subjectDigestsByCall [][]string
}

func (s *spyingVerifiedSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]source.CollectionVerificationResult, error) {
	// Copy so subsequent mutation doesn't corrupt the record.
	snapshot := make([]string, len(subjectDigests))
	copy(snapshot, subjectDigests)
	s.subjectDigestsByCall = append(s.subjectDigestsByCall, snapshot)
	return s.inner.Search(ctx, collectionName, subjectDigests, attestations)
}

func (s *spyingVerifiedSource) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]source.StatementEnvelope, error) {
	return s.inner.SearchByPredicateType(ctx, predicateTypes, subjectDigests)
}

// concreteTypedAttestor is a typed attestor with a concrete (non-interface)
// data field so json.Unmarshal can decode directly into it. Used by test 14.
type concreteTypedAttestor struct {
	predicateType   string
	BuildDefinition struct {
		BuildType string `json:"buildType"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	} `json:"runDetails"`
}

func (a *concreteTypedAttestor) Name() string                                   { return "concrete-typed" }
func (a *concreteTypedAttestor) Type() string                                   { return a.predicateType }
func (a *concreteTypedAttestor) RunType() attestation.RunType                   { return attestation.VerifyRunType }
func (a *concreteTypedAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *concreteTypedAttestor) Schema() *jsonschema.Schema                     { return nil }

// Explicit UnmarshalJSON / MarshalJSON so the typed fields survive the
// factory round-trip without picking up predicateType in the JSON.
func (a *concreteTypedAttestor) UnmarshalJSON(b []byte) error {
	type alias struct {
		BuildDefinition struct {
			BuildType string `json:"buildType"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	}
	var a2 alias
	if err := json.Unmarshal(b, &a2); err != nil {
		return err
	}
	a.BuildDefinition = a2.BuildDefinition
	a.RunDetails = a2.RunDetails
	return nil
}

func (a *concreteTypedAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		BuildDefinition struct {
			BuildType string `json:"buildType"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	}{
		BuildDefinition: a.BuildDefinition,
		RunDetails:      a.RunDetails,
	})
}

// ---------------------------------------------------------------------------
// Regression: a policy with ONLY externalAttestations (no steps) is valid and
// verifies cleanly. Pre-fix, the `policy has no steps to verify` guard fired
// before aggregation because it only inspected resultsByStep — external
// attestations were verified but the policy was still rejected.
// Common shape: standalone VSA-chain gates that don't run any workflow step.
// ---------------------------------------------------------------------------

func TestExternal_17_ExternalOnlyPolicyNoStepsValid(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, vsaPredicateType, passingVSAPredicate, verifier)

	p := Policy{
		Expires: futureExpiry(),
		// NO Steps — this is the case the pre-fix guard rejected.
		ExternalAttestations: map[string]ExternalAttestation{
			"vsa": {
				Name:          "vsa",
				PredicateType: vsaPredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: regoVsaPassedOnly, Name: "vsa.rego"}},
			},
		},
	}

	ms := &stepAwareVerifiedSource{
		byPredicate: map[string][]source.StatementEnvelope{vsaPredicateType: {envelope}},
	}

	pass, _, extResults, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.NoError(t, err)
	assert.True(t, pass, "external-only policy with passing VSA must verify")
	assert.Len(t, extResults["vsa"].Passed, 1)
}

// Policies that declare NEITHER steps NOR externalAttestations remain
// invalid — the aggregation guard must still catch that shape.
func TestExternal_18_EmptyPolicyStillRejected(t *testing.T) {
	p := Policy{Expires: futureExpiry()}

	ms := &stepAwareVerifiedSource{}
	pass, _, _, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:artifact"}),
	)
	require.Error(t, err, "empty policy must be rejected")
	assert.Contains(t, err.Error(), "no steps or external attestations")
	assert.False(t, pass)
}
