// jade:ring local
// Copyright 2026 The Aflock Authors
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	legacySLSAProvenanceV10Type = "https://slsa.dev/provenance/v1.0"
	provenanceWorkflowBuilderID = "https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml@refs/tags/v1"
)

func slsaPredicateWithBuilder(id string) json.RawMessage {
	return json.RawMessage(`{"buildDefinition":{"buildType":"https://example.com/build/v1","externalParameters":{"a":1}},"runDetails":{"builder":{"id":"` + id + `"}}}`)
}

// fulcioVerifier returns an X509 verifier whose leaf carries the Fulcio
// Build Signer URI extension (OID 1.3.6.1.4.1.57264.1.9).
func fulcioVerifier(t *testing.T, buildSignerURI string) *cryptoutil.X509Verifier {
	t.Helper()
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	exts, err := certificate.Extensions{Issuer: "https://token.actions.githubusercontent.com", BuildSignerURI: buildSignerURI}.Render()
	require.NoError(t, err)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(9827),
		Subject:         pkix.Name{CommonName: "signer"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return newVerifierForLeaf(t, leaf, ca)
}

func TestCheckSLSABuilderIdentity(t *testing.T) {
	raw := func(pt, id string) attestation.Attestor {
		return attestation.NewRawAttestation(pt, slsaPredicateWithBuilder(id))
	}
	matching := fulcioVerifier(t, provenanceWorkflowBuilderID)
	other := fulcioVerifier(t, "https://github.com/tenant/app/.github/workflows/ci.yml@refs/heads/main")
	keyOnly, _ := newECDSAVerifier(t)

	cases := []struct {
		name    string
		pt      string
		id      string
		signers []cryptoutil.Verifier
		wantErr bool
	}{
		{"workflow identity backed by the cert's Build Signer URI", slsaProvenanceV1PredicateType, provenanceWorkflowBuilderID, []cryptoutil.Verifier{other, matching}, false},
		{"legacy v1.0 type is refused even with a matching signer", legacySLSAProvenanceV10Type, provenanceWorkflowBuilderID, []cryptoutil.Verifier{matching}, true},
		{"workflow identity signed by a different workflow", slsaProvenanceV1PredicateType, provenanceWorkflowBuilderID, []cryptoutil.Verifier{other}, true},
		{"workflow identity signed by a bare key", slsaProvenanceV1PredicateType, provenanceWorkflowBuilderID, []cryptoutil.Verifier{keyOnly}, true},
		{"workflow identity with no authorized signer", slsaProvenanceV1PredicateType, provenanceWorkflowBuilderID, nil, true},
		{"legacy-typed workflow identity signed by a bare key is refused", legacySLSAProvenanceV10Type, provenanceWorkflowBuilderID, []cryptoutil.Verifier{keyOnly}, true},
		{"host case is not a way around the check", slsaProvenanceV1PredicateType, "https://GitHub.com/aflock-ai/cilock-action/.github/workflows/provenance.yml@refs/tags/v1", []cryptoutil.Verifier{keyOnly}, true},
		{"a GHES workflow identity is checked too", slsaProvenanceV1PredicateType, "https://ghe.example.com/org/repo/.github/workflows/provenance.yml@refs/tags/v1", []cryptoutil.Verifier{keyOnly}, true},
		{"inline id claims no platform identity", slsaProvenanceV1PredicateType, "https://aflock.ai/cilock/inline/github-actions@v1", []cryptoutil.Verifier{keyOnly}, false},
		{"legacy cilock id under the legacy type is refused for its type", legacySLSAProvenanceV10Type, "https://aflock.ai/attestation-github-action-builder@v0.1", []cryptoutil.Verifier{keyOnly}, true},
		{"third-party builder signed by a key is out of scope", slsaProvenanceV1PredicateType, "https://tekton.dev/chains/v2", []cryptoutil.Verifier{keyOnly}, false},
		{"not slsa provenance", "https://aflock.ai/attestations/git/v0.1", provenanceWorkflowBuilderID, []cryptoutil.Verifier{keyOnly}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSLSAProvenance(raw(tc.pt, tc.id), tc.signers, tc.pt)
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			if tc.pt == legacySLSAProvenanceV10Type {
				var legacyErr ErrSLSALegacyProvenanceType
				require.True(t, errors.As(err, &legacyErr), "want ErrSLSALegacyProvenanceType, got %v", err)
				return
			}
			var unbacked ErrSLSABuilderIdentityUnbacked
			require.True(t, errors.As(err, &unbacked), "want ErrSLSABuilderIdentityUnbacked, got %v", err)
		})
	}

	t.Run("an undecodable provenance predicate fails closed", func(t *testing.T) {
		err := checkSLSAProvenance(attestation.NewRawAttestation(slsaProvenanceV1PredicateType, json.RawMessage(`{"runDetails":"nope"}`)), nil, slsaProvenanceV1PredicateType)
		require.Error(t, err)
	})
}

// A collection step carrying slsa provenance whose builder.id claims a
// workflow identity the authorized signer's cert does not carry is rejected.
func TestStepGateRejectsUnbackedSLSABuilderIdentity(t *testing.T) {
	signer := fulcioVerifier(t, "https://github.com/tenant/app/.github/workflows/ci.yml@refs/heads/main")
	step := Step{Name: "build", Attestations: []Attestation{{Type: slsaProvenanceV1PredicateType}}}
	coll := func(id string) source.CollectionVerificationResult {
		return source.CollectionVerificationResult{
			ValidFunctionaries: []cryptoutil.Verifier{signer},
			CollectionEnvelope: source.CollectionEnvelope{Collection: attestation.Collection{
				Name: "build",
				Attestations: []attestation.CollectionAttestation{{
					Type:        slsaProvenanceV1PredicateType,
					Attestation: attestation.NewRawAttestation(slsaProvenanceV1PredicateType, slsaPredicateWithBuilder(id)),
				}},
			}},
		}
	}

	res := step.validateAttestations([]source.CollectionVerificationResult{coll(provenanceWorkflowBuilderID)}, "", nil)
	require.Len(t, res.Rejected, 1)
	var unbacked ErrSLSABuilderIdentityUnbacked
	require.True(t, errors.As(res.Rejected[0].Reason, &unbacked), "got %v", res.Rejected[0].Reason)

	res = step.validateAttestations([]source.CollectionVerificationResult{coll("https://aflock.ai/cilock/inline/github-actions@v1")}, "", nil)
	require.Len(t, res.Passed, 1, "inline provenance must still pass: %v", res.Rejected)
}

// Provenance under the pre-#9827 type is refused by name wherever it appears:
// stored under it, or asked for by a policy that names it.
func TestExternalSLSARefusesTheLegacyPredicateType(t *testing.T) {
	for _, tc := range []struct{ policyType, storedType string }{
		{slsaProvenanceV1PredicateType, legacySLSAProvenanceV10Type},
		{legacySLSAProvenanceV10Type, legacySLSAProvenanceV10Type},
	} {
		t.Run(tc.policyType+" over "+tc.storedType, func(t *testing.T) {
			verifier, keyID := newECDSAVerifier(t)
			envelope := mkExternalEnvelope(t, tc.storedType, passingSLSAPredicate, verifier)
			p := Policy{
				Expires: futureExpiry(),
				Steps:   map[string]Step{"noop": validNoopStep(keyID)},
				ExternalAttestations: map[string]ExternalAttestation{
					"slsa": {
						Name:          "slsa",
						PredicateType: tc.policyType,
						Required:      true,
						Functionaries: []Functionary{{PublicKeyID: keyID}},
						RegoPolicies:  []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
					},
				},
			}
			ms := &stepAwareVerifiedSource{
				byStep:      map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(verifier)}},
				byPredicate: map[string][]source.StatementEnvelope{tc.storedType: {envelope}, tc.policyType: {envelope}},
			}
			pass, _, ext, err := p.VerifyWithExternals(context.Background(), WithVerifiedSource(ms), WithSubjectDigests([]string{"sha256:artifact"}))
			// The required external has no admissible candidate: the verify
			// fails, and says why in the customer's terms.
			require.Error(t, err)
			assert.Contains(t, err.Error(), "is no longer accepted; re-attest with SLSA v1")
			assert.False(t, pass, "provenance under %s must not pass", legacySLSAProvenanceV10Type)
			assert.Empty(t, ext["slsa"].Passed)
			require.Len(t, ext["slsa"].Rejected, 1)
			var legacyErr ErrSLSALegacyProvenanceType
			assert.True(t, errors.As(ext["slsa"].Rejected[0].Reason, &legacyErr), "want the named legacy refusal, got %v", ext["slsa"].Rejected[0].Reason)
		})
	}
}

// An external SLSA provenance whose builder.id claims the isolated provenance
// workflow, signed by a key that is an authorized functionary but carries no
// matching Build Signer URI, is rejected rather than trusted.
func TestExternalSLSARejectsUnbackedBuilderIdentity(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, slsaPredicateWithBuilder(provenanceWorkflowBuilderID), verifier)
	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": validNoopStep(keyID)},
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
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(verifier)}},
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
	}
	pass, _, ext, _ := p.VerifyWithExternals(context.Background(), WithVerifiedSource(ms), WithSubjectDigests([]string{"sha256:artifact"}))
	assert.False(t, pass)
	require.Len(t, ext["slsa"].Rejected, 1)
	var unbacked ErrSLSABuilderIdentityUnbacked
	require.True(t, errors.As(ext["slsa"].Rejected[0].Reason, &unbacked), "got %v", ext["slsa"].Rejected[0].Reason)
}

// Under nested semantics (the latest candidate decides) a candidate the SLSA
// provenance check refuses must still count as the latest verdict. Otherwise
// an older admitted provenance would stand in for a newer one whose
// builder.id claims a workflow identity its signer does not carry.
func TestLatestExternalRefusedBySLSACheckStillDecides(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	epoch := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	mk := func(ref, builder string, tsa int) source.StatementEnvelope {
		signed := epoch.Add(time.Duration(tsa) * time.Second)
		pred := json.RawMessage(`{"timeVerified":"` + signed.Format(time.RFC3339) + `","buildDefinition":{"buildType":"https://example.com/build/v1"},"runDetails":{"builder":{"id":"` + builder + `"}}}`)
		env := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, pred, verifier)
		env.Reference = ref
		env.VerifiedTimestampsByKeyID = map[string][]time.Time{keyID: {signed}}
		return env
	}
	older := mk("older", "https://aflock.ai/cilock/inline/github-actions@v1", 10)
	newer := mk("newer", provenanceWorkflowBuilderID, 20) // key-signed: unbacked
	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": validNoopStep(keyID)},
		ExternalAttestations: map[string]ExternalAttestation{"slsa": {
			Name: "slsa", PredicateType: slsaProvenanceV1PredicateType, Required: true,
			Functionaries:       []Functionary{{PublicKeyID: keyID}},
			RegoPolicies:        []RegoPolicy{{Module: regoAccept, Name: "accept.rego"}},
			TimestampConstraint: &TimestampConstraint{MaxAge: "876000h"},
		}},
	}
	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(verifier)}},
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {older, newer}},
	}
	pass, _, ext, _ := p.VerifyWithExternals(context.Background(), WithVerifiedSource(ms), WithSubjectDigests([]string{"sha256:artifact"}))
	assert.False(t, pass, "the newer, refused provenance must decide: %+v", ext["slsa"])
	assert.Empty(t, ext["slsa"].Passed)

	// Control: with only the older candidate, it decides and passes.
	ms.byPredicate[slsaProvenanceV1PredicateType] = []source.StatementEnvelope{older}
	pass, _, _, err := p.VerifyWithExternals(context.Background(), WithVerifiedSource(ms), WithSubjectDigests([]string{"sha256:artifact"}))
	require.NoError(t, err)
	assert.True(t, pass)
}

// Go's encoding/json matches a struct field to a key case-insensitively and
// keeps the last match, while Rego (and any map-based reader) keeps
// "runDetails" and "rundetails" as distinct keys. A body that spells a key on
// the builder.id path more than once, or only in another case, must be
// refused, or the check and the policy read different builder ids. Every
// level of the path is covered, and so is a key repeated in its exact
// spelling (which a first-wins reader would resolve the other way).
func TestCheckSLSABuilderIdentityRefusesCollidingKeys(t *testing.T) {
	keyOnly, _ := newECDSAVerifier(t)
	const inline = "https://aflock.ai/cilock/inline/github-actions@v1"
	wf := provenanceWorkflowBuilderID
	bodies := map[string]string{
		"runDetails then rundetails": `{"runDetails":{"builder":{"id":"` + wf + `"}},"rundetails":{"builder":{"id":"` + inline + `"}}}`,
		"rundetails then runDetails": `{"rundetails":{"builder":{"id":"` + inline + `"}},"runDetails":{"builder":{"id":"` + wf + `"}}}`,
		"builder then Builder":       `{"runDetails":{"builder":{"id":"` + wf + `"},"Builder":{"id":"` + inline + `"}}}`,
		"id then ID":                 `{"runDetails":{"builder":{"id":"` + wf + `","ID":"` + inline + `"}}}`,
		"id repeated exactly":        `{"runDetails":{"builder":{"id":"` + wf + `","id":"` + inline + `"}}}`,
		"only a case variant":        `{"RunDetails":{"builder":{"id":"` + inline + `"}}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			err := checkSLSAProvenance(attestation.NewRawAttestation(slsaProvenanceV1PredicateType, json.RawMessage(body)), []cryptoutil.Verifier{keyOnly}, slsaProvenanceV1PredicateType)
			var ambiguous ErrSLSABuilderKeyAmbiguous
			require.True(t, errors.As(err, &ambiguous), "want ErrSLSABuilderKeyAmbiguous, got %v", err)
		})
	}

	t.Run("keys off the builder.id path may differ only in case", func(t *testing.T) {
		body := `{"buildDefinition":{"buildType":"b"},"BuildDefinition":{},"runDetails":{"metadata":{},"Metadata":{},"builder":{"id":"` + inline + `","version":{},"Version":{}}}}`
		require.NoError(t, checkSLSAProvenance(attestation.NewRawAttestation(slsaProvenanceV1PredicateType, json.RawMessage(body)), []cryptoutil.Verifier{keyOnly}, slsaProvenanceV1PredicateType))
	})
}

// The external-verification form of the bypass: an authorized bare-key signer
// puts the provenance workflow in runDetails.builder.id, which the policy's
// Rego reads, and "inline" in rundetails.builder.id, which the struct decode
// used to read, skipping the Fulcio binding. It must be refused.
func TestExternalSLSARefusesCaseCollidingBuilderKeys(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	body := json.RawMessage(`{"buildDefinition":{"buildType":"https://example.com/build/v1"},"runDetails":{"builder":{"id":"` + provenanceWorkflowBuilderID + `"}},"rundetails":{"builder":{"id":"https://aflock.ai/cilock/inline/github-actions@v1"}}}`)
	envelope := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, body, verifier)
	requireWorkflow := []byte(`
package test
deny[msg] {
    input.runDetails.builder.id != "` + provenanceWorkflowBuilderID + `"
    msg := "builder is not the provenance workflow"
}
`)
	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": validNoopStep(keyID)},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa": {
				Name:          "slsa",
				PredicateType: slsaProvenanceV1PredicateType,
				Required:      true,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				RegoPolicies:  []RegoPolicy{{Module: requireWorkflow, Name: "workflow.rego"}},
			},
		},
	}
	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(verifier)}},
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {envelope}},
	}
	pass, _, ext, _ := p.VerifyWithExternals(context.Background(), WithVerifiedSource(ms), WithSubjectDigests([]string{"sha256:artifact"}))
	assert.False(t, pass, "a bare-key signer must not pass as the provenance workflow")
	assert.Empty(t, ext["slsa"].Passed)
	require.Len(t, ext["slsa"].Rejected, 1)
	var ambiguous ErrSLSABuilderKeyAmbiguous
	require.True(t, errors.As(ext["slsa"].Rejected[0].Reason, &ambiguous), "got %v", ext["slsa"].Rejected[0].Reason)
}
