// jade:ring local

package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// #10618: a v0.2 collection is a collection, and a recorded failure is never
// evidence. It does not satisfy a required type, so a step requiring the type
// that failed denies exactly as when the attestor was omitted.

func failedCVR(predicateType string, failed []attestation.FailedAttestor, atts ...attestation.CollectionAttestation) func(t *testing.T) (Step, source.CollectionVerificationResult) {
	return func(t *testing.T) (Step, source.CollectionVerificationResult) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		v := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
		keyID, err := v.KeyID()
		require.NoError(t, err)
		cvr := source.CollectionVerificationResult{
			Verifiers: []cryptoutil.Verifier{v},
			CollectionEnvelope: source.CollectionEnvelope{
				Collection: attestation.Collection{Name: "test", Attestations: atts, FailedAttestors: failed},
				Statement:  intoto.Statement{PredicateType: predicateType},
			},
		}
		step := Step{Name: "test", Functionaries: []Functionary{{Type: "publickey", PublicKeyID: keyID}}}
		return step, cvr
	}
}

func TestFailedAttestor_V02CollectionIsTriagedAsACollection(t *testing.T) {
	failed := []attestation.FailedAttestor{{Name: "test-results", Class: attestation.FailureNoInput}}
	step, cvr := failedCVR(attestation.CollectionTypeV02, failed, attestation.CollectionAttestation{Type: "https://example.com/git/v1", Attestation: &dummyAttestor{}})(t)
	res := step.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)
	require.Empty(t, res.Rejected, "%+v", res.Rejected)
	require.Len(t, res.Passed, 1)
}

func TestFailedAttestor_V01CarryingARecordIsRefused(t *testing.T) {
	failed := []attestation.FailedAttestor{{Name: "test-results", Class: attestation.FailureNoInput}}
	step, cvr := failedCVR(attestation.CollectionType, failed)(t)
	res := step.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)
	require.Len(t, res.Rejected, 1)
	require.Contains(t, res.Rejected[0].Reason.Error(), "failedattestors")
}

func TestFailedAttestor_RecordNeverSatisfiesARequiredType(t *testing.T) {
	const required = "https://example.com/test-results/v1"
	failed := []attestation.FailedAttestor{{Name: "test-results", Class: attestation.FailureNoInput}}
	for name, f := range map[string][]attestation.FailedAttestor{"omitted (v0.1)": nil, "recorded failure (v0.2)": failed} {
		t.Run(name, func(t *testing.T) {
			pt := attestation.CollectionType
			if f != nil {
				pt = attestation.CollectionTypeV02
			}
			step, cvr := failedCVR(pt, f, attestation.CollectionAttestation{Type: "https://example.com/git/v1", Attestation: &dummyAttestor{}})(t)
			step.Attestations = []Attestation{{Type: required}}
			res := step.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
			require.Empty(t, res.Passed, "a recorded failure is not the attestation it failed to produce")
			require.Len(t, res.Rejected, 1)
		})
	}
}

// Verify still reports the required type as missing, and now says the
// collection recorded the attempt: "attempted and failed", not "never ran".
func TestFailedAttestor_DiagnoseNamesTheRecordedFailure(t *testing.T) {
	failed := []attestation.FailedAttestor{{Name: "test-results", Class: attestation.FailureNoInput}}
	_, cvr := failedCVR(attestation.CollectionTypeV02, failed, attestation.CollectionAttestation{Type: "https://example.com/git/v1", Attestation: &dummyAttestor{}})(t)
	desc := describeIneligibleCollection(cvr, nil, []string{"https://example.com/test-results/v1"})
	require.Equal(t, []string{"https://example.com/test-results/v1"}, desc.MissingAttestations)
	require.Contains(t, desc.describe(), "is missing required attestation https://example.com/test-results/v1")
	require.Contains(t, desc.describe(), "attempted and failed: test-results (no-input)")
}
