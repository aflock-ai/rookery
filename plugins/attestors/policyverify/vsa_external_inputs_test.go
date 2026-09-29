// jade:ring local

package policyverify

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A parent policy's verdict is decided by its externals as much as by its steps (a child VSA is
// an external). The VSA must name the external evidence that decided it, by the digest of its
// signed payload, or no one can tell from the VSA which child verdict it judged.
func TestVSAInputAttestations_NameDecidingExternals(t *testing.T) {
	actx, err := attestation.NewContext("vsa-test", nil)
	require.NoError(t, err)
	child := []byte(`{"predicateType":"https://slsa.dev/verification_summary/v1"}`)
	other := []byte(`{"predicateType":"https://slsa.dev/verification_summary/v1","n":2}`)
	ext := map[string]policy.ExternalResult{
		"estate": {
			Passed:   []policy.PassedExternal{{Envelope: source.StatementEnvelope{Envelope: dsse.Envelope{Payload: child}, Reference: "estate.vsa.json"}}},
			Rejected: []policy.RejectedExternal{{Envelope: source.StatementEnvelope{Envelope: dsse.Envelope{Payload: other}, Reference: "old.vsa.json"}}},
		},
		"skipped": {Skipped: true},
	}
	want, err := cryptoutil.CalculateDigestSetFromBytes(child, actx.Hashes())
	require.NoError(t, err)

	got := externalInputAttestations(actx, ext, true)
	require.Len(t, got, 1, "a passing verdict names the passed externals only")
	assert.Equal(t, "estate.vsa.json", got[0].URI)
	assert.Equal(t, want, got[0].Digest)

	got = externalInputAttestations(actx, ext, false)
	require.Len(t, got, 2, "a failing verdict also names the rejected ones, as it does for collections")

	// An envelope without a reference is still named, by its external's name.
	noRef := map[string]policy.ExternalResult{"estate": {Passed: []policy.PassedExternal{{Envelope: source.StatementEnvelope{Envelope: dsse.Envelope{Payload: child}}}}}}
	got = externalInputAttestations(actx, noRef, true)
	require.Len(t, got, 1)
	assert.Equal(t, "external:estate", got[0].URI)
}
