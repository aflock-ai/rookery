// jade:ring local

package attestation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// #10618: a v0.2 collection records each attestor that was attempted and
// failed, by name and a fixed error class only. No error text is recorded:
// it can carry paths and tool output (Cole, 2026-10-01).

func TestIsCollectionType(t *testing.T) {
	for _, pt := range []string{CollectionType, LegacyCollectionType, CollectionTypeV02} {
		require.True(t, IsCollectionType(pt), pt)
	}
	for _, pt := range []string{"", "https://aflock.ai/attestation-collection/v0.3", "https://slsa.dev/provenance/v1"} {
		require.False(t, IsCollectionType(pt), pt)
	}
}

func TestFailedAttestorsRoundTripNameAndClassOnly(t *testing.T) {
	c := Collection{Name: "test", FailedAttestors: []FailedAttestor{{Name: "test-results", Class: FailureNoInput}}}
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"test","attestations":null,"failedattestors":[{"name":"test-results","class":"no-input"}]}`, string(raw))

	var back Collection
	require.NoError(t, json.Unmarshal(raw, &back))
	require.Equal(t, c.FailedAttestors, back.FailedAttestors)

	plain, err := json.Marshal(Collection{Name: "test"})
	require.NoError(t, err)
	require.NotContains(t, string(plain), "failedattestors", "a collection with no failures serializes exactly as before")
}

func TestValidateFailedAttestors(t *testing.T) {
	ok := []FailedAttestor{{Name: "test-results", Class: FailureNoInput}, {Name: "sbom", Class: FailureTimeout}}
	require.NoError(t, (&Collection{FailedAttestors: ok}).ValidateFailedAttestors(CollectionTypeV02))
	require.NoError(t, (&Collection{}).ValidateFailedAttestors(CollectionType), "a v0.1 collection without records is unchanged")

	for name, tc := range map[string]struct {
		pt     string
		failed []FailedAttestor
	}{
		"v0.1 carrying a record":   {CollectionType, ok},
		"legacy carrying a record": {LegacyCollectionType, ok},
		"unknown class":            {CollectionTypeV02, []FailedAttestor{{Name: "sbom", Class: "segfault at /home/me"}}},
		"empty name":               {CollectionTypeV02, []FailedAttestor{{Class: FailureCrash}}},
		"duplicate name":           {CollectionTypeV02, []FailedAttestor{{Name: "sbom", Class: FailureCrash}, {Name: "sbom", Class: FailureTimeout}}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, (&Collection{FailedAttestors: tc.failed}).ValidateFailedAttestors(tc.pt))
		})
	}
}
