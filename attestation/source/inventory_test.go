// jade:ring local

package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/require"
)

type inventorySourceTest struct {
	Sourcer
	env             dsse.Envelope
	candidates      []StatementEnvelope
	err             error
	calls           int
	types, subjects []string
}

func (s *inventorySourceTest) SearchByPredicateType(_ context.Context, types, subjects []string) ([]StatementEnvelope, error) {
	s.calls++
	s.types, s.subjects = types, subjects
	if s.candidates != nil {
		return s.candidates, s.err
	}
	return []StatementEnvelope{{Envelope: s.env, Statement: intoto.Statement{Predicate: json.RawMessage(`{"forged":true}`)}}}, s.err
}

func TestInventoryLookupDuplicateEnvelopesAndMalformedCandidates(t *testing.T) {
	body := []byte(`{"schema":"` + fileinventory.Type + `","kind":"product","entries":[]}`)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	valid := dsse.Envelope{PayloadType: intoto.PayloadType, Payload: []byte(`{"predicateType":"` + fileinventory.Type + `","subject":[{"digest":{"sha256":"` + digest + `"}}],"predicate":` + string(body) + `}`)}
	malformed := []dsse.Envelope{
		{PayloadType: intoto.PayloadType, Payload: []byte(`{`)},
		{PayloadType: intoto.PayloadType, Payload: []byte(`{"predicateType":"` + fileinventory.Type + `","subject":[{"digest":{"sha256":"` + digest + `"}}],"predicate":{}}`)},
		{PayloadType: intoto.PayloadType, Payload: []byte(`{"predicateType":"` + fileinventory.Type + `","subject":[],"predicate":` + string(body) + `}`)},
		{PayloadType: "text/plain", Payload: valid.Payload},
	}
	for _, tc := range []struct {
		name          string
		invalidPrefix int
		want          bool
	}{
		{"seventeen-identical-bodies", 0, true},
		{"invalid-before-valid", 1, true},
		{"valid-at-inspection-bound", 15, true},
		{"no-valid-body-within-bound", 16, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &inventorySourceTest{}
			for i := 0; i < 17; i++ {
				env := valid
				if i < tc.invalidPrefix {
					env = malformed[i%len(malformed)]
				}
				env.Signatures = []dsse.Signature{{KeyID: fmt.Sprintf("run-%d", i), Signature: []byte{byte(i)}}}
				s.candidates = append(s.candidates, StatementEnvelope{Envelope: env, Reference: fmt.Sprintf("wrapper-%d", i)})
			}
			got, ok := InventoryLookup(t.Context(), s)(digest)
			require.Equal(t, tc.want, ok)
			if ok {
				require.Equal(t, body, got)
			}
		})
	}
}

func TestInventoryLookupExactPayloadAndSubject(t *testing.T) {
	body := []byte(`{ "schema":"` + fileinventory.Type + `", "kind":"product", "entries":[] }`)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	s := &inventorySourceTest{env: dsse.Envelope{PayloadType: intoto.PayloadType, Payload: []byte(`{"predicateType":"` + fileinventory.Type + `","subject":[{"name":"inventory:product","digest":{"sha256":"` + digest + `"}}],"predicate":` + string(body) + `}`)}}
	lookup := InventoryLookup(context.Background(), s)
	got, ok := lookup(digest)
	require.True(t, ok)
	require.Equal(t, body, got)
	require.Equal(t, []string{fileinventory.Type}, s.types)
	require.Equal(t, []string{digest}, s.subjects)
	_, ok = lookup(digest)
	require.True(t, ok)
	require.Equal(t, 1, s.calls)
	_, ok = lookup("https://untrusted.invalid/inventory")
	require.False(t, ok)
	require.Equal(t, 1, s.calls)
	s.err = errors.New("source unavailable")
	_, ok = InventoryLookup(context.Background(), s)(digest)
	require.False(t, ok)
	s.err = nil
	s.env.Payload = []byte(`{"predicateType":"` + fileinventory.Type + `","subject":[],"predicate":` + string(body) + `}`)
	_, ok = InventoryLookup(context.Background(), s)(digest)
	require.False(t, ok)
}
