// jade:ring local

package secretscan

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// #10618: cilock's own v0.2 collection output (one that records a failed
// attestor) is recognised as its own output, like v0.1.
func TestIsCollectionEnvelopeJSONV02(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"predicateType": attestation.CollectionTypeV02})
	env, _ := json.Marshal(map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"payloadType": intoto.PayloadType,
		"signatures":  []any{map[string]any{"sig": "x"}},
	})
	if !isCollectionEnvelopeJSON(env) {
		t.Fatal("a v0.2 collection envelope is cilock's own output")
	}
}
