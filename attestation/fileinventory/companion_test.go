// jade:ring local

package fileinventory_test

import (
	"bytes"
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/invopop/jsonschema"
	validation "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/require"
)

func TestInventoryCompanion(t *testing.T) {
	ref, body, err := fileinventory.Encode("product", "walk", []fileinventory.Entry{{Path: "a", FileDigest: strings.Repeat("0", 64)}})
	require.NoError(t, err)
	companion := attestation.NewInventoryCompanion("product", body)
	require.Equal(t, fileinventory.Type, companion.Type())
	require.Equal(t, "inventory", companion.Name())
	require.Error(t, companion.Attest(nil))
	raw, err := json.Marshal(companion)
	require.NoError(t, err)
	require.Equal(t, body, raw)
	require.Equal(t, map[string]cryptoutil.DigestSet{"inventory:product": {{Hash: crypto.SHA256}: ref.Digest}}, companion.(attestation.Subjecter).Subjects())
	body[0] = 'x'
	raw, err = json.Marshal(companion)
	require.NoError(t, err, "constructor must own its bytes")
	require.NotEqual(t, body, raw)
}

func TestInventoryCompanionRejectsEncodingChanges(t *testing.T) {
	_, body, err := fileinventory.Encode("product", "walk", []fileinventory.Entry{{Path: "<output>", FileDigest: strings.Repeat("0", 64)}})
	require.NoError(t, err)
	for _, changed := range [][]byte{
		append(append([]byte(nil), body...), '\n'),
		bytes.Replace(body, []byte(`\u003c`), []byte("<"), 1),
	} {
		_, err := json.Marshal(attestation.NewInventoryCompanion("product", changed))
		require.Error(t, err, "embedding must not change bytes under the digest subject")
	}
}

func TestReferenceSchema(t *testing.T) {
	raw, err := json.Marshal(jsonschema.Reflect(&fileinventory.Reference{}))
	require.NoError(t, err)
	schema, err := validation.CompileString("inventory.json", string(raw))
	require.NoError(t, err)
	ref := fileinventory.NewOmitted("material", "walk", 2)
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) {},
		func(m map[string]any) { m["digest"] = strings.Repeat("0", 64) },
		func(m map[string]any) { m["state"] = "detached" },
		func(m map[string]any) { m["captureScope"] = "trace-provider" },
		func(m map[string]any) { m["schema"] = "v9" },
	} {
		body, err := json.Marshal(ref)
		require.NoError(t, err)
		var value map[string]any
		require.NoError(t, json.Unmarshal(body, &value))
		mutate(value)
		var parsed fileinventory.Reference
		body, err = json.Marshal(value)
		require.NoError(t, err)
		if json.Unmarshal(body, &parsed) == nil {
			require.NoError(t, schema.Validate(value))
		} else {
			require.Error(t, schema.Validate(value), string(body))
		}
	}
}
