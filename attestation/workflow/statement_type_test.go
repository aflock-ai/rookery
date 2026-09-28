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

package workflow

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// Every statement a cilock run signs (the collection and every exported
// predicate, SLSA provenance included) carries the in-toto Statement v1
// _type, the one slsa-verifier and gh attestation verify expect.
func TestRunSignsInTotoStatementV1(t *testing.T) {
	exported := &exportingBulkAttestor{bulkAttestor{name: "bulk", typeURI: "https://example.com/bulk/v1", body: "x"}}
	results, err := RunWithExports("statement-type", RunWithSigners(sizeTestSigner(t)), RunWithAttestors([]attestation.Attestor{exported}))
	require.NoError(t, err)

	envelopes := make([][]byte, 0, len(results))
	for _, r := range results {
		envelopes = append(envelopes, r.SignedEnvelope.Payload)
	}
	require.GreaterOrEqual(t, len(envelopes), 2, "want the collection and the exported predicate")
	for _, payload := range envelopes {
		var stmt struct {
			Type string `json:"_type"`
		}
		require.NoError(t, json.Unmarshal(payload, &stmt))
		require.Equal(t, "https://in-toto.io/Statement/v1", stmt.Type)
	}
}

type exportingBulkAttestor struct{ bulkAttestor }

func (e *exportingBulkAttestor) Export() bool { return true }
func (e *exportingBulkAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{"file:x": {{Hash: crypto.SHA256}: "abc"}}
}
