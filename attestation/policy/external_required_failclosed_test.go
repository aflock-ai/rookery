// Copyright 2026 TestifySec, Inc.
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
//
// External-attestation `Required` fail-closed acceptance tests (rookery
// red-team 2026-06-29). Promoted from the redgate scaffold now that the fix has
// landed (ExternalAttestation.UnmarshalJSON defaults an omitted "required" to
// true) — these are the Green acceptance criteria and a regression guard.
//
// The finding: ExternalAttestation.Required is a plain bool whose jsonschema
// documents "When true (default), verification fails if no envelope matches",
// but the Go zero value is false and policies load via plain json.Unmarshal, so
// an author who omitted "required" (per the documented default) to mandate SLSA
// provenance / a VSA got a silently OPTIONAL gate — an artifact with no
// provenance verified.

package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A policy whose external attestation OMITS "required" — i.e. the author relied
// on the documented default ("true") to mandate provenance.
const externalRequiredOmittedPolicyJSON = `{
  "externalAttestations": {
    "prov": {
      "name": "prov",
      "predicateType": "https://slsa.dev/provenance/v1",
      "functionaries": [{"type": "publickey", "publickeyid": "k1"}]
    }
  }
}`

// Parse level: an omitted "required" must default to REQUIRED.
func TestExternalRequired_DefaultsTrueWhenOmitted(t *testing.T) {
	var p Policy
	require.NoError(t, json.Unmarshal([]byte(externalRequiredOmittedPolicyJSON), &p))
	ext, ok := p.ExternalAttestations["prov"]
	require.True(t, ok, "external attestation should be parsed")
	assert.True(t, ext.Required,
		`external attestation with omitted "required" must default to REQUIRED (fail-closed); `+
			`a plain bool zero-value (false) silently makes a mandatory provenance/VSA gate optional`)
}

// An explicit "required": false must still opt out (back-compat for genuinely
// optional externals).
func TestExternalRequired_ExplicitFalseOptsOut(t *testing.T) {
	const optionalJSON = `{
  "externalAttestations": {
    "prov": {
      "name": "prov",
      "predicateType": "https://slsa.dev/provenance/v1",
      "functionaries": [{"type": "publickey", "publickeyid": "k1"}],
      "required": false
    }
  }
}`
	var p Policy
	require.NoError(t, json.Unmarshal([]byte(optionalJSON), &p))
	assert.False(t, p.ExternalAttestations["prov"].Required,
		`an explicit "required": false must remain optional`)
}

// Behavior level: an external that is required-by-default with ZERO matching
// envelopes must fail closed (ErrMissingExternalAttestation), not be Skipped.
func TestExternalRequired_MissingEnvelopeFailsClosed(t *testing.T) {
	var p Policy
	require.NoError(t, json.Unmarshal([]byte(externalRequiredOmittedPolicyJSON), &p))

	vo := &verifyOptions{
		verifiedSource: &mockVerifiedSource{}, // SearchByPredicateType returns 0 envelopes
		subjectDigests: []string{"sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
	}
	_, err := p.verifyExternalAttestations(context.Background(), vo, nil)
	require.Error(t, err,
		"a required-by-default external with no matching envelope must fail closed, not pass")
	var missing ErrMissingExternalAttestation
	assert.ErrorAs(t, err, &missing,
		"missing required external must surface ErrMissingExternalAttestation, not be silently Skipped")
}
