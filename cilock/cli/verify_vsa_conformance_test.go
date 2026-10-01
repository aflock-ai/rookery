// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0
// jade:ring local

package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyVSAConformance(t *testing.T) {
	f := newOfflineVerifyFixture(t)
	artifact := filepath.Join(f.dir, "out.bin")
	require.NoError(t, os.WriteFile(artifact, []byte("verified artifact\n"), 0o600))
	digest := artifactSHA256Hex(t, artifact)
	const predicateType = "https://aflock.ai/attestations/git/v0.1"
	evidence := f.collection(t, "build.att.json", "build", []string{predicateType}, fmt.Sprintf(`{"name":"out.bin","digest":{"sha256":%q}}`, digest))
	policyPath := f.policy(t, "policy.signed.json", map[string][]string{"build": {predicateType}})
	output := filepath.Join(f.dir, "vsa.json")
	_, stderr, err := f.verify(t, policyPath, "-a", evidence, "-f", artifact, "--vsa-outfile", output)
	require.NoError(t, err, "%s", stderr)
	body, err := os.ReadFile(output)
	require.NoError(t, err)
	var statement intoto.Statement
	require.NoError(t, json.Unmarshal(body, &statement))
	assert.Equal(t, "https://in-toto.io/Statement/v1", statement.Type)
	assert.Equal(t, "https://slsa.dev/verification_summary/v1", statement.PredicateType)
	require.Len(t, statement.Subject, 1)
	assert.Equal(t, artifact, statement.Subject[0].Name)
	assert.Equal(t, digest, statement.Subject[0].Digest["sha256"])
	var predicate struct {
		ResourceURI    string   `json:"resourceUri"`
		VerifiedLevels []string `json:"verifiedLevels"`
		Verifier       struct {
			ID string `json:"id"`
		} `json:"verifier"`
	}
	require.NoError(t, json.Unmarshal(statement.Predicate, &predicate))
	expectedURI := (&url.URL{Scheme: "file", Path: filepath.ToSlash(artifact)}).String()
	assert.Equal(t, expectedURI, predicate.ResourceURI)
	assert.Equal(t, []string{"SLSA_BUILD_LEVEL_UNEVALUATED"}, predicate.VerifiedLevels)
	uri, err := url.Parse(predicate.Verifier.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, uri.Scheme, "verifier.id must be an absolute TypeURI")
}
