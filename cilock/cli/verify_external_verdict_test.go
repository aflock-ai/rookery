// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0
// jade:ring local

package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/stretchr/testify/require"
)

// #8121 through `cilock verify --vsa-outfile`: a policy that fails because a
// required external attestation is missing has reached a verdict, so the VSA
// must say FAILED. A verify that reached no verdict at all (here: the policy
// signature does not verify) must write no VSA, never a signed summary whose
// verificationResult is empty.
func TestVerifyVSAOutfile_ExternalVerdictAndNoVerdict(t *testing.T) {
	f := newOfflineVerifyFixture(t)
	artifact := filepath.Join(f.dir, "out.bin")
	require.NoError(t, os.WriteFile(artifact, []byte("verified artifact\n"), 0o600))
	digest := artifactSHA256Hex(t, artifact)
	const predicateType = "https://aflock.ai/attestations/git/v0.1"
	evidence := f.collection(t, "build.att.json", "build", []string{predicateType}, fmt.Sprintf(`{"name":"out.bin","digest":{"sha256":%q}}`, digest))

	stepsOnly := f.policy(t, "steps.signed.json", map[string][]string{"build": {predicateType}})
	raw, err := os.ReadFile(stepsOnly)
	require.NoError(t, err)
	var env struct {
		Payload []byte `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(raw, &env))
	var doc map[string]any
	require.NoError(t, json.Unmarshal(env.Payload, &doc))
	doc["externalAttestations"] = map[string]any{
		"child": map[string]any{
			"name":          "child",
			"predicateType": "https://example.com/child-vsa/v1",
			"functionaries": []any{map[string]any{"type": "publickey", "publickeyid": f.keyID}},
			"required":      true,
		},
	}
	withExternal, err := json.Marshal(doc)
	require.NoError(t, err)

	t.Run("missing required external writes a FAILED VSA", func(t *testing.T) {
		policyPath := f.writeSigned(t, "external.signed.json", policy.PolicyPredicate, withExternal)
		output := filepath.Join(f.dir, "failed.vsa.json")
		_, stderr, err := f.verify(t, policyPath, "-a", evidence, "-f", artifact, "--vsa-outfile", output)
		require.Error(t, err, "%s", stderr)
		v, code := classifyVerifyFailure(err)
		require.Equal(t, VerdictDenied, v, "%v", err)
		require.Equal(t, ExitDenied, code)
		body, readErr := os.ReadFile(output)
		require.NoError(t, readErr, "a denial must still write its VSA: %s", stderr)
		var statement intoto.Statement
		require.NoError(t, json.Unmarshal(body, &statement))
		var predicate slsa.VerificationSummary
		require.NoError(t, json.Unmarshal(statement.Predicate, &predicate))
		require.Equal(t, slsa.FailedVerificationResult, predicate.VerificationResult)
		require.NotEmpty(t, predicate.Policy.Digest)
	})

	t.Run("a policy whose signature does not verify writes no VSA", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		stranger, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
		require.NoError(t, err)
		own := f.signer
		f.signer = stranger
		policyPath := f.writeSigned(t, "stranger.signed.json", policy.PolicyPredicate, withExternal)
		f.signer = own
		output := filepath.Join(f.dir, "noverdict.vsa.json")
		_, stderr, err := f.verify(t, policyPath, "-a", evidence, "-f", artifact, "--vsa-outfile", output)
		require.Error(t, err, "%s", stderr)
		_, statErr := os.Stat(output)
		require.True(t, os.IsNotExist(statErr), "no verdict was reached, so no VSA may be written (stat: %v)", statErr)
	})
}
