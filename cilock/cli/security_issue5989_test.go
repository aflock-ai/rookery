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

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// anonymousKeylessCollectionEnvelope builds the attacker-shaped keyless
// collection envelope #5989 is about: a short-lived leaf cert carrying NO email
// SAN and NO Common Name (an empty Subject), but a real RFC3161 timestamp token.
// This is the worst case for from-commit's evidence-driven derivation: the leaf
// has no recoverable identity, so the current code wildcards every cert
// constraint AND embeds the bundle's own TSA leaf as a trust anchor — producing
// a policy that "trusts whoever supplied the evidence."
func anonymousKeylessCollectionEnvelope(t *testing.T, stepName string, innerTypes []string) dsse.Envelope {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		// Empty Subject: no CN. No EmailAddresses: no SAN email. This is the
		// "no recoverable identity" leaf the attacker controls.
		Subject:               pkix.Name{},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * time.Minute), // short-lived, like Fulcio
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, leafTpl, &leafKey.PublicKey, leafKey)
	require.NoError(t, err)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyID, err := cryptoutil.GeneratePublicKeyID(&leafKey.PublicKey, crypto.SHA256)
	require.NoError(t, err)

	atts := make([]map[string]string, 0, len(innerTypes))
	for _, tp := range innerTypes {
		atts = append(atts, map[string]string{"type": tp})
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"subject":       []map[string]any{{"name": "commithash:abc", "digest": map[string]string{"sha1": "abc"}}},
		"predicateType": collectionPredicateURI,
		"predicate":     map[string]any{"name": stepName, "attestations": atts},
	}
	stmtBytes, err := json.Marshal(stmt)
	require.NoError(t, err)

	sigValue := []byte("attacker-signature-bytes")
	tsToken := mintRFC3161Token(t, sigValue) // reused from policy_from_bundles_test.go

	return dsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     stmtBytes,
		Signatures: []dsse.Signature{
			{
				KeyID:       keyID,
				Signature:   sigValue,
				Certificate: leafPEM,
				Timestamps: []dsse.SignatureTimestamp{
					{Type: dsse.TimestampRFC3161, Data: tsToken},
				},
			},
		},
	}
}

// TestSecurity_Issue5989_WildcardFunctionaryAndBundleTSAFromEvidence is the
// security regression for #5989. An attacker lands an attestation for the target
// commit (no SAN email, no CN, but a real RFC3161 timestamp) into the victim's
// tenant Archivista. When the victim runs `cilock policy from-commit`, the
// derivation must NOT:
//
//  1. emit a fully-wildcard functionary (CN=*, emails=[*], URIs=[*]), which
//     matches ANY identity under the evidence-derived root, nor
//  2. register the bundle's own TSA leaf as a TimestampAuthority trust anchor,
//     which would let the attacker's evidence supply its own proof-of-time.
//
// Both make the resulting policy trivially satisfiable by the attacker who
// supplied the evidence. SECURE behavior: omit the unidentifiable functionary
// and refuse the evidence-derived TSA anchor.
func TestSecurity_Issue5989_WildcardFunctionaryAndBundleTSAFromEvidence(t *testing.T) {
	attackerEnv := anonymousKeylessCollectionEnvelope(t, "build",
		[]string{"https://slsa.dev/provenance/v1"})

	fetcher := &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{
		"gitoid-attacker": attackerEnv,
	}}
	installFakeCommitFetcher(t, fetcher)

	var errOut bytes.Buffer
	pol, _, err := derivePolicyFromCommit(context.Background(), &errOut,
		policyFromCommitOpts{expiresIn: 365 * 24 * time.Hour},
		testCommitSHA, "https://archivista.example", "bearer-token")
	require.NoError(t, err)

	// (1) No derived functionary may be fully-wildcard. A functionary whose
	// CN, every email, and every URI are all AllowAllConstraint ("*") trusts
	// any identity under the evidence-supplied root — the #5989 escalation.
	for _, step := range pol.Steps {
		for _, fn := range step.Functionaries {
			assert.False(t, isFullyWildcardFunctionary(fn),
				"derived functionary must not be fully-wildcard (CN=*, emails=[*], URIs=[*]); "+
					"an unidentifiable leaf must be omitted, not wildcarded: %#v", fn)
		}
	}

	// (2) The policy must carry NO bundle-derived TSA anchor. The attacker's
	// RFC3161 token embeds its own TSA leaf; trusting it lets the evidence
	// supply its own proof-of-signing-time.
	assert.Empty(t, pol.TimestampAuthorities,
		"derived policy must not register the bundle's own TSA leaf as a trust anchor")
}

// TestSecurity_Issue5989_OneShotRefusesAutoPublishWithoutYes is the review-gate
// half of #5989: one-shot from-commit (--product + --tag) derives functionaries
// entirely from platform evidence with no operator key anchor, so it must NOT
// sign+push+bind without explicit --yes confirmation. The command must error and
// print the derived trust surface for review.
func TestSecurity_Issue5989_OneShotRefusesAutoPublishWithoutYes(t *testing.T) {
	installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{
		"g1": pubkeyCollectionEnvelope(t, "build", []string{"https://slsa.dev/provenance/v1"}),
	}})
	srv := newPolicyTestServer(t, func(string, map[string]any, http.ResponseWriter) bool { return true })
	stubSession(t, srv.URL)

	// One-shot WITHOUT --yes must refuse and never reach sign/push/bind.
	out, err := runCmd(t, PolicyFromCommitCmd(), testCommitSHA,
		"--platform-url", srv.URL, "--product", "my-svc", "--tag", "v1")
	require.Error(t, err, "one-shot publish must be refused without --yes; output:\n%s", out)
	assert.Contains(t, err.Error(), "--yes",
		"the refusal must steer the operator to --yes (or author-for-review)")
	assert.Contains(t, err.Error(), "trusts whoever supplied that evidence",
		"the refusal must explain the evidence-derived trust risk")
}

// isFullyWildcardFunctionary reports whether a cert functionary's identity
// constraints are all the AllowAll wildcard ("*") — CN, every email, and every
// URI. Such a functionary matches any identity under its root.
func isFullyWildcardFunctionary(fn policy.Functionary) bool {
	cc := fn.CertConstraint
	if cc.CommonName != policy.AllowAllConstraint {
		return false
	}
	if len(cc.Emails) == 0 || len(cc.URIs) == 0 {
		return false
	}
	for _, e := range cc.Emails {
		if e != policy.AllowAllConstraint {
			return false
		}
	}
	for _, u := range cc.URIs {
		if u != policy.AllowAllConstraint {
			return false
		}
	}
	return true
}
