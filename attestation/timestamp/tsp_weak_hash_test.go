// Copyright 2025 The Witness Contributors
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

package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // building an adversarial SHA-1 fixture on purpose
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/stretchr/testify/require"
)

// --- Adversarial fixture: forge an RFC 3161 timestamp token whose
// messageImprint uses a chosen hash algorithm, signed by a TSA leaf that
// chains to a trusted root and carries the sole id-kp-timeStamping EKU.
//
// The standard digitorus builder (Timestamp.CreateResponseWithOpts) refuses to
// mint a SHA-1 messageImprint token — populateSigningCertificateV2Ext returns
// "for SHA1 use ESSCertID instead of ESSCertIDv2" — which is exactly why TS3 is
// NOT a live end-to-end exploit against the platform TSA today. To exercise the
// VERIFIER in isolation (a trusted TSA that DID emit a weak-hash token, or a
// future/external TSA added to the trust set), we sign the raw TSTInfo directly
// via pkcs7, skipping the ESS attribute that Parse does not require.

// ess-free RFC 3161 TSTInfo structs (subset that timestamp.Parse consumes).
type fixtureMessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type fixtureAccuracy struct {
	Seconds int64 `asn1:"optional"`
}

type fixtureTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint fixtureMessageImprint
	SerialNumber   *big.Int
	Time           time.Time       `asn1:"generalized"`
	Accuracy       fixtureAccuracy `asn1:"optional"`
}

var (
	oidTSTInfo   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidTSAPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	oidHashSHA1  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidHashSHA2  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// trustedTSAChain builds a self-signed CA (the trusted TSA root) and a leaf
// certificate whose ONLY extended key usage is id-kp-timeStamping.
func trustedTSAChain(t *testing.T) (root *x509.Certificate, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-tsa-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-tsa-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Sole timeStamping EKU — passes the verifier's RFC 3161 §2.3 gate.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return root, leaf, leafKey
}

// forgeTimestampToken produces a validly-signed RFC 3161 token whose
// messageImprint uses hashOID over hashedMessage.
func forgeTimestampToken(t *testing.T, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, hashOID asn1.ObjectIdentifier, hashedMessage []byte) []byte {
	t.Helper()

	tst := fixtureTSTInfo{
		Version:      1,
		Policy:       oidTSAPolicy,
		SerialNumber: big.NewInt(1234567890),
		Time:         time.Now().UTC().Truncate(time.Second),
		Accuracy:     fixtureAccuracy{Seconds: 1},
		MessageImprint: fixtureMessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: hashOID, Parameters: asn1.NullRawValue},
			HashedMessage: hashedMessage,
		},
	}
	tstDER, err := asn1.Marshal(tst)
	require.NoError(t, err)

	sd, err := pkcs7.NewSignedData(tstDER)
	require.NoError(t, err)
	sd.SetContentType(oidTSTInfo)
	require.NoError(t, sd.AddSigner(leaf, leafKey, pkcs7.SignerInfoConfig{}))
	token, err := sd.Finish()
	require.NoError(t, err)
	return token
}

// TestSecurity_TS3_VerifierRejectsSHA1MessageImprint is the adversarial proof.
// A SHA-1 messageImprint token signed by a trusted TSA leaf must be REJECTED:
// SHA-1 has practical chosen-prefix collisions, so a legitimately issued
// timestamp over SHA1(P) can be rebound to a colliding payload P', forging
// proof-of-signing-time. Finding TS3 (#5749).
func TestSecurity_TS3_VerifierRejectsSHA1MessageImprint(t *testing.T) {
	root, leaf, leafKey := trustedTSAChain(t)
	payload := []byte("attacker-controlled payload timestamped under a weak hash")

	sha1Digest := sha1.Sum(payload) //nolint:gosec // adversarial fixture
	token := forgeTimestampToken(t, leaf, leafKey, oidHashSHA1, sha1Digest[:])

	// Sanity: the forged token parses and its messageImprint IS SHA-1 (i.e. the
	// fixture is valid and would sail through a naive verifier).
	parsed, err := timestamp.Parse(token)
	require.NoError(t, err, "forged SHA-1 token must be a valid, parseable RFC 3161 token")
	require.Equal(t, crypto.SHA1, parsed.HashAlgorithm, "fixture must use a SHA-1 messageImprint")

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{root}))
	_, err = v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.Error(t, err, "verifier must reject a SHA-1 messageImprint timestamp token")
	require.Contains(t, err.Error(), "collision-resistant",
		"rejection must name the weak-hash reason, not fail incidentally")
}

// TestSecurity_TS3_VerifierAcceptsSHA256MessageImprint is the positive control:
// a SHA-256 messageImprint token from the SAME fixture harness still verifies,
// proving the weak-hash gate does not regress legitimate (SHA-256) timestamps —
// the algorithm the platform TSA actually mints.
func TestSecurity_TS3_VerifierAcceptsSHA256MessageImprint(t *testing.T) {
	root, leaf, leafKey := trustedTSAChain(t)
	payload := []byte("legitimately timestamped payload")

	sha256Digest := sha256.Sum256(payload)
	token := forgeTimestampToken(t, leaf, leafKey, oidHashSHA2, sha256Digest[:])

	parsed, err := timestamp.Parse(token)
	require.NoError(t, err)
	require.Equal(t, crypto.SHA256, parsed.HashAlgorithm)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{root}))
	ts, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.NoError(t, err, "a SHA-256 messageImprint token must still verify")
	require.False(t, ts.IsZero(), "verified timestamp must carry a genTime")
}

// TestSecurity_TS3_CollisionResistanceGate characterizes the allow-list that
// backs the verifier's messageImprint check.
func TestSecurity_TS3_CollisionResistanceGate(t *testing.T) {
	accepted := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
	rejected := []crypto.Hash{crypto.SHA1, crypto.MD5, crypto.MD4, crypto.SHA224, crypto.RIPEMD160, crypto.Hash(0)}

	for _, h := range accepted {
		require.True(t, isCollisionResistantTimestampHash(h), "%v must be accepted", h)
	}
	for _, h := range rejected {
		require.False(t, isCollisionResistantTimestampHash(h), "%v must be rejected", h)
	}
}
