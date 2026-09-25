// jade:ring local

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

package dsse

// formal:differential
//
// Binds the Lean model of this verifier (formal/sigstore, Sigstore/Dsse.lean,
// #9916) to Envelope.Verify. Each vector sets whether the policy supplies TSA
// roots, the timestamp (absent / valid / invalid), a chain fault (none, the
// TSA time outside the leaf's validity window, an untrusted root), a bad
// signature, and an SCT (absent, or a forged one). The verdict must equal
// the model's. Only certificate trust is offered; no raw key verifier is
// passed, so every accept went through path validation.
//
// The vectors live in the Judge monorepo (formal/sigstore/vectors/dsse.json),
// so this test skips when rookery is built on its own, unless
// JADE_FORMAL_DIFFERENTIAL=1, which makes their absence a failure.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/require"
)

const formalSigstoreDSSEVectors = "../../../../formal/sigstore/vectors/dsse.json"

// oidEmbeddedSCTList is RFC 6962's embedded SCT list extension.
var oidEmbeddedSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func formalLeaf(t *testing.T, parent *x509.Certificate, parentPriv any, forgedSCT bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	// P-256, not RSA: 72 RSA-2048 keygens cost ~38s; these cost milliseconds.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := &priv.PublicKey
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "formal leaf"},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(2 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if forgedSCT {
		junk := make([]byte, 48)
		_, err := rand.Read(junk)
		require.NoError(t, err)
		val, err := asn1.Marshal(junk)
		require.NoError(t, err)
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidEmbeddedSCTList, Value: val}}
	}
	cert, err := createCert(parentPriv, pub, tmpl, parent)
	require.NoError(t, err)
	return cert, priv
}

func TestFormalDifferentialSigstoreDSSE(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(formalSigstoreDSSEVectors))
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var v struct {
		Cases []struct {
			TSARoots   bool   `json:"tsa_roots"`
			Timestamp  string `json:"timestamp"`
			ChainFault string `json:"chain_fault"`
			SigOK      bool   `json:"sig_ok"`
			SCT        string `json:"sct"`
			Accept     bool   `json:"accept"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Cases)

	trusted, trustedPriv, err := createRoot()
	require.NoError(t, err)
	stranger, strangerPriv, err := createRoot()
	require.NoError(t, err)

	inWindow := time.Now().Add(time.Hour).Truncate(time.Second)
	outOfWindow := time.Now().Add(36 * time.Hour).Truncate(time.Second)

	var accepted, refused int
	for i, c := range v.Cases {
		parent, parentPriv := trusted, trustedPriv
		if c.ChainFault == "root" {
			parent, parentPriv = stranger, strangerPriv
		}
		leaf, leafPriv := formalLeaf(t, parent, parentPriv, c.SCT == "invalid")
		signer, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
		require.NoError(t, err)

		at := inWindow
		if c.ChainFault == "window" {
			at = outOfWindow
		}
		signOpts := []SignOption{SignWithSigners(signer)}
		if c.Timestamp != "absent" {
			signOpts = append(signOpts, SignWithTimestampers(timestamp.FakeTimestamper{T: at}))
		}
		env, err := Sign("formal/sigstore", bytes.NewReader([]byte("payload")), signOpts...)
		require.NoError(t, err)
		if !c.SigOK {
			env.Signatures[0].Signature[0] ^= 0xff
		}

		verifyOpts := []VerificationOption{VerifyWithRoots(trusted)}
		if c.TSARoots {
			tsa := timestamp.FakeTimestamper{T: at}
			if c.Timestamp == "invalid" {
				// A TSA the policy does not trust for this token: verification fails.
				tsa = timestamp.FakeTimestamper{T: at.Add(time.Second)}
			}
			verifyOpts = append(verifyOpts, VerifyWithTimestampVerifiers(tsa))
		}
		_, err = env.Verify(verifyOpts...)
		got := err == nil
		require.Equal(t, c.Accept, got, "case %d %+v: verify err=%v", i, c, err)
		if got {
			accepted++
		} else {
			refused++
		}
	}
	t.Logf("formal:differential: cases=%d accepted=%d refused=%d", len(v.Cases), accepted, refused)
	require.Positive(t, accepted)
	require.Positive(t, refused)
}
