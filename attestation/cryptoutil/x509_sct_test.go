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

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Tests for #10032: the certificate path must verify the SCT a CT-logging CA
// embeds in its leaves (Sigstore client spec §4.3).

type ctTestPKI struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	logKey   *ecdsa.PrivateKey
	log      CTLog
	now      time.Time
	leafKey  *ecdsa.PrivateKey
	template *x509.Certificate
}

func newCTTestPKI(t *testing.T) *ctTestPKI {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ct test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	log, err := NewCTLog("https://ct.test", &logKey.PublicKey, time.Time{}, time.Time{})
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &ctTestPKI{
		root:    root,
		rootKey: rootKey,
		logKey:  logKey,
		log:     log,
		now:     now,
		leafKey: leafKey,
		template: &x509.Certificate{
			SerialNumber: big.NewInt(2),
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(10 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			// A Fulcio-style extension (OIDC issuer, 1.3.6.1.4.1.57264.1.8).
			ExtraExtensions: []pkix.Extension{{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8},
				Value: []byte{0x0c, 0x05, 'i', 's', 's', 'u', 'r'},
			}},
		},
	}
}

func (p *ctTestPKI) trustRoot() CTTrustRoot {
	return CTTrustRoot{Name: "ct test", CAs: []*x509.Certificate{p.root}, Logs: []CTLog{p.log}}
}

func (p *ctTestPKI) issue(t *testing.T, extra ...pkix.Extension) *x509.Certificate {
	t.Helper()
	tmpl := *p.template
	tmpl.ExtraExtensions = append(append([]pkix.Extension{}, p.template.ExtraExtensions...), extra...)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, p.root, &p.leafKey.PublicKey, p.rootKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// precertTBS is the TBSCertificate the log signs: the leaf without the SCT
// extension. Go appends ExtraExtensions last and derives everything else from
// the template deterministically, so issuing without the SCT extension yields
// exactly the bytes a verifier reconstructs by removing it.
func (p *ctTestPKI) precertTBS(t *testing.T) []byte {
	t.Helper()
	return p.issue(t).RawTBSCertificate
}

// signSCT produces a TLS-serialized v1 SCT over a precert entry, per RFC 6962 §3.2.
func signSCT(t *testing.T, logKey *ecdsa.PrivateKey, issuer *x509.Certificate, tbs []byte, ts time.Time) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	require.NoError(t, err)
	logID := sha256.Sum256(spki)
	millis := uint64(ts.UnixMilli()) //nolint:gosec // test timestamps are positive

	issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	var signed bytes.Buffer
	signed.WriteByte(0) // v1
	signed.WriteByte(0) // certificate_timestamp
	_ = binary.Write(&signed, binary.BigEndian, millis)
	_ = binary.Write(&signed, binary.BigEndian, uint16(1)) // precert_entry
	signed.Write(issuerKeyHash[:])
	signed.Write([]byte{byte(len(tbs) >> 16), byte(len(tbs) >> 8), byte(len(tbs))})
	signed.Write(tbs)
	signed.Write([]byte{0, 0}) // no extensions
	digest := sha256.Sum256(signed.Bytes())
	sig, err := ecdsa.SignASN1(rand.Reader, logKey, digest[:])
	require.NoError(t, err)

	var sct bytes.Buffer
	sct.WriteByte(0)
	sct.Write(logID[:])
	_ = binary.Write(&sct, binary.BigEndian, millis)
	sct.Write([]byte{0, 0})
	sct.WriteByte(4) // sha256
	sct.WriteByte(3) // ecdsa
	_ = binary.Write(&sct, binary.BigEndian, uint16(len(sig)))
	sct.Write(sig)
	return sct.Bytes()
}

func sctListExtension(t *testing.T, scts ...[]byte) pkix.Extension {
	t.Helper()
	var list bytes.Buffer
	for _, s := range scts {
		_ = binary.Write(&list, binary.BigEndian, uint16(len(s)))
		list.Write(s)
	}
	var framed bytes.Buffer
	_ = binary.Write(&framed, binary.BigEndian, uint16(list.Len()))
	framed.Write(list.Bytes())
	value, err := asn1.Marshal(framed.Bytes())
	require.NoError(t, err)
	return pkix.Extension{Id: oidSCTList, Value: value}
}

func verifyLeaf(t *testing.T, p *ctTestPKI, leaf *x509.Certificate, opts ...X509VerifierOption) error {
	t.Helper()
	v, err := NewX509Verifier(leaf, nil, []*x509.Certificate{p.root}, p.now, opts...)
	require.NoError(t, err)
	msg := []byte("attestation payload")
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, p.leafKey, digest[:])
	require.NoError(t, err)
	return v.Verify(bytes.NewReader(msg), sig)
}

func TestX509Verifier_SCT_ValidSCTFromTrustedLogAccepted(t *testing.T) {
	p := newCTTestPKI(t)
	sct := signSCT(t, p.logKey, p.root, p.precertTBS(t), p.now)
	leaf := p.issue(t, sctListExtension(t, sct))
	require.NoError(t, verifyLeaf(t, p, leaf, WithCTTrustRoots(p.trustRoot())))
}

func TestX509Verifier_SCT_CTLoggedLeafWithoutSCTRefused(t *testing.T) {
	p := newCTTestPKI(t)
	leaf := p.issue(t)
	err := verifyLeaf(t, p, leaf, WithCTTrustRoots(p.trustRoot()))
	require.ErrorIs(t, err, ErrSCTVerification)
}

func TestX509Verifier_SCT_UntrustedLogKeyRefused(t *testing.T) {
	p := newCTTestPKI(t)
	rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sct := signSCT(t, rogue, p.root, p.precertTBS(t), p.now)
	leaf := p.issue(t, sctListExtension(t, sct))
	require.ErrorIs(t, verifyLeaf(t, p, leaf, WithCTTrustRoots(p.trustRoot())), ErrSCTVerification)
}

func TestX509Verifier_SCT_SignatureOverOtherCertificateRefused(t *testing.T) {
	p := newCTTestPKI(t)
	// A genuine SCT from the trusted log, but over a different precert: an SCT
	// lifted from another certificate must not carry this one.
	other := *p.template
	other.SerialNumber = big.NewInt(99)
	otherDER, err := x509.CreateCertificate(rand.Reader, &other, p.root, &p.leafKey.PublicKey, p.rootKey)
	require.NoError(t, err)
	otherCert, err := x509.ParseCertificate(otherDER)
	require.NoError(t, err)
	sct := signSCT(t, p.logKey, p.root, otherCert.RawTBSCertificate, p.now)
	leaf := p.issue(t, sctListExtension(t, sct))
	require.ErrorIs(t, verifyLeaf(t, p, leaf, WithCTTrustRoots(p.trustRoot())), ErrSCTVerification)
}

func TestX509Verifier_SCT_OutsideLogValidityRefused(t *testing.T) {
	p := newCTTestPKI(t)
	expired, err := NewCTLog("https://ct.test", &p.logKey.PublicKey, time.Time{}, p.now.Add(-time.Hour))
	require.NoError(t, err)
	sct := signSCT(t, p.logKey, p.root, p.precertTBS(t), p.now)
	leaf := p.issue(t, sctListExtension(t, sct))
	root := CTTrustRoot{Name: "ct test", CAs: []*x509.Certificate{p.root}, Logs: []CTLog{expired}}
	require.ErrorIs(t, verifyLeaf(t, p, leaf, WithCTTrustRoots(root)), ErrSCTVerification)
}

// The differential vector from #10032: a leaf that embeds an unverifiable SCT
// list, chaining to a CA that is not a CT trust root, used to verify.
func TestX509Verifier_SCT_UnverifiableEmbeddedSCTRefusedEvenForUnlistedCA(t *testing.T) {
	p := newCTTestPKI(t)
	junk := make([]byte, 120)
	_, err := rand.Read(junk)
	require.NoError(t, err)
	junk[0] = 0 // v1, so only the signature/log can fail
	leaf := p.issue(t, sctListExtension(t, junk))
	require.ErrorIs(t, verifyLeaf(t, p, leaf), ErrSCTVerification)
}

func TestX509Verifier_SCT_MalformedSCTListRefused(t *testing.T) {
	p := newCTTestPKI(t)
	value, err := asn1.Marshal([]byte{0x00, 0x09, 0x01})
	require.NoError(t, err)
	leaf := p.issue(t, pkix.Extension{Id: oidSCTList, Value: value})
	require.ErrorIs(t, verifyLeaf(t, p, leaf, WithCTTrustRoots(p.trustRoot())), ErrSCTVerification)
}

// The platform Fulcio is built without a CT client (judge-api
// pkg/fulcioca/fulcio.go passes a nil log client), so its leaves carry no SCT
// and its CA is not a CT trust root. Such a leaf still verifies.
func TestX509Verifier_SCT_NotLoggedCALeafWithoutSCTAccepted(t *testing.T) {
	p := newCTTestPKI(t)
	require.NoError(t, verifyLeaf(t, p, p.issue(t)))
}

func TestRemoveSCTListReconstructsPrecertTBS(t *testing.T) {
	p := newCTTestPKI(t)
	want := p.precertTBS(t)
	leaf := p.issue(t, sctListExtension(t, signSCT(t, p.logKey, p.root, want, p.now)))
	got, err := precertTBS(leaf)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func loadPublicGoodChain(t *testing.T) (leaf, intermediate, root *x509.Certificate) {
	t.Helper()
	raw, err := os.ReadFile("testdata/sigstore-public-good-fulcio-chain.pem")
	require.NoError(t, err)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		certs = append(certs, c)
	}
	require.Len(t, certs, 3)
	return certs[0], certs[1], certs[2]
}

// A real public-good Fulcio leaf (sigstore-go examples/bundle-provenance.json,
// issued 2023-04-18, SCT from ctfe.sigstore.dev/2022) verifies under the
// embedded public-good trusted root with no extra configuration. This is the
// path release-hardener.yml and release-self-host-minimal.yml attestations
// take through `cilock verify`.
func TestX509Verifier_SCT_PublicGoodFulcioLeafVerifies(t *testing.T) {
	leaf, intermediate, root := loadPublicGoodChain(t)
	_, hasSCT, err := embeddedSCTs(leaf)
	require.NoError(t, err)
	require.True(t, hasSCT, "fixture must carry an embedded SCT")

	v, err := NewX509Verifier(leaf, []*x509.Certificate{intermediate}, []*x509.Certificate{root}, leaf.NotBefore.Add(time.Minute))
	require.NoError(t, err)
	chains, err := v.verifyChain()
	require.NoError(t, err)
	roots, err := v.ctTrustRoots()
	require.NoError(t, err)
	require.NoError(t, checkCertificateTransparency(leaf, chains, roots))
	msg, sig := publicGoodSignedMessage(t)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig), "the full X509Verifier.Verify path accepts the real public-good leaf")

	publicGood, err := PublicGoodCTTrustRoots()
	require.NoError(t, err)
	require.NotEmpty(t, publicGood)
	require.True(t, ctRootsCover(publicGood, chains), "public-good Fulcio CA must be a CT trust root, so a missing SCT is refused")
}

// release-hardener.yml pins `.chains[0].certificates[0]` of Fulcio's
// /api/v2/trustBundle as the policy root, which is the sigstore-intermediate,
// not the self-signed root. The chain is then [leaf, intermediate]; the SCT
// must still be required and verify.
func TestX509Verifier_SCT_PublicGoodLeafVerifiesWithIntermediatePinnedAsRoot(t *testing.T) {
	leaf, intermediate, _ := loadPublicGoodChain(t)
	require.Equal(t, "sigstore-intermediate", intermediate.Subject.CommonName)
	v, err := NewX509Verifier(leaf, nil, []*x509.Certificate{intermediate}, leaf.NotBefore.Add(time.Minute))
	require.NoError(t, err)
	msg, sig := publicGoodSignedMessage(t)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))

	chains, err := v.verifyChain()
	require.NoError(t, err)
	publicGood, err := PublicGoodCTTrustRoots()
	require.NoError(t, err)
	require.True(t, ctRootsCover(publicGood, chains))
}

func TestX509Verifier_SCT_PublicGoodLeafRefusedWithoutPublicGoodLogs(t *testing.T) {
	leaf, intermediate, root := loadPublicGoodChain(t)
	v, err := NewX509Verifier(leaf, []*x509.Certificate{intermediate}, []*x509.Certificate{root}, leaf.NotBefore.Add(time.Minute))
	require.NoError(t, err)
	chains, err := v.verifyChain()
	require.NoError(t, err)

	// Same CA, but a log key that is not the one that signed the SCT.
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	log, err := NewCTLog("https://foreign.test", &foreign.PublicKey, time.Time{}, time.Time{})
	require.NoError(t, err)
	onlyForeign := []CTTrustRoot{{Name: "foreign", CAs: []*x509.Certificate{intermediate, root}, Logs: []CTLog{log}}}
	require.ErrorIs(t, checkCertificateTransparency(leaf, chains, onlyForeign), ErrSCTVerification)
}

func TestX509Verifier_SCT_PublicGoodLeafWithTamperedSCTRefused(t *testing.T) {
	leaf, intermediate, root := loadPublicGoodChain(t)
	v, err := NewX509Verifier(leaf, []*x509.Certificate{intermediate}, []*x509.Certificate{root}, leaf.NotBefore.Add(time.Minute))
	require.NoError(t, err)
	chains, err := v.verifyChain()
	require.NoError(t, err)

	// Flip one byte of the SCT's timestamp inside the extension. The CA
	// signature over the leaf is not re-checked here; this isolates the SCT
	// signature check on real public-good bytes.
	raw := append([]byte(nil), leaf.Raw...)
	idx := bytes.Index(raw, []byte{0xdd, 0x3d, 0x30, 0x6a}) // ctfe 2022 log ID prefix
	require.Positive(t, idx)
	raw[idx+32+7] ^= 0x01
	tampered, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	tamperedChains := [][]*x509.Certificate{append([]*x509.Certificate{tampered}, chains[0][1:]...)}
	roots, err := v.ctTrustRoots()
	require.NoError(t, err)
	require.ErrorIs(t, checkCertificateTransparency(tampered, tamperedChains, roots), ErrSCTVerification)
}

// publicGoodSignedMessage returns the DSSE pre-authentication encoding and
// signature of the real envelope the public-good fixture leaf signed.
func publicGoodSignedMessage(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/sigstore-public-good-dsse.json")
	require.NoError(t, err)
	var env struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	require.NoError(t, json.Unmarshal(raw, &env))
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	require.NoError(t, err)
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	require.NoError(t, err)
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(env.PayloadType), env.PayloadType, len(payload), payload)
	return []byte(pae), sig
}

var _ crypto.PublicKey = (*ecdsa.PublicKey)(nil)
