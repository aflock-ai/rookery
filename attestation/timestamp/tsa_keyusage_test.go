// jade:ring local

package timestamp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The TSA signing certificate's keyUsage, when present, must permit signing:
// digitalSignature or contentCommitment (RFC 5280 §4.2.1.3). Nothing on the
// token path read it, so a key-encipherment certificate with the timeStamping
// EKU could vouch for signing time. formal/signing-trust (#9917).

var kuOIDSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

type kuGeneralNames struct {
	Name asn1.RawValue `asn1:"optional,tag:4"`
}

type kuIssuerSerial struct {
	Issuer kuGeneralNames
	Serial *big.Int
}

type kuESSCertIDv2 struct {
	CertHash     []byte
	IssuerSerial kuIssuerSerial
}

// kuToken mints a token over payload signed by leaf, carrying a matching
// SigningCertificateV2 so that only the keyUsage decides the verdict.
func kuToken(t *testing.T, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	tstDER, err := asn1.Marshal(fixtureTSTInfo{
		Version:      1,
		Policy:       oidTSAPolicy,
		SerialNumber: big.NewInt(7),
		Time:         time.Now().UTC().Truncate(time.Second),
		MessageImprint: fixtureMessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidHashSHA2, Parameters: asn1.NullRawValue},
			HashedMessage: digest[:],
		},
	})
	require.NoError(t, err)
	contentDigest := sha256.Sum256(tstDER)
	certHash := sha256.Sum256(leaf.Raw)
	ess := struct{ Certs []kuESSCertIDv2 }{[]kuESSCertIDv2{{certHash[:], kuIssuerSerial{
		Issuer: kuGeneralNames{Name: asn1.RawValue{Tag: 4, Class: 2, IsCompound: true, Bytes: leaf.RawIssuer}},
		Serial: leaf.SerialNumber,
	}}}}
	attrs := sortAuthAttrs(t,
		[]asn1.ObjectIdentifier{oidAttrContentType, oidAttrMessageDigest, kuOIDSigningCertV2},
		[]interface{}{oidTSTInfo, contentDigest[:], ess})
	h := sha256.Sum256(marshalAuthAttrs(t, attrs))
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, h[:])
	require.NoError(t, err)
	content, err := asn1.Marshal(tstDER)
	require.NoError(t, err)
	certVal, err := asn1.Marshal(asn1.RawValue{Bytes: leaf.Raw, Class: 2, Tag: 0, IsCompound: true})
	require.NoError(t, err)
	inner, err := asn1.Marshal(tstSignedData{
		Version:                    3,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{{Algorithm: oidDigestSHA256}},
		ContentInfo:                tstContentInfo{ContentType: oidTSTInfo, Content: asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true}},
		Certificates:               tstRawCertificates{Raw: certVal},
		SignerInfos: []tstSignerInfo{{
			Version:                   1,
			IssuerAndSerialNumber:     tstIssuerAndSerial{IssuerName: asn1.RawValue{FullBytes: leaf.RawIssuer}, SerialNumber: leaf.SerialNumber},
			DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
			AuthenticatedAttributes:   attrs,
			DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSigAlgECDSAWithSHA2},
			EncryptedDigest:           sig,
		}},
	})
	require.NoError(t, err)
	outer, err := asn1.Marshal(tstContentInfo{ContentType: oidSignedData, Content: asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true}})
	require.NoError(t, err)
	return outer
}

func TestTSPVerifierSignerKeyUsage(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ku-tsa-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	payload := []byte("signature bytes")
	cases := []struct {
		name   string
		ku     x509.KeyUsage
		accept bool
	}{
		{"digitalSignature", x509.KeyUsageDigitalSignature, true},
		{"contentCommitment", x509.KeyUsageContentCommitment, true},
		{"no keyUsage extension", 0, true},
		{"keyEncipherment only", x509.KeyUsageKeyEncipherment, false},
		{"certSign only", x509.KeyUsageCertSign, false},
		{"digitalSignature plus keyCertSign on a non-CA", x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, false},
		{"digitalSignature plus cRLSign on a non-CA", x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign, false},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			leafTmpl := &x509.Certificate{
				SerialNumber: big.NewInt(int64(10 + i)), Subject: pkix.Name{CommonName: "ku-tsa-leaf"},
				NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute),
				KeyUsage: c.ku, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, caKey)
			require.NoError(t, err)
			leaf, err := x509.ParseCertificate(leafDER)
			require.NoError(t, err)
			_, verr := NewVerifier(VerifyWithCerts([]*x509.Certificate{root})).
				Verify(context.Background(), bytes.NewReader(kuToken(t, leaf, leafKey, payload)), bytes.NewReader(payload))
			if c.accept {
				require.NoError(t, verr)
			} else {
				require.Error(t, verr, "a TSA signer whose keyUsage does not permit signing was accepted")
			}
		})
	}
}
