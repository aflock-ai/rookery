// jade:ring local

package timestamp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5816 ESSCertID (v1) identifies the signer by a SHA-1 certificate hash
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// RFC 3161 §2.4.1: "The ESS SigningCertificate attribute MUST be included"
// to identify the TSA's certificate; RFC 5816 §2.2.1 allows ESSCertIDv2 in its
// place. The SignerInfo's issuerAndSerialNumber is not signed, so the ESS
// attribute is what binds the signer certificate to the signature. Neither
// digitorus/timestamp nor digitorus/pkcs7 reads it back, so a token with no
// ESS attribute, or one naming another certificate, used to verify.
// formal/signing-trust refutes this as ce_token_without_ess and
// ce_token_ess_names_other_cert (#9917).

var (
	essTestOIDv1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	essTestOIDv2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

type essTestGeneralNames struct {
	Name asn1.RawValue `asn1:"optional,tag:4"`
}

type essTestIssuerSerial struct {
	Issuer essTestGeneralNames
	Serial *big.Int
}

type essTestCertID struct {
	CertHash     []byte
	IssuerSerial essTestIssuerSerial `asn1:"optional"`
}

type essTestCertIDv2Alg struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	CertHash      []byte
}

// essV2For returns the SigningCertificateV2 attribute (type and value) that
// names leaf, as a conforming TSA writes it. Hand-rolled token fixtures add it
// so that they fail, when they fail, for the reason under test.
func essV2For(leaf *x509.Certificate) (asn1.ObjectIdentifier, interface{}) {
	h := sha256.Sum256(leaf.Raw)
	return essTestOIDv2, struct{ Certs []essTestCertID }{[]essTestCertID{{h[:], essTestIssuerSerialOf(leaf, leaf.SerialNumber)}}}
}

func essTestIssuerSerialOf(c *x509.Certificate, serial *big.Int) essTestIssuerSerial {
	return essTestIssuerSerial{
		Issuer: essTestGeneralNames{Name: asn1.RawValue{Tag: 4, Class: 2, IsCompound: true, Bytes: c.RawIssuer}},
		Serial: serial,
	}
}

// essTestToken mints a token over payload signed by leaf with the given extra
// authenticated attributes (the ESS attribute under test, or none).
func essTestToken(t *testing.T, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, payload []byte, types []asn1.ObjectIdentifier, values []interface{}) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	tstDER, err := asn1.Marshal(fixtureTSTInfo{
		Version:      1,
		Policy:       oidTSAPolicy,
		SerialNumber: big.NewInt(11),
		Time:         time.Now().UTC().Truncate(time.Second),
		MessageImprint: fixtureMessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidHashSHA2, Parameters: asn1.NullRawValue},
			HashedMessage: digest[:],
		},
	})
	require.NoError(t, err)
	contentDigest := sha256.Sum256(tstDER)
	attrs := sortAuthAttrs(t,
		append([]asn1.ObjectIdentifier{oidAttrContentType, oidAttrMessageDigest}, types...),
		append([]interface{}{oidTSTInfo, contentDigest[:]}, values...))
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

func TestTSPVerifierRequiresESSSigningCertificate(t *testing.T) {
	root, leaf, leafKey := trustedTSAChain(t)
	_, other, _ := trustedTSAChain(t)
	payload := []byte("signature bytes")

	h2 := sha256.Sum256(leaf.Raw)
	o2 := sha256.Sum256(other.Raw)
	h384 := sha512.Sum384(leaf.Raw)
	h1 := sha1.Sum(leaf.Raw)  //nolint:gosec // ESSCertID v1 is SHA-1 by definition
	o1 := sha1.Sum(other.Raw) //nolint:gosec
	is := essTestIssuerSerialOf(leaf, leaf.SerialNumber)
	badSerial := essTestIssuerSerialOf(leaf, new(big.Int).Add(leaf.SerialNumber, big.NewInt(1)))
	v2 := func(ids ...essTestCertID) interface{} { return struct{ Certs []essTestCertID }{ids} }
	v1 := v2

	cases := []struct {
		name   string
		types  []asn1.ObjectIdentifier
		values []interface{}
		accept bool
	}{
		{"v2 naming the signer", []asn1.ObjectIdentifier{essTestOIDv2}, []interface{}{v2(essTestCertID{h2[:], is})}, true},
		{"v2 without issuerSerial", []asn1.ObjectIdentifier{essTestOIDv2}, []interface{}{v2(essTestCertID{CertHash: h2[:]})}, true},
		{"v2 with an explicit sha384 hash", []asn1.ObjectIdentifier{essTestOIDv2},
			[]interface{}{struct{ Certs []essTestCertIDv2Alg }{[]essTestCertIDv2Alg{{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}}, h384[:]}}}}, true},
		{"v1 naming the signer", []asn1.ObjectIdentifier{essTestOIDv1}, []interface{}{v1(essTestCertID{h1[:], is})}, true},
		{"no ESS attribute", nil, nil, false},
		{"v2 naming another certificate", []asn1.ObjectIdentifier{essTestOIDv2}, []interface{}{v2(essTestCertID{o2[:], is})}, false},
		{"v2 naming another serial", []asn1.ObjectIdentifier{essTestOIDv2}, []interface{}{v2(essTestCertID{h2[:], badSerial})}, false},
		{"v1 naming another certificate", []asn1.ObjectIdentifier{essTestOIDv1}, []interface{}{v1(essTestCertID{o1[:], is})}, false},
		{"v2 with an empty certs list", []asn1.ObjectIdentifier{essTestOIDv2}, []interface{}{v2()}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := essTestToken(t, leaf, leafKey, payload, c.types, c.values)
			_, err := NewVerifier(VerifyWithCerts([]*x509.Certificate{root})).
				Verify(context.Background(), bytes.NewReader(tok), bytes.NewReader(payload))
			if c.accept {
				require.NoError(t, err)
			} else {
				require.Error(t, err, "a token whose ESS attribute does not identify the signer was accepted")
			}
		})
	}
}
