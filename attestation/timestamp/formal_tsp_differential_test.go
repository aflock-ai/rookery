// jade:ring local

package timestamp

// formal:differential signing-trust TestFormalTSPDifferential
//
// Binds the Lean model of RFC 3161 / RFC 5816 token verification
// (formal/signing-trust, SigningTrust/Tsp.lean) to TSPVerifier.Verify. Each
// case of the model's "tsp" vectors is minted for real: a TSA leaf with the
// model's keyUsage, extKeyUsage and validity under a fixed root, a TSTInfo
// with the model's imprint algorithm, imprint and genTime, an optional PKCS#9
// signingTime, the model's ESS signing-certificate attribute (v2, v1, absent,
// or naming another certificate), and a CMS signature that is valid or not.
// The verifier trusts the model's anchors and must return the model's time,
// or refuse when the model refuses.
//
// tspModel names which model the shipped code must match: "asbuilt" (no
// signer keyUsage or ESS check), "kuonly" (the keyUsage fix alone), or
// "required" (both fixes).
//
// The test skips when the vectors are not on disk and FAILS instead when
// JADE_FORMAL_DIFFERENTIAL=1.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5816 ESSCertID v1 carries a SHA-1 certificate hash; the model mints one
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const tspModel = "required"

type formalTSPCase struct {
	Alg         string     `json:"alg"`
	ImprintOk   bool       `json:"imprintOk"`
	SigOk       bool       `json:"sigOk"`
	GenTime     int        `json:"genTime"`
	SigningTime *int       `json:"signingTime"`
	Leaf        formalCert `json:"leaf"`
	Root        formalCert `json:"root"`
	ESS         string     `json:"ess"`
	Anchors     []int      `json:"anchors"`
	AsBuilt     *int       `json:"asbuilt"`
	KUOnly      *int       `json:"kuonly"`
	Required    *int       `json:"required"`
}

var (
	formalOIDSigningCertV1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	formalOIDSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

type formalGeneralNames struct {
	Name asn1.RawValue `asn1:"optional,tag:4"`
}

type formalIssuerSerial struct {
	Issuer formalGeneralNames
	Serial *big.Int
}

type formalESSCertIDv2 struct {
	CertHash     []byte
	IssuerSerial formalIssuerSerial
}

type formalESSCertID struct {
	CertHash     []byte
	IssuerSerial formalIssuerSerial
}

func formalIssuerSerialOf(c *x509.Certificate, serial *big.Int) formalIssuerSerial {
	return formalIssuerSerial{
		Issuer: formalGeneralNames{Name: asn1.RawValue{Tag: 4, Class: 2, IsCompound: true, Bytes: c.RawIssuer}},
		Serial: serial,
	}
}

// formalESSAttr returns the ESS attribute (type, value) for a variant, or nil.
func formalESSAttr(variant string, leaf, other *x509.Certificate) (asn1.ObjectIdentifier, interface{}) {
	h2 := sha256.Sum256(leaf.Raw)
	o2 := sha256.Sum256(other.Raw)
	h1 := sha1.Sum(leaf.Raw)  //nolint:gosec // ESSCertID v1 is SHA-1 by definition
	o1 := sha1.Sum(other.Raw) //nolint:gosec
	is := formalIssuerSerialOf(leaf, leaf.SerialNumber)
	switch variant {
	case "v2":
		return formalOIDSigningCertV2, struct{ Certs []formalESSCertIDv2 }{[]formalESSCertIDv2{{h2[:], is}}}
	case "v2BadHash":
		return formalOIDSigningCertV2, struct{ Certs []formalESSCertIDv2 }{[]formalESSCertIDv2{{o2[:], is}}}
	case "v2BadSerial":
		bad := formalIssuerSerialOf(leaf, new(big.Int).Add(leaf.SerialNumber, big.NewInt(1)))
		return formalOIDSigningCertV2, struct{ Certs []formalESSCertIDv2 }{[]formalESSCertIDv2{{h2[:], bad}}}
	case "v1":
		return formalOIDSigningCertV1, struct{ Certs []formalESSCertID }{[]formalESSCertID{{h1[:], is}}}
	case "v1BadHash":
		return formalOIDSigningCertV1, struct{ Certs []formalESSCertID }{[]formalESSCertID{{o1[:], is}}}
	}
	return nil, nil
}

func formalImprint(t *testing.T, alg string, data []byte) (asn1.ObjectIdentifier, []byte) {
	t.Helper()
	var h crypto.Hash
	var oid asn1.ObjectIdentifier
	switch alg {
	case "sha1":
		h, oid = crypto.SHA1, oidHashSHA1
	case "sha256":
		h, oid = crypto.SHA256, oidHashSHA2
	case "sha384":
		h, oid = crypto.SHA384, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	case "sha512":
		h, oid = crypto.SHA512, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	default:
		t.Fatalf("unknown alg %q", alg)
	}
	w := h.New()
	w.Write(data)
	return oid, w.Sum(nil)
}

// formalMintToken builds the token a case describes.
func formalMintToken(t *testing.T, base time.Time, c formalTSPCase, leaf, root *x509.Certificate, leafKey *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	imprinted := payload
	if !c.ImprintOk {
		imprinted = append([]byte("not "), payload...)
	}
	oid, digest := formalImprint(t, c.Alg, imprinted)
	gen := time.Time{}
	if c.GenTime != 0 {
		gen = formalAt(base, c.GenTime)
	}
	tst := fixtureTSTInfo{
		Version:      1,
		Policy:       oidTSAPolicy,
		SerialNumber: big.NewInt(99),
		Time:         gen,
		Accuracy:     fixtureAccuracy{Seconds: 1},
		MessageImprint: fixtureMessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue},
			HashedMessage: digest,
		},
	}
	tstDER, err := asn1.Marshal(tst)
	require.NoError(t, err)
	contentDigest := sha256.Sum256(tstDER)
	types := []asn1.ObjectIdentifier{oidAttrContentType, oidAttrMessageDigest}
	values := []interface{}{oidTSTInfo, contentDigest[:]}
	if c.SigningTime != nil {
		types = append(types, oidAttrSigningTime)
		values = append(values, formalAt(base, *c.SigningTime))
	}
	if essOID, essVal := formalESSAttr(c.ESS, leaf, root); essOID != nil {
		types = append(types, essOID)
		values = append(values, essVal)
	}
	attrs := sortAuthAttrs(t, types, values)
	h := sha256.Sum256(marshalAuthAttrs(t, attrs))
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, h[:])
	require.NoError(t, err)
	if !c.SigOk {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		sig, err = ecdsa.SignASN1(rand.Reader, other, h[:])
		require.NoError(t, err)
	}
	content, err := asn1.Marshal(tstDER)
	require.NoError(t, err)
	certVal, err := asn1.Marshal(asn1.RawValue{Bytes: leaf.Raw, Class: 2, Tag: 0, IsCompound: true})
	require.NoError(t, err)
	sd := tstSignedData{
		Version:                    3,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{{Algorithm: oidDigestSHA256}},
		ContentInfo: tstContentInfo{
			ContentType: oidTSTInfo,
			Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
		},
		Certificates: tstRawCertificates{Raw: certVal},
		SignerInfos: []tstSignerInfo{{
			Version:                   1,
			IssuerAndSerialNumber:     tstIssuerAndSerial{IssuerName: asn1.RawValue{FullBytes: leaf.RawIssuer}, SerialNumber: leaf.SerialNumber},
			DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
			AuthenticatedAttributes:   attrs,
			DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSigAlgECDSAWithSHA2},
			EncryptedDigest:           sig,
		}},
	}
	inner, err := asn1.Marshal(sd)
	require.NoError(t, err)
	outer, err := asn1.Marshal(tstContentInfo{ContentType: oidSignedData, Content: asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true}})
	require.NoError(t, err)
	return outer
}

func TestFormalTSPDifferential(t *testing.T) {
	path := filepath.Join("..", "..", "formal", "signing-trust", "vectors", "signing-trust.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") != "" {
			t.Fatalf("JADE_FORMAL_DIFFERENTIAL is set but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal vectors not on disk (%v); the differential needs the repository checkout", err)
	}
	var v struct {
		TSP []formalTSPCase `json:"tsp"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	if len(v.TSP) == 0 {
		t.Fatal("vectors have no tsp section")
	}
	base := time.Now().UTC().Truncate(time.Second)
	payload := []byte("formal signing-trust signature bytes")
	bad, accepted := 0, 0
	for i, c := range v.TSP {
		certs, keys := formalChain(t, base, []formalCert{c.Leaf, c.Root})
		var anchors []*x509.Certificate
		for j, fc := range []formalCert{c.Leaf, c.Root} {
			if slices.Contains(c.Anchors, fc.ID) {
				anchors = append(anchors, certs[j])
			}
		}
		tok := formalMintToken(t, base, c, certs[0], certs[1], keys[0], payload)
		got := "refused"
		if ts, verr := NewVerifier(VerifyWithCerts(anchors)).Verify(context.Background(), bytes.NewReader(tok), bytes.NewReader(payload)); verr == nil {
			got = ts.UTC().Format(time.RFC3339)
			accepted++
		}
		wantT := c.AsBuilt
		switch tspModel {
		case "kuonly":
			wantT = c.KUOnly
		case "required":
			wantT = c.Required
		}
		want := "refused"
		if wantT != nil {
			want = formalAt(base, *wantT).UTC().Format(time.RFC3339)
		}
		if got != want {
			bad++
			if bad <= 20 {
				js, _ := json.Marshal(c)
				t.Errorf("tsp case %d: code %s, %s model %s\n  %s", i, got, tspModel, want, js)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("tsp: %d of %d cases disagree with the %s model", bad, len(v.TSP), tspModel)
	}
	t.Logf("tsp: %d cases (%d accepted) agree with the %s model", len(v.TSP), accepted, tspModel)
}

// formalCert is one certificate as the signing-trust model describes it.
type formalCert struct {
	ID      int  `json:"id"`
	BC      bool `json:"bc"`
	CA      bool `json:"ca"`
	PathLen *int `json:"pathLen"`
	KU      *struct {
		DS bool `json:"ds"`
		CC bool `json:"cc"`
		CS bool `json:"cs"`
	} `json:"ku"`
	EKU  string `json:"eku"`
	NB   int    `json:"nb"`
	NA   int    `json:"na"`
	Crit bool   `json:"crit"`
}

// formalAt maps a model time to a wall-clock time: model 1000 is base.
func formalAt(base time.Time, m int) time.Time {
	return base.Add(time.Duration(m-1000) * time.Minute)
}

var formalTSPUnknownCriticalOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// formalTemplate turns a model certificate into a template.
func formalTemplate(base time.Time, c formalCert) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(1000 + c.ID)),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("formal-cert-%d", c.ID)},
		NotBefore:             formalAt(base, c.NB),
		NotAfter:              formalAt(base, c.NA),
		BasicConstraintsValid: c.BC,
		IsCA:                  c.CA,
		MaxPathLen:            -1,
	}
	if c.PathLen != nil {
		tmpl.MaxPathLen = *c.PathLen
		tmpl.MaxPathLenZero = *c.PathLen == 0
	}
	if c.KU != nil {
		tmpl.KeyUsage = formalKeyUsage(c.KU.DS, c.KU.CC, c.KU.CS)
	}
	switch c.EKU {
	case "codeSigning":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	case "timeStamping":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	case "serverAuth":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "any":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	case "codeAndServer":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageServerAuth}
	case "tsAndServer":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth}
	}
	if c.Crit {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: formalTSPUnknownCriticalOID, Critical: true, Value: []byte{0x05, 0x00}}}
	}
	return tmpl
}

// formalChain builds a linear chain, leaf first, each certificate issued by
// the next and the last self-signed. It returns the certificates and keys.
func formalChain(t *testing.T, base time.Time, chain []formalCert) ([]*x509.Certificate, []*ecdsa.PrivateKey) {
	t.Helper()
	n := len(chain)
	certs := make([]*x509.Certificate, n)
	keys := make([]*ecdsa.PrivateKey, n)
	for i := range keys {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
	}
	for i := n - 1; i >= 0; i-- {
		tmpl := formalTemplate(base, chain[i])
		parent, parentKey := tmpl, keys[i]
		if i < n-1 {
			parent, parentKey = certs[i+1], keys[i+1]
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &keys[i].PublicKey, parentKey)
		if err != nil {
			t.Fatalf("create cert %d: %v", chain[i].ID, err)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			t.Fatal(err)
		}
	}
	return certs, keys
}

// formalKeyUsage is the key usage a formal case's ku flags name. No flag set
// means a certificate that asserts only keyEncipherment.
func formalKeyUsage(ds, cc, cs bool) x509.KeyUsage {
	ku := x509.KeyUsage(0)
	if ds {
		ku |= x509.KeyUsageDigitalSignature
	}
	if cc {
		ku |= x509.KeyUsageContentCommitment
	}
	if cs {
		ku |= x509.KeyUsageCertSign
	}
	if ku == 0 {
		ku = x509.KeyUsageKeyEncipherment
	}
	return ku
}
