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

// --- Finding TS4: the verifier must validate the TSA chain at the token's
// TSTInfo genTime — the value Verify RETURNS as the trusted signing time.
//
// An RFC 3161 token carries two independently signed time fields: TSTInfo
// genTime and the PKCS#9 signingTime authenticated attribute. digitorus/pkcs7
// builds the chain at signingTime when present and at wall clock otherwise; it
// never looks at genTime. So a token whose signingTime sits inside the signer
// certificate's validity while its genTime lies far outside it used to verify,
// handing the caller an out-of-window genTime that anchors evidence-certificate
// validation downstream (dsse.verifyTimestamps).
//
// These fixtures are hand-rolled rather than built with pkcs7.NewSignedData
// because pkcs7.AddSigner unconditionally stamps signingTime = time.Now(),
// which makes a back-dated or divergent-time token impossible to model with the
// stock builder. The structs below mirror pkcs7's own (unexported) ASN.1 shapes.

type tstAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type tstIssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type tstSignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     tstIssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []tstAttribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []tstAttribute `asn1:"optional,omitempty,tag:1"`
}

type tstRawCertificates struct {
	Raw asn1.RawContent
}

type tstContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type tstSignedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                tstContentInfo
	Certificates               tstRawCertificates     `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []tstSignerInfo        `asn1:"set"`
}

var (
	oidSignedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidDigestSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSigAlgECDSAWithSHA2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// marshalAuthAttrs reproduces pkcs7.marshalAttributes: a DER SET OF attribute.
func marshalAuthAttrs(t *testing.T, attrs []tstAttribute) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(struct {
		A []tstAttribute `asn1:"set"`
	}{A: attrs})
	require.NoError(t, err)
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(encoded, &raw)
	require.NoError(t, err)
	return raw.Bytes
}

// sortAuthAttrs reproduces pkcs7 attributes.ForMarshalling DER SET ordering.
func sortAuthAttrs(t *testing.T, types []asn1.ObjectIdentifier, values []interface{}) []tstAttribute {
	t.Helper()
	type sortable struct {
		key  []byte
		attr tstAttribute
	}
	out := make([]sortable, 0, len(types))
	for i := range types {
		v, err := asn1.Marshal(values[i])
		require.NoError(t, err)
		a := tstAttribute{Type: types[i], Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: v}}
		enc, err := asn1.Marshal(a)
		require.NoError(t, err)
		out = append(out, sortable{key: enc, attr: a})
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(out[j].key, out[j-1].key) < 0; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	attrs := make([]tstAttribute, len(out))
	for i := range out {
		attrs[i] = out[i].attr
	}
	return attrs
}

// tsaChainWithValidity builds a root + sole-timeStamping-EKU leaf with EXPLICIT
// validity windows, so a test can place genTime inside or outside the leaf's window.
func tsaChainWithValidity(t *testing.T, rootNB, rootNA, leafNB, leafNA time.Time) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ts4-tsa-root"},
		NotBefore:             rootNB,
		NotAfter:              rootNA,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ts4-tsa-leaf"},
		NotBefore:    leafNB,
		NotAfter:     leafNA,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return root, leaf, leafKey
}

// forgeTokenWithTimes mints an RFC 3161 token over payload with an arbitrary
// genTime. signingTime == nil OMITS the PKCS#9 signingTime attribute entirely,
// modelling a third-party TSA that does not stamp it.
func forgeTokenWithTimes(t *testing.T, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, payload []byte, genTime time.Time, signingTime *time.Time) []byte {
	t.Helper()

	digest := sha256.Sum256(payload)
	tst := fixtureTSTInfo{
		Version:      1,
		Policy:       oidTSAPolicy,
		SerialNumber: big.NewInt(99),
		Time:         genTime.UTC().Truncate(time.Second),
		Accuracy:     fixtureAccuracy{Seconds: 1},
		MessageImprint: fixtureMessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidHashSHA2, Parameters: asn1.NullRawValue},
			HashedMessage: digest[:],
		},
	}
	tstDER, err := asn1.Marshal(tst)
	require.NoError(t, err)

	contentDigest := sha256.Sum256(tstDER)
	types := []asn1.ObjectIdentifier{oidAttrContentType, oidAttrMessageDigest}
	values := []interface{}{oidTSTInfo, contentDigest[:]}
	if signingTime != nil {
		types = append(types, oidAttrSigningTime)
		values = append(values, signingTime.UTC().Truncate(time.Second))
	}
	attrs := sortAuthAttrs(t, types, values)

	toSign := marshalAuthAttrs(t, attrs)
	h := sha256.Sum256(toSign)
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, h[:])
	require.NoError(t, err)

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
			Version: 1,
			IssuerAndSerialNumber: tstIssuerAndSerial{
				IssuerName:   asn1.RawValue{FullBytes: leaf.RawIssuer},
				SerialNumber: leaf.SerialNumber,
			},
			DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
			AuthenticatedAttributes:   attrs,
			DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSigAlgECDSAWithSHA2},
			EncryptedDigest:           sig,
		}},
	}
	inner, err := asn1.Marshal(sd)
	require.NoError(t, err)
	outer, err := asn1.Marshal(tstContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	})
	require.NoError(t, err)
	return outer
}

func timePtr(t time.Time) *time.Time { return &t }

// TestSecurity_TS4_ChainValidatedAtGenTime is the table that pins the contract:
// BOTH the TSTInfo genTime and (when present) the PKCS#9 signingTime must fall
// inside the signer certificate's validity window.
//
// Cases E and F are the defect: a token whose signingTime is in-window but whose
// genTime is a year outside it. They verified before the CurrentTime pin, and the
// out-of-window genTime was what Verify returned.
//
// Case G is the end-to-end control that the pin did not TRADE one check for the
// other: genTime in-window but signingTime out-of-window must still be rejected.
// Note where that rejection actually comes from — timestamp.Parse calls
// p7.Verify() internally whenever the token embeds certificates, and that runs
// pkcs7's signingTime-vs-validity guard before Verify ever reaches the chain
// build. So G pins the BEHAVIOR but does not isolate verifySignatureAtTime's own
// copy of the guard (verify.go:137-146); Parse short-circuits first. Both layers
// enforce it, which is why the entry-point switch is safe.
func TestSecurity_TS4_ChainValidatedAtGenTime(t *testing.T) {
	now := time.Now()
	payload := []byte("ts4 payload")

	cases := []struct {
		name           string
		leafNB, leafNA time.Time
		genTime        time.Time
		signingTime    *time.Time
		wantErr        string // "" == must verify
	}{
		{
			name:   "A_valid_now_with_signingTime",
			leafNB: now.Add(-1 * time.Hour), leafNA: now.Add(1 * time.Hour),
			genTime: now.Add(-30 * time.Minute), signingTime: timePtr(now.Add(-30 * time.Minute)),
		},
		{
			// Chain expired as of wall clock, but both time fields sit inside the
			// window. RFC 3161 verification is about validity AT SIGNING TIME, so
			// this must keep verifying — an expired TSA cert does not invalidate
			// timestamps it legitimately issued while valid.
			name:   "B_chain_expired_now_both_times_in_window",
			leafNB: now.Add(-48 * time.Hour), leafNA: now.Add(-24 * time.Hour),
			genTime: now.Add(-36 * time.Hour), signingTime: timePtr(now.Add(-36 * time.Hour)),
		},
		{
			// BEHAVIOR CHANGE. A third-party TSA that omits signingTime, whose chain
			// has since expired, used to fall to the wall-clock path and FAIL. With
			// the chain validated at genTime it now PASSES, which is the
			// RFC 3161-correct outcome and matches case B.
			name:   "C_chain_expired_now_NO_signingTime_attr",
			leafNB: now.Add(-48 * time.Hour), leafNA: now.Add(-24 * time.Hour),
			genTime: now.Add(-36 * time.Hour), signingTime: nil,
		},
		{
			name:   "D_valid_now_NO_signingTime_attr",
			leafNB: now.Add(-1 * time.Hour), leafNA: now.Add(1 * time.Hour),
			genTime: now.Add(-30 * time.Minute), signingTime: nil,
		},
		{
			name:   "E_genTime_before_notBefore_signingTime_in_window",
			leafNB: now.Add(-1 * time.Hour), leafNA: now.Add(1 * time.Hour),
			genTime: now.Add(-8760 * time.Hour), signingTime: timePtr(now.Add(-30 * time.Minute)),
			wantErr: "failed to verify certificate chain",
		},
		{
			name:   "F_genTime_after_notAfter_signingTime_in_window",
			leafNB: now.Add(-1 * time.Hour), leafNA: now.Add(1 * time.Hour),
			genTime: now.Add(8760 * time.Hour), signingTime: timePtr(now.Add(-30 * time.Minute)),
			wantErr: "failed to verify certificate chain",
		},
		{
			name:   "G_signingTime_out_of_window_genTime_in_window",
			leafNB: now.Add(-1 * time.Hour), leafNA: now.Add(1 * time.Hour),
			genTime: now.Add(-30 * time.Minute), signingTime: timePtr(now.Add(-8760 * time.Hour)),
			wantErr: "signing time",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Root is always long-lived and valid across every window under test,
			// so a failure can only come from the LEAF validity check.
			root, leaf, leafKey := tsaChainWithValidity(t, now.Add(-87600*time.Hour), now.Add(87600*time.Hour), tc.leafNB, tc.leafNA)
			token := forgeTokenWithTimes(t, leaf, leafKey, payload, tc.genTime, tc.signingTime)

			v := NewVerifier(VerifyWithCerts([]*x509.Certificate{root}))
			ts, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))

			if tc.wantErr != "" {
				require.Error(t, err, "token must be rejected")
				require.Contains(t, err.Error(), tc.wantErr,
					"rejection must name the real reason, not fail incidentally")
				require.True(t, ts.IsZero(), "a rejected token must not return a timestamp")
				return
			}

			require.NoError(t, err, "token must verify")
			require.Equal(t, tc.genTime.UTC().Truncate(time.Second), ts.UTC(),
				"Verify must return the TSTInfo genTime")
		})
	}
}

// TestSecurity_TS4_ZeroGenTimeRejected closes the one bypass the CurrentTime pin
// would otherwise introduce: x509.VerifyOptions treats a zero CurrentTime as
// "unset", so pkcs7 would silently fall back to the wall-clock/signingTime path.
// A zero genTime IS DER-encodable as a GeneralizedTime (0001-01-01T00:00:00Z) and
// timestamp.Parse copies it through unchecked, so this is reachable, not theoretical.
func TestSecurity_TS4_ZeroGenTimeRejected(t *testing.T) {
	now := time.Now()
	payload := []byte("zero gentime payload")
	root, leaf, leafKey := tsaChainWithValidity(t, now.Add(-72*time.Hour), now.Add(72*time.Hour), now.Add(-1*time.Hour), now.Add(1*time.Hour))

	// signingTime is in-window, so WITHOUT the zero guard this token verifies
	// via the wall-clock path and hands back a year-1 timestamp.
	signingTime := now.Add(-30 * time.Minute)
	token := forgeTokenWithTimes(t, leaf, leafKey, payload, time.Time{}, &signingTime)

	parsed, err := timestamp.Parse(token)
	require.NoError(t, err, "fixture must be a parseable RFC 3161 token")
	require.True(t, parsed.Time.IsZero(), "fixture must actually carry a zero genTime")

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{root}))
	ts, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.Error(t, err, "a zero-genTime token must be rejected, not silently downgraded to wall clock")
	require.Contains(t, err.Error(), "zero genTime")
	require.True(t, ts.IsZero())
}

// TestSecurity_TS4_PlatformTokenStillVerifies is the compatibility control: a
// token minted through the EXACT library path the platform TSA uses
// (timestamp.Timestamp.CreateResponseWithOpts) must still round-trip. It carries
// both genTime and signingTime in-window, so the tightened check is a no-op for it.
func TestSecurity_TS4_PlatformTokenStillVerifies(t *testing.T) {
	now := time.Now()
	root, leaf, leafKey := tsaChainWithValidity(t, now.Add(-72*time.Hour), now.Add(72*time.Hour), now.Add(-1*time.Hour), now.Add(1*time.Hour))

	payload := []byte("platform tsa round trip")
	digest := sha256.Sum256(payload)

	tsStruct := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest[:],
		Time:              now.UTC(),
		Policy:            oidTSAPolicy,
		Accuracy:          time.Second,
		AddTSACertificate: true,
	}
	resp, err := tsStruct.CreateResponseWithOpts(leaf, leafKey, crypto.SHA256)
	require.NoError(t, err)
	parsed, err := timestamp.ParseResponse(resp)
	require.NoError(t, err)
	token := parsed.RawToken

	// The platform path stamps signingTime unconditionally; both fields present
	// and in-window is precisely why this fix is inert for platform-minted tokens.
	p7, err := pkcs7.Parse(token)
	require.NoError(t, err)
	var signingTime time.Time
	require.NoError(t, p7.UnmarshalSignedAttribute(oidAttrSigningTime, &signingTime),
		"platform-minted tokens are expected to carry a PKCS#9 signingTime attribute")

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{root}))
	ts, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.NoError(t, err, "a platform-minted token must still verify")
	require.Equal(t, now.UTC().Truncate(time.Second), ts.UTC())
}
