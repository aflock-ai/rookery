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

// jade:ring local

package assurance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Twin of judge-api/pkg/fulcioca/assurance_test.go. The platform stamps the
// URN its ACRForShort renders on the approver's leaf, so every level it mints
// must read back as the same short level here, and everything its table does
// not know must read as no level.
func TestShortAALMatchesThePlatformTable(t *testing.T) {
	for acr, want := range map[string]string{
		"urn:testifysec:params:acr:nist-800-63b:aal1": "aal1",
		"urn:testifysec:params:acr:nist-800-63b:aal2": "aal2",
		"urn:testifysec:params:acr:nist-800-63b:aal3": "aal3",
		// Leaves minted before the URN existed carry the bare short form.
		"aal1": "aal1",
		"aal2": "aal2",
		"aal3": "aal3",
		"":     "",
		"high": "", // the lexical-order trap
		"aal4": "", // a tier this build does not know
		"AAL2": "", // case matters: not the value the platform mints
		"urn:testifysec:params:acr:nist-800-63b:":    "",
		"http://idmanagement.gov/ns/assurance/aal/2": "",
		"urn:evil:params:acr:nist-800-63b:aal3":      "",
	} {
		assert.Equal(t, want, ShortAAL(acr), "ShortAAL(%q)", acr)
	}
}

func TestFromLeafReadsTheForkExtension(t *testing.T) {
	utf8 := func(s string) []byte {
		der, err := asn1.MarshalWithParams(s, "utf8")
		require.NoError(t, err)
		return der
	}
	// Spelled out, not read from OIDLeafAssurance, so a change to the
	// production constant fails this test.
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 100}
	other := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: utf8("aal3")}
	const urn = "urn:testifysec:params:acr:nist-800-63b:aal2"
	for name, tc := range map[string]struct {
		exts           []pkix.Extension
		acr            string
		present, fails bool
	}{
		"another Fulcio extension only": {exts: []pkix.Extension{other}},
		"after another extension":       {exts: []pkix.Extension{other, {Id: oid, Value: utf8(urn)}}, acr: urn, present: true},
		"trailing bytes":                {exts: []pkix.Extension{{Id: oid, Value: append(utf8("aal2"), 0x00)}}, present: true, fails: true},
		"not DER":                       {exts: []pkix.Extension{{Id: oid, Value: []byte{0xff, 0x01}}}, present: true, fails: true},
		// A leaf that states the level twice states none a reader can rely on,
		// whichever occurrence it would have read. crypto/x509 refuses such a
		// certificate at parse time, so these reach FromLeaf only through a
		// certificate built in memory or parsed by something else; judge's
		// certverify.assuranceLevel refuses them the same way.
		"twice, same value":            {exts: []pkix.Extension{{Id: oid, Value: utf8(urn)}, {Id: oid, Value: utf8(urn)}}, present: true, fails: true},
		"twice, lower level first":     {exts: []pkix.Extension{{Id: oid, Value: utf8("aal1")}, {Id: oid, Value: utf8("aal3")}}, present: true, fails: true},
		"twice, higher level first":    {exts: []pkix.Extension{{Id: oid, Value: utf8("aal3")}, {Id: oid, Value: utf8("aal1")}}, present: true, fails: true},
		"twice, second one unreadable": {exts: []pkix.Extension{{Id: oid, Value: utf8(urn)}, {Id: oid, Value: []byte{0xff, 0x01}}}, present: true, fails: true},
	} {
		acr, present, err := FromLeaf(&x509.Certificate{Extensions: tc.exts})
		assert.Equal(t, tc.fails, err != nil, "%s: %v", name, err)
		assert.Equal(t, tc.present, present, "%s: an unreadable extension is not an absent one", name)
		assert.Equal(t, tc.acr, acr, name)
	}
}

// Refusing a repeated extension changes nothing for a certificate that
// crypto/x509 parses: the parser refuses a certificate carrying any extension
// twice. This pins that premise, so the refusal above stays defense in depth
// for certificates built in memory, and a Go release that relaxed the parser
// would fail here rather than silently widen what FromLeaf sees.
func TestParserRefusesARepeatedAssuranceExtension(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v, err := asn1.MarshalWithParams("aal2", "utf8")
	require.NoError(t, err)
	ext := pkix.Extension{Id: OIDLeafAssurance, Value: v}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext, ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return // refused at creation: no such certificate reaches a parser
	}
	_, err = x509.ParseCertificate(der)
	require.Error(t, err, "crypto/x509 parsed a certificate carrying the assurance extension twice")
}
