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

package policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
)

func leafWith(values ...string) *x509.Certificate {
	cert := &x509.Certificate{}
	for _, v := range values {
		var der []byte
		if v == "~" {
			der = []byte{0xff, 0x00} // an occurrence that is not a UTF8String
		} else {
			der, _ = asn1.MarshalWithParams(v, "utf8")
		}
		cert.Extensions = append(cert.Extensions, pkix.Extension{Id: oidAuthenticatorAssuranceLevel, Value: der})
	}
	return cert
}

func TestMinAssuranceRejectsUnknownMinimum(t *testing.T) {
	require.Error(t, checkMinAssurance("AAL2", leafWith("aal3")))
	require.Error(t, checkMinAssurance("aal4", leafWith("aal3")))
}

func TestMinAssuranceUnsetIsNoConstraint(t *testing.T) {
	require.True(t, CertConstraint{}.MinAssuranceLevel == "")
	require.True(t, CertConstraint{MinAssuranceLevel: "aal2"}.IsSet())
}

// A PrintableString (or IA5String) occurrence is not a UTF8String: Go's asn1
// decodes any universal string tag into a string despite the "utf8" param, so
// the tag must be checked before the value counts.
func TestMinAssuranceRejectsNonUTF8StringTags(t *testing.T) {
	for _, params := range []string{"printable", "ia5"} {
		der, err := asn1.MarshalWithParams("aal3", params)
		require.NoError(t, err)
		cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidAuthenticatorAssuranceLevel, Value: der}}}
		require.Equal(t, 0, leafAssuranceRank(cert), params)
		require.Error(t, checkMinAssurance("aal2", cert), params)
	}
	require.Equal(t, 3, leafAssuranceRank(leafWith("aal3")))
}
