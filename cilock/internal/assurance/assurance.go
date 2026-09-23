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

// Package assurance reads the authenticator assurance level the platform's
// Fulcio fork stamps on a keyless leaf. Its table is a port of the one in
// judge-api/pkg/fulcioca/assurance.go (acrToShort and ShortAAL), which cilock
// cannot import: judge-api is a separate module and rookery is a published
// subtree. The URNs are frozen there; keep the two tables in step.
package assurance

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

// OIDLeafAssurance is the fork-local extension
// (subtrees/fulcio/pkg/identity/email/principal.go,
// OIDAuthenticatorAssuranceLevel): a non-critical DER UTF8String holding the
// signing token's acr claim, absent when the token carried none.
var OIDLeafAssurance = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 100}

// acrToShort maps each URN the platform mints (fulcioca.ACRForShort) to its level.
var acrToShort = map[string]string{
	"urn:testifysec:params:acr:nist-800-63b:aal1": "aal1",
	"urn:testifysec:params:acr:nist-800-63b:aal2": "aal2",
	"urn:testifysec:params:acr:nist-800-63b:aal3": "aal3",
}

// ShortAAL collapses an acr value to "aal1", "aal2" or "aal3", or "" when it
// names no level this build knows. The bare short form maps to itself,
// because leaves minted before the URN existed carry it. Anything else is no
// level, never a guess.
func ShortAAL(acr string) string {
	if short, ok := acrToShort[acr]; ok {
		return short
	}
	for _, short := range acrToShort {
		if acr == short {
			return short
		}
	}
	return ""
}

// FromLeaf returns the acr value the leaf records and whether it records one.
// An extension that is not one DER UTF8String is an error, never an absence.
func FromLeaf(leaf *x509.Certificate) (acr string, present bool, err error) {
	for _, e := range leaf.Extensions {
		if !e.Id.Equal(OIDLeafAssurance) {
			continue
		}
		var value string
		if rest, uerr := asn1.UnmarshalWithParams(e.Value, &value, "utf8"); uerr != nil || len(rest) > 0 {
			return "", true, errors.New("the certificate's assurance extension is not one DER UTF8String")
		}
		return value, true, nil
	}
	return "", false, nil
}
