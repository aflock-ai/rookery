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
	"encoding/asn1"
	"fmt"
	"unicode/utf8"
)

// Signer assurance, modeled in formal/cilock-policy (Trust.lean meetsMin,
// TrustProofs.lean meetsMin_sound) and held to it by TestFormalDifferentialAssurance.
//
// The platform Fulcio stamps the signing token's `acr` on the leaf in a fork-local
// extension; judge reads it in jade/factory/admission/certverify. A policy that means
// "a person, at AAL2" needs the same reading, or an agent's leaf (which has no such
// extension) and a person's are indistinguishable to the functionary.

var oidAuthenticatorAssuranceLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 100}

var assuranceLevels = map[string]int{
	"urn:testifysec:params:acr:nist-800-63b:aal1": 1,
	"urn:testifysec:params:acr:nist-800-63b:aal2": 2,
	"urn:testifysec:params:acr:nist-800-63b:aal3": 3,
	"aal1": 1, "aal2": 2, "aal3": 3,
}

var minAssuranceRanks = map[string]int{"aal1": 1, "aal2": 2, "aal3": 3}

// leafAssuranceRank is the leaf's level as a rank, or 0 when the extension is
// absent, repeated, not a UTF8String, or an unknown value (leafRank in the model).
func leafAssuranceRank(cert *x509.Certificate) int {
	rank, seen := 0, 0
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidAuthenticatorAssuranceLevel) {
			continue
		}
		seen++
		// Decode as a raw value and check the tag: asn1 decodes any universal
		// string type (PrintableString, IA5String, ...) into a Go string even
		// with the "utf8" param, and only a UTF8String counts.
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &raw)
		if err != nil || len(rest) != 0 || raw.Class != asn1.ClassUniversal ||
			raw.Tag != asn1.TagUTF8String || raw.IsCompound || !utf8.Valid(raw.Bytes) {
			rank = 0
			continue
		}
		rank = assuranceLevels[string(raw.Bytes)]
	}
	if seen != 1 {
		return 0
	}
	return rank
}

// checkMinAssurance enforces CertConstraint.MinAssuranceLevel (meetsMin in the model).
func checkMinAssurance(min string, cert *x509.Certificate) error {
	if min == "" {
		return nil
	}
	want, ok := minAssuranceRanks[min]
	if !ok {
		return fmt.Errorf("minassurancelevel %q is not aal1, aal2 or aal3; failing closed", min)
	}
	if got := leafAssuranceRank(cert); got < want {
		if got == 0 {
			return fmt.Errorf("signer's leaf states no single known assurance level; %s required", min)
		}
		return fmt.Errorf("signer's leaf is at aal%d; %s required", got, min)
	}
	return nil
}
