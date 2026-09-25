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

package timestamp

import (
	"bytes"
	"crypto"
	"crypto/sha1" //nolint:gosec // RFC 5816 ESSCertID (v1) identifies the signer by a SHA-1 certificate hash
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/digitorus/pkcs7"
)

// RFC 3161 §2.4.1 requires the ESS SigningCertificate attribute in every
// time-stamp token, and RFC 5816 §2.2.1 allows ESSCertIDv2 in its place, "to
// identify the certificate of the TSA". It binds the signer certificate into
// the signed attributes: the SignerInfo's issuerAndSerialNumber is NOT
// signed, so without this binding any certificate for the same key can be
// substituted for the one the TSA signed under — including a re-issued TSA
// certificate whose validity window covers a genTime the original did not.
// digitorus/timestamp writes the attribute and neither it nor digitorus/pkcs7
// ever reads it back, so it is checked here.
var (
	oidSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	oidESSSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidESSSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidESSSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// ErrSigningCertificate is returned when a token's ESS signing-certificate
// attribute is missing, malformed, or does not name the signer certificate.
var ErrSigningCertificate = errors.New("timestamp token ESS signing-certificate attribute does not identify the signer")

type essIssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"` // DEFAULT sha256
	CertHash      []byte
	IssuerSerial  essIssuerSerial `asn1:"optional"`
}

type essSigningCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

type essCertID struct {
	CertHash     []byte
	IssuerSerial essIssuerSerial `asn1:"optional"`
}

type essSigningCertificate struct {
	Certs    []essCertID
	Policies asn1.RawValue `asn1:"optional"`
}

// signedAttribute returns the single value of the signer's authenticated
// attribute oid, whether it was present, and an error when it appears more
// than once or carries more than one value.
func signedAttribute(p7 *pkcs7.PKCS7, oid asn1.ObjectIdentifier) ([]byte, bool, error) {
	if len(p7.Signers) != 1 {
		return nil, false, fmt.Errorf("%w: token must have exactly one signer", ErrSigningCertificate)
	}
	var found []byte
	seen := false
	for _, attr := range p7.Signers[0].AuthenticatedAttributes {
		if !attr.Type.Equal(oid) {
			continue
		}
		if seen {
			return nil, true, fmt.Errorf("%w: attribute %v appears more than once", ErrSigningCertificate, oid)
		}
		seen = true
		var values []asn1.RawValue
		rest, err := asn1.UnmarshalWithParams(attr.Value.FullBytes, &values, "set")
		if err != nil || len(rest) != 0 || len(values) != 1 {
			return nil, true, fmt.Errorf("%w: attribute %v must hold exactly one value", ErrSigningCertificate, oid)
		}
		found = values[0].FullBytes
	}
	return found, seen, nil
}

// checkIssuerSerial compares an optional IssuerSerial with the signer: the
// GeneralNames must hold the signer's issuer as a directoryName and the
// serial must be the signer's.
func checkIssuerSerial(is essIssuerSerial, signer *x509.Certificate) error {
	if is.Serial == nil && len(is.Issuer.FullBytes) == 0 {
		return nil // absent
	}
	if is.Serial == nil || is.Serial.Cmp(signer.SerialNumber) != 0 {
		return fmt.Errorf("%w: issuerSerial names serial %v, the signer's is %v", ErrSigningCertificate, is.Serial, signer.SerialNumber)
	}
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(is.Issuer.FullBytes, &names); err != nil || len(rest) != 0 {
		return fmt.Errorf("%w: issuerSerial issuer is not GeneralNames", ErrSigningCertificate)
	}
	for _, n := range names {
		// directoryName [4] EXPLICIT Name
		if n.Class == asn1.ClassContextSpecific && n.Tag == 4 && bytes.Equal(n.Bytes, signer.RawIssuer) {
			return nil
		}
	}
	return fmt.Errorf("%w: issuerSerial does not name the signer's issuer", ErrSigningCertificate)
}

// verifySigningCertificateV2 checks a SigningCertificateV2 attribute: its first
// ESSCertIDv2 must hash the signer certificate with SHA-256 (the default when
// the algorithm is omitted), SHA-384 or SHA-512, and name its issuer and serial.
func verifySigningCertificateV2(v2 []byte, signer *x509.Certificate) error {
	var sc essSigningCertificateV2
	if rest, err := asn1.Unmarshal(v2, &sc); err != nil || len(rest) != 0 || len(sc.Certs) == 0 {
		return fmt.Errorf("%w: malformed SigningCertificateV2", ErrSigningCertificate)
	}
	id := sc.Certs[0]
	h := crypto.SHA256
	switch alg := id.HashAlgorithm.Algorithm; {
	case len(alg) == 0 || alg.Equal(oidESSSHA256):
	case alg.Equal(oidESSSHA384):
		h = crypto.SHA384
	case alg.Equal(oidESSSHA512):
		h = crypto.SHA512
	default:
		return fmt.Errorf("%w: SigningCertificateV2 certHash algorithm %v is not SHA-256/384/512", ErrSigningCertificate, alg)
	}
	w := h.New()
	w.Write(signer.Raw)
	if !bytes.Equal(w.Sum(nil), id.CertHash) {
		return fmt.Errorf("%w: SigningCertificateV2 certHash names another certificate", ErrSigningCertificate)
	}
	return checkIssuerSerial(id.IssuerSerial, signer)
}

// verifySigningCertificate requires the token's ESS attribute to identify the
// signer certificate: SigningCertificateV2 (any SHA-2 certificate hash) when
// present, else SigningCertificate (SHA-1), per RFC 5816 §2.2.1. The first
// ESSCertID names the signing certificate (RFC 5035 §5.4).
func verifySigningCertificate(p7 *pkcs7.PKCS7, signer *x509.Certificate) error {
	v2, hasV2, err := signedAttribute(p7, oidSigningCertificateV2)
	if err != nil {
		return err
	}
	if hasV2 {
		return verifySigningCertificateV2(v2, signer)
	}
	v1, hasV1, err := signedAttribute(p7, oidSigningCertificate)
	if err != nil {
		return err
	}
	if !hasV1 {
		return fmt.Errorf("%w: no SigningCertificate or SigningCertificateV2 attribute (RFC 3161 §2.4.1)", ErrSigningCertificate)
	}
	var sc essSigningCertificate
	if rest, err := asn1.Unmarshal(v1, &sc); err != nil || len(rest) != 0 || len(sc.Certs) == 0 {
		return fmt.Errorf("%w: malformed SigningCertificate", ErrSigningCertificate)
	}
	sum := sha1.Sum(signer.Raw) //nolint:gosec // ESSCertID is SHA-1 by definition (RFC 2634 §5.4.1)
	if !bytes.Equal(sum[:], sc.Certs[0].CertHash) {
		return fmt.Errorf("%w: SigningCertificate certHash names another certificate", ErrSigningCertificate)
	}
	return checkIssuerSerial(sc.Certs[0].IssuerSerial, signer)
}
