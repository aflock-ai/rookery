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
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrSigningKeyUsage is returned when a certificate that verifies a signature
// carries a keyUsage extension that does not permit signing.
var ErrSigningKeyUsage = errors.New("certificate keyUsage does not permit signing")

// CheckSigningKeyUsage refuses a signing certificate whose keyUsage extension
// is present but asserts neither digitalSignature nor, when
// allowContentCommitment is set, contentCommitment (RFC 5280 §4.2.1.3).
//
// Go's x509.Verify ignores a leaf's keyUsage bits entirely (it checks
// keyCertSign on issuers, in CheckSignatureFrom), so without this a
// certificate issued only for key encipherment verifies signatures. An absent
// extension (KeyUsage == 0) places no restriction. RFC 3161 time-stamp
// signers may assert contentCommitment (nonRepudiation) instead of
// digitalSignature; DSSE signing leaves may not.
//
// A signing certificate that is not a CA must not assert keyCertSign or
// cRLSign either: RFC 5280 §4.2.1.9 requires cA for keyCertSign, and a leaf
// claiming CA-only usages is misissued. (A CA certificate never reaches this
// check on the signing path; X509Verifier refuses it first.)
func CheckSigningKeyUsage(cert *x509.Certificate, allowContentCommitment bool) error {
	ku := cert.KeyUsage
	if !(cert.BasicConstraintsValid && cert.IsCA) && ku&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return fmt.Errorf("%w: %q is not a CA but asserts keyCertSign or cRLSign (keyUsage %#x)", ErrSigningKeyUsage, cert.Subject.String(), int(ku))
	}
	if ku == 0 || ku&x509.KeyUsageDigitalSignature != 0 {
		return nil
	}
	if allowContentCommitment && ku&x509.KeyUsageContentCommitment != 0 {
		return nil
	}
	return fmt.Errorf("%w: %q has keyUsage %#x", ErrSigningKeyUsage, cert.Subject.String(), int(ku))
}
