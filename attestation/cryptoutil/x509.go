// Copyright 2021 The Witness Contributors
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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"
)

type X509Verifier struct {
	cert          *x509.Certificate
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	verifier      Verifier
	trustedTime   time.Time
	// ctRoots are CT trust roots beyond the always-present Sigstore
	// public-good root (see sct.go).
	ctRoots []CTTrustRoot
}

// ErrCACertificateAsLeaf is returned when the certificate presented as the
// signer is a CA (BasicConstraints cA=TRUE).
var ErrCACertificateAsLeaf = errors.New("signing certificate is a CA certificate; a CA is never a signing leaf")

func NewX509Verifier(cert *x509.Certificate, intermediates, roots []*x509.Certificate, trustedTime time.Time, opts ...X509VerifierOption) (*X509Verifier, error) {
	verifier, err := NewVerifier(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	v := &X509Verifier{
		cert:          cert,
		roots:         roots,
		intermediates: intermediates,
		verifier:      verifier,
		trustedTime:   trustedTime,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

func (v *X509Verifier) KeyID() (string, error) {
	return v.verifier.KeyID()
}

// checkSigningLeaf refuses a certificate that is not a signing leaf. First, a
// CA certificate on the signing path. Chain building and the codeSigning EKU
// check do not: an intermediate that carries codeSigning (the platform Fulcio
// CA does) chains to its root, and a self-signed root without EKU verifies
// against a pool holding itself. Either lets a CA key sign attestations
// directly, bypassing the short-lived leaf and the identity and SAN
// constraints it carries. Go sets IsCA only when the basicConstraints
// extension is present. Second, a leaf whose keyUsage does not assert
// digitalSignature, which Go's chain check ignores (CheckSigningKeyUsage).
func (v *X509Verifier) checkSigningLeaf() error {
	if v.cert.BasicConstraintsValid && v.cert.IsCA {
		return fmt.Errorf("%w: %q", ErrCACertificateAsLeaf, v.cert.Subject.String())
	}
	return CheckSigningKeyUsage(v.cert, false)
}

func (v *X509Verifier) Verify(body io.Reader, sig []byte) error {
	if err := v.checkSigningLeaf(); err != nil {
		return err
	}
	chains, err := v.verifyChain()
	if err != nil {
		return err
	}
	// A CT-logging CA's leaf must carry an SCT that verifies (#10032).
	ctRoots, err := v.ctTrustRoots()
	if err != nil {
		return err
	}
	if err := checkCertificateTransparency(v.cert, chains, ctRoots); err != nil {
		return err
	}

	return v.verifier.Verify(body, sig)
}

func (v *X509Verifier) verifyChain() ([][]*x509.Certificate, error) {
	return v.cert.Verify(x509.VerifyOptions{
		CurrentTime:   v.trustedTime,
		Roots:         certificatesToPool(v.roots),
		Intermediates: certificatesToPool(v.intermediates),
		// Attestation/signing leaves are code-signing certs (our Fulcio CA
		// stamps ExtKeyUsageCodeSigning). Require it so a cert chaining to a
		// trusted root but issued for another purpose (e.g. TLS serverAuth)
		// can't be substituted on the signature path. A leaf with no EKU
		// extension stays valid (Go treats an absent EKU as unrestricted).
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
}

func (v *X509Verifier) BelongsToRoot(root *x509.Certificate) error {
	if err := v.checkSigningLeaf(); err != nil {
		return err
	}
	rootPool := certificatesToPool([]*x509.Certificate{root})
	intermediatePool := certificatesToPool(v.intermediates)
	_, err := v.cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   v.trustedTime,
		// Same code-signing EKU requirement as Verify (see note there).
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})

	return err
}

func (v *X509Verifier) Bytes() ([]byte, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.cert.Raw})
	return pemBytes, nil
}

func (v *X509Verifier) Certificate() *x509.Certificate {
	return v.cert
}

func (v *X509Verifier) Intermediates() []*x509.Certificate {
	return v.intermediates
}

func (v *X509Verifier) Roots() []*x509.Certificate {
	return v.roots
}

type X509Signer struct {
	cert          *x509.Certificate
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	signer        Signer
}

type ErrInvalidSigner struct{}

func (e ErrInvalidSigner) Error() string {
	return "signer must not be nil"
}

type ErrInvalidCertificate struct{}

func (e ErrInvalidCertificate) Error() string {
	return "certificate must not be nil"
}

func NewX509Signer(signer Signer, cert *x509.Certificate, intermediates, roots []*x509.Certificate) (*X509Signer, error) {
	if signer == nil {
		return nil, ErrInvalidSigner{}
	}

	if cert == nil {
		return nil, ErrInvalidCertificate{}
	}

	return &X509Signer{
		signer:        signer,
		cert:          cert,
		roots:         roots,
		intermediates: intermediates,
	}, nil
}

func (s *X509Signer) KeyID() (string, error) {
	return s.signer.KeyID()
}

func (s *X509Signer) Sign(r io.Reader) ([]byte, error) {
	return s.signer.Sign(r)
}

func (s *X509Signer) Verifier() (Verifier, error) {
	verifier, err := s.signer.Verifier()
	if err != nil {
		return nil, err
	}

	return &X509Verifier{
		verifier:      verifier,
		cert:          s.cert,
		roots:         s.roots,
		intermediates: s.intermediates,
	}, nil
}

func (s *X509Signer) Certificate() *x509.Certificate {
	return s.cert
}

func (s *X509Signer) Intermediates() []*x509.Certificate {
	return s.intermediates
}

func (s *X509Signer) Roots() []*x509.Certificate {
	return s.roots
}

// CryptoSigner forwards the underlying in-memory capability when the signer
// supports it. X.509Signer itself still exposes no private-key bytes.
func (s *X509Signer) CryptoSigner() crypto.Signer {
	provider, ok := s.signer.(CryptoSignerProvider)
	if !ok {
		return nil
	}
	return provider.CryptoSigner()
}

func certificatesToPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool
}
