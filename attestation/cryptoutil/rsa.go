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
	"crypto/rand"
	"crypto/rsa"
	"io"

	"github.com/aflock-ai/rookery/attestation/log"
)

type RSASigner struct {
	priv *rsa.PrivateKey
	hash crypto.Hash
}

func NewRSASigner(priv *rsa.PrivateKey, hash crypto.Hash) *RSASigner {
	return &RSASigner{priv, hash}
}

func (s *RSASigner) KeyID() (string, error) {
	return GeneratePublicKeyID(&s.priv.PublicKey, s.hash)
}

func (s *RSASigner) Sign(r io.Reader) ([]byte, error) {
	digest, err := Digest(r, s.hash)
	if err != nil {
		return nil, err
	}

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       s.hash,
	}

	return rsa.SignPSS(rand.Reader, s.priv, s.hash, digest, opts)
}

func (s *RSASigner) Verifier() (Verifier, error) {
	return NewRSAVerifier(&s.priv.PublicKey, s.hash), nil
}

type RSAVerifier struct {
	pub  *rsa.PublicKey
	hash crypto.Hash
	// allowPKCS1v15Fallback opts the verifier into accepting a PKCS#1 v1.5
	// signature when PSS verification fails. PSS is always the preferred and
	// expected scheme; this fallback is OFF by default because PKCS#1 v1.5 is
	// the weaker scheme and silently accepting it widens the set of signatures
	// the verifier will trust. It exists for providers (e.g. AWS KMS) that sign
	// with PKCS#1 v1.5 only.
	allowPKCS1v15Fallback bool
}

// RSAVerifierOption configures an RSAVerifier built via NewRSAVerifierWithOptions.
type RSAVerifierOption func(*RSAVerifier)

// WithPKCS1v15Fallback opts the verifier into accepting a PKCS#1 v1.5 signature
// when PSS verification fails. Use only for signers that cannot produce PSS
// (e.g. AWS KMS); prefer PSS-only verification otherwise.
func WithPKCS1v15Fallback() RSAVerifierOption {
	return func(v *RSAVerifier) {
		v.allowPKCS1v15Fallback = true
	}
}

// NewRSAVerifier returns an RSAVerifier that accepts only RSASSA-PSS signatures.
// To also accept the weaker PKCS#1 v1.5 scheme, build the verifier with
// NewRSAVerifierWithOptions(pub, hash, WithPKCS1v15Fallback()).
func NewRSAVerifier(pub *rsa.PublicKey, hash crypto.Hash) *RSAVerifier {
	return &RSAVerifier{pub: pub, hash: hash}
}

// NewRSAVerifierWithOptions returns an RSAVerifier configured by the given
// options. With no options it behaves identically to NewRSAVerifier (PSS only).
func NewRSAVerifierWithOptions(pub *rsa.PublicKey, hash crypto.Hash, opts ...RSAVerifierOption) *RSAVerifier {
	v := &RSAVerifier{pub: pub, hash: hash}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func (v *RSAVerifier) KeyID() (string, error) {
	return GeneratePublicKeyID(v.pub, v.hash)
}

func (v *RSAVerifier) Verify(data io.Reader, sig []byte) error {
	digest, err := Digest(data, v.hash)
	if err != nil {
		return err
	}

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       v.hash,
	}

	pssErr := rsa.VerifyPSS(v.pub, v.hash, digest, sig, pssOpts)
	if pssErr == nil {
		return nil
	}

	// PKCS#1 v1.5 is the weaker scheme; only attempt it when the verifier was
	// explicitly opted in (e.g. AWS KMS compatibility). Otherwise the PSS
	// failure is the verdict.
	if v.allowPKCS1v15Fallback {
		if pkcs1Err := rsa.VerifyPKCS1v15(v.pub, v.hash, digest, sig); pkcs1Err == nil {
			log.Warn("RSA signature verified using opt-in PKCS1v15 fallback (PSS failed); this may indicate the signer uses AWS KMS or another provider that does not support PSS")
			return nil
		}
	}

	// PSS failed (and any opted-in fallback also failed) — return the PSS error
	// as the primary failure since PSS is the expected scheme.
	return pssErr
}

func (v *RSAVerifier) Bytes() ([]byte, error) {
	return PublicPemBytes(v.pub)
}
