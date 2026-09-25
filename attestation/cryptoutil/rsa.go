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

	return rsa.SignPSS(rand.Reader, s.priv, s.hash, digest, pssOptions(s.hash))
}

// pssOptions is the one RSASSA-PSS parameter set rookery signs and verifies:
// MGF1 with the message hash and a salt as long as the hash (RFC 8017 §9.1;
// the parameters Wycheproof and the KMS providers use). Verification pins the
// same salt length rather than detecting it, so a signature made under
// different parameters is refused instead of silently accepted.
func pssOptions(h crypto.Hash) *rsa.PSSOptions {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
}

func (s *RSASigner) Verifier() (Verifier, error) {
	return NewRSAVerifier(&s.priv.PublicKey, s.hash), nil
}

type RSAVerifier struct {
	pub  *rsa.PublicKey
	hash crypto.Hash
	// pkcs1v15 selects RSASSA-PKCS1-v1_5 INSTEAD of RSASSA-PSS. A verifier
	// accepts exactly one scheme: accepting both would reduce the key's
	// security to the weaker padding's (Wycheproof WrongPrimitive). It exists
	// for providers (e.g. AWS KMS) whose keys sign with PKCS#1 v1.5 only.
	pkcs1v15 bool
}

// RSAVerifierOption configures an RSAVerifier built via NewRSAVerifierWithOptions.
type RSAVerifierOption func(*RSAVerifier)

// WithPKCS1v15 makes the verifier accept RSASSA-PKCS1-v1_5 signatures, and
// only those. Use it for keys that sign with PKCS#1 v1.5 (e.g. some KMS keys);
// the default verifier accepts RSASSA-PSS only.
func WithPKCS1v15() RSAVerifierOption {
	return func(v *RSAVerifier) {
		v.pkcs1v15 = true
	}
}

// NewRSAVerifier returns an RSAVerifier that accepts only RSASSA-PSS signatures
// with a hash-length salt. For PKCS#1 v1.5 keys build the verifier with
// NewRSAVerifierWithOptions(pub, hash, WithPKCS1v15()).
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
	if v.pkcs1v15 {
		return rsa.VerifyPKCS1v15(v.pub, v.hash, digest, sig)
	}
	return rsa.VerifyPSS(v.pub, v.hash, digest, sig, pssOptions(v.hash))
}
func (v *RSAVerifier) Bytes() ([]byte, error) {
	return PublicPemBytes(v.pub)
}
