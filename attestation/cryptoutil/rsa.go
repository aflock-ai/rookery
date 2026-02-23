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
}

func NewRSAVerifier(pub *rsa.PublicKey, hash crypto.Hash) *RSAVerifier {
	return &RSAVerifier{pub, hash}
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

	// Fallback: AWS KMS may sign with PKCS1v15 instead of PSS.
	// This is a weaker scheme — log a warning so operators are aware.
	pkcs1Err := rsa.VerifyPKCS1v15(v.pub, v.hash, digest, sig)
	if pkcs1Err == nil {
		log.Warn("RSA signature verified using PKCS1v15 fallback (PSS failed); this may indicate the signer uses AWS KMS or another provider that does not support PSS")
		return nil
	}

	// Both failed — return the PSS error as the primary failure since PSS is
	// the expected scheme.
	return pssErr
}

func (v *RSAVerifier) Bytes() ([]byte, error) {
	return PublicPemBytes(v.pub)
}
