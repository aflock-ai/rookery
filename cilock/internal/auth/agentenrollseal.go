// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// SEALED DELIVERY: why the enrollment credential is never carried in the clear.
//
// THE ATTACK THIS CLOSES. The refresh credential used to travel as a plain form
// field to `http://localhost:<port>/callback`. That port is ephemeral and
// UNAUTHENTICATED: once cilock's ceremony times out and the listener closes,
// any other local process can bind the same port. A human who then approves a
// stale browser tab mints a durable principal and POSTs its long-lived
// credential straight to whatever is listening. Probing "is something alive on
// the port" cannot fix that — it authenticates a PORT, and the attacker owns
// the port. The delivery channel is simply not trustworthy, so the payload must
// not depend on it.
//
// THE SHAPE. cilock mints an EPHEMERAL ECDH keypair per ceremony — P-256,
// because that is the curve `crypto.subtle` implements natively, so the browser
// half needs no library — and publishes only the PUBLIC key, in the enroll URL.
// The approve page derives a shared secret
// against that public key with its own ephemeral key, and encrypts the
// credential to it. Whoever holds the port receives CIPHERTEXT and no way to
// read it — the private half never leaves the cilock process, never touches
// disk, and dies with the ceremony. This is ECIES, and it is the same reasoning
// as PKCE (which the reviewer suggested): bind the payload to a secret the
// legitimate client proved it holds, rather than to a channel nobody can prove
// anything about.
//
// WHY NOT LITERAL PKCE. PKCE would exchange a one-time CODE at the loopback and
// redeem it server-side for the credential. That is equally sound and needs a
// new platform endpoint, a stored challenge, and a migration. Sealing needs
// none of those and gives the same property — a port-squatter gets something
// useless — so it is the smaller change for the identical guarantee. What PKCE
// would additionally buy is atomic delivery (no principal minted unless the
// code is redeemed); that residue is handled separately and stated honestly in
// BrowserEnroll rather than claimed away.
//
// THE STATE IS BOUND INTO THE CIPHERTEXT as additional authenticated data, so a
// sealed blob captured from one ceremony cannot be replayed into another: the
// AEAD open fails outright rather than yielding a credential meant for a
// different enrollment.

// sealInfo is the HKDF context string. It pins this key derivation to this
// protocol version, so a future sealed format cannot be confused with this one.
const sealInfo = "cilock/agent-enroll/v1"

// errSealOpen is the ONE error every failure path below returns. Which step
// failed — a malformed key, a point off the curve, a truncated blob, a bad tag,
// the wrong ceremony's state — is not something a caller on an open loopback
// port gets to learn, so there is deliberately nothing to distinguish. Keeping
// it a single package-level value rather than eight constructed errors is what
// makes that property structural instead of a convention someone has to
// maintain; TestMalformedSealedInputIsRefusedUniformly holds it in place.
var errSealOpen = errors.New("the sealed credential could not be opened")

// enrollSealKey is one ceremony's ephemeral recipient key. The private half is
// held only in the enrolling process's memory.
type enrollSealKey struct {
	priv *ecdh.PrivateKey
}

// newEnrollSealKey mints the per-ceremony recipient keypair.
func newEnrollSealKey() (*enrollSealKey, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate the enrollment sealing key: %w", err)
	}
	return &enrollSealKey{priv: priv}, nil
}

// PublicKeyB64 is the value published in the enroll URL: the uncompressed
// P-256 point, base64url without padding. It is PUBLIC by construction — it
// authorizes nothing, it only names where a credential may be sealed to.
func (k *enrollSealKey) PublicKeyB64() string {
	return base64.RawURLEncoding.EncodeToString(k.priv.PublicKey().Bytes())
}

// openSealedCredential decrypts what the approve page sealed.
//
// ephemeralPubB64 is the page's one-time public key; sealedB64 is
// nonce||ciphertext. state is bound as additional authenticated data, so a blob
// from another ceremony fails to open rather than decrypting into the wrong
// enrollment. Every failure returns one shape: a caller cannot learn from the
// error WHICH part was wrong.
func (k *enrollSealKey) openSealedCredential(ephemeralPubB64, sealedB64, state string) (string, error) {
	peerBytes, err := base64.RawURLEncoding.DecodeString(ephemeralPubB64)
	if err != nil {
		return "", errSealOpen
	}
	peer, err := ecdh.P256().NewPublicKey(peerBytes)
	if err != nil {
		return "", errSealOpen
	}
	shared, err := k.priv.ECDH(peer)
	if err != nil {
		return "", errSealOpen
	}
	// HKDF over the raw ECDH output: the shared X coordinate is not uniformly
	// random and must never be used directly as a key.
	aeadKey, err := hkdf.Key(sha256.New, shared, nil, sealInfo, 32)
	if err != nil {
		return "", errSealOpen
	}
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return "", errSealOpen
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", errSealOpen
	}
	sealed, err := base64.RawURLEncoding.DecodeString(sealedB64)
	if err != nil || len(sealed) < aead.NonceSize() {
		return "", errSealOpen
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, []byte(state))
	if err != nil {
		return "", errSealOpen
	}
	if len(plain) == 0 {
		return "", errSealOpen
	}
	return string(plain), nil
}
