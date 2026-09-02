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
	"strings"
	"testing"
)

// sealForTest is the BROWSER half of the ceremony, written independently of the
// production opener so these tests exercise a real ECDH+HKDF+AES-GCM round trip
// rather than a function calling its own inverse. It mirrors exactly what
// web/src/pages/auth/enroll-seal.ts does with WebCrypto — if the two ever
// diverge, this test cannot detect it, which is why the browser side carries
// its own vector test against a fixture produced HERE.
func sealForTest(t *testing.T, recipientPubB64, plaintext, aad string) (ephemeralPubB64, sealedB64 string) {
	t.Helper()
	peerBytes, err := base64.RawURLEncoding.DecodeString(recipientPubB64)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.P256().NewPublicKey(peerBytes)
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Key(sha256.New, shared, nil, sealInfo, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	// nonce ‖ ciphertext in one buffer sized up front. This mirrors the framing
	// enroll-seal.ts builds, and avoids appending onto `nonce` — which would
	// alias its backing array the moment that slice is ever given spare capacity.
	framed := make([]byte, 0, len(nonce)+len(ct))
	framed = append(framed, nonce...)
	framed = append(framed, ct...)
	return base64.RawURLEncoding.EncodeToString(eph.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(framed)
}

// ── THE CROSS-LANGUAGE VECTOR ────────────────────────────────────────────────
//
// Duplicated verbatim in web/src/pages/auth/enroll-seal.test.ts. The browser
// seals with WebCrypto and this package opens with crypto/ecdh; the two halves
// share no code and are built by different toolchains, so a round-trip test
// inside either language is blind to the two having drifted apart —
// sealForTest below is a Go reimplementation of the browser, and if my reading
// of WebCrypto were wrong it would be wrong in both places identically.
//
// Only a vector both sides are pinned to can catch that. Change the protocol
// and you must regenerate BOTH copies; update one alone and the other goes red,
// which is the alarm working.
const (
	vectorRecipientPriv = "iWXyuqkf0dXL0f7AoKYRWdfI7LONWHdfDLE2aSj6xWQ"
	vectorEphemeralPub  = "BPvP1LEn6Ad-Aq81lN-zvpK_ADkC9-1duh4ac_H74JiDhbbpNN4YBFk4sHEgLhYzQgkh3H-i5GTX6Bfo1DftApI"
	vectorState         = "vector-state-0001"
	vectorCredential    = "cilock-agent-refresh-credential-vector"
	vectorSealed        = "ESIzRFVmd4iZqrvM3_z-Lfqgg8MMqy6e9Dn2TGBtxxZc82O_e8BirWT93BqQ0mzwdM7RzA5K28n9TD23-7E8ejaf"
)

func vectorKey(t *testing.T) *enrollSealKey {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(vectorRecipientPriv)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &enrollSealKey{priv: priv}
}

// THE INTEROP PROOF, cilock half: bytes the BROWSER is pinned to produce must
// open here. Together with the TypeScript half this is the only evidence that a
// credential sealed in a real browser is one a real cilock can read — every
// other test in this file seals with Go and opens with Go.
func TestAWebCryptoSealOpensInGo(t *testing.T) {
	got, err := vectorKey(t).openSealedCredential(vectorEphemeralPub, vectorSealed, vectorState)
	if err != nil {
		t.Fatalf("the vector the browser is pinned to did not open: %v\n"+
			"the two implementations have drifted; regenerate BOTH copies of the vector", err)
	}
	if got != vectorCredential {
		t.Fatalf("opened %q, want %q", got, vectorCredential)
	}
}

// The same vector under a different state must NOT open: proof the state is
// genuinely bound as AEAD additional data on the wire the browser produces, not
// merely compared somewhere in Go before opening.
func TestTheWebCryptoVectorIsBoundToItsState(t *testing.T) {
	if _, err := vectorKey(t).openSealedCredential(vectorEphemeralPub, vectorSealed, "a-different-ceremony"); err == nil {
		t.Fatal("a browser-sealed blob opened under the wrong state; the AAD binding is not in effect")
	}
}

func TestSealedCredentialRoundTrips(t *testing.T) {
	k, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "the-one-time-refresh-credential"
	ephPub, sealed := sealForTest(t, k.PublicKeyB64(), secret, "the-state")

	got, err := k.openSealedCredential(ephPub, sealed, "the-state")
	if err != nil {
		t.Fatalf("a correctly sealed credential failed to open: %v", err)
	}
	if got != secret {
		t.Fatalf("opened %q, want %q", got, secret)
	}
	// The wire form must not be the plaintext — otherwise the whole exercise is
	// theatre and a port-squatter reads the secret straight off the form field.
	if strings.Contains(sealed, secret) || strings.Contains(ephPub, secret) {
		t.Fatal("the credential appears in the sealed wire form")
	}
}

// THE ATTACK THE ROUND-5 REVIEW NAMED: cilock's ceremony times out, its
// listener closes, another local process binds the freed port, and the human
// then approves a stale tab. The impostor receives the POST.
//
// With plain delivery it read a long-lived credential straight off a form
// field. Sealed, it holds ciphertext addressed to a private key that lives only
// in the real cilock process — so this test asserts the impostor CANNOT open
// what it received, using its own freshly generated key exactly as a squatter
// would.
func TestAPortSquatterCannotOpenAnInterceptedCredential(t *testing.T) {
	victim, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "the-one-time-refresh-credential"
	ephPub, sealed := sealForTest(t, victim.PublicKeyB64(), secret, "the-state")

	// The squatter binds the port and receives the identical POST. It has its
	// own key — it never had the victim's private half.
	squatter, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := squatter.openSealedCredential(ephPub, sealed, "the-state"); err == nil {
		t.Fatalf("a port squatter opened the credential: %q", got)
	}

	// And the victim can still open it — the seal protects against the
	// impostor without breaking the legitimate ceremony.
	if _, err := victim.openSealedCredential(ephPub, sealed, "the-state"); err != nil {
		t.Fatalf("the real ceremony could not open its own credential: %v", err)
	}
}

// A blob captured from one ceremony must not open in another. The state is
// bound as AEAD additional data precisely so a replay fails at the crypto
// rather than being caught (or missed) by a later equality check.
func TestASealedBlobDoesNotReplayIntoAnotherCeremony(t *testing.T) {
	k, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	ephPub, sealed := sealForTest(t, k.PublicKeyB64(), "secret", "ceremony-A-state")

	if _, err := k.openSealedCredential(ephPub, sealed, "ceremony-B-state"); err == nil {
		t.Fatal("a blob sealed for one ceremony opened under another ceremony's state")
	}
}

// Malformed input is refused uniformly — and the error text never says WHICH
// part was wrong, so a prober on the loopback learns nothing about the key, the
// state, or the format from the failure it gets back.
func TestMalformedSealedInputIsRefusedUniformly(t *testing.T) {
	k, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	goodEph, goodSealed := sealForTest(t, k.PublicKeyB64(), "secret", "st")

	other, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	otherEph, _ := sealForTest(t, other.PublicKeyB64(), "secret", "st")

	var messages []string
	for name, tc := range map[string]struct{ eph, sealed string }{
		"garbage ephemeral key":  {"!!!not-base64!!!", goodSealed},
		"empty ephemeral key":    {"", goodSealed},
		"not a point":            {base64.RawURLEncoding.EncodeToString([]byte("0123456789")), goodSealed},
		"garbage ciphertext":     {goodEph, "!!!not-base64!!!"},
		"empty ciphertext":       {goodEph, ""},
		"truncated below nonce":  {goodEph, base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})},
		"ciphertext for another": {otherEph, goodSealed},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := k.openSealedCredential(tc.eph, tc.sealed, "st")
			if err == nil {
				t.Fatal("malformed input opened")
			}
			messages = append(messages, err.Error())
		})
	}
	for _, m := range messages {
		if m != messages[0] {
			t.Fatalf("failures are distinguishable: %q vs %q — the error must not say which part was wrong", m, messages[0])
		}
	}
}
