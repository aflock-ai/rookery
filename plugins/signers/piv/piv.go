// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package piv provides a pure-Go (CGO_ENABLED=0) YubiKey PIV signer for cilock.
//
// It drives the smart card directly over PC/SC via goscard/purego (no cgo),
// reusing the battle-tested go-piv protocol layer (vendored, cgo-free) with a
// goscard-backed transport. The signer:
//
//   - opens slot 9c (Digital Signature) on a connected YubiKey,
//   - reads the slot certificate (the public key the attestation chain pins),
//   - prompts for the PIV PIN INTERACTIVELY (never via an argv flag — DELEG-5),
//   - signs with GENERAL AUTHENTICATE (touch is required by policy), and
//   - exposes a cryptoutil.Signer so cilock can sign DSSE envelopes with it.
//
// Enrollment helpers (GenerateKey, Attest) are provided for provisioning.
package piv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	pivgo "github.com/aflock-ai/rookery/plugins/signers/piv/internal/vendored"
)

// SignatureSlot is the PIV "Digital Signature" slot (9c). Its PIN policy is
// "PIN always", so every signature requires a fresh PIN verification; with a
// touch-required key the card additionally blocks until the user touches it.
var SignatureSlot = pivgo.SlotSignature

// PINPrompter returns the PIV PIN. Implementations MUST read interactively
// (e.g. from the TTY) and MUST NOT source the PIN from an argv flag.
type PINPrompter func() (string, error)

// TouchPrompter is invoked immediately before a blocking, touch-gated card
// operation so the user knows to touch the key. It writes to stderr in the
// default implementation.
type TouchPrompter func()

// Card is an open, exclusive connection to a YubiKey PIV applet.
type Card struct {
	yk *pivgo.YubiKey
}

// Open connects to the first reader whose name looks like a YubiKey. The
// returned Card holds an exclusive PC/SC transaction and must be Closed.
func Open() (*Card, error) {
	readers, err := pivgo.Cards()
	if err != nil {
		return nil, fmt.Errorf("listing smart card readers: %w", err)
	}
	reader, ok := pivgo.FindReaderName(readers)
	if !ok {
		if len(readers) == 0 {
			return nil, errors.New("no smart card readers found (is the YubiKey inserted?)")
		}
		return nil, fmt.Errorf("no YubiKey reader found among %v", readers)
	}
	return OpenReader(reader)
}

// OpenReader connects to a specific PC/SC reader by name.
func OpenReader(reader string) (*Card, error) {
	yk, err := pivgo.Open(reader)
	if err != nil {
		return nil, fmt.Errorf("opening yubikey %q: %w", reader, err)
	}
	return &Card{yk: yk}, nil
}

// Close releases the card connection.
func (c *Card) Close() error { return c.yk.Close() }

// Serial returns the YubiKey serial number.
func (c *Card) Serial() (uint32, error) { return c.yk.Serial() }

// Certificate returns the X.509 certificate stored in the given slot.
func (c *Card) Certificate(slot pivgo.Slot) (*x509.Certificate, error) {
	return c.yk.Certificate(slot)
}

// Attest produces a Yubico attestation certificate for the key in the given
// slot, chaining to the on-device attestation key. Callers verify it against
// the device attestation certificate (c.AttestationCertificate) plus Yubico's
// roots to prove the private key was generated on, and never left, the device.
func (c *Card) Attest(slot pivgo.Slot) (*x509.Certificate, error) {
	return c.yk.Attest(slot)
}

// AttestationCertificate returns the device's attestation certificate.
func (c *Card) AttestationCertificate() (*x509.Certificate, error) {
	return c.yk.AttestationCertificate()
}

// GenerateKey provisions a fresh ECDSA P-256 key in the given slot (enrollment).
// The management key authenticates the operation; the returned public key is
// what you would enroll / certify. Touch and PIN policies are set to "always".
func (c *Card) GenerateKey(managementKey []byte, slot pivgo.Slot) (crypto.PublicKey, error) {
	return c.yk.GenerateKey(managementKey, slot, pivgo.Key{
		Algorithm:   pivgo.AlgorithmEC256,
		PINPolicy:   pivgo.PINPolicyAlways,
		TouchPolicy: pivgo.TouchPolicyAlways,
	})
}

// SignerOption configures the signer returned by Card.Signer.
type SignerOption func(*signerConfig)

type signerConfig struct {
	pinPrompt   PINPrompter
	touchPrompt TouchPrompter
}

// WithPINPrompt sets the interactive PIN prompter (required).
func WithPINPrompt(p PINPrompter) SignerOption {
	return func(c *signerConfig) { c.pinPrompt = p }
}

// WithTouchPrompt sets the pre-sign touch prompter. Defaults to the stderr
// "Touch your security key" prompt.
func WithTouchPrompt(t TouchPrompter) SignerOption {
	return func(c *signerConfig) { c.touchPrompt = t }
}

// Signer returns a cryptoutil.Signer backed by slot 9c. The slot certificate
// is read up front (its public key is what verifiers pin), and the hardware
// crypto.Signer performs the GENERAL AUTHENTICATE under PIN + touch.
//
// hardwareSigner is the seam swapped in tests: pass nil to use the real card.
func (c *Card) Signer(slot pivgo.Slot, opts ...SignerOption) (cryptoutil.Signer, error) {
	cfg := &signerConfig{touchPrompt: DefaultTouchPrompt}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.pinPrompt == nil {
		return nil, errors.New("a PIN prompt is required (PIN must be entered interactively, never via a flag)")
	}

	cert, err := c.yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("reading slot %x certificate: %w", slot.Key, err)
	}

	auth := pivgo.KeyAuth{
		PINPrompt: pinThenTouch(cfg.pinPrompt, cfg.touchPrompt),
		PINPolicy: pivgo.PINPolicyAlways,
	}
	priv, err := c.yk.PrivateKey(slot, cert.PublicKey, auth)
	if err != nil {
		return nil, fmt.Errorf("loading slot %x private key: %w", slot.Key, err)
	}
	hw, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("slot %x key is not a crypto.Signer (%T)", slot.Key, priv)
	}
	// touch is fired from the PIN prompt above; the hardwareSigner itself must
	// not also fire it (that would print the reminder twice and too early).
	return newHardwareSigner(hw, cert)
}

// pinThenTouch wraps the interactive PIN prompt so that the touch reminder is
// printed immediately AFTER a PIN is successfully entered. The vendored layer
// issues GENERAL AUTHENTICATE (which blocks on the user's touch) right after it
// verifies the PIN, so this ordering matches what the user does: enter the PIN,
// then touch the key. Firing the reminder before the PIN prompt (the old
// behavior, when it lived in hardwareSigner.Sign) printed "Touch your security
// key" while the card was actually still waiting for the PIN. If the PIN prompt
// errors, the touch reminder is suppressed. A nil touch is a no-op.
func pinThenTouch(pin PINPrompter, touch TouchPrompter) func() (string, error) {
	return func() (string, error) {
		p, err := pin()
		if err != nil {
			return "", err
		}
		if touch != nil {
			touch()
		}
		return p, nil
	}
}

// hardwareSigner adapts a hardware-backed crypto.Signer (whose Sign blocks on
// PIN + touch) to cryptoutil.Signer / TrustBundler. It hashes the input stream
// itself (cryptoutil.Signer.Sign takes an io.Reader) and asks the hardware to
// sign the resulting digest. It is the ONLY thing that needs a mock in tests.
//
// The touch reminder is NOT fired here: in the real flow the PIN prompt and the
// GENERAL AUTHENTICATE both run inside the inner signer's Sign, and the correct
// moment for the touch reminder is between them — see Card.Signer, which fires
// it from the PIN-prompt callback.
type hardwareSigner struct {
	signer crypto.Signer
	cert   *x509.Certificate
	hash   crypto.Hash
}

func newHardwareSigner(signer crypto.Signer, cert *x509.Certificate) (*hardwareSigner, error) {
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("unsupported slot key type %T (only ECDSA is supported by this signer)", signer.Public())
	}
	return &hardwareSigner{
		signer: signer,
		cert:   cert,
		hash:   crypto.SHA256,
	}, nil
}

func (s *hardwareSigner) KeyID() (string, error) {
	return cryptoutil.GeneratePublicKeyID(s.signer.Public(), s.hash)
}

func (s *hardwareSigner) Sign(r io.Reader) ([]byte, error) {
	digest, err := cryptoutil.Digest(r, s.hash)
	if err != nil {
		return nil, err
	}
	// The inner hardware signer collects the PIN (KeyAuth.PINPrompt), then
	// issues GENERAL AUTHENTICATE which blocks on the user's touch. The touch
	// reminder is printed from the PIN-prompt callback wired in Card.Signer.
	return s.signer.Sign(nil, digest, s.hash)
}

func (s *hardwareSigner) Verifier() (cryptoutil.Verifier, error) {
	pub, ok := s.signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type %T", s.signer.Public())
	}
	return cryptoutil.NewECDSAVerifier(pub, s.hash), nil
}

// Certificate / Intermediates / Roots satisfy cryptoutil.TrustBundler so the
// slot certificate travels with the signature.
func (s *hardwareSigner) Certificate() *x509.Certificate     { return s.cert }
func (s *hardwareSigner) Intermediates() []*x509.Certificate { return nil }
func (s *hardwareSigner) Roots() []*x509.Certificate         { return nil }

var _ cryptoutil.Signer = (*hardwareSigner)(nil)
var _ cryptoutil.TrustBundler = (*hardwareSigner)(nil)

// ensure the context-taking shape is available for callers that hold a ctx.
var _ = context.Background
