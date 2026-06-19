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

// Package yubipiv verifies YubiKey PIV attestations in pure Go.
//
// A YubiKey can attest that a key in one of its PIV slots was generated
// on-card (and therefore is non-exportable) by issuing a per-slot attestation
// certificate signed by the device's f9 attestation key, which in turn chains
// to the Yubico PIV Root CA. The attestation certificate carries Yubico
// extensions (firmware version, device serial, PIN policy, touch policy, form
// factor) under the arc 1.3.6.1.4.1.41482.3.
//
// This package verifies that chain against the vendored Yubico PIV Root CA and
// parses those extensions. It intentionally does NOT touch a smart card or
// PKCS#11 module — it operates only on certificates a caller already holds — so
// it compiles with CGO_ENABLED=0 and is safe to use inside a server (e.g. a
// platform enrollment endpoint) or any verifier. Reading the certificates off a
// physical YubiKey (the cgo half) is the caller's concern.
//
// The OID layout and policy byte values are documented by Yubico
// (https://developers.yubico.com/PIV/Introduction/PIV_attestation.html) and the
// piv-go project; the parsing here was confirmed against a real YubiKey 5
// attestation (firmware 5.4.3, pin+touch policy byte pair 0x02 0x02).
package yubipiv

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Yubico PIV attestation extension OIDs (arc 1.3.6.1.4.1.41482.3).
var (
	oidFirmware   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPINTouch   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
	oidFormFactor = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}
)

// TouchPolicy is the YubiKey PIV touch policy for a slot key: a touch gate that
// requires physical presence for cryptographic operations.
type TouchPolicy uint8

const (
	TouchPolicyNever  TouchPolicy = 0x01 // no touch required
	TouchPolicyAlways TouchPolicy = 0x02 // a touch is required for every operation
	TouchPolicyCached TouchPolicy = 0x03 // a touch is cached for 15s after use
)

func (t TouchPolicy) String() string {
	switch t {
	case TouchPolicyNever:
		return "never"
	case TouchPolicyAlways:
		return "always"
	case TouchPolicyCached:
		return "cached"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(t))
	}
}

// PINPolicy is the YubiKey PIV PIN policy for a slot key.
type PINPolicy uint8

const (
	PINPolicyNever  PINPolicy = 0x01 // no PIN required
	PINPolicyOnce   PINPolicy = 0x02 // PIN required once per session
	PINPolicyAlways PINPolicy = 0x03 // PIN required for every operation
)

func (p PINPolicy) String() string {
	switch p {
	case PINPolicyNever:
		return "never"
	case PINPolicyOnce:
		return "once"
	case PINPolicyAlways:
		return "always"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(p))
	}
}

// Attestation is the verified result of a YubiKey PIV attestation: the device
// properties Yubico vouched for, plus the attested slot's public key.
type Attestation struct {
	// Serial is the YubiKey's device serial number.
	Serial uint32
	// Firmware is the device firmware version, e.g. "5.4.3".
	Firmware string
	// PINPolicy / TouchPolicy are the policies the attested slot key was
	// generated with. These cannot be changed after generation, so an
	// attestation asserting TouchPolicyAlways is proof the key requires a
	// physical touch for every signature.
	PINPolicy   PINPolicy
	TouchPolicy TouchPolicy
	// FormFactor is the raw Yubico form-factor byte.
	FormFactor byte
	// PublicKey is the public key of the attested slot key. A CSR or enrolled
	// public key MUST equal this (see MatchesPublicKey) to bind the enrollment
	// to the hardware-attested key.
	PublicKey crypto.PublicKey
	// Leaf is the verified attestation certificate.
	Leaf *x509.Certificate
}

// ErrMissingExtension is returned when a required Yubico attestation extension
// is absent (i.e. the certificate is not a YubiKey PIV attestation).
var ErrMissingExtension = errors.New("yubipiv: required Yubico attestation extension not found")

// Verify chains the per-slot attestation leaf through the device f9
// attestation intermediate to the vendored Yubico PIV Root CA, then parses and
// returns the Yubico attestation extensions. It returns an error if the chain
// does not verify or the certificate is not a YubiKey PIV attestation.
func Verify(leaf, intermediate *x509.Certificate) (*Attestation, error) {
	roots, err := yubicoRoots()
	if err != nil {
		return nil, err
	}
	return verify(leaf, intermediate, roots)
}

// VerifyWithRoots is Verify with a caller-supplied root pool, for tests or to
// trust a rotated/alternate Yubico root.
func VerifyWithRoots(leaf, intermediate *x509.Certificate, roots *x509.CertPool) (*Attestation, error) {
	if roots == nil {
		return nil, errors.New("yubipiv: nil root pool")
	}
	return verify(leaf, intermediate, roots)
}

func verify(leaf, intermediate *x509.Certificate, roots *x509.CertPool) (*Attestation, error) {
	if leaf == nil || intermediate == nil {
		return nil, errors.New("yubipiv: nil certificate")
	}
	inter := x509.NewCertPool()
	inter.AddCert(intermediate)
	// Attestation certificates are not TLS certs and carry no serverAuth EKU,
	// so accept any EKU; the trust decision is the chain to the Yubico root.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("yubipiv: attestation chain does not verify to the Yubico PIV Root CA: %w", err)
	}
	return parse(leaf)
}

// parse extracts the Yubico attestation extensions from a (already
// chain-verified) attestation leaf.
func parse(leaf *x509.Certificate) (*Attestation, error) {
	a := &Attestation{PublicKey: leaf.PublicKey, Leaf: leaf}

	ext := make(map[string][]byte, len(leaf.Extensions))
	for _, e := range leaf.Extensions {
		ext[e.Id.String()] = e.Value
	}

	// Firmware: 3 raw bytes {major, minor, patch}.
	if v, ok := ext[oidFirmware.String()]; ok && len(v) == 3 {
		a.Firmware = fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
	}

	// Serial: a DER-encoded INTEGER.
	if v, ok := ext[oidSerial.String()]; ok {
		var serial int64
		if _, err := asn1.Unmarshal(v, &serial); err != nil {
			return nil, fmt.Errorf("yubipiv: parse serial extension: %w", err)
		}
		if serial < 0 {
			return nil, fmt.Errorf("yubipiv: negative serial %d", serial)
		}
		a.Serial = uint32(serial)
	}

	// PIN + touch policy: 2 raw bytes {pinPolicy, touchPolicy}. This is the
	// load-bearing extension — its absence means we cannot assert touch policy,
	// so treat it as fatal.
	v, ok := ext[oidPINTouch.String()]
	if !ok || len(v) != 2 {
		return nil, fmt.Errorf("%w: pin+touch policy (%s)", ErrMissingExtension, oidPINTouch)
	}
	a.PINPolicy = PINPolicy(v[0])
	a.TouchPolicy = TouchPolicy(v[1])

	// Form factor: 1 raw byte (optional).
	if v, ok := ext[oidFormFactor.String()]; ok && len(v) >= 1 {
		a.FormFactor = v[0]
	}

	return a, nil
}

// RequireTouchAlways returns an error unless the attested slot key was
// generated with touch policy ALWAYS — i.e. proof that every signature requires
// a physical touch. This is the control that closes the "silent signing" gap:
// a verifier gating release approval should require it.
func (a *Attestation) RequireTouchAlways() error {
	if a.TouchPolicy != TouchPolicyAlways {
		return fmt.Errorf("yubipiv: touch policy is %q, require %q", a.TouchPolicy, TouchPolicyAlways)
	}
	return nil
}

// MatchesPublicKey reports whether pub is the same key the attestation vouches
// for. Enrollment must call this against the submitted CSR / enrolled public
// key so the stored identity is the hardware-attested key, not an unrelated one.
func (a *Attestation) MatchesPublicKey(pub crypto.PublicKey) bool {
	type equaler interface {
		Equal(x crypto.PublicKey) bool
	}
	if a.PublicKey == nil || pub == nil {
		return false
	}
	if eq, ok := a.PublicKey.(equaler); ok {
		return eq.Equal(pub)
	}
	return false
}
