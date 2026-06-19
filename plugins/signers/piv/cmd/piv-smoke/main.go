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

// Command piv-smoke is a hardware smoke test for the pure-Go YubiKey PIV
// signer. It is intended to be run by a maintainer on real macOS hardware with
// a YubiKey inserted:
//
//	CGO_ENABLED=0 go run ./cmd/piv-smoke
//
// It connects to the card, selects the PIV applet, reads the slot-9c
// certificate (printing its subject), prompts for the PIN interactively, signs
// a fixed test digest via GENERAL AUTHENTICATE (requiring a touch), then
// locally verifies the signature against the certificate's public key and
// prints PASS or FAIL.
//
// It NEVER takes the PIN as a flag — the PIN is always read interactively.
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"

	piv "github.com/aflock-ai/rookery/plugins/signers/piv"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Fprintln(os.Stderr, "piv-smoke: pure-Go (CGO_ENABLED=0) YubiKey PIV signer smoke test")

	card, err := piv.Open()
	if err != nil {
		return fmt.Errorf("opening YubiKey: %w", err)
	}
	defer func() { _ = card.Close() }()

	if serial, err := card.Serial(); err == nil {
		fmt.Fprintf(os.Stderr, "Connected to YubiKey serial %d\n", serial)
	}

	cert, err := card.Certificate(piv.SignatureSlot)
	if err != nil {
		return fmt.Errorf("reading slot 9c certificate (is a key provisioned in slot 9c?): %w", err)
	}
	fmt.Fprintf(os.Stderr, "Slot 9c certificate subject: %s\n", cert.Subject.String())
	fmt.Fprintf(os.Stderr, "Slot 9c public key type:     %T\n", cert.PublicKey)

	signer, err := card.Signer(
		piv.SignatureSlot,
		piv.WithPINPrompt(piv.InteractivePINPrompt()),
		piv.WithTouchPrompt(piv.DefaultTouchPrompt),
	)
	if err != nil {
		return fmt.Errorf("constructing signer: %w", err)
	}

	// Sign a fixed, well-known message so the test is deterministic. The signer
	// hashes the stream with SHA-256 internally; we recompute it to verify.
	msg := []byte("testifysec piv-smoke fixed test vector v1")
	sum := sha256.Sum256(msg)
	fmt.Fprintf(os.Stderr, "Signing SHA-256(%q) = %x\n", msg, sum[:8])

	sig, err := signer.Sign(bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("signing (GENERAL AUTHENTICATE): %w", err)
	}
	fmt.Fprintf(os.Stderr, "Got signature (%d bytes)\n", len(sig))

	verifier, err := signer.Verifier()
	if err != nil {
		return fmt.Errorf("getting verifier: %w", err)
	}
	if err := verifier.Verify(bytes.NewReader(msg), sig); err != nil {
		return fmt.Errorf("signature verification FAILED: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Signature verified against slot-9c public key.")
	fmt.Println("PASS")
	return nil
}
