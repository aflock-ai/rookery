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

package piv

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/signer"
)

func init() {
	signer.Register("piv", func() signer.SignerProvider { return New() },
		registry.StringConfigOption(
			"reader",
			"PC/SC reader name to use (defaults to the first YubiKey-looking reader)",
			"",
			func(sp signer.SignerProvider, reader string) (signer.SignerProvider, error) {
				psp, ok := sp.(SignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a piv signer provider")
				}
				psp.Reader = reader
				return psp, nil
			},
		),
	)
}

// SignerProvider is the rookery signer plugin for a YubiKey PIV slot-9c key.
// It opens the card lazily in Signer() so that nothing touches hardware until a
// signature is actually requested. The PIN is always prompted interactively.
type SignerProvider struct {
	// Reader optionally pins a specific PC/SC reader name. Empty => auto-detect
	// the first YubiKey reader.
	Reader string

	// pinPrompt/touchPrompt are overridable for testing; nil => the interactive
	// terminal prompts.
	pinPrompt   PINPrompter
	touchPrompt TouchPrompter
}

// New constructs a piv SignerProvider with the interactive terminal prompts.
func New() SignerProvider {
	return SignerProvider{}
}

// Signer opens the YubiKey and returns a cryptoutil.Signer for slot 9c. The
// returned signer holds the open card; cilock signs through it (PIN + touch on
// each call). NOTE: the connection is exclusive for the signer's lifetime.
func (sp SignerProvider) Signer(_ context.Context) (cryptoutil.Signer, error) {
	var card *Card
	var err error
	if sp.Reader != "" {
		card, err = OpenReader(sp.Reader)
	} else {
		card, err = Open()
	}
	if err != nil {
		return nil, err
	}

	pin := sp.pinPrompt
	if pin == nil {
		pin = InteractivePINPrompt()
	}
	touch := sp.touchPrompt
	if touch == nil {
		touch = DefaultTouchPrompt
	}

	s, err := card.Signer(SignatureSlot, WithPINPrompt(pin), WithTouchPrompt(touch))
	if err != nil {
		_ = card.Close()
		return nil, err
	}
	return &cardBoundSigner{Signer: s, card: card}, nil
}

// cardBoundSigner keeps the open Card alive alongside the signer. It forwards
// the cryptoutil.Signer methods and the cryptoutil.TrustBundler methods (DSSE
// type-asserts the signer to TrustBundler to embed the slot certificate, so we
// MUST forward them rather than let the embedding shadow the assertion). cilock
// does not currently close signers, so the card is released when the process
// exits; a future caller wanting deterministic release can type-assert to
// io.Closer via Close.
type cardBoundSigner struct {
	cryptoutil.Signer
	card *Card
}

func (c *cardBoundSigner) Close() error { return c.card.Close() }

// Certificate / Intermediates / Roots forward the inner signer's TrustBundler
// implementation if present (the hardwareSigner always implements it).
func (c *cardBoundSigner) Certificate() *x509.Certificate {
	if tb, ok := c.Signer.(cryptoutil.TrustBundler); ok {
		return tb.Certificate()
	}
	return nil
}

func (c *cardBoundSigner) Intermediates() []*x509.Certificate {
	if tb, ok := c.Signer.(cryptoutil.TrustBundler); ok {
		return tb.Intermediates()
	}
	return nil
}

func (c *cardBoundSigner) Roots() []*x509.Certificate {
	if tb, ok := c.Signer.(cryptoutil.TrustBundler); ok {
		return tb.Roots()
	}
	return nil
}

var _ cryptoutil.TrustBundler = (*cardBoundSigner)(nil)
