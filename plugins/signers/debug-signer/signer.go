package debugsigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/signer"
)

const (
	Name = "debug"
)

func init() {
	signer.Register(Name, func() signer.SignerProvider { return New() },
		registry.BoolConfigOption(
			"enabled",
			"Use debug signer (auto-generates ephemeral key)",
			false,
			func(sp signer.SignerProvider, enabled bool) (signer.SignerProvider, error) {
				// No-op, existence of flag is enough to trigger this signer
				return sp, nil
			},
		),
	)
}

// DebugSignerProvider provides ephemeral signing keys for testing
type DebugSignerProvider struct {
	privateKey *ecdsa.PrivateKey
}

func New() *DebugSignerProvider {
	return &DebugSignerProvider{}
}

func (d *DebugSignerProvider) Signer(ctx context.Context) (cryptoutil.Signer, error) {
	// Generate ephemeral key if not already generated
	if d.privateKey == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
		}
		d.privateKey = key

		// Calculate key ID for logging
		keyID, err := cryptoutil.GeneratePublicKeyID(&key.PublicKey, crypto.SHA256)
		if err == nil {
			log.Info("Generated ephemeral signing key", "keyid", keyID[:16]+"...")
		}
	}

	return &DebugSigner{
		privateKey: d.privateKey,
		hash:       crypto.SHA256,
	}, nil
}

// DebugSigner implements cryptoutil.Signer with an ephemeral key
type DebugSigner struct {
	privateKey *ecdsa.PrivateKey
	hash       crypto.Hash
}

func (d *DebugSigner) KeyID() (string, error) {
	return cryptoutil.GeneratePublicKeyID(&d.privateKey.PublicKey, d.hash)
}

func (d *DebugSigner) Sign(r io.Reader) ([]byte, error) {
	digest, err := cryptoutil.Digest(r, d.hash)
	if err != nil {
		return nil, err
	}

	return ecdsa.SignASN1(rand.Reader, d.privateKey, digest)
}

func (d *DebugSigner) Verifier() (cryptoutil.Verifier, error) {
	return cryptoutil.NewECDSAVerifier(&d.privateKey.PublicKey, d.hash), nil
}
