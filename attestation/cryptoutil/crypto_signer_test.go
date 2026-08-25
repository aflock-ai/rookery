// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoSignerCapabilityDoesNotExposeConcretePrivateKey(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := NewECDSASigner(key, crypto.SHA256)
	capability := signer.CryptoSigner()

	_, exposesKey := capability.(*ecdsa.PrivateKey)
	assert.False(t, exposesKey)
	digest := sha256.Sum256([]byte("git commit payload"))
	signature, err := capability.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature))
}
