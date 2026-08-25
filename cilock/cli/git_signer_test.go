// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/digitorus/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsGitSignerInvocation(t *testing.T) {
	t.Parallel()
	assert.True(t, IsGitSignerInvocation([]string{"--status-fd=2", "-bsau", "identity"}))
	assert.False(t, IsGitSignerInvocation([]string{"--status-fd=2"}))
	assert.False(t, IsGitSignerInvocation([]string{"status"}))
}

func TestParseGitSignerArgs(t *testing.T) {
	t.Parallel()
	got, err := parseGitSignerArgs([]string{"--status-fd=2", "-bsau", "identity"})
	require.NoError(t, err)
	assert.Equal(t, gitSignerArgs{statusFD: 2, sign: true, detached: true, armor: true}, got)

	_, err = parseGitSignerArgs([]string{"--status-fd=2", "-sau", "identity"})
	assert.ErrorContains(t, err, "detached armored")
	_, err = parseGitSignerArgs([]string{"--status-fd=2", "-bsau", "identity", "one", "two"})
	assert.ErrorContains(t, err, "at most one input")
}

func TestParseGitVerifyArgs(t *testing.T) {
	t.Parallel()
	got, err := parseGitVerifyArgs([]string{"--status-fd=1", "--verify", "signature.pem", "-"})
	require.NoError(t, err)
	assert.Equal(t, gitVerifyArgs{statusFD: 1, signaturePath: "signature.pem", contentPath: "-"}, got)

	_, err = parseGitVerifyArgs([]string{"--status-fd=1", "--verify", "signature.pem"})
	assert.ErrorContains(t, err, "signature file, and signed content")
}

func TestRunGitSignerDefaultsToPlatformAndRequiresTimestamp(t *testing.T) {
	signer := newTestGitSigner(t)
	oldResolve, oldLoad, oldTimestamp := resolveGitSigningToken, loadGitSigningSigner, addGitSignatureTimestamp
	t.Cleanup(func() {
		resolveGitSigningToken, loadGitSigningSigner, addGitSignatureTimestamp = oldResolve, oldLoad, oldTimestamp
	})

	resolveGitSigningToken = func(platformURL, audience string) (auth.SignTokenResult, error) {
		assert.Equal(t, platformconfig.DefaultPlatformURL, platformURL)
		assert.Equal(t, "sigstore", audience)
		return auth.SignTokenResult{Token: "short-lived-test-token"}, nil
	}
	loadGitSigningSigner = func(_ context.Context, fulcioURL, token string) (cryptoutil.Signer, error) {
		assert.Equal(t, platformconfig.DefaultPlatformURL+"/fulcio", fulcioURL)
		assert.Equal(t, "short-lived-test-token", token)
		return signer, nil
	}
	addGitSignatureTimestamp = func(_ context.Context, signed *pkcs7.SignedData, tsaURL string) error {
		assert.Equal(t, platformconfig.DefaultPlatformURL+"/api/v1/timestamp", tsaURL)
		data := signed.GetSignedData()
		require.Len(t, data.SignerInfos, 1)
		token := mintRFC3161Token(t, data.SignerInfos[0].EncryptedDigest)
		return data.SignerInfos[0].SetUnauthenticatedAttributes([]pkcs7.Attribute{{
			Type:  oidAttributeTimeStampToken,
			Value: asn1.RawValue{FullBytes: token},
		}})
	}
	t.Setenv(platformconfig.PlatformURLEnv, "")

	payload := []byte("tree deadbeef\nauthor test\n")
	var stdout, stderr bytes.Buffer
	err := RunGitSigner(context.Background(), []string{"--status-fd=2", "-bsau", "identity"}, bytes.NewReader(payload), &stdout, &stderr)
	require.NoError(t, err)
	assert.Contains(t, stderr.String(), "[GNUPG:] BEGIN_SIGNING")
	assert.Contains(t, stderr.String(), "[GNUPG:] SIG_CREATED D 19 8")
	assert.NotContains(t, stdout.String(), "short-lived-test-token")
	assert.NotContains(t, stderr.String(), "short-lived-test-token")

	block, rest := pem.Decode(stdout.Bytes())
	require.NotNil(t, block)
	assert.Equal(t, "SIGNED MESSAGE", block.Type)
	assert.Empty(t, rest)
	p7, err := pkcs7.Parse(block.Bytes)
	require.NoError(t, err)
	require.Len(t, p7.Signers, 1)
	assert.Len(t, p7.Signers[0].UnauthenticatedAttributes, 1)
	p7.Content = payload
	require.NoError(t, p7.Verify())
}

func TestRunGitSignerFailsClosedWhenTimestampFails(t *testing.T) {
	signer := newTestGitSigner(t)
	oldResolve, oldLoad, oldTimestamp := resolveGitSigningToken, loadGitSigningSigner, addGitSignatureTimestamp
	t.Cleanup(func() {
		resolveGitSigningToken, loadGitSigningSigner, addGitSignatureTimestamp = oldResolve, oldLoad, oldTimestamp
	})
	resolveGitSigningToken = func(string, string) (auth.SignTokenResult, error) {
		return auth.SignTokenResult{Token: "short-lived-test-token"}, nil
	}
	loadGitSigningSigner = func(context.Context, string, string) (cryptoutil.Signer, error) { return signer, nil }
	addGitSignatureTimestamp = func(context.Context, *pkcs7.SignedData, string) error {
		return errors.New("TSA unavailable")
	}

	var stdout, stderr bytes.Buffer
	err := RunGitSigner(context.Background(), []string{"--status-fd=2", "-bsau", "identity"}, bytes.NewReader([]byte("commit")), &stdout, &stderr)
	assert.ErrorContains(t, err, "timestamp Git signature")
	assert.Empty(t, stdout.Bytes(), "a commit signature must never be emitted without its TSA token")
	assert.Empty(t, stderr.Bytes(), "success status must never be emitted before timestamping succeeds")
}

func TestRunGitSignerRejectsInsecurePlatformBeforeIdentityResolution(t *testing.T) {
	oldResolve := resolveGitSigningToken
	t.Cleanup(func() { resolveGitSigningToken = oldResolve })
	called := false
	resolveGitSigningToken = func(string, string) (auth.SignTokenResult, error) {
		called = true
		return auth.SignTokenResult{}, nil
	}
	t.Setenv(platformconfig.PlatformURLEnv, "http://platform.example")

	err := RunGitSigner(
		context.Background(),
		[]string{"--status-fd=2", "-bsau", "identity"},
		bytes.NewReader([]byte("commit")),
		io.Discard,
		io.Discard,
	)
	assert.ErrorContains(t, err, "https")
	assert.False(t, called, "an insecure platform must be rejected before resolving a signing token")
}

func TestReadGitSignInputBound(t *testing.T) {
	t.Parallel()
	_, err := readGitSignInput("", bytes.NewReader(make([]byte, maxGitSignInput+1)))
	assert.ErrorContains(t, err, "exceeds")
}

func TestGitTimestampTokenRequired(t *testing.T) {
	t.Parallel()
	signer := newTestGitSigner(t)
	bundler := signer.(cryptoutil.TrustBundler)
	provider := signer.(cryptoutil.CryptoSignerProvider)
	signed, err := pkcs7.NewSignedData([]byte("commit"))
	require.NoError(t, err)
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	require.NoError(t, signed.AddSignerChain(
		bundler.Certificate(), provider.CryptoSigner(), nil, pkcs7.SignerInfoConfig{},
	))
	signed.Detach()
	der, err := signed.Finish()
	require.NoError(t, err)
	p7, err := pkcs7.Parse(der)
	require.NoError(t, err)
	_, err = gitTimestampToken(p7)
	assert.ErrorContains(t, err, "no mandatory RFC 3161 timestamp")
}

func newTestGitSigner(t *testing.T) cryptoutil.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CI/lock Git signing test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(
		key,
		cryptoutil.SignWithHash(crypto.SHA256),
		cryptoutil.SignWithCertificate(cert),
	)
	require.NoError(t, err)
	return signer
}
