// jade:ring local
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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gitVerifySPIFFE = "spiffe://judge.example/tenant/11111111-1111-1111-1111-111111111111/agent/22222222-2222-2222-2222-222222222222"

// gitVerifyPlatform is a platform with a Fulcio-like root and a TSA, served
// over an httptest discovery endpoint that counts its requests.
type gitVerifyPlatform struct {
	url        string
	bundlePEM  string
	pin        string
	fulcioKey  *ecdsa.PrivateKey
	fulcioRoot *x509.Certificate
	tsaKey     *ecdsa.PrivateKey
	tsaLeaf    *x509.Certificate
	hits       atomic.Int32
}

func newGitVerifyPlatform(t *testing.T) *gitVerifyPlatform {
	t.Helper()
	p := &gitVerifyPlatform{}
	p.fulcioKey, p.fulcioRoot = mintGitTestCA(t, "test fulcio root")
	tsaRootKey, tsaRoot := mintGitTestCA(t, "test tsa root")
	p.tsaKey, p.tsaLeaf = mintGitTestLeaf(t, tsaRoot, tsaRootKey, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	})
	p.bundlePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.fulcioRoot.Raw}))
	sum := sha256.Sum256([]byte(p.bundlePEM))
	p.pin = hex.EncodeToString(sum[:])
	tsaChain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.tsaLeaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tsaRoot.Raw})...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		switch r.URL.Path {
		case "/.well-known/judge-configuration":
			_ = json.NewEncoder(w).Encode(platformconfig.Discovery{Signing: &platformconfig.SigningDiscovery{
				TrustBundlePEM:  p.bundlePEM,
				TSACertChainURL: p.url + "/tsa-chain",
			}})
		case "/tsa-chain":
			_, _ = w.Write(tsaChain)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

func mintGitTestCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

func mintGitTestLeaf(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, shape func(*x509.Certificate)) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	shape(tpl)
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// sign produces the exact CMS shape RunGitSigner emits: detached SignedData
// under a SPIFFE-SAN code-signing leaf, with the platform TSA's token.
func (p *gitVerifyPlatform) sign(t *testing.T, content []byte) string {
	t.Helper()
	spiffe, err := url.Parse(gitVerifySPIFFE)
	require.NoError(t, err)
	leafKey, leaf := mintGitTestLeaf(t, p.fulcioRoot, p.fulcioKey, func(c *x509.Certificate) {
		c.URIs = []*url.URL{spiffe}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	})
	signed, err := pkcs7.NewSignedData(content)
	require.NoError(t, err)
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	require.NoError(t, signed.AddSignerChain(leaf, leafKey, nil, pkcs7.SignerInfoConfig{}))
	signed.Detach()
	data := signed.GetSignedData()
	digest := sha256.Sum256(data.SignerInfos[0].EncryptedDigest)
	resp, err := (&timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: digest[:], Time: time.Now(),
		Nonce: big.NewInt(1), Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}, AddTSACertificate: true,
	}).CreateResponse(p.tsaLeaf, p.tsaKey)
	require.NoError(t, err)
	parsed, err := timestamp.ParseResponse(resp)
	require.NoError(t, err)
	require.NoError(t, data.SignerInfos[0].SetUnauthenticatedAttributes([]pkcs7.Attribute{{
		Type: oidAttributeTimeStampToken, Value: asn1.RawValue{FullBytes: parsed.RawToken},
	}}))
	der, err := signed.Finish()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "sig.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der}), 0o600))
	return path
}

// verify runs Git's verification protocol exactly as `git verify-commit` does.
func verifyGitSignature(t *testing.T, sigPath string, content []byte) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := RunGitVerifier(context.Background(), []string{"--status-fd=1", "--verify", sigPath, "-"},
		bytes.NewReader(content), &stdout, &stderr)
	return stdout.String() + stderr.String(), err
}

func gitVerifyEnv(t *testing.T, platformURL string) {
	t.Helper()
	isolateStores(t)
	t.Setenv("JUDGE_SHARED_SESSION", "")
	t.Setenv(platformconfig.PlatformURLEnv, platformURL)
}

func saveHumanSession(t *testing.T, platformURL, pin string, expiresAt time.Time) {
	t.Helper()
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: platformURL, Token: "human-token", Email: "human@example.com",
		ExpiresAt: expiresAt, TrustBundleSPKI: pin,
	}))
}

func storedAgentPin(t *testing.T, platformURL string) string {
	t.Helper()
	c, err := auth.LookupAgent(platformURL)
	require.NoError(t, err)
	require.NotNil(t, c)
	return c.TrustBundleSPKI
}

var gitVerifyContent = []byte("tree deadbeef\nauthor agent\n\nfeat: agent commit\n")

// Baseline, green on main: a human with a live session and no agent still
// verifies and pins onto the session.
func TestGitVerify_HumanSessionUnchanged(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, p.url)
	saveHumanSession(t, p.url, "", time.Now().Add(time.Hour))

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.NoError(t, err)
	assert.Contains(t, out, "[GNUPG:] GOODSIG")
	human, err := auth.LookupAny(p.url)
	require.NoError(t, err)
	assert.Equal(t, p.pin, human.TrustBundleSPKI)
}

// B6: an enrolled agent with no human session verifies its own commit, and
// the verifier finds the agent's platform with CILOCK_PLATFORM_URL unset
// (AgentPlatformWinsWhenEnvUnset).
func TestGitVerify_EnrolledAgentVerifiesWithoutHumanSession(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, "")
	enrollTestAgent(t, p.url)

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.NoError(t, err, "an enrolled agent must never be told to run a human login")
	assert.Contains(t, out, "[GNUPG:] GOODSIG")
	assert.Contains(t, out, gitVerifySPIFFE)
	assert.Equal(t, p.pin, storedAgentPin(t, p.url), "first use must pin onto the agent credential")
	assert.EqualValues(t, 2, p.hits.Load(), "discovery and the TSA chain must come from the agent's platform")
}

// CILOCK_PLATFORM_URL selects the platform for verification even when the
// agent is enrolled elsewhere (B6-Q2): verifying a signature from another
// platform is not signing as anything else.
func TestGitVerify_EnvUrlWinsForVerification(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, p.url)
	enrollTestAgent(t, "http://127.0.0.1:9")
	saveHumanSession(t, p.url, "", time.Now().Add(time.Hour))

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.NoError(t, err)
	assert.Contains(t, out, "[GNUPG:] GOODSIG")
}

func TestGitVerify_AgentPinMismatchRefuses(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, "")
	enrollTestAgent(t, p.url)
	c, err := auth.LookupAgent(p.url)
	require.NoError(t, err)
	stale := hex.EncodeToString(make([]byte, 32))
	persisted, err := auth.PinAgentTrustBundle(*c, stale)
	require.NoError(t, err)
	require.True(t, persisted)

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cilock enroll agent")
	assert.NotContains(t, out, "GOODSIG")
	assert.Equal(t, stale, storedAgentPin(t, p.url), "a refused rotation must not re-pin")
}

// The credential disappears between lookup and pin: persisted=false must be
// a refusal, never a verification against an unpinned network bundle.
func TestGitVerify_AgentPinNotPersistedRefuses(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, "")
	enrollTestAgent(t, p.url)
	orig := pinAgentGitTrust
	t.Cleanup(func() { pinAgentGitTrust = orig })
	pinAgentGitTrust = func(expect auth.AgentCredential, spki string) (bool, error) {
		_, err := auth.DeleteAgentIf(expect)
		require.NoError(t, err)
		return orig(expect, spki)
	}

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.Error(t, err)
	assert.NotContains(t, out, "GOODSIG")
	gone, lerr := auth.LookupAgent(p.url)
	require.NoError(t, lerr)
	assert.Nil(t, gone)
}

// A pin in the human store binds the agent path too: the agent cannot adopt
// a bundle the human session already rejected (no downgrade by switching
// principal).
func TestGitVerify_HumanPinStillBinds(t *testing.T) {
	for name, expires := range map[string]time.Time{
		"live":    time.Now().Add(time.Hour),
		"expired": time.Now().Add(-time.Hour), // ExpiredHumanPinStillBinds
	} {
		t.Run(name, func(t *testing.T) {
			p := newGitVerifyPlatform(t)
			gitVerifyEnv(t, "")
			enrollTestAgent(t, p.url)
			stale := hex.EncodeToString(make([]byte, 32))
			saveHumanSession(t, p.url, stale, expires)

			out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "human session")
			assert.NotContains(t, out, "GOODSIG")
			assert.Empty(t, storedAgentPin(t, p.url), "the agent must not pin a bundle the human pin refuses")
		})
	}
}

// A delivered-but-unredeemed credential already targets its platform, so it
// pins and verifies like an active one.
func TestGitVerify_PendingAgentVerifies(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, "")
	require.NoError(t, auth.SavePendingAgent(auth.AgentCredential{
		PlatformURL: p.url, TenantID: "t", AgentID: "a", RefreshCredential: "r",
	}))

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.NoError(t, err)
	assert.Contains(t, out, "[GNUPG:] GOODSIG")
	pending, err := auth.LookupPendingAgent(p.url)
	require.NoError(t, err)
	require.NoError(t, auth.PromotePendingAgentIf(*pending))
	assert.Equal(t, p.pin, storedAgentPin(t, p.url), "promotion carries the pin")
}

// B6-Q1: verification is not signing authority, so a credential past its
// signing ceiling still verifies.
func TestGitVerify_ExpiredAgentStillVerifies(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, "")
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL: p.url, TenantID: "t", AgentID: "a", RefreshCredential: "r",
		ExpiresAt: time.Now().Add(-time.Hour),
	}))

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.NoError(t, err)
	assert.Contains(t, out, "[GNUPG:] GOODSIG")
}

func TestGitVerify_UnreadableAgentStoreFailsClosed(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, p.url)
	saveHumanSession(t, p.url, "", time.Now().Add(time.Hour))
	path, err := auth.AgentStorePath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.Error(t, err, "an unreadable agent store must not fall through to the human session")
	assert.NotContains(t, out, "GOODSIG")
}

func TestGitVerify_MultipleAgentsWithoutEnvRefuses(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, "")
	enrollTestAgent(t, p.url)
	enrollTestAgent(t, "http://127.0.0.1:9")

	_, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple agent principals")
	assert.Contains(t, err.Error(), "verify")
	assert.Zero(t, p.hits.Load())
}

func TestGitVerify_NothingToTrustNamesBothRemedies(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, p.url)

	_, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), gitVerifyContent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cilock enroll agent")
	assert.Contains(t, err.Error(), "cilock login")
	assert.Zero(t, p.hits.Load(), "nothing to pin with means no trust material is fetched")
}

func TestGitVerify_TamperedPayloadRefused(t *testing.T) {
	p := newGitVerifyPlatform(t)
	gitVerifyEnv(t, "")
	enrollTestAgent(t, p.url)

	out, err := verifyGitSignature(t, p.sign(t, gitVerifyContent), []byte("tree deadbeef\nauthor attacker\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify Git signature at trusted timestamp", "refused by the signature check, not before it")
	assert.NotContains(t, out, "GOODSIG")
}
