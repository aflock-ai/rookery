// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	agentTestSPIFFEID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	agentTestSecret   = "refresh-credential-do-not-print-9d3f"
)

func isolateAgentConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
}

// agentExchangePlatform answers the credential-exchange contract with a token
// whose `sub` is the SPIFFE ID, exactly as the platform's exchange does.
func agentExchangePlatform(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/credential-exchange" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      agentTestJWT(agentTestSPIFFEID),
			"token_type": "oidc",
			"spiffe_id":  agentTestSPIFFEID,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// agentTestJWT is the compact JWS the exchange hands back: `sub` carries the
// SPIFFE ID and `exp` satisfies the provider's lifetime check. Nothing verifies
// the signature — the provider forwards the token to Fulcio unverified.
func agentTestJWT(subject string) string {
	payload, _ := json.Marshal(map[string]any{"sub": subject, "exp": time.Now().Add(10 * time.Minute).Unix()})
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + enc(payload) + "." + enc([]byte("unverified"))
}

// spiffeSANFromToken shapes the fake Fulcio's leaf from the token it was
// presented: the token's subject becomes a URI SAN and the default email SAN is
// dropped. A leaf built this way can only carry the SPIFFE ID if the exchanged
// token is what reached the certificate authority.
func spiffeSANFromToken(leaf *x509.Certificate, token string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return
	}
	uri, err := url.Parse(claims.Sub)
	if err != nil || claims.Sub == "" {
		return
	}
	leaf.URIs = []*url.URL{uri}
	leaf.EmailAddresses = nil
}

// TestAgentRunSignsWithASPIFFECertificate is the end-to-end shape: a stored
// agent credential is exchanged, the exchanged token buys a Fulcio certificate,
// and that certificate carries the agent's SPIFFE URI SAN — not the human's
// email — even though a human session is also stored for the same platform.
//
// It pins the two-token boundary from the far side as well: the refresh
// credential appears in nothing Fulcio ever received.
func TestAgentRunSignsWithASPIFFECertificate(t *testing.T) {
	isolateAgentConfig(t)
	platform := agentExchangePlatform(t)
	fulcio := newFakeFulcioShaped(t, nil, spiffeSANFromToken)

	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: platform.URL,
		Token:       "stored-human-session",
		Email:       "cole@example.com",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platform.URL,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
	}))

	cmd := &cobra.Command{Use: "run"}
	ro := &options.RunOptions{}
	ro.AddFlags(cmd)
	require.NoError(t, cmd.ParseFlags([]string{"--platform-url", platform.URL}))

	ro.ResolvePlatformDefaults(cmd)
	require.NoError(t, ro.AgentIdentityError())
	require.Equal(t, agentTestSPIFFEID, ro.ResolvedAgentPrincipal())

	token := cmd.Flags().Lookup("signer-fulcio-token").Value.String()
	require.NotEmpty(t, token, "the agent exchange must install a signing token")

	signers, err := loadSigners(context.Background(),
		staticFulcioSignerOptions(fulcio.URL, &token),
		options.KMSSignerProviderOptions{}, onlyFulcio)
	require.NoError(t, err)
	require.Len(t, signers, 1)

	_, err = signers[0].Sign(bytes.NewBufferString("payload"))
	require.NoError(t, err)

	bundler, ok := signers[0].(cryptoutil.TrustBundler)
	require.True(t, ok, "a keyless signer must carry its certificate")
	cert := bundler.Certificate()
	require.NotNil(t, cert)

	uris := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}
	assert.Contains(t, uris, agentTestSPIFFEID, "the leaf must carry the agent's SPIFFE URI SAN")
	assert.Empty(t, cert.EmailAddresses, "an agent leaf must not carry a human email subject")

	requests := fulcio.Requests()
	require.NotEmpty(t, requests, "Fulcio must actually have been asked for a certificate")
	for _, req := range requests {
		assert.NotContains(t, req.Body, agentTestSecret,
			"the refresh credential must never reach Fulcio; only the exchanged token does")
	}
}

// `cilock agent login` takes the credential on stdin so it never lands in shell
// history, and prints the identifiers back without ever echoing the secret.
func TestAgentLoginReadsStdinAndNeverEchoesTheCredential(t *testing.T) {
	isolateAgentConfig(t)

	login := AgentLoginCmd()
	var out bytes.Buffer
	login.SetOut(&out)
	login.SetErr(&out)
	login.SetIn(strings.NewReader(agentTestSecret + "\n"))
	login.SetArgs([]string{
		"--platform-url", "https://p.example.com",
		"--tenant-id", "t-1", "--agent-id", "a-1",
	})
	require.NoError(t, login.Execute())

	stored, err := auth.LookupAgent("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, agentTestSecret, stored.RefreshCredential, "the trailing newline must be trimmed off")

	status := AgentStatusCmd()
	var statusOut bytes.Buffer
	status.SetOut(&statusOut)
	status.SetArgs([]string{"--platform-url", "https://p.example.com"})
	require.NoError(t, status.Execute())

	for name, text := range map[string]string{"login output": out.String(), "status output": statusOut.String()} {
		assert.NotContains(t, text, agentTestSecret, "the credential is accepted once and never printed again ("+name+")")
		assert.Contains(t, text, "a-1", "the agent id is not secret and is what an operator needs to see")
	}
}

// A stored credential is not an identity until the platform has redeemed it:
// the store keeps an unredeemed credential across a transient refusal on
// purpose, and `agent status` exiting 0 with "Agent principal for" over one
// of those is what let an end-to-end run read a 503 as success. The trust
// domain is pinned only by a successful exchange, so it is the record of
// redemption, and status says which state the credential is in.
func TestAgentStatusDistinguishesPendingFromRedeemed(t *testing.T) {
	isolateAgentConfig(t)
	pending := auth.AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-1", RefreshCredential: agentTestSecret}
	require.NoError(t, auth.SaveAgent(pending))

	run := func() string {
		status := AgentStatusCmd()
		var out bytes.Buffer
		status.SetOut(&out)
		status.SetArgs([]string{"--platform-url", "https://p.example.com"})
		require.NoError(t, status.Execute())
		return out.String()
	}

	before := run()
	assert.Contains(t, before, "not yet redeemed", "an unpinned credential is pending, and status must say so: %s", before)
	assert.NotContains(t, before, "spiffe://", "no identity can be named before the platform answered: %s", before)

	require.NoError(t, auth.PinAgentTrustDomain(pending, "factory.example"))
	after := run()
	assert.Contains(t, after, "spiffe://factory.example/tenant/t-1/agent/a-1", "a redeemed credential names the whole identity, authority included: %s", after)
	assert.NotContains(t, after, "not yet redeemed")
}

// A ceremony's delivery sits in the pending slot beside the credential that
// signs; status names both, each as what it is, so an operator who sees a
// stalled activation knows which identity their runs use meanwhile.
func TestAgentStatusNamesAPendingDeliveryBesideTheActiveIdentity(t *testing.T) {
	isolateAgentConfig(t)
	active := auth.AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-active", RefreshCredential: agentTestSecret, TrustDomain: "p.example.com"}
	require.NoError(t, auth.SaveAgent(active))
	require.NoError(t, auth.SavePendingAgent(auth.AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-new", RefreshCredential: "new-" + agentTestSecret}))

	status := AgentStatusCmd()
	var out bytes.Buffer
	status.SetOut(&out)
	status.SetArgs([]string{"--platform-url", "https://p.example.com"})
	require.NoError(t, status.Execute())
	text := out.String()
	assert.Contains(t, text, "Pending for https://p.example.com: agent a-new")
	assert.Contains(t, text, "spiffe://p.example.com/tenant/t-1/agent/a-active", "the active identity is still the one named as signing")
	assert.NotContains(t, text, agentTestSecret)
}
