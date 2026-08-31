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
