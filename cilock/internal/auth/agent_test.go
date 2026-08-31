// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// theSecret is the refresh credential every test here seeds. Nothing cilock
// prints — a log line, a run summary, an error — may contain it.
const theSecret = "refresh-credential-do-not-print-9d3f"

func TestAgentStoreRoundTripIsSeparateFromTheHumanSession(t *testing.T) {
	isolateConfig(t)

	require.NoError(t, SaveAgent(AgentCredential{
		PlatformURL:       "https://p.example.com/",
		TenantID:          "11111111-1111-1111-1111-111111111111",
		AgentID:           "22222222-2222-2222-2222-222222222222",
		RefreshCredential: theSecret,
	}))

	// The trailing slash must normalize to the same key on save and lookup.
	got, err := LookupAgent("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, theSecret, got.RefreshCredential)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", got.AgentID)

	// A secret file, at 0600, in its OWN file — not the human session store.
	agentPath, err := AgentStorePath()
	require.NoError(t, err)
	humanPath, err := StorePath()
	require.NoError(t, err)
	assert.NotEqual(t, humanPath, agentPath, "the agent credential must not share a file with the human session")
	info, err := os.Stat(agentPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// The human session lookup must not see the agent credential: an agent
	// credential is never resolvable as a login, in either direction.
	human, err := LookupAny("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, human, "an enrolled agent credential must never resolve as a human session")

	removed, err := DeleteAgent("https://p.example.com/")
	require.NoError(t, err)
	assert.True(t, removed)
	got, err = LookupAgent("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestAgentCredentialFormattingRedactsTheSecret(t *testing.T) {
	c := AgentCredential{
		PlatformURL:       "https://p.example.com",
		TenantID:          "tenant-1",
		AgentID:           "agent-1",
		RefreshCredential: theSecret,
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", c),
		// c.String() rather than fmt.Sprintf("%s", c): the two are the same call,
		// and staticcheck S1025 flags the wrapper. The point of the case is that
		// the String method is what %s reaches, so calling it directly tests the
		// same thing more plainly.
		c.String(),
		fmt.Sprintf("%v", &c),
		fmt.Errorf("wrapped: %v", c).Error(),
	} {
		assert.NotContains(t, rendered, theSecret, "a formatted agent credential must never carry the bearer")
		assert.Contains(t, rendered, "agent-1", "the non-secret identifiers stay readable")
	}
}

// agentExchangeStub answers the credential-exchange contract, recording the
// request body so a test can prove what the client actually sent.
func agentExchangeStub(t *testing.T, spiffeID string, gotBody *[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent/credential-exchange" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if gotBody != nil {
			*gotBody = body
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": jwtWithSubject(t, spiffeID), "token_type": "oidc", "spiffe_id": spiffeID,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeAgentCredentialSendsTheContractAndReadsTheSPIFFEID(t *testing.T) {
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	var body []byte
	srv := agentExchangeStub(t, spiffeID, &body)

	id, err := ExchangeAgentCredential(srv.URL, AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.NoError(t, err)
	assert.Equal(t, jwtWithSubject(t, spiffeID), id.Token, "the returned token must be the one naming the enrolled principal")
	assert.Equal(t, "oidc", id.TokenType)
	assert.Equal(t, spiffeID, id.SPIFFEID)

	var sent map[string]string
	require.NoError(t, json.Unmarshal(body, &sent))
	assert.Equal(t, map[string]string{
		"tenant_id": "t-1", "agent_id": "a-1", "refresh_credential": theSecret,
	}, sent, "the exchange endpoint is the ONLY place the refresh credential goes")
}

// A refused exchange must surface the server's own message and nothing more.
// The platform answers every refusal identically — unknown credential, foreign
// tenant, revoked principal, unknown agent — so the client must not guess which
// happened, and must never echo the credential it presented.
func TestExchangeAgentCredentialReportsTheServersRefusalWithoutTheSecret(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("agent credential not accepted"))
	}))
	defer srv.Close()

	cred := AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	}
	require.NoError(t, SaveAgent(cred))

	_, err := ExchangeAgentCredential(srv.URL, cred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "agent credential not accepted", "report the server's message as-is")
	assert.Contains(t, err.Error(), "401")

	// The local diagnosis: everything an operator can act on, drawn only from
	// state this machine already holds.
	assert.Contains(t, err.Error(), NormalizeURL(srv.URL), "name the platform URL cilock actually resolved")
	assert.Contains(t, err.Error(), "t-1", "the tenant id is a SPIFFE path segment, not a secret")
	assert.Contains(t, err.Error(), "a-1", "the agent id is a SPIFFE path segment, not a secret")
	assert.Contains(t, err.Error(), "revoked", "revocation is checked server-side and is a real cause to check")
	assert.Contains(t, err.Error(), "cannot tell which refusal this is",
		"the diagnosis must say plainly that it is NOT naming the server's reason")

	// The one thing the diagnosis must never gain by being helpful.
	assert.NotContains(t, err.Error(), theSecret, "a refusal must never echo the credential")
}

// The local diagnosis must be derived from local state ONLY. This proves the
// discipline structurally rather than by keyword: two refusals that differ in
// status code and body produce a byte-identical diagnosis block, so nothing in
// it can be branching on which refusal the server chose.
func TestRefusalDiagnosisDoesNotVaryWithTheServersAnswer(t *testing.T) {
	isolateConfig(t)

	// One server, two DIFFERENT refusals — same URL, so any difference in the
	// diagnosis could only come from the response.
	answers := []struct {
		status int
		body   string
	}{
		{http.StatusUnauthorized, "agent credential not accepted"},
		{http.StatusForbidden, "some other wording entirely"},
	}
	var call int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a := answers[call%len(answers)]
		call++
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	}))
	defer srv.Close()

	cred := AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	}
	require.NoError(t, SaveAgent(cred))

	diagnose := func() string {
		_, err := ExchangeAgentCredential(srv.URL, cred)
		require.Error(t, err)
		// Keep only the diagnosis block; the first line carries the server's own
		// message, which legitimately differs.
		_, block, found := strings.Cut(err.Error(), "\n")
		require.True(t, found, "a refusal must carry a local diagnosis block")
		return block
	}

	first, second := diagnose(), diagnose()
	assert.Equal(t, first, second,
		"the local diagnosis must not vary with the server's answer, or it becomes the oracle the uniform refusal denies")
	assert.NotContains(t, first, theSecret)
}

// A response with no SPIFFE ID is a refusal, not a partial success: an agent run
// whose principal cannot be named is the ambiguity this path exists to remove.
func TestExchangeAgentCredentialRefusesAnUnattributableResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "t", "token_type": "oidc"})
	}))
	defer srv.Close()

	_, err := ExchangeAgentCredential(srv.URL, AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spiffe")
}

// The refresh credential must never travel in cleartext to a non-loopback host.
func TestExchangeAgentCredentialRefusesCleartextRemotePlatform(t *testing.T) {
	_, err := ExchangeAgentCredential("http://platform.example.com", AgentCredential{
		TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), theSecret)
}

func TestLookupAgentIsNilWhenNothingIsEnrolled(t *testing.T) {
	isolateConfig(t)
	// A human session alone must not manufacture an agent principal.
	require.NoError(t, Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "human-session",
		AuthMode:    AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	got, err := LookupAgent("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got)
}
