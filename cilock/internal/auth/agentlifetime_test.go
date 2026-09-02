// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An enrolled agent is TIME-BOUND: the human confirms a TTL at enrollment (8h
// by default, 7d at most) and the platform refuses the credential past it. The
// client's half of that contract is small — carry the human's choice to the
// page, remember the ceiling the platform answered with, refuse to present a
// credential it already knows is dead, and redeem the credential once so a
// ceremony whose delivery failed leaves nothing usable behind.

func TestEnrollURLCarriesTheTTLHintInSeconds(t *testing.T) {
	u := agentEnrollURL("https://platform.example.com", "http://localhost:1/callback", "s", "pub",
		EnrollParams{TTL: 90 * time.Minute})
	parsed, err := url.Parse(u)
	require.NoError(t, err)
	assert.Equal(t, "5400", parsed.Query().Get("ttl"), "the page pre-selects from whole seconds")

	none := agentEnrollURL("https://platform.example.com", "http://localhost:1/callback", "s", "pub", EnrollParams{})
	parsed, err = url.Parse(none)
	require.NoError(t, err)
	assert.False(t, parsed.Query().Has("ttl"), "no --ttl means the page's own default, not a zero")
}

func TestAValidCallbackStoresTheExpiryThePlatformAnswered(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	require.NoError(t, err)
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, "the-real-state", seal, resultCh)

	expires := time.Now().Add(8 * time.Hour).UTC().Truncate(time.Second)
	form := newSealedForm(t, seal, "the-real-state", "the-minted-secret",
		"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
	form.Set("expires_at", expires.Format(time.RFC3339))
	rec := postEnrollCallback(t, h, form)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	cred, err := LookupPendingAgent(platform)
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.True(t, cred.ExpiresAt.Equal(expires), "stored expiry = %v, want %v", cred.ExpiresAt, expires)
	o := <-resultCh
	require.NoError(t, o.err)
	assert.True(t, o.cred.ExpiresAt.Equal(expires), "the outcome reports the ceiling so the command can print it")
}

func TestACallbackWithAnUnreadableExpiryIsRefusedAndNotStored(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	require.NoError(t, err)
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, "the-real-state", seal, resultCh)

	form := newSealedForm(t, seal, "the-real-state", "the-minted-secret",
		"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
	form.Set("expires_at", "next tuesday")
	rec := postEnrollCallback(t, h, form)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	cred, err := LookupAgent(platform)
	require.NoError(t, err)
	assert.Nil(t, cred, "a credential whose lifetime cannot be read is not stored — status would lie about it")
	select {
	case o := <-resultCh:
		t.Fatalf("a refused callback must leave the ceremony open for the genuine one, but it ended with %+v", o)
	default:
	}
}

func TestExchangeRefusesACredentialItKnowsHasExpired(t *testing.T) {
	isolateConfig(t)
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cred := AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	_, err := ExchangeAgentCredential(srv.URL, cred)
	require.Error(t, err)
	assert.False(t, reached, "a credential past its own ceiling is not presented at all")
	assert.Contains(t, err.Error(), "expired")
	assert.Contains(t, err.Error(), "cilock enroll agent", "the remedy is a new ceremony")
	assert.NotContains(t, err.Error(), theSecret)
}

func TestExchangeStillPresentsACredentialWithNoKnownExpiry(t *testing.T) {
	// Zero means "not recorded", not "expired": the platform is the authority
	// and answers for itself. The local check only saves a round trip it can
	// prove is pointless.
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	srv := agentExchangeStub(t, spiffeID, nil)
	_, err := ExchangeAgentCredential(srv.URL, AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.NoError(t, err)
}

func TestActivateEnrolledAgentRedeemsTheStoredCredentialOnce(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	var body []byte
	srv := agentExchangeStub(t, spiffeID, &body)
	require.NoError(t, SavePendingAgent(AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	}))

	id, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-1"})
	require.NoError(t, err)
	assert.Equal(t, spiffeID, id.SPIFFEID)
	assert.NotEmpty(t, body, "activation IS an exchange: the platform must have seen the credential")

	cred, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, cred, "a redeemed credential is promoted to the one this machine signs with")
	assert.Equal(t, "platform.example.com", cred.TrustDomain, "the first exchange pins the trust domain, as always")
}

func TestActivateEnrolledAgentDiscardsACredentialThePlatformRefuses(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"agent_credential_rejected","remediation":"agent credential not accepted"}`))
	}))
	defer srv.Close()
	require.NoError(t, SavePendingAgent(AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	}))

	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
	assert.NotContains(t, err.Error(), theSecret)

	cred, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	assert.Nil(t, cred, "a credential the platform would not redeem must not linger — "+
		"every later run would present it again, and `agent status` would name an identity that does not sign")
	active, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	assert.Nil(t, active, "and nothing was ever promoted")
}

func TestActivateEnrolledAgentKeepsTheCredentialWhenThePlatformDidNotAnswer(t *testing.T) {
	isolateConfig(t)
	// A 503 is the signer being down, not the credential being wrong. The
	// platform activates only after minting, so nothing was spent; the next
	// run redeems.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret}))

	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kept")
	assert.NotContains(t, err.Error(), theSecret)

	cred, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, cred, "a transient failure must not discard a credential the platform never refused")
	assert.Equal(t, "a-1", cred.AgentID)
}

func TestActivateEnrolledAgentKeepsTheCredentialWhenTheNetworkFails(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused from here on
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: url, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret}))

	_, err := ActivateEnrolledAgent(url, AgentCredential{TenantID: "t-1", AgentID: "a-1"})
	require.Error(t, err)
	cred, err := LookupPendingAgent(url)
	require.NoError(t, err)
	assert.NotNil(t, cred)
}

func TestIsAgentCredentialRejectedNamesOnlyThePlatformsRefusal(t *testing.T) {
	isolateConfig(t)
	// The platform's verdict is its status AND its body; a bare status is
	// what any proxy speaks (TestOnlyTheStructuredRefusalCountsAsRejected
	// covers the bodies).
	for _, tc := range []struct {
		status   int
		rejected bool
	}{
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusServiceUnavailable, false},
		{http.StatusBadGateway, false},
		{http.StatusInternalServerError, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"error":"agent_credential_rejected"}`))
		}))
		_, err := ExchangeAgentCredential(srv.URL, AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret})
		srv.Close()
		require.Error(t, err, "status=%d", tc.status)
		assert.Equal(t, tc.rejected, IsAgentCredentialRejected(err), "status=%d", tc.status)
	}
	// A locally-expired credential is our own refusal, not the platform's.
	_, err := ExchangeAgentCredential("https://platform.example.com", AgentCredential{
		PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	require.Error(t, err)
	assert.False(t, IsAgentCredentialRejected(err))
}

func TestExchangeRecordsThePlatformsExpiryOverTheCallbacks(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	authoritative := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": jwtWithSubject(t, spiffeID), "token_type": "oidc", "spiffe_id": spiffeID,
			"expires_at": authoritative.Format(time.RFC3339),
		})
	}))
	defer srv.Close()
	// The callback said seven days; a forged or stale callback value must not
	// survive the first exchange.
	require.NoError(t, SaveAgent(AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}))
	cred, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	_, err = ExchangeAgentCredential(srv.URL, *cred)
	require.NoError(t, err)

	after, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	assert.True(t, after.ExpiresAt.Equal(authoritative), "stored %v, want the platform's %v", after.ExpiresAt, authoritative)
}

func TestExchangeRefusesAnUnreadableExpiryFromThePlatform(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": jwtWithSubject(t, spiffeID), "token_type": "oidc", "spiffe_id": spiffeID, "expires_at": "soon",
		})
	}))
	defer srv.Close()
	_, err := ExchangeAgentCredential(srv.URL, AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret})
	require.Error(t, err)
	assert.False(t, IsAgentCredentialRejected(err))
}

func TestAMalformedCallbackDoesNotConsumeTheCeremony(t *testing.T) {
	// The enroll URL — state and sealing key included — is printed in the
	// terminal. A local process that read it can POST the right state with
	// garbage around it; that must not spend the one-shot, or the genuine
	// browser callback arrives to a 409.
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	require.NoError(t, err)
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, "the-real-state", seal, resultCh)

	// 1. Right state, no identity.
	form := newSealedForm(t, seal, "the-real-state", "the-minted-secret", "", "")
	assert.Equal(t, http.StatusBadRequest, postEnrollCallback(t, h, form).Code)
	// 2. Right state, identity, but a blob sealed to someone else's key.
	other, err := newEnrollSealKey()
	require.NoError(t, err)
	form = newSealedForm(t, other, "the-real-state", "the-minted-secret", "t-1", "a-1")
	assert.Equal(t, http.StatusBadRequest, postEnrollCallback(t, h, form).Code)
	// 3. Right state, valid seal, unreadable expiry.
	form = newSealedForm(t, seal, "the-real-state", "the-minted-secret", "t-1", "a-1")
	form.Set("expires_at", "next tuesday")
	assert.Equal(t, http.StatusBadRequest, postEnrollCallback(t, h, form).Code)

	cred, err := LookupAgent(platform)
	require.NoError(t, err)
	assert.Nil(t, cred, "nothing stored by any of them")
	select {
	case o := <-resultCh:
		t.Fatalf("a malformed callback must not end the ceremony, but it produced %+v", o)
	default:
	}

	// The genuine callback still completes.
	form = newSealedForm(t, seal, "the-real-state", "the-minted-secret", "t-1", "a-1")
	require.Equal(t, http.StatusOK, postEnrollCallback(t, h, form).Code)
	o := <-resultCh
	require.NoError(t, o.err)
	assert.Equal(t, "a-1", o.cred.AgentID)
}

func TestActivateEnrolledAgentWithNothingStoredIsAnError(t *testing.T) {
	isolateConfig(t)
	_, err := ActivateEnrolledAgent("https://platform.example.com", AgentCredential{TenantID: "t-1", AgentID: "a-1"})
	require.Error(t, err)
	// An ACTIVE credential is not what a ceremony activates either: the
	// ceremony delivered nothing pending, so there is nothing to redeem.
	require.NoError(t, SaveAgent(AgentCredential{PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-1", RefreshCredential: "s"}))
	_, err = ActivateEnrolledAgent("https://platform.example.com", AgentCredential{TenantID: "t-1", AgentID: "a-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pending")
}

func TestActivateEnrolledAgentRefusesToRedeemACredentialThatIsNotThisCeremonys(t *testing.T) {
	// Between the callback delivering agent A and the activation, a
	// concurrent ceremony delivered agent B into the pending slot. Redeeming B
	// while the command reports A would corrupt attribution; nothing is
	// exchanged.
	isolateConfig(t)
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-B", RefreshCredential: "b-secret"}))

	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-A"})
	require.Error(t, err)
	assert.False(t, reached, "a credential that is not this ceremony's is never presented")
	assert.Contains(t, err.Error(), "a-A")
	assert.Contains(t, err.Error(), "a-B")
	assert.NotContains(t, err.Error(), "b-secret")

	cred, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, cred, "the other ceremony's credential is left exactly as it was")
	assert.Equal(t, "a-B", cred.AgentID)
}

func TestAGetCarryingEveryFieldIsNotADelivery(t *testing.T) {
	// ParseForm folds the query string in for a GET. A credential in a URL
	// is a credential in shell history and proxy logs, so the callback
	// accepts nothing but a POST — checked before anything is parsed.
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	require.NoError(t, err)
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, "the-real-state", seal, resultCh)

	form := newSealedForm(t, seal, "the-real-state", "the-minted-secret", "t-1", "a-1")
	req := httptest.NewRequest(http.MethodGet, "/callback?"+form.Encode(), nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))

	cred, err := LookupAgent(platform)
	require.NoError(t, err)
	assert.Nil(t, cred, "a GET must never store a credential")
	select {
	case o := <-resultCh:
		t.Fatalf("a GET must not end the ceremony, but it produced %+v", o)
	default:
	}
	// And the real POST still lands.
	require.Equal(t, http.StatusOK, postEnrollCallback(t, h, form).Code)
}

// --- The store is compare-and-swap for everything an exchange derives --------

func TestExchangeDerivedWritesLandOnlyOnTheCredentialThatWasExchanged(t *testing.T) {
	// The platform answers for credential A. Between the request and the
	// writes, another command stored credential B under the same platform.
	// The pin and the ceiling A's answer produced must not land on B, and B
	// must be left exactly as that command stored it.
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-A"
	a := AgentCredential{PlatformURL: "", TenantID: "t-1", AgentID: "a-A", RefreshCredential: "a-secret"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The swap happens while the request is in flight.
		require.NoError(t, SaveAgent(AgentCredential{PlatformURL: a.PlatformURL, TenantID: "t-1", AgentID: "a-B", RefreshCredential: "b-secret"}))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": jwtWithSubject(t, spiffeID), "token_type": "oidc", "spiffe_id": spiffeID,
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer srv.Close()
	a.PlatformURL = srv.URL
	require.NoError(t, SaveAgent(a))

	_, err := ExchangeAgentCredential(srv.URL, a)
	require.Error(t, err, "an exchange whose derived writes could not land on the presented credential is not a clean success")
	assert.False(t, IsAgentCredentialRejected(err), "the platform did not refuse; the store moved")

	b, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "a-B", b.AgentID)
	assert.Equal(t, "", b.TrustDomain, "A's pin must not land on B")
	assert.True(t, b.ExpiresAt.IsZero(), "A's ceiling must not land on B")
}

func TestActivationDoesNotReportSuccessIfThePendingSlotMovedDuringTheExchange(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-A"
	a := AgentCredential{TenantID: "t-1", AgentID: "a-A", RefreshCredential: "a-secret"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Another ceremony delivers B while A's exchange is in flight.
		require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: a.PlatformURL, TenantID: "t-1", AgentID: "a-B", RefreshCredential: "b-secret"}))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": jwtWithSubject(t, spiffeID), "token_type": "oidc", "spiffe_id": spiffeID})
	}))
	defer srv.Close()
	a.PlatformURL = srv.URL
	require.NoError(t, SavePendingAgent(a))

	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-A"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replaced")
	b, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "a-B", b.AgentID, "the other ceremony's credential is left as it was")
	active, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	assert.Nil(t, active, "and nothing was promoted: B was never redeemed")
}

func TestRefusedActivationNeverDeletesAReplacement(t *testing.T) {
	isolateConfig(t)
	a := AgentCredential{TenantID: "t-1", AgentID: "a-A", RefreshCredential: "a-secret"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: a.PlatformURL, TenantID: "t-1", AgentID: "a-B", RefreshCredential: "b-secret"}))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"agent_credential_rejected"}`))
	}))
	defer srv.Close()
	a.PlatformURL = srv.URL
	require.NoError(t, SavePendingAgent(a))

	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-A"})
	require.Error(t, err)
	b, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "a-B", b.AgentID, "the delete must not remove a credential another ceremony delivered")
}
