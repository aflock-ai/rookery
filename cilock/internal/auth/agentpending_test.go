package auth

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A credential the ceremony delivered is PENDING until the platform redeems
// it; the credential this machine signs with is ACTIVE. The two live in
// separate slots. Before this, the callback overwrote the active slot and the
// previous credential survived only in the enrolling process's memory: a
// transient outage at activation kept the unredeemable new credential in the
// slot, and once the ten-minute redemption window closed the machine had lost
// the identity that was working AND gained one that never would. Codex,
// round 7.

const pendingSecret = "pending-secret-must-not-print"

func TestSavePendingAgentLeavesTheActiveCredentialAlone(t *testing.T) {
	isolateConfig(t)
	active := AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-active", RefreshCredential: "active-secret", TrustDomain: "p.example.com"}
	require.NoError(t, SaveAgent(active))
	pending := AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}
	require.NoError(t, SavePendingAgent(pending))

	got, err := LookupAgent("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-active", got.AgentID, "what this machine signs with did not change because a ceremony delivered something")
	p, err := LookupPendingAgent("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "a-new", p.AgentID)
}

func TestPromotePendingAgentIfMovesItWholeIntoTheActiveSlot(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, SaveAgent(AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-active", RefreshCredential: "active-secret"}))
	pending := AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}
	require.NoError(t, SavePendingAgent(pending))
	// What the exchange pinned on the pending credential travels with it.
	require.NoError(t, PinAgentTrustDomain(pending, "p.example.com"))

	require.NoError(t, PromotePendingAgentIf(pending))
	got, err := LookupAgent("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-new", got.AgentID)
	assert.Equal(t, "p.example.com", got.TrustDomain, "promoted with its pin")
	p, err := LookupPendingAgent("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, p, "nothing is pending once it is active")

	// A second promotion has nothing to promote: the slot moved.
	assert.ErrorIs(t, PromotePendingAgentIf(pending), ErrAgentCredentialReplaced)
}

func TestPromoteAndDeletePendingAreCompareAndSwap(t *testing.T) {
	isolateConfig(t)
	first := AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-1", RefreshCredential: "s-1"}
	second := AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-2", RefreshCredential: "s-2"}
	require.NoError(t, SavePendingAgent(first))
	require.NoError(t, SavePendingAgent(second)) // a later ceremony replaced it

	assert.ErrorIs(t, PromotePendingAgentIf(first), ErrAgentCredentialReplaced, "the first ceremony's redemption must not promote the second's credential")
	removed, err := DeletePendingAgentIf(first)
	require.NoError(t, err)
	assert.False(t, removed, "nor delete it")
	p, err := LookupPendingAgent("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "a-2", p.AgentID)

	removed, err = DeletePendingAgentIf(second)
	require.NoError(t, err)
	assert.True(t, removed)
}

func TestExchangeDerivedWritesLandOnAPendingCredentialToo(t *testing.T) {
	// The pin and the ceiling belong to the credential that was exchanged,
	// whichever slot it is in: a pending credential is exchanged at
	// redemption, and its answers must stick to it.
	isolateConfig(t)
	pending := AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}
	require.NoError(t, SavePendingAgent(pending))
	require.NoError(t, PinAgentTrustDomain(pending, "p.example.com"))
	p, err := LookupPendingAgent("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "p.example.com", p.TrustDomain)
	got, err := LookupAgent("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got, "and nothing appeared in the active slot")
}

func TestDeleteAgentClearsBothSlots(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, SaveAgent(AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-active", RefreshCredential: "s"}))
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}))
	existed, err := DeleteAgent("https://p.example.com")
	require.NoError(t, err)
	assert.True(t, existed)
	got, _ := LookupAgent("https://p.example.com")
	p, _ := LookupPendingAgent("https://p.example.com")
	assert.Nil(t, got)
	assert.Nil(t, p, "a logout removes the pending credential as well — the operator asked for no identity here")
}

// --- Activation over the two slots --------------------------------------

func TestActivationOutageKeepsThePreviousCredentialSigning(t *testing.T) {
	// THE REGRESSION CODEX ASKED FOR. A working credential is active; a new
	// ceremony delivers; the platform answers 503 at activation. The active
	// credential must still be the one this machine signs with, and the new
	// one must still be pending for the next run to redeem — neither lost.
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	active := AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-old", RefreshCredential: "old-secret", TrustDomain: "platform.example.com"}
	require.NoError(t, SaveAgent(active))
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}))

	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-new"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kept")
	assert.NotContains(t, err.Error(), pendingSecret)

	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-old", got.AgentID, "the working identity is untouched by an outage")
	assert.Equal(t, "platform.example.com", got.TrustDomain)
	p, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "a-new", p.AgentID, "the delivered credential waits for the next run")
}

func TestActivationRefusalDropsOnlyThePendingCredential(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"agent_credential_rejected","remediation":"run cilock enroll agent"}`))
	}))
	defer srv.Close()
	require.NoError(t, SaveAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-old", RefreshCredential: "old-secret"}))
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}))

	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-new"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
	assert.Contains(t, err.Error(), "a-old", "the operator is told which identity still signs")

	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-old", got.AgentID)
	p, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	assert.Nil(t, p, "a credential the platform refused is gone")
}

func TestActivationSuccessPromotesThePendingCredential(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-new"
	var body []byte
	srv := agentExchangeStub(t, spiffeID, &body)
	require.NoError(t, SaveAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-old", RefreshCredential: "old-secret"}))
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}))

	id, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-new"})
	require.NoError(t, err)
	assert.Equal(t, spiffeID, id.SPIFFEID)

	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-new", got.AgentID, "redeemed, so now the identity this machine signs with")
	assert.Equal(t, "platform.example.com", got.TrustDomain, "with the pin the redemption made")
	p, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	assert.Nil(t, p)
}

// --- The run path redeems what is pending -------------------------------

func TestRedeemPendingAgentPromotesOnSuccessAndIsQuietWhenNothingIsPending(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-new"
	var body []byte
	srv := agentExchangeStub(t, spiffeID, &body)
	require.NoError(t, RedeemPendingAgent(srv.URL), "nothing pending is nothing to do")
	assert.Empty(t, body, "and no exchange was made")

	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}))
	require.NoError(t, RedeemPendingAgent(srv.URL))
	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-new", got.AgentID)
}

func TestRedeemPendingAgentDropsARefusedCredentialAndKeepsSigningWithTheActiveOne(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"agent_credential_rejected"}`))
	}))
	defer srv.Close()
	require.NoError(t, SaveAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-old", RefreshCredential: "old-secret"}))
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}))

	err := RedeemPendingAgent(srv.URL)
	require.Error(t, err)
	assert.True(t, IsAgentCredentialRejected(err))
	p, _ := LookupPendingAgent(srv.URL)
	assert.Nil(t, p)
	got, _ := LookupAgent(srv.URL)
	require.NotNil(t, got)
	assert.Equal(t, "a-old", got.AgentID)
}

func TestRedeemPendingAgentKeepsBothOnAnOutage(t *testing.T) {
	isolateConfig(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	require.NoError(t, SaveAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-old", RefreshCredential: "old-secret"}))
	require.NoError(t, SavePendingAgent(AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-new", RefreshCredential: pendingSecret}))

	err := RedeemPendingAgent(srv.URL)
	require.Error(t, err)
	assert.False(t, IsAgentCredentialRejected(err))
	assert.Equal(t, int32(1), calls.Load())
	p, _ := LookupPendingAgent(srv.URL)
	require.NotNil(t, p)
	got, _ := LookupAgent(srv.URL)
	require.NotNil(t, got)
	assert.Equal(t, "a-old", got.AgentID)
}

// --- Only the platform's own verdict is a rejection ----------------------

func TestOnlyTheStructuredRefusalCountsAsRejected(t *testing.T) {
	// A 401 or 403 from an ingress, a WAF, or an unrelated authorization
	// layer never examined the credential. Discarding on those would turn a
	// misconfigured proxy into a lost identity. The platform's own refusal is
	// the constant body it writes: {"error":"agent_credential_rejected", …}.
	isolateConfig(t)
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		ctype    string
		rejected bool
	}{
		{"platform refusal, 401", http.StatusUnauthorized, `{"error":"agent_credential_rejected","remediation":"..."}`, "application/json", true},
		{"platform refusal, 403", http.StatusForbidden, `{"error":"agent_credential_rejected"}`, "application/json", true},
		{"WAF html 403", http.StatusForbidden, `<html><body>Access denied</body></html>`, "text/html", false},
		{"proxy 401, no body", http.StatusUnauthorized, ``, "text/plain", false},
		{"another layer's json 401", http.StatusUnauthorized, `{"error":"missing_session"}`, "application/json", false},
		{"platform outage 503", http.StatusServiceUnavailable, `{"error":"platform_unavailable"}`, "application/json", false},
		{"refusal body on a 200 is not a refusal", http.StatusOK, `{"error":"agent_credential_rejected"}`, "application/json", false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", tc.ctype)
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := ExchangeAgentCredential(srv.URL, AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: pendingSecret})
		srv.Close()
		require.Error(t, err, tc.name)
		assert.Equal(t, tc.rejected, IsAgentCredentialRejected(err), tc.name)
		assert.NotContains(t, err.Error(), pendingSecret, tc.name)
	}
}

// An explicit `cilock agent login` is the operator choosing the identity NOW.
// A credential a ceremony delivered earlier and never redeemed must not be
// able to overrule it on the next run: saving an active credential clears
// the pending slot in the same write, so there is nothing left to promote —
// and a promotion that lost the race to a login finds the slot gone.
func TestSavingAnActiveCredentialInvalidatesAPendingOne(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-old"
	var body []byte
	srv := agentExchangeStub(t, spiffeID, &body)
	old := AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-old", RefreshCredential: pendingSecret}
	require.NoError(t, SavePendingAgent(old))

	// The operator logs in with a different, newer identity.
	login := AgentCredential{PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-login", RefreshCredential: "login-secret"}
	require.NoError(t, SaveAgent(login))

	p, err := LookupPendingAgent(srv.URL)
	require.NoError(t, err)
	assert.Nil(t, p, "the login superseded the delivery; nothing is pending")

	// The next run has nothing to redeem and signs as the login.
	require.NoError(t, RedeemPendingAgent(srv.URL))
	assert.Empty(t, body, "no exchange was made for the superseded credential")
	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-login", got.AgentID)

	// And a promotion that had the old credential in hand — its exchange
	// already answered when the login landed — finds the slot gone.
	assert.ErrorIs(t, PromotePendingAgentIf(old), ErrAgentCredentialReplaced)
	got, _ = LookupAgent(srv.URL)
	assert.Equal(t, "a-login", got.AgentID, "the login is never overwritten by a stale promotion")
}
