// jade:ring local

package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The platform answers the repository scope on every successful exchange
// (judge#9626). cilock records it as a REPORT for `agent status`: it never
// refuses a run, never authorizes anything, and the gate's answer at push
// decides. These tests are written from the platform's side of the wire: what
// can a platform (older, newer, broken, or hostile) put in `scope`, and what
// may that do to the machine's signing and to the record status prints?

const scopeSPIFFEID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"

// scopeExchangeStub answers the exchange contract with rawScope spliced in as
// the `scope` value (omitted entirely when rawScope is ""). onRequest, when
// set, runs while the exchange is in flight, before the answer is written.
func scopeExchangeStub(t *testing.T, spiffeID, rawScope string, onRequest func()) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/credential-exchange" {
			http.NotFound(w, r)
			return
		}
		if onRequest != nil {
			onRequest()
		}
		body := map[string]json.RawMessage{}
		for k, v := range map[string]string{"token": jwtWithSubject(t, spiffeID), "token_type": "oidc", "spiffe_id": spiffeID} {
			b, _ := json.Marshal(v)
			body[k] = b
		}
		if rawScope != "" {
			body["scope"] = json.RawMessage(rawScope)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func scopeCred(platformURL string) AgentCredential {
	return AgentCredential{PlatformURL: platformURL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: "scope-secret"}
}

// previousScope is a record an earlier exchange left behind. Tests that must
// prove a record was CLEARED seed it, so "nil afterwards" cannot pass by
// nothing ever having been written.
func previousScope() *AgentScope {
	return &AgentScope{Mode: "listed", Repositories: []ScopedRepository{{ID: "42", URL: "https://github.com/o/old.git"}}, AnsweredAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
}

// captureAgentWarnings swaps the warning sink for a buffer for one test.
func captureAgentWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := agentWarnings
	agentWarnings = &buf
	t.Cleanup(func() { agentWarnings = prev })
	return &buf
}

func TestExchangeRecordsTheScopeThePlatformAnswered(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      AgentScope
	}{
		{"listed, one repository", `{"mode":"listed","repositories":[{"id":"1379794283","url":"https://github.com/o/r.git"}]}`,
			AgentScope{Mode: "listed", Repositories: []ScopedRepository{{ID: "1379794283", URL: "https://github.com/o/r.git"}}}},
		{"listed, none", `{"mode":"listed","repositories":[]}`, AgentScope{Mode: "listed", Repositories: []ScopedRepository{}}},
		{"all", `{"mode":"all"}`, AgentScope{Mode: "all"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			srv := scopeExchangeStub(t, scopeSPIFFEID, tc.raw, nil)
			require.NoError(t, SaveAgent(scopeCred(srv.URL)))
			before := time.Now()
			_, err := ExchangeAgentCredential(srv.URL, scopeCred(srv.URL))
			require.NoError(t, err)
			got, err := LookupAgent(srv.URL)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.NotNil(t, got.Scope, "the answered scope is recorded")
			assert.Equal(t, tc.want.Mode, got.Scope.Mode)
			assert.Equal(t, tc.want.Repositories, got.Scope.Repositories, "listed is never nil, even when empty")
			assert.False(t, got.Scope.AnsweredAt.Before(before.Add(-time.Second)), "answered_at is the time of this exchange")
		})
	}
}

// B9-Q1: an answer cilock cannot read is recorded as unknown and signing
// continues. A newer platform adding a mode must not break every 4.5 client's
// signing over a report that grants nothing, and no malformed answer may be
// read as "all".
func TestExchangeSignsThroughAnUnreadableScope(t *testing.T) {
	for name, raw := range map[string]string{
		"a string":                       `"sometimes"`,
		"null":                           `null`,
		"an unknown mode":                `{"mode":"sometimes"}`,
		"listed without the key":         `{"mode":"listed"}`,
		"listed with a null list":        `{"mode":"listed","repositories":null}`,
		"an entry without an id":         `{"mode":"listed","repositories":[{"url":"x"}]}`,
		"an entry with a numeric id":     `{"mode":"listed","repositories":[{"id":1379794283}]}`,
		"all that also lists":            `{"mode":"all","repositories":[{"id":"1"}]}`,
		"a terminal escape in the id":    `{"mode":"listed","repositories":[{"id":"1\u001b[2J"}]}`,
		"a terminal escape in the url":   `{"mode":"listed","repositories":[{"id":"1","url":"https://x\u001b]8;;evil\u0007"}]}`,
		"an uppercase mode":              `{"mode":"ALL"}`,
		"a list where an object belongs": `[{"mode":"all"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			isolateConfig(t)
			srv := scopeExchangeStub(t, scopeSPIFFEID, raw, nil)
			seeded := scopeCred(srv.URL)
			seeded.Scope = previousScope()
			require.NoError(t, SaveAgent(seeded))
			id, err := ExchangeAgentCredential(srv.URL, scopeCred(srv.URL))
			require.NoError(t, err, "a report cilock cannot read must never stop signing")
			assert.Equal(t, scopeSPIFFEID, id.SPIFFEID)
			got, err := LookupAgent(srv.URL)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Nil(t, got.Scope, "unreadable reads unknown, and replaces the previous record")
		})
	}
}

// B9-Q2: an absent answer (an older platform, or one that stopped answering)
// clears the record. Unlike expiry, a scope can shrink; showing yesterday's
// list as current is the misleading outcome.
func TestExchangeAbsentScopeClearsTheRecord(t *testing.T) {
	isolateConfig(t)
	srv := scopeExchangeStub(t, scopeSPIFFEID, "", nil)
	seeded := scopeCred(srv.URL)
	seeded.Scope = previousScope()
	require.NoError(t, SaveAgent(seeded))
	_, err := ExchangeAgentCredential(srv.URL, scopeCred(srv.URL))
	require.NoError(t, err)
	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.Scope)
}

// The redemption exchange runs on the PENDING slot and promotion copies the
// record into the active slot, so what `cilock enroll agent` redeemed is what
// status reads.
func TestRedemptionCarriesTheScopeIntoTheActiveSlot(t *testing.T) {
	isolateConfig(t)
	srv := scopeExchangeStub(t, scopeSPIFFEID, `{"mode":"listed","repositories":[{"id":"7"}]}`, nil)
	require.NoError(t, SavePendingAgent(scopeCred(srv.URL)))
	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: "t-1", AgentID: "a-1"})
	require.NoError(t, err)
	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.Scope)
	assert.Equal(t, []ScopedRepository{{ID: "7"}}, got.Scope.Repositories)
}

// Another command replaces the stored credential while the exchange is in
// flight. The scope answered for the OLD credential must not land on the
// replacement, and losing that write must not fail the exchange (B9-Q5).
func TestScopeAnsweredForAReplacedCredentialNeverLands(t *testing.T) {
	isolateConfig(t)
	warnings := captureAgentWarnings(t)
	var platform string
	srv := scopeExchangeStub(t, scopeSPIFFEID, `{"mode":"all"}`, func() {
		assert.NoError(t, SaveAgent(AgentCredential{PlatformURL: platform, TenantID: "t-1", AgentID: "a-other", RefreshCredential: "other-secret", TrustDomain: "platform.example.com"}))
	})
	platform = srv.URL
	cred := scopeCred(srv.URL)
	cred.TrustDomain = "platform.example.com" // pinned, so the scope write is the only store write
	require.NoError(t, SaveAgent(cred))

	_, err := ExchangeAgentCredential(srv.URL, cred)
	require.NoError(t, err, "a lost report write never fails the exchange")
	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "a-other", got.AgentID)
	assert.Nil(t, got.Scope, "the replacement's record is left alone")
	assert.Contains(t, warnings.String(), "could not record the repository scope")
}

// A concurrent first-use exchange pinned another trust domain; this exchange's
// pin write refuses. No scope may be recorded for an exchange that was refused.
func TestPinMismatchRecordsNoScope(t *testing.T) {
	isolateConfig(t)
	srv := scopeExchangeStub(t, "spiffe://attacker.example.com/tenant/t-1/agent/a-1", `{"mode":"all"}`, nil)
	stored := scopeCred(srv.URL)
	stored.TrustDomain = "platform.example.com"
	require.NoError(t, SaveAgent(stored))

	_, err := ExchangeAgentCredential(srv.URL, scopeCred(srv.URL)) // read before the pin landed
	require.Error(t, err, "the pin mismatch refuses")
	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.Scope, "a refused exchange records no scope")
}

// B9-Q5: a failed write keeps the previous dated record and warns; it never
// refuses the exchange the way expiry's write does.
func TestScopeWriteFailureWarnsAndSigns(t *testing.T) {
	isolateConfig(t)
	warnings := captureAgentWarnings(t)
	prev := recordAgentScope
	recordAgentScope = func(AgentCredential, *AgentScope) error { return errors.New("disk full") }
	t.Cleanup(func() { recordAgentScope = prev })

	srv := scopeExchangeStub(t, scopeSPIFFEID, `{"mode":"all"}`, nil)
	seeded := scopeCred(srv.URL)
	seeded.Scope = previousScope()
	require.NoError(t, SaveAgent(seeded))

	id, err := ExchangeAgentCredential(srv.URL, scopeCred(srv.URL))
	require.NoError(t, err, "a report write failure must not stop signing")
	assert.Equal(t, scopeSPIFFEID, id.SPIFFEID)
	assert.Contains(t, warnings.String(), "cilock: warning: could not record the repository scope the platform answered (agent status keeps the previous answer): disk full")
	got, err := LookupAgent(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, previousScope(), got.Scope, "the previous dated record stays")
}
