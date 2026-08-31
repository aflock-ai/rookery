// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// THE ENROLLED AGENT MUST WIN, AND MUST NEVER FALL BACK TO THE HUMAN.
//
// Written from the state that actually matters: a machine holding BOTH an agent
// principal and a human session. That is the ordinary shape of an enrolled
// workstation, and it is exactly where signing used to resolve to the human —
// `cilock agent status` promised the operator that "runs against this platform
// sign as this agent, taking precedence over `cilock login`", the attestation
// path kept that promise, and the GIT SIGNING path silently broke it.
//
// A test that seeded only an agent could not see the defect: with no human
// session there is nothing to fall back to, and the old code would have failed
// rather than borrowed. The two credentials must both be present.

// agentAndHumanPlatform answers both the agent credential-exchange endpoint and
// the human sign-token endpoint, recording whether the human one was reached.
// Reaching it while an agent is enrolled IS the defect, so that flag is the
// assertion rather than a detail.
func agentAndHumanPlatform(t *testing.T, spiffeID string, agentExchangeOK bool) (*httptest.Server, *bool) {
	t.Helper()
	humanExchanged := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/credential-exchange" {
			if !agentExchangeOK {
				// The platform answers every agent refusal identically.
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token":      jwtWithSubject(t, spiffeID),
				"token_type": "oidc",
				"spiffe_id":  spiffeID,
			})
			return
		}
		humanExchanged = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": "human.email.token", "assurance_level": "aal1",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &humanExchanged
}

func seedHumanSession(t *testing.T, platformURL string) {
	t.Helper()
	if err := Save(Credential{
		PlatformURL: platformURL,
		Token:       "stored-platform-session",
		AuthMode:    AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed human session: %v", err)
	}
}

func seedEnrolledAgent(t *testing.T, platformURL string) {
	t.Helper()
	if err := SaveAgent(AgentCredential{
		PlatformURL:       NormalizeURL(platformURL),
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: "refresh-do-not-print",
	}); err != nil {
		t.Fatalf("seed agent credential: %v", err)
	}
}

func TestResolveSigningTokenPrefersTheEnrolledAgentOverTheHumanSession(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	srv, humanExchanged := agentAndHumanPlatform(t, spiffeID, true)
	seedHumanSession(t, srv.URL)
	seedEnrolledAgent(t, srv.URL)

	got, err := ResolveSigningToken(srv.URL, "sigstore")
	if err != nil {
		t.Fatalf("ResolveSigningToken: %v", err)
	}
	if *humanExchanged {
		t.Fatal("the human sign-token endpoint was reached while an agent was enrolled — " +
			"this is the borrowed-identity defect, and the commit would carry the human's email")
	}
	if got.Token == "human.email.token" {
		t.Fatal("resolution returned the HUMAN's signing token on an enrolled machine")
	}
	if got.AssuranceLevel != "agent" {
		t.Fatalf("assurance = %q, want %q — an AAL here would report a human ceremony that never happened",
			got.AssuranceLevel, "agent")
	}
}

func TestResolveSigningTokenRefusesRatherThanBorrowingWhenTheAgentExchangeFails(t *testing.T) {
	isolateConfig(t)
	srv, humanExchanged := agentAndHumanPlatform(t, "spiffe://p/tenant/t-1/agent/a-1", false)
	seedHumanSession(t, srv.URL)
	seedEnrolledAgent(t, srv.URL)

	// A revoked principal, a foreign tenant, or a platform outage all arrive
	// here as a refused exchange. The only identity left to fall through to is
	// the human's, which is what the agent principal exists to remove — so this
	// must abort. A missing signature is visible and fixable; a signature naming
	// the wrong principal is a false attestation nobody notices.
	got, err := ResolveSigningToken(srv.URL, "sigstore")
	if err == nil {
		t.Fatalf("a refused agent exchange resolved anyway: %#v", got)
	}
	if *humanExchanged {
		t.Fatal("a refused agent exchange fell through to the human sign-token endpoint")
	}
	if got.Token != "" {
		t.Fatalf("a refused exchange still returned a token: %#v", got)
	}
	if strings.Contains(err.Error(), "refresh-do-not-print") {
		t.Fatalf("the refusal leaked the refresh credential: %v", err)
	}
}

// The human workstation must be untouched by any of this. Without this case a
// change that simply broke human signing would pass the two above.
func TestResolveSigningTokenStillUsesTheHumanSessionWhenNoAgentIsEnrolled(t *testing.T) {
	isolateConfig(t)
	srv, humanExchanged := agentAndHumanPlatform(t, "", true)
	seedHumanSession(t, srv.URL)

	got, err := ResolveSigningToken(srv.URL, "sigstore")
	if err != nil {
		t.Fatalf("ResolveSigningToken: %v", err)
	}
	if !*humanExchanged {
		t.Fatal("the human sign-token endpoint was not reached on a machine with no agent enrolled")
	}
	if got.Token != "human.email.token" || got.AssuranceLevel != "aal1" {
		t.Fatalf("the human path regressed: %#v", got)
	}
}

// AN AUDIENCE THIS PATH CANNOT SERVE IS REFUSED, AND REFUSED BEFORE THE MINT.
//
// Derive carries three audiences — "sigstore" for Fulcio signing, one for
// Archivista, one for login — and ResolveSigningToken's contract is that the
// argument keeps a token minted for one from being replayed into another. The
// agent exchange mints signing tokens only, so any other request must be
// refused rather than answered with a credential Fulcio would accept.
//
// The assertion that matters is not merely the error: it is that NO exchange
// happened. A refusal issued after minting would still have produced the token.
func TestResolveSigningTokenRefusesAnAudienceTheAgentExchangeCannotServe(t *testing.T) {
	isolateConfig(t)
	srv, humanExchanged := agentAndHumanPlatform(t, "spiffe://p/tenant/t-1/agent/a-1", true)
	seedHumanSession(t, srv.URL)
	seedEnrolledAgent(t, srv.URL)

	derived := config.Derive(srv.URL)
	for name, audience := range map[string]string{
		"the Archivista audience": derived.OIDCAudience,
		"the login audience":      derived.OIDCLoginAudience,
		"an unrelated audience":   "https://someone-elses.example/api",
		"an empty audience":       "",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ResolveSigningToken(srv.URL, audience)
			if err == nil {
				t.Fatalf("audience %q was served a signing token: %#v", audience, got)
			}
			if got.Token != "" {
				t.Fatalf("a refused audience still returned a token: %#v", got)
			}
			if *humanExchanged {
				t.Fatal("a refused audience fell through to the human sign-token endpoint")
			}
		})
	}
}

// The audience the agent path DOES serve still works — without this, a change
// that refused everything would pass the case above.
func TestResolveSigningTokenServesTheFulcioSigningAudience(t *testing.T) {
	isolateConfig(t)
	const spiffeID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	srv, _ := agentAndHumanPlatform(t, spiffeID, true)
	seedEnrolledAgent(t, srv.URL)

	got, err := ResolveSigningToken(srv.URL, config.Derive(srv.URL).OIDCClientID)
	if err != nil {
		t.Fatalf("the Fulcio signing audience was refused: %v", err)
	}
	if got.AssuranceLevel != "agent" {
		t.Fatalf("assurance = %q, want %q", got.AssuranceLevel, "agent")
	}
}
