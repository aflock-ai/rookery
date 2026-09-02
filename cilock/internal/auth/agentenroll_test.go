// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The enrollment callback's threat model is ANY OTHER LOCAL PROCESS: the
// loopback listener is reachable by everything on the machine, and what it
// guards is which principal this machine signs under from now on. So these
// tests are written from the forger's side — POSTs the platform never sent —
// and the property asserted each time is not just the HTTP status but the
// STORE: a refused credential must leave nothing behind, because a 403 with a
// stored credential is an accepted credential with better manners.

func postEnrollCallback(t *testing.T, h http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// newSealedForm builds the form the approve page really sends: identity in the
// clear (it is not secret — those are SPIFFE path segments) and the credential
// SEALED to this ceremony's key with the state bound in.
func newSealedForm(t *testing.T, k *enrollSealKey, state, credential, tenantID, agentID string) url.Values {
	t.Helper()
	ephPub, sealed := sealForTest(t, k.PublicKeyB64(), credential, state)
	return url.Values{
		"state":             {state},
		"ephemeral_pub":     {ephPub},
		"sealed_credential": {sealed},
		"tenant_id":         {tenantID},
		"agent_id":          {agentID},
	}
}

func TestAForgedCredentialUnderTheWrongStateIsRefusedAndNotStored(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, "the-real-state", seal, resultCh)

	for name, state := range map[string]string{
		"wrong state": "attacker-guess",
		"empty state": "",
	} {
		t.Run(name, func(t *testing.T) {
			// The forger seals under the state it believes in; the handler
			// compares against the real one first and refuses before opening.
			form := newSealedForm(t, seal, state, "attacker-chosen-secret",
				"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
			rec := postEnrollCallback(t, h, form)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			cred, err := LookupAgent(platform)
			if err != nil {
				t.Fatal(err)
			}
			if cred != nil {
				t.Fatalf("a refused POST left a credential in the store: this machine would now sign as %s", cred.AgentID)
			}
			select {
			case o := <-resultCh:
				t.Fatalf("a refused POST produced an outcome (%+v); the ceremony must keep waiting for the real one", o)
			default:
			}
		})
	}
}

func TestACredentialWithNoIdentityIsRefusedAndNotStored(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, "the-real-state", seal, resultCh)

	form := newSealedForm(t, seal, "the-real-state", "s3cret", "", "")
	// tenant_id and agent_id deliberately empty: a secret with no identity to
	// file it under must not be stored.
	rec := postEnrollCallback(t, h, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	cred, err := LookupAgent(platform)
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		t.Fatalf("an unattributable credential was stored: %+v", cred)
	}
	// The ceremony stays OPEN. An earlier version ended it here ("fail loudly
	// rather than keep waiting"), which handed any local process that read the
	// printed enroll URL a one-POST veto over the genuine callback. The
	// browser still sees the 400; cilock keeps listening for the callback that
	// is actually valid, and its own timeout bounds the wait.
	select {
	case o := <-resultCh:
		t.Fatalf("a malformed callback must not end the ceremony, but it produced %+v", o)
	default:
	}
}

func TestAValidCallbackStoresTheSecretAndReturnsOnlyIdentifiers(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, "the-real-state", seal, resultCh)

	form := newSealedForm(t, seal, "the-real-state", "the-minted-secret",
		"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
	form.Set("display_name", "claude on coles-mbp")
	rec := postEnrollCallback(t, h, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	// The secret was opened and reached the store — PENDING, not active: a
	// delivery is not a redemption, and the identity this machine signs with
	// does not change until the platform has answered for this credential.
	cred, err := LookupPendingAgent(platform)
	if err != nil || cred == nil {
		t.Fatalf("lookup after a valid callback: cred=%v err=%v", cred, err)
	}
	if cred.RefreshCredential != "the-minted-secret" {
		t.Fatalf("the stored credential is not the one the platform sealed")
	}
	if active, _ := LookupAgent(platform); active != nil {
		t.Fatalf("a delivery landed in the ACTIVE slot: %v", active)
	}

	// ...and nowhere else. The outcome carries identifiers only, and the
	// success page — readable by whoever holds the browser tab — must not echo
	// the secret either.
	o := <-resultCh
	if o.err != nil {
		t.Fatalf("valid callback produced an error: %v", o.err)
	}
	if o.cred.RefreshCredential != "" {
		t.Fatal("the outcome leaked the refresh credential out of the handler")
	}
	if o.cred.TenantID != "11111111-1111-1111-1111-111111111111" || o.cred.AgentID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("outcome identifiers = %+v", o.cred)
	}
	if strings.Contains(rec.Body.String(), "the-minted-secret") {
		t.Fatal("the success page echoed the refresh credential")
	}
}

// A crafted display_name on the callback POST must not become live markup: the
// loopback is reachable by any local process, and the success page renders in
// the human's browser.
func TestTheSuccessPageEscapesACraftedDisplayName(t *testing.T) {
	isolateConfig(t)
	seal, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler("https://platform.example.com", "st", seal, resultCh)

	form := newSealedForm(t, seal, "st", "s", "t", "a")
	form.Set("display_name", `<script>alert(1)</script>`)
	rec := postEnrollCallback(t, h, form)
	<-resultCh
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("the success page rendered a crafted display_name as live markup")
	}
}

// A GET (or any payload-less request) MUST NOT LEAK THE STATE.
//
// The round-4 finding. The handler used to redirect a bare GET to the approve
// page — and that URL carries `state` in its query. So any local process could
// GET the loopback, read `state` out of the 302 Location header, then POST a
// forged callback carrying that state and pass the constant-time check. The fix
// is a bare 405 with no Location and no body: the listener still answers (a
// liveness probe sees "alive"), but the secret never appears in a response.
func TestACredentiallessRequestNeverLeaksTheState(t *testing.T) {
	isolateConfig(t)
	const state = "the-secret-verifier"
	seal, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler("https://platform.example.com", state, seal, resultCh)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/callback", nil)
			rec := httptest.NewRecorder()
			h(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", rec.Code)
			}
			// The verifier must appear NOWHERE in the response — not the body,
			// not the Location, not any header.
			if strings.Contains(rec.Body.String(), state) {
				t.Fatalf("the state leaked into the response body: %q", rec.Body.String())
			}
			for k, vs := range rec.Header() {
				for _, v := range vs {
					if strings.Contains(v, state) {
						t.Fatalf("the state leaked into header %q: %q", k, v)
					}
				}
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("a payload-less request got a redirect to %q; it must get a bare 405", loc)
			}
		})
	}
}

// THE STATE IS SINGLE-SHOT: a second valid callback cannot overwrite the first.
//
// Once one correct callback stores a credential, the verifier is spent. A
// racing or replayed second POST — even correctly sealed, with the right state
// and a different principal — is refused, so an attacker who somehow learned
// the state cannot wait for the real enrollment and then clobber it.
func TestTheStateIsConsumedAfterOneValidCallback(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	const state = "st"
	seal, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 2)
	h := enrollCallbackHandler(platform, state, seal, resultCh)

	first := postEnrollCallback(t, h, newSealedForm(t, seal, state, "real-secret", "t-real", "a-real"))
	if first.Code != http.StatusOK {
		t.Fatalf("first callback status = %d, want 200", first.Code)
	}

	second := postEnrollCallback(t, h, newSealedForm(t, seal, state, "attacker-secret", "t-evil", "a-evil"))
	if second.Code == http.StatusOK {
		t.Fatal("a second valid callback was accepted; the state must be single-shot")
	}
	cred, err := LookupPendingAgent(platform)
	if err != nil || cred == nil {
		t.Fatalf("lookup: cred=%v err=%v", cred, err)
	}
	if cred.AgentID != "a-real" {
		t.Fatalf("the store now holds %q; a replayed callback overwrote the real enrollment", cred.AgentID)
	}
}

// A CREDENTIAL SEALED TO SOMEONE ELSE'S KEY IS REFUSED AND STORES NOTHING —
// the handler-level counterpart of the port-squatter test.
//
// This is the end-to-end shape of the round-5 finding: a POST that is correct
// in every visible respect (right state, well-formed identity) but whose
// payload was sealed to a different recipient must not enroll anything. Before
// sealing, the equivalent POST simply handed over a usable credential.
func TestACredentialSealedToAnotherKeyIsRefused(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	const state = "st"
	mine, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 1)
	h := enrollCallbackHandler(platform, state, mine, resultCh)

	// Sealed to THEIRS, delivered to a handler holding MINE.
	rec := postEnrollCallback(t, h, newSealedForm(t, theirs, state, "secret", "t", "a"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	cred, err := LookupAgent(platform)
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		t.Fatalf("a credential sealed to another key was stored: %+v", cred)
	}
	// And the ceremony stays open for the callback that IS sealed to it — a
	// blob sealed to a stranger's key is exactly what a port-squatter or a
	// local forger would send, and neither may end the genuine ceremony.
	select {
	case o := <-resultCh:
		t.Fatalf("a foreign-sealed callback must not end the ceremony, but it produced %+v", o)
	default:
	}
}
