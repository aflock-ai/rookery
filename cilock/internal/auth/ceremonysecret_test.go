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
	"time"
)

// THE THREAT THESE TESTS HOLD IN PLACE (#8739).
//
// Both browser ceremonies print a URL "in case it doesn't open", and that URL
// carries the flow's one-time verifier — `state` for both, plus `seal_pub` for
// enrollment. Anything that can read the terminal (the agent being enrolled,
// another lane, a captured transcript, a log) holds every value the loopback
// callback checks: it can seal a credential of ITS OWN to the published
// recipient key with the published state bound in, POST it first, and spend
// the one-shot. The genuine browser then gets a 409 and the machine signs
// under an identity the human never approved.
//
// The callback CANNOT tell the two POSTs apart — that is the whole point, and
// it is why the fix is at the printing layer, not in the handler: a verifier
// that was never printed cannot be replayed by something that only read the
// output. What the handler owes is the other half: once a ceremony has
// delivered, nothing else may be examined against it.

const (
	testCeremonyState   = "0123456789abcdef0123456789abcdef"
	testCeremonySealPub = "BExamplePublicKeyBytesNotRealJustDistinctive"
)

func testEnrollCeremonyURL() string {
	return agentEnrollURL(
		"https://platform.example.com",
		"http://localhost:54321/callback",
		testCeremonyState,
		testCeremonySealPub,
		EnrollParams{DisplayName: "claude on coles-mbp", Repo: "acme/repo", TTL: time.Hour},
	)
}

func testLoginCeremonyURL() string {
	return cliAuthURL(
		"https://platform.example.com",
		"http://localhost:54321/callback",
		testCeremonyState,
		LoginParams{Tenant: "acme", Product: "judge", Purpose: "ci"},
	)
}

// A browser was opened, so the human already HAS the URL. Printing it again
// only publishes the verifier to everything that can read the output.
func TestThePrintedCeremonyURLWithholdsTheVerifierWhenABrowserOpened(t *testing.T) {
	for name, ceremonyURL := range map[string]string{
		"enroll": testEnrollCeremonyURL(),
		"login":  testLoginCeremonyURL(),
	} {
		t.Run(name, func(t *testing.T) {
			printed := ceremonyInvitation("visit", ceremonyURL, true)
			for _, secret := range []string{testCeremonyState, testCeremonySealPub} {
				if strings.Contains(printed, secret) {
					t.Fatalf("the printed invitation carries a ceremony secret %q:\n%s", secret, printed)
				}
			}
			// It must still say WHERE the ceremony is — a human who cannot see
			// the platform cannot tell a real ceremony from a redirected one.
			if !strings.Contains(printed, "platform.example.com") {
				t.Fatalf("the printed invitation hides the platform entirely:\n%s", printed)
			}
			// And it must name the way back for a human whose browser silently
			// did nothing; withholding the URL with no recourse is a bug, not
			// a control.
			if !strings.Contains(printed, "BROWSER=none") {
				t.Fatalf("the printed invitation offers no way to recover the full URL:\n%s", printed)
			}
		})
	}
}

// Nothing opened, so this output IS the only channel to the human — and to the
// UAT harness, which sets BROWSER=none and reads the first URL line. Withhold
// the verifier here and the ceremony simply cannot be completed.
func TestThePrintedCeremonyURLIsWholeWhenNothingOpened(t *testing.T) {
	for name, ceremonyURL := range map[string]string{
		"enroll": testEnrollCeremonyURL(),
		"login":  testLoginCeremonyURL(),
	} {
		t.Run(name, func(t *testing.T) {
			printed := ceremonyInvitation("visit", ceremonyURL, false)
			if !strings.Contains(printed, ceremonyURL) {
				t.Fatalf("nothing opened a browser, so the whole URL must print:\n%s", printed)
			}
			// jade's UAT reader takes the FIRST line that is itself a URL
			// (jade/cmd/testuat_cilock.go). Keep that line shape.
			var urlLine string
			for _, line := range strings.Split(printed, "\n") {
				if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "http") {
					urlLine = trimmed
					break
				}
			}
			if urlLine != ceremonyURL {
				t.Fatalf("the first URL line is %q, want the whole ceremony URL", urlLine)
			}
		})
	}
}

// The UAT harness drives the whole enrollment ceremony headlessly: it sets
// BROWSER=none and takes the FIRST line of cilock's stdout that is itself a URL
// as the ceremony URL (jade/cmd/testuat_cilock.go). Withholding parameters is a
// change to that output, so the reader's contract is pinned here — including
// that no preamble line before it can be mistaken for the URL.
func TestTheHeadlessOutputStillYieldsTheCeremonyURLFirst(t *testing.T) {
	ceremonyURL := testEnrollCeremonyURL()
	out := "Opening browser to enroll this agent with https://platform.example.com ...\n" +
		"Your human signs in and approves there.\n" +
		ceremonyInvitation("have them approve", ceremonyURL, false)
	var first string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
			first = trimmed
			break
		}
	}
	if first != ceremonyURL {
		t.Fatalf("the UAT reader would take %q, want the whole ceremony URL %q", first, ceremonyURL)
	}
}

// Redaction is not truncation: everything a human needs to recognize the
// ceremony survives, and only what authorizes is withheld.
func TestRedactCeremonyURLKeepsEveryNonAuthorizingParameter(t *testing.T) {
	redacted := redactCeremonyURL(testEnrollCeremonyURL())
	u, err := url.Parse(redacted)
	if err != nil {
		t.Fatalf("the redacted URL does not parse: %v", err)
	}
	q := u.Query()
	for key, want := range map[string]string{
		"callback": "http://localhost:54321/callback",
		"client":   "cilock",
		"name":     "claude on coles-mbp",
		"repo":     "acme/repo",
		"ttl":      "3600",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("redaction dropped %s: got %q want %q", key, got, want)
		}
	}
	for _, secret := range secretCeremonyParams {
		if got := q.Get(secret); got != redactedParam {
			t.Errorf("%s is %q, want it withheld", secret, got)
		}
	}
}

// --- `cilock login`: the same mechanism, the version that still leaks -------

func newLoginHandler(t *testing.T, state string) (http.HandlerFunc, chan *Credential) {
	t.Helper()
	resultCh := make(chan *Credential, 4)
	h := loginCallbackHandler("https://platform.example.com", state, "", resultCh)
	return h, resultCh
}

// The enrollment callback closed this in round 5 and the contract names it
// (pushgate-agent-policy-contract.md, "Credential-less request"): a response
// that redirects to the approve page puts `state` in the `Location` header, so
// any local process can GET the loopback, read the verifier, and POST a forged
// token. `cilock login` still redirects.
func TestALoginCallbackProbeNeverLeaksTheState(t *testing.T) {
	h, _ := newLoginHandler(t, testCeremonyState)
	for name, req := range map[string]*http.Request{
		"GET with nothing": httptest.NewRequest(http.MethodGet, "/callback", nil),
		"POST with no token": httptest.NewRequest(http.MethodPost, "/callback",
			strings.NewReader(url.Values{"tenant": {"acme"}}.Encode())),
	} {
		t.Run(name, func(t *testing.T) {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			h(rec, req)
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("the probe got a Location header %q", loc)
			}
			whole := rec.Header().Get("Location") + rec.Body.String()
			if strings.Contains(whole, testCeremonyState) {
				t.Fatalf("the probe read the state out of the response:\n%s", whole)
			}
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status %d, want 405 — the listener answers, and says nothing else", rec.Code)
			}
		})
	}
}

// A URL is the one shape a session token must never travel in: it lands in
// shell history, browser history and every proxy log. ParseForm folds the
// query string in for a GET, so without a method check a GET carrying token
// and state IS a delivery.
func TestALoginCallbackDeliversOnlyOverPOST(t *testing.T) {
	h, resultCh := newLoginHandler(t, testCeremonyState)
	q := url.Values{"token": {"forged.jwt.value"}, "state": {testCeremonyState}}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405 for a GET delivery", rec.Code)
	}
	select {
	case c := <-resultCh:
		t.Fatalf("a GET delivered a credential: %+v", c)
	default:
	}
}

// One valid callback ends the flow. Without this, a racing or replayed POST
// overwrites what the browser just delivered — and `cilock login` had no
// single-shot at all, only a buffered channel.
func TestTheLoginStateIsConsumedAfterOneValidCallback(t *testing.T) {
	h, resultCh := newLoginHandler(t, testCeremonyState)
	post := func(token string) *httptest.ResponseRecorder {
		form := url.Values{"token": {token}, "state": {testCeremonyState}, "tenant": {"acme"}}
		req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	if rec := post("the.genuine.token"); rec.Code != http.StatusOK {
		t.Fatalf("the genuine callback got %d, want 200", rec.Code)
	}
	if rec := post("the.replayed.token"); rec.Code != http.StatusConflict {
		t.Fatalf("the second callback got %d, want 409", rec.Code)
	}
	got := <-resultCh
	if got.Token != "the.genuine.token" {
		t.Fatalf("delivered token %q, want the first one", got.Token)
	}
	select {
	case c := <-resultCh:
		t.Fatalf("a second credential was delivered: %+v", c)
	default:
	}
}

// --- enrollment: a delivered flow is examined against nothing further -------

// After delivery the ceremony is over. A later POST carrying the right state
// must be refused as "already delivered" WITHOUT the handler taking the
// attacker's bytes to the ceremony's private key: the seal is opened before
// the single-shot is checked today, so a second callback with a garbage blob
// answers 400 ("bad seal") — which both spends work on attacker input and
// tells the caller its state was accepted.
func TestADeliveredEnrollFlowExaminesNothingFurther(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	seal, err := newEnrollSealKey()
	if err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan enrollOutcome, 2)
	h := enrollCallbackHandler(platform, testCeremonyState, seal, resultCh)

	genuine := newSealedForm(t, seal, testCeremonyState, "the-real-credential", "tenant-1", "agent-1")
	if rec := postEnrollCallback(t, h, genuine); rec.Code != http.StatusOK {
		t.Fatalf("the genuine callback got %d, want 200", rec.Code)
	}
	second := url.Values{
		"state":             {testCeremonyState},
		"ephemeral_pub":     {"not-a-key"},
		"sealed_credential": {"not-a-blob"},
		"tenant_id":         {"attacker-tenant"},
		"agent_id":          {"attacker-agent"},
	}
	rec := postEnrollCallback(t, h, second)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409 — a delivered flow is examined against nothing further", rec.Code)
	}
}
