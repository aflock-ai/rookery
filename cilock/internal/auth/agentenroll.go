// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"
)

// EnrollParams carries the optional pre-fill hints `cilock enroll agent`
// passes to the platform's enrollment page. Hints only: the human sees and can
// change every one of them in the browser before approving, so nothing here is
// authority over what gets minted.
type EnrollParams struct {
	// DisplayName pre-fills the principal's human-facing label, e.g.
	// "claude on coles-mbp". Not identity — renameable and absent from the
	// certificate subject.
	DisplayName string
	// Repo pre-selects a repository scope on the page (owner/name or URL),
	// so an enroll launched from a repository's setup document lands with
	// that repository already ticked.
	Repo string
	// TTL pre-selects how long the principal lives before the platform refuses
	// it (the platform defaults to eight hours and caps at seven days). Zero
	// means "the page's default". A hint like the others: the human sees the
	// choice and can change it, and the server clamps whatever arrives.
	TTL time.Duration
}

// BrowserEnroll runs the agent-enrollment ceremony: it opens the platform's
// /auth/agent-enroll page, where a HUMAN signs in, steps up to AAL2, reviews
// what is being minted, and approves. The platform then creates the agent
// principal server-side — inside the very session whose assurance level it
// observed — and POSTs the one-time refresh credential back to a loopback
// listener, which stores it and never prints it.
//
// This is deliberately BrowserLogin's machinery with three substitutions (the
// approve page, the payload, the store) rather than a new flow: the one-time
// state verifier, the loopback listener, the POST-not-URL secret return, and
// the constant-time state compare are all load-bearing there for the same
// threats they close here. See docs/design/agent-enroll-ceremony.md in the
// judge repository for the full mapping.
//
// The human's involvement is the browser tab. The caller — usually an agent —
// receives only the stored credential's IDENTIFIERS; the secret goes straight
// from the platform's POST into SaveAgent's 0600 store.
func BrowserEnroll(judgeURL string, params EnrollParams) (*AgentCredential, error) {
	judgeURL = NormalizeURL(judgeURL)
	state, err := newState()
	if err != nil {
		return nil, err
	}
	// One ephemeral recipient key per ceremony. Its PUBLIC half goes in the
	// enroll URL; the private half stays in this process and dies with it, which
	// is what makes the untrusted loopback safe to deliver over.
	seal, err := newEnrollSealKey()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port //nolint:errcheck // guaranteed *net.TCPAddr
	callbackURL := fmt.Sprintf("http://localhost:%d/callback", port)

	resultCh := make(chan enrollOutcome, 1)
	mux := http.NewServeMux()
	// Bounded read and bounded drain (loopback.go): a local process that
	// stalls a POST mid-body must neither hold the handler nor hold the
	// command after the genuine callback has delivered.
	srv := newLoopbackServer(mux)
	mux.HandleFunc("/callback", enrollCallbackHandler(judgeURL, state, seal, resultCh))

	go func() { _ = srv.Serve(listener) }()
	defer shutdownLoopback(srv)

	enrollURL := agentEnrollURL(judgeURL, callbackURL, state, seal.PublicKeyB64(), params)
	fmt.Printf("Opening browser to enroll this agent with %s ...\n", judgeURL)
	fmt.Printf("Your human signs in and approves there. If it doesn't open, have them visit:\n  %s\n\n", enrollURL)
	openBrowserURL(enrollURL)

	select {
	case o := <-resultCh:
		return o.cred, o.err
	// Longer than login's 5 minutes on purpose: this ceremony can include a
	// fresh sign-in AND an AAL2 step-up (or even second-factor enrollment) —
	// a human doing all three should not race a timer.
	case <-time.After(10 * time.Minute):
		return nil, fmt.Errorf("enrollment timed out after 10 minutes; run `cilock enroll agent` again to restart the ceremony")
	}
}

// enrollOutcome is what the callback hands back to the waiting command: the
// stored credential's IDENTIFIERS (its secret is blanked before it leaves the
// handler), or the reason enrollment failed.
type enrollOutcome struct {
	cred *AgentCredential
	err  error
}

// enrollCallbackHandler is the loopback endpoint the platform POSTs the minted
// credential to. Extracted from BrowserEnroll so its decisions are EXECUTED by
// tests rather than read: buried in the server closure, the only way to reach
// this logic was a live browser ceremony, and a guard nothing can exercise is
// a guard nothing can trust.
//
// The decisions, in refusal-first order:
//   - a non-POST request, or a POST with no credential, gets a bare 405 with NO
//     body and NO Location header. THE STATE IS NEVER ECHOED. An earlier version
//     redirected a GET to the approve page — whose URL carries `state` — so any
//     local process could GET the loopback, read `state` out of the 302
//     Location, then POST a forged credential and identity that passed the
//     constant-time check because it now held the verifier. A liveness probe
//     still gets a response (the listener answers 405, which is "alive"), and
//     that is all a probe needs.
//   - a credential under a WRONG or missing state is refused (403) and nothing
//     is stored — constant-time compare, so a local forger learns nothing from
//     timing.
//   - a credential with NO tenant/agent identity is refused (400) and nothing
//     is stored — a secret we cannot attribute is a liability, not an identity.
//   - a valid POST is stored 0600 via SavePendingAgent INSIDE the handler —
//     PENDING, beside whatever credential is active, never over it; the
//     secret never travels further than this function, and the outcome
//     carries identifiers only.
//
// SINGLE-SHOT: the state is consumed on the first VALID callback. A second POST,
// even with the correct state, is refused — so a replayed or racing callback
// cannot overwrite the credential just stored, and the verifier is good for
// exactly one enrollment.
func enrollCallbackHandler(judgeURL, state string, seal *enrollSealKey, resultCh chan<- enrollOutcome) http.HandlerFunc {
	var consumed atomic.Bool
	return func(w http.ResponseWriter, r *http.Request) {
		// POST, and nothing else, BEFORE the form is read: ParseForm folds the
		// query string in for a GET, so without this a GET carrying every field
		// in its URL would be a delivery — and a URL is the one shape a
		// credential must never travel in (it lands in history and logs).
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		// A ParseForm error is deliberately not inspected: it fails CLOSED. Every
		// FormValue below then returns "", so an oversized or malformed body falls
		// straight into the credential-less 405 path rather than reaching any
		// decision. Reading the error would only let us produce a more specific
		// answer, and specific answers on this port are exactly what we withhold.
		_ = r.ParseForm()
		sealed := r.FormValue("sealed_credential")

		// Nothing sealed (a GET liveness probe, a stray request, an empty POST):
		// answer WITHOUT leaking anything. 405, no body, no Location, no state.
		if sealed == "" {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.FormValue("state")), []byte(state)) != 1 {
			http.Error(w, "invalid state", http.StatusForbidden)
			return
		}
		// NOTHING BELOW CONSUMES THE CEREMONY UNTIL THE CALLBACK IS WHOLLY
		// VALID. `state` and the sealing public key are printed in the terminal
		// (the enroll URL carries both) and so are known to any local process
		// that can read the agent's output; a callback that carried the right
		// state but garbage for everything else used to claim the one-shot and
		// leave the genuine browser POST with a 409. Now a malformed callback
		// is refused and consumes nothing; only a callback that opens, names an
		// identity, and parses is the one that spends the state.
		tenantID := r.FormValue("tenant_id")
		agentID := r.FormValue("agent_id")
		if tenantID == "" || agentID == "" {
			http.Error(w, "missing tenant_id or agent_id", http.StatusBadRequest)
			return
		}
		// The credential arrives SEALED to this ceremony's ephemeral key. A
		// process that squatted the port after a timeout cannot produce a blob
		// that opens here, and cannot read one it intercepts.
		credential, err := seal.openSealedCredential(r.FormValue("ephemeral_pub"), sealed, state)
		if err != nil {
			http.Error(w, "the sealed credential could not be opened", http.StatusBadRequest)
			return
		}
		// The platform's answer for when this identity stops signing — a hint
		// until the first exchange replaces it with the platform's own copy.
		// Read strictly even so: a ceiling that cannot be parsed is not
		// "unbounded".
		expiresAt, err := parseCallbackExpiry(r.FormValue("expires_at"))
		if err != nil {
			http.Error(w, "unreadable expires_at", http.StatusBadRequest)
			return
		}
		// One VALID callback consumes the state. A racing or replayed second
		// POST — even with the right state — is refused rather than allowed to
		// overwrite what the first one stored.
		if !consumed.CompareAndSwap(false, true) {
			http.Error(w, "already enrolled", http.StatusConflict)
			return
		}
		cred := AgentCredential{
			PlatformURL:       judgeURL,
			TenantID:          tenantID,
			AgentID:           agentID,
			RefreshCredential: credential,
			ExpiresAt:         expiresAt,
		}
		// PENDING, not active. Delivery is not redemption: until the platform
		// answers for this credential the identity this machine signs with is
		// whatever it was, and a working credential is never overwritten by
		// one that has not yet proved it works (ActivateEnrolledAgent).
		if err := SavePendingAgent(cred); err != nil {
			http.Error(w, "failed to store the credential", http.StatusInternalServerError)
			resultCh <- enrollOutcome{err: fmt.Errorf("store the enrolled agent credential: %w", err)}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		writeEnrollCallbackPage(w, r.FormValue("display_name"), agentID)
		cred.RefreshCredential = "" // identifiers only leave this handler
		resultCh <- enrollOutcome{cred: &cred}
	}
}

// parseCallbackExpiry reads the platform's `expires_at` off the callback POST.
// Empty is allowed and yields the zero time ("not recorded"): a platform that
// predates time-bound principals sends none, and the exchange still answers
// for itself. Anything non-empty must be RFC 3339 or the callback is refused.
func parseCallbackExpiry(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// ActivateEnrolledAgent redeems the credential a ceremony just delivered —
// the PENDING one — and, only if the platform accepted it, promotes it to
// the credential this machine signs with. The exchange is the redemption:
// the platform activates the principal in the request that first presents
// its credential, so an enrollment whose credential was never exchanged is
// not an identity the platform will ever accept, and the command must not
// say "Enrolled." over one.
//
// The three outcomes, and what each leaves in the store:
//   - Redeemed. The pending credential is promoted into the active slot,
//     pin and ceiling included; whatever was active before is superseded.
//   - Refused by the platform itself (IsAgentCredentialRejected — the
//     platform's own structured verdict, not any 401/403 a proxy might
//     produce). Retrying the same credential cannot succeed, so the PENDING
//     credential is removed. The active credential — the identity that was
//     working before the ceremony — is untouched; there is nothing to
//     restore because nothing was overwritten.
//   - Anything else — the request did not complete, the signer was down,
//     the answer failed our own checks. The platform did not activate (it
//     activates only after minting), the redemption window is still open,
//     and the credential may be perfectly good. Both slots are left as they
//     are: the machine keeps signing with the active credential, and the
//     next run redeems the pending one (RedeemPendingAgent). An outage
//     therefore costs nothing — before the slots were separate it cost the
//     working identity once the ten-minute window closed.
//
// expected names the principal THIS ceremony minted (the callback's tenant
// and agent ids). A concurrent ceremony can replace the pending slot between
// the callback and this call; activating whatever is there now would redeem
// one identity while the command reports another. So the pending credential
// must be the ceremony's own, or nothing is exchanged — and the identity
// returned is the one the platform actually answered with, which the
// exchange has already checked names the same tenant and agent.
func ActivateEnrolledAgent(platformURL string, expected AgentCredential) (AgentSigningIdentity, error) {
	cred, err := LookupPendingAgent(platformURL)
	if err != nil {
		return AgentSigningIdentity{}, err
	}
	if cred == nil {
		return AgentSigningIdentity{}, fmt.Errorf("no delivered agent credential is pending for %s to activate", NormalizeURL(platformURL))
	}
	if cred.TenantID != expected.TenantID || cred.AgentID != expected.AgentID {
		return AgentSigningIdentity{}, fmt.Errorf("the pending agent credential for %s (tenant %s, agent %s) is not the one this ceremony minted (tenant %s, agent %s) — another enrollment replaced it; nothing was activated, run `cilock enroll agent` again",
			NormalizeURL(platformURL), cred.TenantID, cred.AgentID, expected.TenantID, expected.AgentID)
	}
	id, err := redeemPending(platformURL, *cred)
	if err == nil {
		return id, nil
	}
	if errors.Is(err, ErrAgentCredentialReplaced) {
		return AgentSigningIdentity{}, fmt.Errorf("another command replaced this machine's pending credential during activation; nothing was changed: %w", err)
	}
	if !IsAgentCredentialRejected(err) {
		return AgentSigningIdentity{}, fmt.Errorf("the agent principal could not be activated yet (the platform did not answer, or answered badly); "+
			"the delivered credential is kept pending and the next `cilock run` within ten minutes of enrollment will redeem it; "+
			"any previously enrolled identity keeps signing meanwhile: %w", err)
	}
	if active, lookErr := LookupAgent(platformURL); lookErr == nil && active != nil {
		return AgentSigningIdentity{}, fmt.Errorf("the agent principal was refused, so the delivered credential was discarded; the previously enrolled identity (agent %s) still signs; run `cilock enroll agent` again: %w", active.AgentID, err)
	}
	return AgentSigningIdentity{}, fmt.Errorf("the agent principal was refused, so the delivered credential was discarded; run `cilock enroll agent` again: %w", err)
}

// RedeemPendingAgent is the run path's half of the ceremony: if a delivered
// credential is pending for platformURL, exchange it; promote it on success,
// discard it on the platform's own refusal, leave it on anything else. It
// returns nil when nothing is pending or the redemption succeeded, and the
// exchange's error otherwise — a caller that still holds an active credential
// may sign with that one in the meantime (a transient failure), or must not
// (IsAgentCredentialRejected says the pending one is gone for good, which
// is only informational to a caller that has an active credential to use).
func RedeemPendingAgent(platformURL string) error {
	cred, err := LookupPendingAgent(platformURL)
	if err != nil {
		return err
	}
	if cred == nil {
		return nil
	}
	_, err = redeemPending(platformURL, *cred)
	return err
}

// ResolveAgentCredential is what a signing path asks for: the credential this
// machine signs with against platformURL, after giving a pending one its
// chance to be redeemed. Nil with no error means no agent is enrolled.
//
// The order is the point. A delivered credential is tried FIRST, so a
// ceremony whose activation stalled is completed by the next run without
// anyone re-enrolling; if the platform refuses it, it is discarded and the
// active credential (if any) signs on; if the platform did not answer, the
// active credential signs on too and the pending one waits. Only when there
// is NO active credential does a pending one that cannot be redeemed become
// this run's error — the run has no identity to fall back to, and that is
// the message the operator needs.
func ResolveAgentCredential(platformURL string) (*AgentCredential, error) {
	redeemErr := RedeemPendingAgent(platformURL)
	active, err := LookupAgent(platformURL)
	if err != nil {
		return nil, err
	}
	if active != nil {
		return active, nil
	}
	if redeemErr != nil {
		return nil, fmt.Errorf("a delivered agent credential is pending for %s and could not be redeemed: %w", NormalizeURL(platformURL), redeemErr)
	}
	return nil, nil
}

// redeemPending exchanges ONE pending credential and applies the outcome to
// the store: promote on success (re-verifying that the pending slot still
// holds it), delete on the platform's refusal, leave on anything else. Every
// store write is a compare-and-swap against *cred — the exact credential
// presented, bearer included — so a replacement that lands DURING the
// exchange is never pinned onto, never promoted, and never deleted.
func redeemPending(platformURL string, cred AgentCredential) (AgentSigningIdentity, error) {
	id, err := ExchangeAgentCredential(platformURL, cred)
	if err == nil {
		// PROMOTE BEFORE CLAIMING. Success is reported only once the
		// redeemed credential is what this machine will sign with.
		if perr := PromotePendingAgentIf(cred); perr != nil {
			if errors.Is(perr, ErrAgentCredentialReplaced) {
				return AgentSigningIdentity{}, fmt.Errorf("the agent principal was activated, but another command replaced this machine's pending credential during the exchange; what is stored now is not the identity that was redeemed — check `cilock agent status` and re-run `cilock enroll agent` if it is not the one you want")
			}
			return AgentSigningIdentity{}, perr
		}
		return id, nil
	}
	if IsAgentCredentialRejected(err) {
		if _, delErr := DeletePendingAgentIf(cred); delErr != nil {
			return AgentSigningIdentity{}, fmt.Errorf("the agent principal was refused (%w); and the unusable credential could not be removed: %v", err, delErr)
		}
	}
	return AgentSigningIdentity{}, err
}

// writeEnrollCallbackPage renders the loopback success page. Both interpolated
// values arrive on the callback POST and are HTML-escaped for the same reason
// the login page escapes its tenant: the listener is reachable by any local
// process, so nothing it echoes may carry live markup.
func writeEnrollCallbackPage(w io.Writer, displayName, agentID string) {
	label := displayName
	if label == "" {
		label = "agent"
	}
	//nolint:gosec // G705: both interpolations are html-escaped; loopback-only, state-gated page
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8">`+
		`<style>body{font-family:-apple-system,system-ui,sans-serif;background:#1e1b4b;color:#e2e8f0;`+
		`display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}`+
		`.card{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);border-radius:16px;`+
		`padding:40px;max-width:420px;text-align:center}.ok{color:#34d399;font-size:48px}`+
		`code{color:#a5b4fc}</style></head>`+
		`<body><div class="card"><div class="ok">&#x2713;</div><h2>Agent enrolled</h2>`+
		`<p><strong>%s</strong> now signs with its own identity<br><code>agent/%s</code></p>`+
		`<p style="color:#94a3b8">You can close this window.</p></div>`+
		`<script>setTimeout(function(){window.close()},3000)</script></body></html>`,
		html.EscapeString(label), html.EscapeString(agentID))
}

// agentEnrollURL builds the /auth/agent-enroll URL. callback is the loopback
// the SEALED credential is POSTed back to, state is the one-time verifier the
// page echoes back and which is bound into the seal, sealPub is this
// ceremony's ephemeral PUBLIC key, and the rest are pre-fill hints the human
// can override on the page.
//
// Publishing sealPub in the URL is safe and is the point: it authorizes
// nothing, it only names the one recipient this ceremony's credential may be
// encrypted to. Its private half never leaves the cilock process.
func agentEnrollURL(judgeURL, callbackURL, state, sealPub string, params EnrollParams) string {
	q := url.Values{}
	q.Set("callback", callbackURL)
	q.Set("client", "cilock")
	q.Set("state", state)
	q.Set("seal_pub", sealPub)
	if params.DisplayName != "" {
		q.Set("name", params.DisplayName)
	}
	if params.Repo != "" {
		q.Set("repo", params.Repo)
	}
	if params.TTL > 0 {
		q.Set("ttl", strconv.FormatInt(int64(params.TTL/time.Second), 10))
	}
	return judgeURL + "/auth/agent-enroll?" + q.Encode()
}
