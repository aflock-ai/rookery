package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// jwtWithSubject builds an unsigned JWT carrying only `sub`. The exchange never
// verifies the signature — Fulcio does — so an unsigned token is the right
// fixture for a check about the SUBJECT.
func jwtWithSubject(t *testing.T, sub string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"sub": sub})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + "." + enc([]byte("sig"))
}

// TestExchangeRefusesATokenForADifferentPrincipal is the binding this whole
// path exists for.
//
// The failure it prevents: a response naming the ENROLLED agent in `spiffe_id`
// while returning a token whose subject is a HUMAN. Every earlier check passes
// — the SPIFFE ID matches the credential's own ids exactly — but Fulcio derives
// the certificate's SAN from the token's `sub`, so the leaf would carry the
// human identity while the run summary states the agent signed. Truthful
// reporting of a value that does not describe the signature.
func TestExchangeRefusesATokenForADifferentPrincipal(t *testing.T) {
	cred := bindingCred("")
	enrolled := "spiffe://td/tenant/" + cred.TenantID + "/agent/" + cred.AgentID

	cases := map[string]string{
		"a human email subject":      "cole@example.com",
		"a different agent":          "spiffe://td/tenant/" + cred.TenantID + "/agent/deadbeef",
		"an empty subject":           "",
		"the trust domain by itself": "spiffe://td",
	}

	for name, tokenSubject := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				// spiffe_id is the ENROLLED principal — this response passes every
				// check except the token binding.
				_ = json.NewEncoder(w).Encode(map[string]string{
					"token":      jwtWithSubject(t, tokenSubject),
					"token_type": "oidc",
					"spiffe_id":  enrolled,
				})
			}))
			defer srv.Close()

			_, err := ExchangeAgentCredential(srv.URL, bindingCred(srv.URL))
			if err == nil {
				t.Fatalf("must refuse a token whose subject is %q while naming %q", tokenSubject, enrolled)
			}
			if !strings.Contains(err.Error(), "subject") {
				t.Fatalf("the refusal must name the subject mismatch as the cause, got %q", err)
			}
		})
	}
}

// TestExchangeAcceptsAMatchingToken is the positive control: without it the
// test above could pass by refusing every response.
func TestExchangeAcceptsAMatchingToken(t *testing.T) {
	cred := bindingCred("")
	enrolled := "spiffe://td/tenant/" + cred.TenantID + "/agent/" + cred.AgentID

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      jwtWithSubject(t, enrolled),
			"token_type": "oidc",
			"spiffe_id":  enrolled,
		})
	}))
	defer srv.Close()

	got, err := ExchangeAgentCredential(srv.URL, bindingCred(srv.URL))
	if err != nil {
		t.Fatalf("a token whose subject IS the enrolled principal must be accepted: %v", err)
	}
	if got.SPIFFEID != enrolled {
		t.Fatalf("SPIFFEID = %q, want %q", got.SPIFFEID, enrolled)
	}
}

// TestExchangeRefusesAMalformedToken pins that a token cilock cannot read is a
// refusal, not a pass-through. An unreadable token cannot be checked against the
// principal, and signing with an unattributable token is the thing this path
// removes.
func TestExchangeRefusesAMalformedToken(t *testing.T) {
	cred := bindingCred("")
	enrolled := "spiffe://td/tenant/" + cred.TenantID + "/agent/" + cred.AgentID

	for name, token := range map[string]string{
		"not a jwt":          "just-a-string",
		"two segments":       "aaa.bbb",
		"payload not base64": "aaa.!!!not-base64!!!.ccc",
		"payload not json":   "aaa." + base64.RawURLEncoding.EncodeToString([]byte("plain text")) + ".ccc",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"token": token, "token_type": "oidc", "spiffe_id": enrolled,
				})
			}))
			defer srv.Close()

			if _, err := ExchangeAgentCredential(srv.URL, bindingCred(srv.URL)); err == nil {
				t.Fatalf("must refuse an unreadable token (%s)", name)
			}
		})
	}
}
