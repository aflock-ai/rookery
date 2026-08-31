package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bindingCred is the enrolled credential every test here presents. The ids are
// the authority the response is checked against.
func bindingCred(platformURL string) AgentCredential {
	return AgentCredential{
		PlatformURL:       platformURL,
		TenantID:          "11111111-1111-1111-1111-111111111111",
		AgentID:           "22222222-2222-2222-2222-222222222222",
		RefreshCredential: "s3cret-refresh-credential-value",
	}
}

// TestExchangeRefusesToFollowARedirect pins that the refresh credential is
// never forwarded to another location.
//
// RFC 9110 requires 307/308 to preserve the method AND the body, so a followed
// redirect hands the long-lived secret to whatever host `Location` names —
// including a cleartext one. The test proves the secret never reaches the
// redirect target by having that target record every body it receives.
func TestExchangeRefusesToFollowARedirect(t *testing.T) {
	var leaked []string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf) //nolint:errcheck // best effort; any read at all is the failure
		leaked = append(leaked, string(buf[:n]))
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/api/agent/credential-exchange", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	cred := bindingCred(redirector.URL)
	_, err := ExchangeAgentCredential(redirector.URL, cred)
	if err == nil {
		t.Fatal("a redirected exchange must fail; following it forwards the refresh credential")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("the error must name the redirect as the cause, got %q", err)
	}
	for _, body := range leaked {
		if strings.Contains(body, cred.RefreshCredential) {
			t.Fatal("the refresh credential reached the redirect target; this is the exfiltration path")
		}
	}
	if strings.Contains(err.Error(), cred.RefreshCredential) {
		t.Fatal("the refresh credential leaked into the redirect error")
	}
}

// TestExchangeRefusesAPrincipalItDidNotAskFor pins that the returned SPIFFE ID
// names the credential that was presented.
//
// A prefix check accepts any spiffe:// string, so a server answering with a
// different tenant or agent would have cilock sign under one principal while
// the run summary — which reads this field — names another. Each case below is
// SPIFFE-shaped and would pass a prefix check.
func TestExchangeRefusesAPrincipalItDidNotAskFor(t *testing.T) {
	cred := bindingCred("")

	cases := map[string]string{
		"a different tenant": "spiffe://td/tenant/99999999-9999-9999-9999-999999999999/agent/" + cred.AgentID,
		"a different agent":  "spiffe://td/tenant/" + cred.TenantID + "/agent/88888888-8888-8888-8888-888888888888",
		"no tenant segment":  "spiffe://td/agent/" + cred.AgentID,
		"a tenant that merely embeds ours": "spiffe://td/tenant/" + cred.TenantID +
			"-extra/agent/" + cred.AgentID,
		"the right ids in the wrong order": "spiffe://td/tenant/" + cred.AgentID + "/agent/" + cred.TenantID,
	}

	for name, spiffeID := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"token": "a-token", "token_type": "oidc", "spiffe_id": spiffeID,
				})
			}))
			defer srv.Close()

			c := bindingCred(srv.URL)
			_, err := ExchangeAgentCredential(srv.URL, c)
			if err == nil {
				t.Fatalf("must refuse %q: it is not the principal this credential enrolls", spiffeID)
			}
			if !strings.Contains(err.Error(), c.TenantID) || !strings.Contains(err.Error(), c.AgentID) {
				t.Fatalf("the refusal must name the ids that were presented, got %q", err)
			}
			if strings.Contains(err.Error(), c.RefreshCredential) {
				t.Fatal("the refresh credential leaked into the mismatch error")
			}
		})
	}
}

// TestExchangeAcceptsThePrincipalItAskedFor is the positive control. Without it
// the test above could pass by refusing everything.
func TestExchangeAcceptsThePrincipalItAskedFor(t *testing.T) {
	cred := bindingCred("")
	want := "spiffe://td/tenant/" + cred.TenantID + "/agent/" + cred.AgentID

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The token must name the same principal: the exchange now binds the
		// token's subject to the reported SPIFFE ID, so a placeholder string is
		// correctly refused.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": jwtWithSubject(t, want), "token_type": "oidc", "spiffe_id": want,
		})
	}))
	defer srv.Close()

	got, err := ExchangeAgentCredential(srv.URL, bindingCred(srv.URL))
	if err != nil {
		t.Fatalf("the matching principal must be accepted: %v", err)
	}
	if got.SPIFFEID != want {
		t.Fatalf("SPIFFEID = %q, want %q", got.SPIFFEID, want)
	}
}
