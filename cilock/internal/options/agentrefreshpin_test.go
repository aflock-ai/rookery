package options

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// THE PIN MUST HOLD WITHIN THE RUN THAT CREATES IT, not merely across runs.
//
// On first use an enrolled credential arrives with an empty TrustDomain: there
// is nothing local to compare against yet, so the first exchange is accepted
// and its answer is pinned. The refresher, however, closes over the credential
// as it was BEFORE that pin — so unless the captured copy is updated, every
// later exchange in the same run is an unpinned exchange again and will accept
// a DIFFERENT authority.
//
// That is the whole TOFU guarantee defeated in the window it was established:
// the pin is written to disk correctly and bypassed by the very run that wrote
// it. cilock would sign under trust domain A, then minutes later under B, both
// times reporting an enrolled agent.
//
// The server here answers with domain A once and B forever after, which is
// exactly the shape a compromised or misrouted platform produces.
func TestRefreshCannotSwitchTrustDomainMidRun(t *testing.T) {
	isolateCredentialStore(t)

	const (
		idA = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
		idB = "spiffe://attacker.example.com/tenant/t-1/agent/a-1"
	)

	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/credential-exchange" {
			http.NotFound(w, r)
			return
		}
		i := atomic.AddInt64(&n, 1)
		id := idA
		if i > 1 {
			id = idB
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": testAgentJWT(id, i), "token_type": "oidc", "spiffe_id": id, "upload_token": "test-upload-bearer",
		})
	}))
	defer srv.Close()

	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("the first exchange names the enrolled agent and must succeed: %v", err)
	}

	refresh := ro.FulcioTokenRefresher()
	if refresh == nil {
		t.Fatal("an agent run must install a refresher")
	}

	err := refresh()
	if err == nil {
		t.Fatal("the refresh accepted a DIFFERENT trust domain; the pin established by the first exchange was bypassed within the same run")
	}
	if !strings.Contains(err.Error(), "trust domain") {
		t.Fatalf("the refusal should name the trust domain mismatch, got %v", err)
	}

	// And the token installed for signing must still be the one from the
	// principal that was actually verified — a refusal must not leave a
	// half-applied identity behind.
	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != testAgentJWT(idA, 1) {
		t.Fatalf("a refused refresh replaced the signing token: %q", got)
	}
}

// The control: when the platform keeps answering with the SAME trust domain,
// the refresh still works. Without it the test above would pass on a refresher
// that always failed.
func TestRefreshSucceedsWhenTheTrustDomainIsUnchanged(t *testing.T) {
	isolateCredentialStore(t)

	srv := agentExchangeServer(t)
	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("agent path failed: %v", err)
	}

	refresh := ro.FulcioTokenRefresher()
	if refresh == nil {
		t.Fatal("an agent run must install a refresher")
	}
	if err := refresh(); err != nil {
		t.Fatalf("a refresh naming the same principal must succeed, got %v", err)
	}
	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != testAgentJWT(agentSPIFFEID, 2) {
		t.Fatalf("the refresh did not install the SECOND exchange's token: %q", got)
	}
}
