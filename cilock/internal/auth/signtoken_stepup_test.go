package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THE REFUSAL HAS TO REACH THE HUMAN WHOLE.
//
// The server's remediation says the step-up URL is "below", and it sends the
// URL as a PATH because only the client knows which platform host it called.
// A client that parses `remediation` and drops `step_up_url` therefore prints
// a sentence pointing at nothing, and the human is stuck: `cilock login` alone
// never raises a session's assurance level, so re-running it mints another
// credential at the same level and earns the same refusal.
func TestExchangeSignTokenSurfacesTheStepUpURL(t *testing.T) {
	const stepUpPath = "/self-service/login/browser?aal=aal2&refresh=true"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		// The exact shape POST /oauth/sign-token returns for an AAL refusal.
		_, _ = w.Write([]byte(`{"error":"aal2_required",` +
			`"remediation":"signing requires a passkey session (AAL2). Complete the step-up at the URL below.",` +
			`"step_up_url":"` + stepUpPath + `"}`))
	}))
	defer server.Close()

	_, err := ExchangeSignTokenResult(server.URL, "session-token")
	if err == nil {
		t.Fatal("a 403 refusal must be an error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "passkey session (AAL2)") {
		t.Errorf("the server's remediation must survive: %q", msg)
	}
	if !strings.Contains(msg, stepUpPath) {
		t.Errorf("the step-up path must reach the human, or the refusal is a loop: %q", msg)
	}
	if !strings.Contains(msg, server.URL) {
		t.Errorf("the path must be resolved against the platform the client called: %q", msg)
	}
}

// A refusal that carries no step-up path is passed through untouched, so an
// older server (or a refusal that has nothing to offer) does not gain a
// dangling "Step up here:" with an empty target.
func TestExchangeSignTokenWithoutAStepUpURLIsUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"aal2_required","remediation":"re-issue this credential."}`))
	}))
	defer server.Close()

	_, err := ExchangeSignTokenResult(server.URL, "session-token")
	if err == nil {
		t.Fatal("a 403 refusal must be an error")
	}
	if got := err.Error(); got != "re-issue this credential." {
		t.Errorf("a refusal with no step-up path must pass through unchanged, got %q", got)
	}
}

func TestWithStepUpURLResolvesAgainstThePlatform(t *testing.T) {
	got := withStepUpURL("do the thing.", "https://platform.example.com/", "/self-service/login/browser?aal=aal2")
	want := "do the thing.\n\nStep up here: https://platform.example.com/self-service/login/browser?aal=aal2"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// An absolute URL from the server is used as-is rather than double-prefixed.
	abs := withStepUpURL("do the thing.", "https://platform.example.com", "https://idp.example.com/step-up")
	if !strings.HasSuffix(abs, "https://idp.example.com/step-up") {
		t.Errorf("an absolute step-up URL must not be rewritten: %q", abs)
	}

	if plain := withStepUpURL("do the thing.", "https://platform.example.com", "   "); plain != "do the thing." {
		t.Errorf("a blank path must add nothing: %q", plain)
	}
}
