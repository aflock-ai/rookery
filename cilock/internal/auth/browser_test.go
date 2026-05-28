package auth

import (
	"net/url"
	"testing"
)

func TestNewStateIsRandomAndHex(t *testing.T) {
	a, err := newState()
	if err != nil {
		t.Fatalf("newState: %v", err)
	}
	b, err := newState()
	if err != nil {
		t.Fatalf("newState: %v", err)
	}
	if a == b {
		t.Fatalf("expected distinct states, got identical %q", a)
	}
	// 32 random bytes hex-encoded = 64 chars.
	if len(a) != 64 {
		t.Fatalf("expected 64-char hex state, got %d (%q)", len(a), a)
	}
}

func TestCLIAuthURLCarriesStateAndClient(t *testing.T) {
	const state = "deadbeef"
	raw := cliAuthURL("https://platform.testifysec.com", "http://localhost:5000/callback", state, LoginParams{
		Tenant:  "acme",
		Product: "vault",
		Purpose: "ci signing",
	})

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	q := u.Query()

	if got := q.Get("state"); got != state {
		t.Errorf("state = %q, want %q", got, state)
	}
	if got := q.Get("client"); got != "cilock" {
		t.Errorf("client = %q, want cilock", got)
	}
	if got := q.Get("callback"); got != "http://localhost:5000/callback" {
		t.Errorf("callback = %q", got)
	}
	if got := q.Get("tenant"); got != "acme" {
		t.Errorf("tenant = %q, want acme", got)
	}
	if got := q.Get("product"); got != "vault" {
		t.Errorf("product = %q, want vault", got)
	}
	if got := q.Get("purpose"); got != "ci signing" {
		t.Errorf("purpose = %q, want 'ci signing'", got)
	}
	// No repository parameter is ever emitted — cilock identity is the user.
	if q.Has("repo") || q.Has("repository") {
		t.Errorf("unexpected repo parameter in %q", raw)
	}
}

func TestCLIAuthURLOmitsEmptyHints(t *testing.T) {
	raw := cliAuthURL("https://platform.testifysec.com", "http://localhost:5000/callback", "s", LoginParams{})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	for _, k := range []string{"tenant", "product", "purpose"} {
		if q.Has(k) {
			t.Errorf("expected %q to be omitted when empty, got %q", k, q.Get(k))
		}
	}
	// state and client are always present.
	if q.Get("state") != "s" || q.Get("client") != "cilock" {
		t.Errorf("state/client missing: %q", raw)
	}
}
