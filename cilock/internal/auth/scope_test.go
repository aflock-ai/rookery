package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// makeJWT builds an unsigned JWT-shaped string with the given scope claim so
// the client-side pre-flight decoder can be tested without real crypto. The
// signature segment is irrelevant — TokenAuthorizedForScope never verifies it.
func makeJWT(t *testing.T, scopes any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claims := map[string]any{"sub": "cred-1", "tenant_id": "t1"}
	if scopes != nil {
		claims["scope"] = scopes
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

func TestTokenAuthorizedForScope(t *testing.T) {
	// The exact scope set a DEFAULT `cilock login` session carries (CILOCK_SCOPES
	// on the web approve page). This is the staging-bug repro: trust needs
	// oidc:write but the default session never has it.
	defaultSession := makeJWT(t, []string{"attestation:upload", "attestation:read", "sign"})
	// What `cilock login --allow-trust` produces.
	trustSession := makeJWT(t, []string{"attestation:upload", "attestation:read", "sign", "oidc:write"})

	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"default cilock session lacks oidc:write", defaultSession, false},
		{"allow-trust session carries oidc:write", trustSession, true},
		{"wildcard scope is full access", makeJWT(t, []string{"*"}), true},
		{"empty scope array is full access (server parity)", makeJWT(t, []string{}), true},
		{"absent scope claim is full access", makeJWT(t, nil), true},
		{"undecodable token fails open (server decides)", "not-a-jwt", true},
		{"opaque two-part token fails open", "aaa.bbb", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TokenAuthorizedForScope(c.token, "oidc:write"); got != c.want {
				t.Fatalf("TokenAuthorizedForScope(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
