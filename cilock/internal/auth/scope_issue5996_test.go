package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

// jwtWithScopes builds an unsigned three-segment JWT whose payload carries the
// given scope claim. The signature segment is irrelevant — TokenAuthorizedForScope
// decodes without verification.
func jwtWithScopes(t *testing.T, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return strings.Join([]string{header, body, "sig"}, ".")
}

// TestSecurity_Issue5996_ScopePreflightFailClosed asserts the SECURE behavior:
// the pre-flight must fail CLOSED — an undecodable token or an empty scope set
// is treated as NOT authorized. Wildcard and explicit-scope handling is retained.
func TestSecurity_Issue5996_ScopePreflightFailClosed(t *testing.T) {
	t.Run("undecodable token is not authorized", func(t *testing.T) {
		if TokenAuthorizedForScope("not-a-jwt", "read:foo") {
			t.Fatal("undecodable token MUST fail closed (not authorized)")
		}
	})

	t.Run("empty scope set is not authorized", func(t *testing.T) {
		tok := jwtWithScopes(t, `{"scope":[]}`)
		if TokenAuthorizedForScope(tok, "read:foo") {
			t.Fatal("empty scope set MUST fail closed (not authorized)")
		}
	})

	t.Run("absent scope claim is not authorized", func(t *testing.T) {
		tok := jwtWithScopes(t, `{}`)
		if TokenAuthorizedForScope(tok, "read:foo") {
			t.Fatal("absent scope claim MUST fail closed (not authorized)")
		}
	})

	t.Run("wildcard is authorized", func(t *testing.T) {
		tok := jwtWithScopes(t, `{"scope":["*"]}`)
		if !TokenAuthorizedForScope(tok, "read:foo") {
			t.Fatal("wildcard scope must remain authorized")
		}
	})

	t.Run("matching explicit scope is authorized", func(t *testing.T) {
		tok := jwtWithScopes(t, `{"scope":["read:foo","write:bar"]}`)
		if !TokenAuthorizedForScope(tok, "read:foo") {
			t.Fatal("explicit matching scope must be authorized")
		}
	})

	t.Run("missing explicit scope is not authorized", func(t *testing.T) {
		tok := jwtWithScopes(t, `{"scope":["write:bar"]}`)
		if TokenAuthorizedForScope(tok, "read:foo") {
			t.Fatal("non-matching scope set must not be authorized")
		}
	})
}
