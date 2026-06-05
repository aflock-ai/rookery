package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// scopeWildcard mirrors the platform's full-access scope sentinel.
const scopeWildcard = "*"

// TokenAuthorizedForScope reports whether a stored session JWT carries the given
// API scope, mirroring the platform's server-side hasScope semantics so a
// client-side pre-flight reaches the same verdict the server would:
//
//   - an empty/absent scope set means full access (returns true);
//   - the wildcard "*" means full access (returns true);
//   - otherwise the scope must be present in the list.
//
// The token is decoded WITHOUT signature verification — this is purely a
// pre-flight to surface an actionable error before the platform rejects the
// request with an opaque "missing required scope" message; the platform remains
// the authority. If the token can't be decoded the function fails OPEN (returns
// true) so a parsing quirk never blocks a call the server would actually accept.
func TokenAuthorizedForScope(token, scope string) bool {
	scopes, ok := tokenScopes(token)
	if !ok {
		return true // undecodable — let the server decide
	}
	if len(scopes) == 0 {
		return true // empty scopes == full access (server parity)
	}
	for _, s := range scopes {
		if s == scope || s == scopeWildcard {
			return true
		}
	}
	return false
}

// tokenScopes extracts the "scope" claim from a JWT payload without verifying
// the signature. ok is false when the token isn't a decodable three-segment JWT
// or its payload isn't JSON with a string-array "scope" claim.
func tokenScopes(token string) (scopes []string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims struct {
		Scope []string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	return claims.Scope, true
}
