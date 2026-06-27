package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// scopeWildcard mirrors the platform's full-access scope sentinel.
const scopeWildcard = "*"

// TokenAuthorizedForScope reports whether a stored session JWT carries the given
// API scope, mirroring the platform's server-side hasScope semantics so a
// client-side pre-flight reaches the same verdict the server would:
//
//   - the wildcard "*" means full access (returns true);
//   - otherwise the scope must be present in the list.
//
// The token is decoded WITHOUT signature verification — this is purely a
// pre-flight to surface an actionable error before the platform rejects the
// request with an opaque "missing required scope" message; the platform remains
// the authority. This pre-flight fails CLOSED: an undecodable token or an empty
// scope set is treated as NOT authorized so a parsing quirk or a scopeless token
// never grants an admin-path action the pre-flight is meant to guard.
func TokenAuthorizedForScope(token, scope string) bool {
	scopes, ok := tokenScopes(token)
	if !ok {
		return false // undecodable — fail closed
	}
	if len(scopes) == 0 {
		return false // no scopes carried — fail closed
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

// decodeClaims decodes a JWT payload WITHOUT verifying the signature into the
// raw claim map. ok is false when the token isn't a decodable three-segment JWT
// whose payload is a JSON object. Like tokenScopes this is a pre-flight only —
// the platform remains the authority on signature/issuer.
func decodeClaims(token string) (claims map[string]json.RawMessage, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c map[string]json.RawMessage
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, false
	}
	return c, true
}

// tokenExp extracts the `exp` claim (NumericDate — seconds since the Unix
// epoch) from a JWT payload without verifying the signature. ok is false when
// the token can't be decoded or carries no numeric `exp`. The returned time is
// the real server-side expiry, so a credential can be gated on it rather than a
// synthetic client-side window that ignores when the platform actually revokes
// the session.
func tokenExp(token string) (exp time.Time, ok bool) {
	claims, decoded := decodeClaims(token)
	if !decoded {
		return time.Time{}, false
	}
	raw, present := claims["exp"]
	if !present {
		return time.Time{}, false
	}
	var secs float64
	if err := json.Unmarshal(raw, &secs); err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0), true
}
