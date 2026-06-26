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

// tokenAud extracts the `aud` claim from a JWT payload without verifying the
// signature. Per RFC 7519 `aud` may be a single string or an array of strings;
// both shapes are returned as a slice. ok is false when the token can't be
// decoded or carries no `aud`.
func tokenAud(token string) (aud []string, ok bool) {
	claims, decoded := decodeClaims(token)
	if !decoded {
		return nil, false
	}
	raw, present := claims["aud"]
	if !present {
		return nil, false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, true
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, true
	}
	return nil, false
}

// tokenHasAudience reports whether the token's `aud` claim contains want. When
// the token carries no decodable `aud` it fails OPEN (returns true) — a parsing
// quirk must not block a token the server would accept; the server remains the
// authority. Only a token that DOES declare an audience set NOT containing want
// is rejected, which is the confused-deputy case this gate exists to catch.
func tokenHasAudience(token, want string) bool {
	auds, ok := tokenAud(token)
	if !ok {
		return true // no decodable aud — let the server decide
	}
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}
