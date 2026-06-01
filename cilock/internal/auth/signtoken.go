package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// signTokenPath is the platform endpoint that exchanges an authenticated cilock
// session (a sign-scoped API credential) for a short-lived, email-identity OIDC
// token the platform's embedded Fulcio trusts. It lives under the authenticated
// /auth subrouter on the Judge API.
const signTokenPath = "/oauth/sign-token" //nolint:gosec // G101 false positive: a URL path on the platform API, not a credential.

// ExchangeSignToken trades a stored platform session credential for a
// short-lived OIDC token suitable for keyless Fulcio signing. It POSTs to
// <platformURL>/auth/oauth/sign-token with the session credential as a bearer
// token; the platform resolves the signing email server-side from the
// credential's creator and returns a fresh signing token.
//
// The long-lived session credential never reaches Fulcio — only the returned
// short token does. Callers must only ever send the credential to its own
// platform origin (the caller owns that origin check).
func ExchangeSignToken(platformURL, sessionToken string) (string, error) {
	endpoint := strings.TrimRight(NormalizeURL(platformURL), "/") + signTokenPath

	req, err := http.NewRequest(http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build sign-token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("sign-token request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // diagnostic only
		return "", fmt.Errorf("sign-token exchange returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Token          string `json:"token"`
		Email          string `json:"email"`
		AssuranceLevel string `json:"assurance_level"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("decode sign-token response: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("sign-token response carried no token")
	}
	// The server resolves the signing identity (email) and the assurance level
	// (acr) it minted at; persist the email onto the stored session when it has
	// none, so later `cilock verify` can default the expected signer to it. The
	// platform URL is the lookup key. Best-effort — a persistence failure must
	// not fail the signing path.
	if out.Email != "" {
		if cred, lookupErr := Lookup(platformURL); lookupErr == nil && cred != nil && cred.Email == "" {
			cred.Email = out.Email
			_ = Save(*cred)
		}
	}
	return out.Token, nil
}
