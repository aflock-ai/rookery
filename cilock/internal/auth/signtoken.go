package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// signTokenPath is the platform endpoint that exchanges an authenticated cilock
// session (a sign-scoped API credential) for a short-lived, email-identity OIDC
// token the platform's embedded Fulcio trusts. It lives under the authenticated
// /auth subrouter on the Judge API.
const signTokenPath = "/oauth/sign-token" //nolint:gosec // G101 false positive: a URL path on the platform API, not a credential.

// SignTokenResult is the outcome of a sign-token exchange: the short-lived
// keyless signing token plus the assurance level (acr) the platform minted the
// signing identity at. AssuranceLevel is surfaced in the run summary so an
// operator sees the strength of the identity that signed.
type SignTokenResult struct {
	Token          string
	AssuranceLevel string
}

// ResolveSigningToken returns a short-lived OIDC token for the identity that
// should sign in the current environment. A local session is exchanged through
// the platform's purpose-specific sign-token endpoint; a registered CI workflow
// uses a fresh ambient OIDC token. Neither token is persisted here.
//
// audience is the Fulcio OIDC audience (normally "sigstore"), not a platform
// API audience. Keeping the argument explicit prevents a token minted for login
// or Archivista from being replayed into the signer.
func ResolveSigningToken(platformURL, audience string) (SignTokenResult, error) {
	// AN ENROLLED AGENT TAKES PRECEDENCE, AND FAILS CLOSED.
	//
	// This is the same rule applyAgentKeylessFulcioToken already applies on the
	// attestation path, and the same one `cilock agent status` already promises
	// the operator ("runs against this platform sign as this agent, taking
	// precedence over `cilock login`"). Until this branch existed the promise was
	// kept for attestations and silently broken for GIT SIGNING: with an agent
	// enrolled, resolution fell straight through to the human session and
	// ExchangeSignToken minted a certificate for the credential creator's EMAIL.
	// The agent's own commits were therefore signed by the human it exists to
	// stop borrowing from — while the run summary said an agent signed.
	//
	// Both failure modes below refuse rather than continue. An unreadable store
	// or a refused exchange leaves exactly one identity to fall through to, the
	// human's, which is the borrowed-identity result this whole path removes. A
	// missing certificate is a visible, fixable error; a certificate naming the
	// wrong principal is a false attestation nobody notices.
	agentCred, agentErr := LookupAgent(platformURL)
	if agentErr != nil {
		return SignTokenResult{}, fmt.Errorf("read the enrolled agent credential: %w", agentErr)
	}
	if agentCred != nil {
		// REFUSE AN AUDIENCE THIS PATH CANNOT SERVE, BEFORE MINTING ANYTHING.
		//
		// The agent credential-exchange endpoint mints ONE kind of token: a
		// short-lived signing identity for the platform's embedded Fulcio. But
		// Derive carries three distinct audiences — OIDCClientID ("sigstore") for
		// signing, OIDCAudience for Archivista, and OIDCLoginAudience for login —
		// and this function's own contract says the argument exists to "prevent a
		// token minted for login or Archivista from being replayed into the
		// signer".
		//
		// Returning the signing token for whatever audience was asked would break
		// that separation in the direction that matters: a caller requesting the
		// Archivista or login audience would receive a credential that Fulcio
		// accepts. Refusing is checkable locally, costs no round trip, and cannot
		// hand out a token for a purpose nobody authorized.
		if want := config.Derive(platformURL).OIDCClientID; audience != want {
			return SignTokenResult{}, fmt.Errorf(
				"the enrolled agent credential mints signing tokens for the %q audience only, "+
					"but %q was requested; the agent exchange cannot serve login or Archivista audiences",
				want, audience)
		}
		id, exchangeErr := ExchangeAgentCredential(platformURL, *agentCred)
		if exchangeErr != nil {
			return SignTokenResult{}, fmt.Errorf(
				"an agent principal is enrolled for %s, so this signature must be the agent's, "+
					"but exchanging its credential failed: %w", NormalizeURL(platformURL), exchangeErr)
		}
		// "agent" rather than an AAL: no human ceremony produced this identity,
		// and reporting an assurance level nobody demonstrated is the confusion
		// the agent path exists to remove. The workflow branch below reports
		// "workload" for the same reason.
		return SignTokenResult{Token: id.Token, AssuranceLevel: "agent"}, nil
	}

	cred, err := LookupAny(platformURL)
	if err != nil {
		return SignTokenResult{}, fmt.Errorf("resolve platform session: %w", err)
	}
	if cred != nil && cred.AuthMode != AuthModeWorkflowOIDC {
		if cred.Token == "" {
			return SignTokenResult{}, fmt.Errorf("platform session carries no signing credential")
		}
		return ExchangeSignTokenResult(platformURL, cred.Token)
	}
	if cred != nil && cred.AuthMode == AuthModeWorkflowOIDC && WorkflowOIDCAvailable() {
		token, err := workflowOIDCFetcher(audience)
		if err != nil {
			return SignTokenResult{}, fmt.Errorf("mint workflow signing token: %w", err)
		}
		if token == "" {
			return SignTokenResult{}, fmt.Errorf("workflow signing token was empty")
		}
		return SignTokenResult{Token: token, AssuranceLevel: "workload"}, nil
	}
	return SignTokenResult{}, fmt.Errorf("no CI/lock platform signing identity; run 'cilock login' or register this workflow and grant permissions: id-token: write")
}

// ExchangeSignToken trades a stored platform session credential for a
// short-lived OIDC token suitable for keyless Fulcio signing. It POSTs to
// <platformURL>/auth/oauth/sign-token with the session credential as a bearer
// token; the platform resolves the signing email server-side from the
// credential's creator and returns a fresh signing token.
//
// The long-lived session credential never reaches Fulcio — only the returned
// short token does. Callers must only ever send the credential to its own
// platform origin (the caller owns that origin check).
//
// Returns the bare token (existing contract). Callers needing the assurance
// level call ExchangeSignTokenResult.
func ExchangeSignToken(platformURL, sessionToken string) (string, error) {
	res, err := ExchangeSignTokenResult(platformURL, sessionToken)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

// ExchangeSignTokenResult is ExchangeSignToken plus the platform-reported
// assurance level, for callers that surface it (the run summary).
func ExchangeSignTokenResult(platformURL, sessionToken string) (SignTokenResult, error) {
	// Refuse to attach the session bearer over cleartext to a non-loopback host
	// (#5997): this bearer can mint Fulcio signing tokens, so it must never leak
	// to an on-path observer via a downgraded http:// platform URL.
	if err := config.RequireSecurePlatformURL(platformURL); err != nil {
		return SignTokenResult{}, err
	}
	endpoint := strings.TrimRight(NormalizeURL(platformURL), "/") + signTokenPath

	req, err := http.NewRequest(http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return SignTokenResult{}, fmt.Errorf("build sign-token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return SignTokenResult{}, fmt.Errorf("sign-token request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // diagnostic only
		return SignTokenResult{}, fmt.Errorf("sign-token exchange returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Token          string `json:"token"`
		Email          string `json:"email"`
		AssuranceLevel string `json:"assurance_level"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return SignTokenResult{}, fmt.Errorf("decode sign-token response: %w", err)
	}
	if out.Token == "" {
		return SignTokenResult{}, fmt.Errorf("sign-token response carried no token")
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
	return SignTokenResult{Token: out.Token, AssuranceLevel: out.AssuranceLevel}, nil
}
