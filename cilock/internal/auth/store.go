// Package auth handles cilock's interactive login to a Judge platform. A
// browser authorization-code-with-loopback flow yields a tenant-scoped session
// JWT, stored locally for subsequent platform calls (Archivista reads, Fulcio
// signing-token exchange). See docs/design/cilock-platform-identity-signing.md.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
)

// AuthMode records how a stored credential was obtained, so `cilock whoami`
// can describe the session and `cilock run` can tell a real session JWT apart
// from a workflow-identity marker that carries no stored token.
const (
	// AuthModeToken — credential is a directly-supplied --token.
	AuthModeToken = "token"
	// AuthModeBrowser — credential came from the interactive browser flow.
	AuthModeBrowser = "browser"
	// AuthModeWorkflowOIDC — CI workflow identity. No long-lived token is
	// stored; `cilock run` sources a fresh ambient OIDC token per call.
	AuthModeWorkflowOIDC = "workflow-oidc"
)

// Credential is a stored platform session, keyed by platform URL. It also
// carries the working scope (tenant + product) negotiated during login so
// cilock can bind attestations to the product without re-prompting.
type Credential struct {
	PlatformURL string `json:"platform_url"`
	Token       string `json:"token"`
	// AuthMode is how this credential was obtained (see AuthMode* constants).
	// A workflow-oidc credential intentionally carries an empty Token.
	AuthMode    string    `json:"auth_mode,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	TenantName  string    `json:"tenant_name,omitempty"`
	ProductID   string    `json:"product_id,omitempty"`
	ProductName string    `json:"product_name,omitempty"`
	Email       string    `json:"email,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	// TrustBundleSPKI is the trust-on-first-use pin for this platform's
	// discovery-served policy-signer trust bundle: the SHA-256 (hex) of the
	// raw trust_bundle_pem first adopted for this platform. On later resolves a
	// changed bundle is refused unless the operator re-pins with
	// --trust-discovery, so a compromised platform cannot silently swap in an
	// attacker CA as the policy-signature trust anchor (GHSA #5988). Empty until
	// the first discovery-trust adoption; omitted from older stores (backward
	// compatible — an absent pin just means "not yet pinned").
	TrustBundleSPKI string `json:"trust_bundle_spki,omitempty"`
}

// Expired reports whether the credential has a known expiry in the past.
func (c Credential) Expired() bool {
	return !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt)
}

// TokenCredential builds a session credential from an explicit --token (the
// CI/headless login path), validating the JWT client-side before it is stored
// (GHSA #5991):
//
//   - ExpiresAt is taken from the token's own `exp` claim so a server-expired
//     token is recognized as expired rather than replayed for a synthetic
//     now+30d window; a token with no decodable `exp` falls back to the bounded
//     defaultSessionTTL.
//   - The `aud` claim must include loginAudience (the platform's dedicated
//     login audience, config.PlatformConfig.OIDCLoginAudience). A token minted
//     for a different audience — e.g. the Archivista upload audience — is
//     REJECTED rather than silently stored as a session bearer, closing the
//     confused-deputy gap the workflow path already guards. A token carrying no
//     decodable `aud` fails open (the server stays the authority).
//
// The token is decoded WITHOUT signature verification — this is a pre-flight;
// the platform remains the authority on signature and issuer.
func TokenCredential(platformURL, token, loginAudience string) (*Credential, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	if !tokenHasAudience(token, loginAudience) {
		return nil, fmt.Errorf("token audience does not match the platform login audience %q "+
			"(a token minted for a different audience — e.g. attestation upload — must not be "+
			"used as a login session); obtain a session token via `cilock login`", loginAudience)
	}
	expiresAt := time.Now().Add(defaultSessionTTL)
	if exp, ok := tokenExp(token); ok {
		expiresAt = exp
	}
	return &Credential{
		PlatformURL: platformURL,
		Token:       token,
		AuthMode:    AuthModeToken,
		ExpiresAt:   expiresAt,
	}, nil
}

type fileStore struct {
	Credentials map[string]Credential `json:"credentials"`
	// CurrentPlatform is the platform of the most recent login/use — the active
	// working platform, so `cilock run`/`trust` default to where you logged in
	// instead of the compiled-in default. Cleared when its credential is deleted.
	CurrentPlatform string `json:"current_platform,omitempty"`
}

// NormalizeURL trims a trailing slash so lookups are stable.
func NormalizeURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

// StorePath is cilock's own credential file (~/.config/cilock/credentials.json
// on Linux; Application Support on macOS). cilock owns this file; it does not
// write jctl's config.
func StorePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "cilock", "credentials.json"), nil
}

func load() (*fileStore, error) {
	path, err := StorePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is under the user's own config dir
	if os.IsNotExist(err) {
		return &fileStore{Credentials: map[string]Credential{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read credential store: %w", err)
	}
	var s fileStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse credential store %s: %w", path, err)
	}
	if s.Credentials == nil {
		s.Credentials = map[string]Credential{}
	}
	return &s, nil
}

// Save writes (or replaces) the credential for its platform URL at 0600.
func Save(c Credential) error {
	c.PlatformURL = NormalizeURL(c.PlatformURL)
	s, err := load()
	if err != nil {
		return err
	}
	s.Credentials[c.PlatformURL] = c
	// The most recently written credential becomes the active working platform.
	s.CurrentPlatform = c.PlatformURL
	path, err := StorePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credential store: %w", err)
	}
	return nil
}

// SetScope updates only the working tenant/product binding on the stored
// credential for platformURL, preserving its token, auth mode, email, and
// expiry. It requires an existing cilock credential (run `cilock login` first);
// it does not write to jctl's config. Empty arguments are left unchanged, so a
// caller can rebind product alone or tenant alone. This is the mechanism behind
// `cilock use` and the headless binding path — mirroring jctl's
// `config set-product`, which writes the scope onto the active context.
func SetScope(platformURL, tenantID, tenantName, productID, productName string) error {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return err
	}
	c, ok := s.Credentials[key]
	if !ok {
		return fmt.Errorf("not logged in to %s (run: cilock login --platform-url %s)", key, key)
	}
	if tenantID != "" {
		c.TenantID = tenantID
	}
	if tenantName != "" {
		c.TenantName = tenantName
	}
	if productID != "" {
		c.ProductID = productID
	}
	if productName != "" {
		c.ProductName = productName
	}
	return Save(c)
}

// SetTrustBundleSPKI records the trust-on-first-use pin (the SHA-256 hex of the
// platform's discovery trust_bundle_pem) onto the stored credential for
// platformURL, preserving its token, scope, email, and expiry. It is a no-op
// when no cilock credential exists for the platform (a jctl-only session has no
// cilock store entry to pin onto; verify falls back to refusing a later change
// only when a pin was actually persisted). Used by verify's discovery-trust
// adoption (GHSA #5988).
func SetTrustBundleSPKI(platformURL, spki string) error {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return err
	}
	c, ok := s.Credentials[key]
	if !ok {
		return nil // nothing in cilock's own store to pin onto
	}
	if c.TrustBundleSPKI == spki {
		return nil // already pinned to this value; avoid a needless rewrite
	}
	c.TrustBundleSPKI = spki
	return Save(c)
}

// ActivePlatformURL returns the platform a bare command should target when
// --platform-url is not given: the most recent login/use (CurrentPlatform) if it
// still has a stored credential, else the sole stored credential's URL, else ""
// (callers then fall back to the compiled default). This is what lets
// `cilock run` / `cilock trust` default to the platform you logged into rather
// than the hard-coded prod default.
func ActivePlatformURL() string {
	s, err := load()
	if err != nil {
		return ""
	}
	if s.CurrentPlatform != "" {
		if _, ok := s.Credentials[s.CurrentPlatform]; ok {
			return s.CurrentPlatform
		}
	}
	if len(s.Credentials) == 1 {
		for url := range s.Credentials {
			return url
		}
	}
	return ""
}

// Delete removes the credential for a platform URL. Returns whether one existed.
func Delete(platformURL string) (bool, error) {
	s, err := load()
	if err != nil {
		return false, err
	}
	key := NormalizeURL(platformURL)
	if _, ok := s.Credentials[key]; !ok {
		return false, nil
	}
	delete(s.Credentials, key)
	if s.CurrentPlatform == key {
		s.CurrentPlatform = "" // don't leave a dangling active platform
	}
	path, _ := StorePath()
	data, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, fmt.Errorf("write credential store: %w", err)
	}
	return true, nil
}

// Lookup returns a non-expired credential for the platform URL. It checks
// cilock's own store first, then falls back to a best-effort read of jctl's
// ~/.jctl/config.yaml (so a prior `jctl login` works for cilock too). The jctl
// read-through takes the token from the YAML when present, or from the OS
// keychain entry jctl scrubbed it into (see lookupJctl).
func Lookup(platformURL string) (*Credential, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := s.Credentials[key]; ok && c.Token != "" && !c.Expired() {
		return &c, nil
	}
	if c, ok := lookupJctl(key); ok {
		return c, nil
	}
	return nil, nil
}

// LookupAny returns a non-expired stored credential for the platform URL
// regardless of whether it carries a token. Unlike Lookup (which gates on a
// non-empty Token because callers attach it as a Bearer), this also returns a
// workflow-identity marker (AuthModeWorkflowOIDC, empty Token). Use it for
// status/display (`cilock whoami`), never to obtain a bearer token.
func LookupAny(platformURL string) (*Credential, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := s.Credentials[key]; ok && !c.Expired() {
		return &c, nil
	}
	if c, ok := lookupJctl(key); ok {
		return c, nil
	}
	return nil, nil
}

// LookupAnyIncludingExpired returns the credential the platform call would use,
// but unlike LookupAny it will surface an EXPIRED cilock credential rather than
// collapsing it to nil — so diagnostic callers (e.g. `cilock doctor`) can tell
// an EXPIRED session apart from a MISSING one (LookupAny reports both as "not
// logged in", which would pass preflight on expired auth).
//
// Precedence mirrors LookupAny so the doctor's verdict matches what `cilock run`
// actually does: a usable (non-expired) cilock credential first, then a
// jctl-sourced one. Only when neither exists is an expired cilock credential
// returned — so an expired session is reported as EXPIRED when it is the only
// thing available, without masking a valid jctl fallback behind a stale cilock
// entry (which would make the doctor over-report FAIL on an environment a real
// run would handle). NEVER use this to obtain a bearer token — an expired
// credential must not sign; gate on Expired() before any use.
func LookupAnyIncludingExpired(platformURL string) (*Credential, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := s.Credentials[key]; ok && !c.Expired() {
		return &c, nil
	}
	if c, ok := lookupJctl(key); ok {
		return c, nil
	}
	if c, ok := s.Credentials[key]; ok { // expired — surfaced for diagnosis only
		return &c, nil
	}
	return nil, nil
}

// jctlKeyringService is jctl's keychain service identifier — every token jctl
// scrubs out of ~/.jctl/config.yaml lives in the OS keychain under this
// service, keyed by the context NAME as the account. Must stay in sync with
// judge-api/cmd/jctl/internal/config (keyringService).
const jctlKeyringService = "jctl"

// jctlKeyringTimeout caps the keychain read. A wedged secret-service daemon
// (broken GNOME Keyring, zombie session bus on Linux) can otherwise hang
// every cilock command indefinitely — same guard as jctl's own startup probe.
// A var (not const) so tests can shrink it.
var jctlKeyringTimeout = 3 * time.Second

// getJctlKeyringToken is a seam over keyring.Get so tests can simulate a
// hanging or failing keychain backend.
var getJctlKeyringToken = func(contextName string) (string, error) {
	return keyring.Get(jctlKeyringService, contextName)
}

// jctlKeyringToken reads the token jctl stored in the OS keychain for
// contextName, bounded by jctlKeyringTimeout. Any error, miss, or timeout
// reports ok=false — the caller then behaves exactly as if the context had no
// token, which is the pre-fallback behavior. On timeout the read goroutine is
// abandoned; its buffered channel send cannot block, so it exits whenever the
// backend finally answers.
func jctlKeyringToken(contextName string) (string, bool) {
	type result struct {
		token string
		err   error
	}
	// Capture the seam before spawning: the goroutine must only touch locals,
	// so an abandoned (timed-out) read can never race a test restoring the var.
	get := getJctlKeyringToken
	ch := make(chan result, 1)
	go func() {
		token, err := get(contextName)
		ch <- result{token: token, err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil || r.token == "" {
			return "", false
		}
		return r.token, true
	case <-time.After(jctlKeyringTimeout):
		return "", false
	}
}

// jctlContext is the per-context shape cilock reads from jctl's config.
type jctlContext struct {
	JudgeURL    string `yaml:"judgeURL"`
	Token       string `yaml:"token"`
	TenantID    string `yaml:"tenant_id"`
	TenantName  string `yaml:"tenant_name"`
	ProductID   string `yaml:"product_id"`
	ProductName string `yaml:"product_name"`
}

// credential builds the cilock Credential a jctl context resolves to. token
// is passed explicitly because it may come from the YAML or the OS keychain.
func (ctx jctlContext) credential(platformURL, token string) *Credential {
	return &Credential{
		PlatformURL: platformURL,
		Token:       token,
		TenantID:    ctx.TenantID,
		TenantName:  ctx.TenantName,
		ProductID:   ctx.ProductID,
		ProductName: ctx.ProductName,
	}
}

// lookupJctl reads ~/.jctl/config.yaml (best-effort) for a context whose
// judgeURL matches. Tokens come from the YAML when present (jctl file mode /
// JCTL_DISABLE_KEYRING=1); when the YAML token is empty, jctl scrubbed it
// into the OS keychain (service "jctl", account = context name) and the
// fallback reads it from there — otherwise the documented "jctl login works
// for cilock too" interop is silently dead on macOS and desktop Linux, where
// the keychain is jctl's default.
func lookupJctl(platformURL string) (*Credential, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(home, ".jctl", "config.yaml")) //nolint:gosec // user's own jctl config
	if err != nil {
		return nil, false
	}
	var cfg struct {
		Contexts map[string]jctlContext `yaml:"contexts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, false
	}
	// Pass 1: contexts whose token is inline in the YAML. Exactly the
	// pre-keychain behavior, and it never touches the keychain — a wedged
	// daemon can't slow down an install that already works.
	for _, ctx := range cfg.Contexts {
		if NormalizeURL(ctx.JudgeURL) == platformURL && ctx.Token != "" {
			return ctx.credential(platformURL, ctx.Token), true
		}
	}
	// Pass 2: matching contexts with an empty YAML token — read the keychain
	// entry jctl scrubbed the token into. The account is the context NAME (the
	// YAML map key), not a recomputed hostname. Any miss/error/timeout leaves
	// us exactly where we were before this fallback: no credential.
	for name, ctx := range cfg.Contexts {
		if NormalizeURL(ctx.JudgeURL) != platformURL || ctx.Token != "" {
			continue
		}
		if token, ok := jctlKeyringToken(name); ok {
			return ctx.credential(platformURL, token), true
		}
	}
	return nil, false
}
