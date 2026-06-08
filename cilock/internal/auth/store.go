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
}

// Expired reports whether the credential has a known expiry in the past.
func (c Credential) Expired() bool {
	return !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt)
}

type fileStore struct {
	Credentials map[string]Credential `json:"credentials"`
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
// read-through only succeeds when jctl stored the token in the file rather than
// the OS keychain (jctl scrubs the token to the keychain when available).
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

// lookupJctl reads ~/.jctl/config.yaml (best-effort) for a context whose
// judgeURL matches and that carries a non-empty token.
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
		Contexts map[string]struct {
			JudgeURL    string `yaml:"judgeURL"`
			Token       string `yaml:"token"`
			TenantID    string `yaml:"tenant_id"`
			TenantName  string `yaml:"tenant_name"`
			ProductID   string `yaml:"product_id"`
			ProductName string `yaml:"product_name"`
		} `yaml:"contexts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, false
	}
	for _, ctx := range cfg.Contexts {
		if NormalizeURL(ctx.JudgeURL) == platformURL && ctx.Token != "" {
			return &Credential{
				PlatformURL: platformURL,
				Token:       ctx.Token,
				TenantID:    ctx.TenantID,
				TenantName:  ctx.TenantName,
				ProductID:   ctx.ProductID,
				ProductName: ctx.ProductName,
			}, true
		}
	}
	return nil, false
}
