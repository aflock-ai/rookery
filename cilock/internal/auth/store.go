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

// Credential is a stored platform session, keyed by platform URL. It also
// carries the working scope (tenant + product) negotiated during login so
// cilock can bind attestations to the product without re-prompting.
type Credential struct {
	PlatformURL string    `json:"platform_url"`
	Token       string    `json:"token"`
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
			JudgeURL   string `yaml:"judgeURL"`
			Token      string `yaml:"token"`
			TenantID   string `yaml:"tenant_id"`
			TenantName string `yaml:"tenant_name"`
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
			}, true
		}
	}
	return nil, false
}
