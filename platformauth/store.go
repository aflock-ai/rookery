// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// metadataSchemaVersion is the on-disk metadata file's schema version. A future
// format change bumps it and migrates older files forward on load, so an
// upgraded tool can read a store written by an older one.
const metadataSchemaVersion = 1

// metadata is the on-disk file shape: a schema version, the per-platform
// credentials keyed by normalized platform URL, and the active-platform pointer.
// In keyring mode every Credential.Token is scrubbed before the file is written;
// in fallback mode the token is serialized inline (the file is 0600).
type metadata struct {
	// Version is the schema version of this file (metadataSchemaVersion).
	Version int `json:"version"`
	// Credentials maps a normalized platform URL to its stored session.
	Credentials map[string]Credential `json:"credentials"`
	// CurrentPlatform is the platform of the most recent login/use — the active
	// working platform, so a bare command defaults to where you logged in instead
	// of the compiled-in default. Cleared when its credential is deleted.
	CurrentPlatform string `json:"current_platform,omitempty"`
}

// Store is a keyring-backed session store. The bearer token lives in the OS
// keyring (service "judge", account = normalized platform URL); non-secret
// metadata lives in a 0600 JSON file under the user's XDG config dir. When the
// keyring is unavailable the token falls back to the file (still 0600).
//
// The zero value is not usable; construct one with NewStore or DefaultStore.
type Store struct {
	// path is the metadata file path.
	path string
}

// DefaultStore returns the store at the platform's default location:
// $XDG_CONFIG_HOME/judge/session.json (falling back to ~/.config/judge/session.json
// when XDG_CONFIG_HOME is unset), per the XDG Base Directory spec.
func DefaultStore() (*Store, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, "session.json")}, nil
}

// NewStore returns a store backed by the given metadata file path. Used by tests
// and by callers that want an explicit location.
func NewStore(path string) *Store { return &Store{path: path} }

// Path returns the metadata file path.
func (s *Store) Path() string { return s.path }

// configDir resolves the judge config directory honoring $XDG_CONFIG_HOME, then
// falling back to ~/.config (the XDG default).
func configDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "judge"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "judge"), nil
}

// load reads the metadata file and overlays keyring tokens. A missing file
// yields an empty metadata. In keyring mode, a token still present inline in the
// file (a fallback-mode write, or a freshly migrated legacy store) is reconciled:
// pushed to the keyring and scrubbed from the file on the next save.
func (s *Store) load() (*metadata, error) {
	warnKeyringUnavailableOnce(s.path)
	data, err := os.ReadFile(s.path) //nolint:gosec // path is under the user's own config dir
	if errors.Is(err, os.ErrNotExist) {
		return &metadata{Version: metadataSchemaVersion, Credentials: map[string]Credential{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session store: %w", err)
	}
	var m metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse session store %s: %w", s.path, err)
	}
	if m.Credentials == nil {
		m.Credentials = map[string]Credential{}
	}
	m.Version = metadataSchemaVersion

	if !keyringAvailable() {
		// File mode: the file is authoritative for both metadata and tokens.
		return &m, nil
	}

	// Keyring mode: overlay the keyring token for each credential, reconciling
	// any token still inline in the file.
	store := selectStore()
	needsScrub := false
	for key, cred := range m.Credentials {
		ringToken, err := store.Load(key)
		if err != nil {
			return nil, fmt.Errorf("keyring load for %q: %w", key, err)
		}
		resolved, scrub := reconcileToken(key, cred, ringToken, store)
		m.Credentials[key] = resolved
		if scrub {
			needsScrub = true
		}
	}
	if needsScrub {
		// Strip migrated tokens from the file. Silent on failure: the keyring
		// write already succeeded, so the next load still reads the right token;
		// the file just isn't cleaned yet. Don't break the caller over it.
		if err := s.save(&m); err != nil {
			fmt.Fprintf(os.Stderr, "judge: warning: failed to complete token migration for %s: %v\n", s.path, err)
		}
	}
	return &m, nil
}

// reconcileToken merges a credential's inline (file) token with the keyring's
// stored token and returns the resolved credential plus whether the file needs
// scrubbing. Cases:
//  1. inline != "" && ring != "" && inline != ring — conflict. The inline value
//     is the freshly-written surface, so it wins; overwrite the keyring. If the
//     keyring write fails, keep the inline token in memory and leave the file
//     intact so the next launch retries.
//  2. ring != "" — the keyring is authoritative. If the file has a matching
//     inline value, scrub it (idempotent retry of a partial migration).
//  3. inline != "" — a legacy/fallback write. Stage it for save to migrate it.
func reconcileToken(key string, cred Credential, ringToken string, store tokenStore) (Credential, bool) {
	inline := cred.Token
	switch {
	case inline != "" && ringToken != "" && inline != ringToken:
		cred.Token = inline
		if err := store.Save(key, inline); err != nil {
			fmt.Fprintf(os.Stderr, "judge: warning: failed to update keyring for %q: %v (keeping in-memory token)\n", key, err)
			return cred, false
		}
		return cred, true
	case ringToken != "":
		cred.Token = ringToken
		return cred, inline != ""
	case inline != "":
		cred.Token = inline
		return cred, true
	default:
		cred.Token = ""
		return cred, false
	}
}

// save writes the metadata file. In keyring mode each token is pushed to the
// keyring and scrubbed from the file copy before marshaling; in fallback mode
// tokens stay inline. The file and its directory are created at 0700/0600.
func (s *Store) save(m *metadata) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	m.Version = metadataSchemaVersion

	warnKeyringUnavailableOnce(s.path)
	onDisk := *m
	if keyringAvailable() {
		scrubbed, err := pushTokensToKeyring(selectStore(), m.Credentials)
		if err != nil {
			return err
		}
		onDisk.Credentials = scrubbed
	}

	data, err := json.MarshalIndent(&onDisk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session store: %w", err)
	}
	return writeFile0600(s.path, data)
}

// writeFile0600 writes data to path with mode 0600, ENFORCED even when path
// already exists at a looser mode (os.WriteFile alone leaves a pre-existing
// 0644 file world-readable — a bearer token in fallback mode would then sit in
// a readable file). It writes to a sibling temp file created 0600, fsync-free
// chmods it to 0600 to defend against a permissive umask, then atomically
// renames it over the target so a concurrent reader never sees a partial or
// looser-mode file. A pre-existing target is also chmod-tightened directly as a
// belt-and-suspenders step in case the rename path is ever bypassed.
func writeFile0600(path string, data []byte) error {
	// Tighten an existing target up front: even though the rename below replaces
	// it, doing this first closes the window where the old looser file is still
	// the one on disk, and covers any platform where rename preserves the
	// destination inode's mode.
	if _, statErr := os.Stat(path); statErr == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("tighten session store perms: %w", err)
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp session store: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we bail before the rename; after a successful rename
	// the temp path no longer exists, so the remove is a harmless no-op.
	defer func() { _ = os.Remove(tmpPath) }()
	// CreateTemp makes the file 0600 already, but chmod explicitly so the mode is
	// not at the mercy of the process umask.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temp session store perms: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp session store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp session store: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil { //nolint:gosec // path is the store's own session file under the user's config dir, not external input
		return fmt.Errorf("write session store: %w", err)
	}
	return nil
}

// pushTokensToKeyring writes each credential's token to the keyring (deleting any
// stale entry for a token-less credential) and returns a copy of the credential
// map with every Token scrubbed, ready to marshal into the metadata file.
func pushTokensToKeyring(store tokenStore, creds map[string]Credential) (map[string]Credential, error) {
	scrubbed := make(map[string]Credential, len(creds))
	for key, cred := range creds {
		if err := pushOneToken(store, key, cred.Token); err != nil {
			return nil, err
		}
		credCopy := cred
		credCopy.Token = "" // scrub before the file is written
		scrubbed[key] = credCopy
	}
	return scrubbed, nil
}

// pushOneToken stores a single credential's token in the keyring. An empty token
// (a workflow-identity marker, or a credential being removed) carries no secret;
// any stale keyring entry is cleared so a token never lingers past its metadata.
func pushOneToken(store tokenStore, key, token string) error {
	if token == "" {
		if err := store.Delete(key); err != nil {
			return fmt.Errorf("keyring delete for %q: %w", key, err)
		}
		return nil
	}
	if err := store.Save(key, token); err != nil {
		return fmt.Errorf("keyring save for %q: %w", key, err)
	}
	return nil
}

// Save writes (or replaces) the credential for its platform URL and makes it the
// active working platform.
func (s *Store) Save(c Credential) error {
	c.PlatformURL = NormalizeURL(c.PlatformURL)
	m, err := s.load()
	if err != nil {
		return err
	}
	m.Credentials[c.PlatformURL] = c
	m.CurrentPlatform = c.PlatformURL
	return s.save(m)
}

// Get returns the stored credential for the platform URL (token overlaid from
// the keyring), or (nil, nil) if none is stored. It applies no expiry/mode
// filtering — that is the resolver's job.
func (s *Store) Get(platformURL string) (*Credential, error) {
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	if c, ok := m.Credentials[NormalizeURL(platformURL)]; ok {
		return &c, nil
	}
	return nil, nil
}

// SetScope updates only the working tenant/product binding on the stored
// credential for platformURL, preserving its token, auth mode, email, and
// expiry. It requires an existing credential. Empty arguments are left
// unchanged, so a caller can rebind product alone or tenant alone.
func (s *Store) SetScope(platformURL, tenantID, tenantName, productID, productName string) error {
	key := NormalizeURL(platformURL)
	m, err := s.load()
	if err != nil {
		return err
	}
	c, ok := m.Credentials[key]
	if !ok {
		return fmt.Errorf("not logged in to %s", key)
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
	m.Credentials[key] = c
	m.CurrentPlatform = key
	return s.save(m)
}

// SetTrustBundleSPKI records the trust-on-first-use pin (the SHA-256 hex of the
// platform's discovery trust_bundle_pem) onto the stored credential for
// platformURL, preserving its token, scope, email, and expiry. It is used by the
// verify discovery-trust adoption (GHSA #5988).
//
// It returns persisted=true only when the pin was actually written. When no
// credential exists for the platform it returns persisted=false with a nil error:
// the pin is UN-PINNABLE for this session and the caller must treat that as a
// hard security stop for silent first-use adoption rather than a benign no-op. A
// non-nil error is a real store I/O failure, not the un-pinnable case.
func (s *Store) SetTrustBundleSPKI(platformURL, spki string) (persisted bool, err error) {
	key := NormalizeURL(platformURL)
	m, err := s.load()
	if err != nil {
		return false, err
	}
	c, ok := m.Credentials[key]
	if !ok {
		return false, nil // nothing to pin onto — un-pinnable
	}
	if c.TrustBundleSPKI == spki {
		return true, nil // already pinned to this value; avoid a needless rewrite
	}
	c.TrustBundleSPKI = spki
	m.Credentials[key] = c
	if err := s.save(m); err != nil {
		return false, err
	}
	return true, nil
}

// forceActivePlatform writes the active-platform pointer to an exact, caller-
// resolved value — including clearing it (empty target). It is the deterministic
// counterpart to the implicit CurrentPlatform stamp Save/SetScope apply: a caller
// that writes several credentials in an arbitrary order (e.g. a legacy-store
// migration) uses it to pin the working platform back to the user's real active
// platform instead of inheriting whichever write happened to land last in Go's
// randomized map order. The caller owns resolving the target deterministically;
// this method just persists it.
func (s *Store) forceActivePlatform(target string) error {
	key := NormalizeURL(target)
	m, err := s.load()
	if err != nil {
		return err
	}
	if m.CurrentPlatform == key {
		return nil // already at the target; avoid a needless rewrite
	}
	m.CurrentPlatform = key
	return s.save(m)
}

// SetActivePlatform is the exported, deterministic active-platform setter for a
// CONSUMING module (e.g. jctl's shared-store bridge) that writes several
// credentials in arbitrary order and must then pin the working platform to the
// user's real current context — not inherit whichever Save landed last in Go's
// randomized map order. An empty target clears the pointer (the caller's current
// context is unknown/absent): the working platform is then left undetermined
// rather than pointing at a random session. It delegates to forceActivePlatform
// so the persistence and clear-on-empty semantics live in one place.
func (s *Store) SetActivePlatform(target string) error { return s.forceActivePlatform(target) }

// ActivePlatformURL returns the platform a bare command should target when no
// platform URL is given: the most recent login/use if it still has a stored
// credential, else the sole stored credential's URL, else "" (callers fall back
// to the compiled default).
func (s *Store) ActivePlatformURL() string {
	m, err := s.load()
	if err != nil {
		return ""
	}
	if m.CurrentPlatform != "" {
		if _, ok := m.Credentials[m.CurrentPlatform]; ok {
			return m.CurrentPlatform
		}
	}
	if len(m.Credentials) == 1 {
		for url := range m.Credentials {
			return url
		}
	}
	return ""
}

// Snapshot returns a copy of every stored credential (token overlaid from the
// keyring, keyed by normalized platform URL) plus the current-platform pointer.
// It is the read-only enumeration a tool needs to present ALL stored sessions —
// e.g. jctl building its named-context view, where a single login per platform
// must surface under each context so `--context <host>` still resolves. The
// returned map is a fresh copy the caller may mutate freely; it does not alias
// the store.
func (s *Store) Snapshot() (creds map[string]Credential, currentPlatform string, err error) {
	m, err := s.load()
	if err != nil {
		return nil, "", err
	}
	out := make(map[string]Credential, len(m.Credentials))
	for k, c := range m.Credentials {
		out[k] = c
	}
	return out, m.CurrentPlatform, nil
}

// Delete removes the credential for a platform URL (and its keyring token).
// Returns whether one existed.
func (s *Store) Delete(platformURL string) (bool, error) {
	key := NormalizeURL(platformURL)
	m, err := s.load()
	if err != nil {
		return false, err
	}
	if _, ok := m.Credentials[key]; !ok {
		return false, nil
	}
	delete(m.Credentials, key)
	if m.CurrentPlatform == key {
		m.CurrentPlatform = "" // don't leave a dangling active platform
	}
	// Drop the keyring entry directly: save scrubs only credentials still in the
	// map, so a removed one's token would otherwise linger in the keyring.
	if keyringAvailable() {
		if derr := selectStore().Delete(key); derr != nil {
			return false, fmt.Errorf("keyring delete for %q: %w", key, derr)
		}
	}
	if err := s.save(m); err != nil {
		return false, err
	}
	return true, nil
}
