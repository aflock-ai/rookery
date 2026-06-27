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

// legacyCilockStore is the shape of cilock's old cleartext credential file
// (~/.config/cilock/credentials.json): a token-bearing 0600 JSON map keyed by
// normalized platform URL, plus the active-platform pointer. Reading it is the
// one-time bridge that lets a logged-in cilock user keep their session after the
// shared keyring store takes over — with no re-login.
type legacyCilockStore struct {
	Credentials     map[string]Credential `json:"credentials"`
	CurrentPlatform string                `json:"current_platform,omitempty"`
}

// legacyCilockPath returns the path to cilock's old credential file under the
// XDG config dir, honoring $XDG_CONFIG_HOME (matching how cilock wrote it via
// os.UserConfigDir).
func legacyCilockPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "cilock", "credentials.json"), nil
}

// MigrateLegacyCilock imports any sessions from cilock's old cleartext store
// into the shared keyring store, exactly once. It is idempotent and transparent:
//
//   - A platform already present in the shared store is left untouched (the
//     shared store is authoritative once written), so a re-run never clobbers a
//     fresh login with a stale legacy one.
//   - Each remaining legacy credential is written through Store.Save, which
//     pushes the token to the keyring and writes only metadata to disk. The
//     user's session keeps working without a re-login.
//   - The migration is fail-atomic and retryable. A credential is recorded in the
//     local map ONLY AFTER its Save succeeds (persist-then-record), so a Save that
//     fails partway never leaves a phantom (unsaved) credential behind — and in
//     particular never lets one drive the active-platform restore below. A failing
//     Save is skipped (logged) rather than aborting the whole migration, so the
//     remaining sessions still migrate; the collected error is returned so the
//     caller leaves its one-shot guard UNSET and the next launch retries the
//     skipped credentials. The token is never dropped: the legacy file stays in
//     place for the retry.
//
// It returns the number of credentials successfully migrated. A missing legacy
// file is not an error (nothing to migrate). The legacy file is NOT deleted here —
// leaving it in place keeps the migration safely re-runnable and reversible (a
// flag flip back to the legacy store still finds it); a later cleanup phase, gated
// on a clean migration, removes it.
func MigrateLegacyCilock(store *Store) (int, error) {
	path, err := legacyCilockPath()
	if err != nil {
		return 0, err
	}
	legacy, err := readLegacyCilock(path)
	if err != nil {
		return 0, err
	}
	if legacy == nil || len(legacy.Credentials) == 0 {
		return 0, nil
	}

	m, err := store.load()
	if err != nil {
		return 0, err
	}
	// The active platform that should survive the migration, resolved before any
	// Save side-effect can overwrite it. Default to the platform that was active
	// before the migration (empty for a fresh store); upgrade to the legacy
	// pointer below once we confirm its credential is actually persisted.
	desiredActive := m.CurrentPlatform

	// saved tracks the set of platform keys that ARE present in the store after
	// this pass: the ones already owned by the shared store, plus the ones whose
	// Save succeeded just now. A credential whose Save failed is deliberately
	// absent, so it can neither be reported as migrated nor selected as active.
	saved := make(map[string]bool, len(m.Credentials))
	for key := range m.Credentials {
		saved[key] = true
	}

	migrated := 0
	var saveErrs []error
	for url, cred := range legacy.Credentials {
		key := NormalizeURL(url)
		if saved[key] {
			continue // shared store already owns this platform — do not overwrite
		}
		cred.PlatformURL = key
		// Persist-then-record: only after Save durably writes the credential do we
		// treat it as present. On failure, skip-and-continue (and remember the error
		// so the caller retries) — never record an unsaved phantom.
		if err := store.Save(cred); err != nil {
			saveErrs = append(saveErrs, fmt.Errorf("migrate cilock session for %q: %w", key, err))
			continue
		}
		saved[key] = true
		migrated++
	}

	// Prefer the user's real legacy active platform, but only if its credential is
	// actually persisted in the store (migrated now or already owned). A phantom
	// from a failed Save is not in `saved`, so it can never be chosen. An empty or
	// dangling legacy pointer leaves desiredActive as the pre-migration value.
	if legacyActive := NormalizeURL(legacy.CurrentPlatform); legacyActive != "" {
		if saved[legacyActive] {
			desiredActive = legacyActive
		}
	}

	// Pin the active platform deterministically. Save stamps CurrentPlatform on
	// every write, so after the loop it would otherwise be whichever credential
	// iterated LAST in Go's randomized map order — nondeterministic and usually
	// wrong. forceActivePlatform overrides that with the resolved target (clearing
	// it when desiredActive is empty), so a bare run/sign/verify/trust targets the
	// right platform after the cutover.
	if err := store.forceActivePlatform(desiredActive); err != nil {
		saveErrs = append(saveErrs, fmt.Errorf("restore active platform %q after cilock migration: %w", desiredActive, err))
	}
	if len(saveErrs) > 0 {
		// Surface the failure so the caller leaves its one-shot guard unset and the
		// next launch retries the skipped credentials. The successfully-migrated
		// count is still returned.
		return migrated, errors.Join(saveErrs...)
	}
	return migrated, nil
}

// readLegacyCilock reads and parses cilock's old credential file. A missing file
// yields (nil, nil) — nothing to migrate.
func readLegacyCilock(path string) (*legacyCilockStore, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is under the user's own config dir
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read legacy cilock store: %w", err)
	}
	var s legacyCilockStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse legacy cilock store %s: %w", path, err)
	}
	if s.Credentials == nil {
		s.Credentials = map[string]Credential{}
	}
	return &s, nil
}
