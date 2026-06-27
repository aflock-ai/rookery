// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Token storage abstraction.
//
// Tokens (JWTs) are sensitive credentials. By default they live in the
// OS-native keyring (macOS Keychain, GNOME Keyring / KWallet on Linux via
// secret-service, Windows Credential Manager) through github.com/zalando/go-keyring.
// When the keyring is unavailable (headless Linux without a running
// secret-service daemon, most CI containers, WSL without a keyring helper),
// the store falls back to serializing the token inline in the 0600 metadata
// file. The non-sensitive portion of a credential (URL, tenant metadata,
// expiry, product, the trust pin) always lives in the file, keyring or not.
//
// Set JUDGE_DISABLE_KEYRING=1 to force the file fallback (e.g. in a CI
// container where D-Bus exists but is flaky).
package platformauth

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

// keyringService is the "service" identifier under which platform-session
// tokens are stored in the OS keyring. Per-platform credentials map to
// "account" names under this service (the normalized platform URL).
const keyringService = "judge"

// keyringProbeAccount is a throwaway account name used to decide whether a
// usable keyring backend is present. It is never written to — only Get is
// attempted and the error classified.
const keyringProbeAccount = "__judge_probe__"

// disableEnvVar, when set to "1" / "true", forces the file-based fallback.
const disableEnvVar = "JUDGE_DISABLE_KEYRING"

// keyringDisabled reports whether the env var asks for the file fallback.
func keyringDisabled() bool {
	v := os.Getenv(disableEnvVar)
	return v == "1" || v == "true"
}

// keyringProbeTimeout caps how long the startup probe waits for the OS keyring
// backend to respond. A wedged secret-service daemon (broken GNOME Keyring,
// zombie session bus on Linux) can otherwise hang the CLI on first use. 3s is
// generous for a healthy backend and a short stall for a broken one.
var keyringProbeTimeout = 3 * time.Second

// errKeyringProbeTimeout is the synthetic error recorded when the probe times
// out — treated identically to a real backend error and triggers fallback.
var errKeyringProbeTimeout = errors.New("keyring probe timed out")

// tokenStore is the abstract backend for storing per-platform JWTs. Two
// implementations exist: keyringStore (OS keyring) and fileStore (metadata YAML).
type tokenStore interface {
	Save(account, token string) error
	Load(account string) (string, error)
	Delete(account string) error
}

// keyringStore writes tokens into the OS keyring via go-keyring.
type keyringStore struct{}

func (keyringStore) Save(account, token string) error {
	if account == "" {
		return errors.New("account is required")
	}
	return keyring.Set(keyringService, account, token)
}

func (keyringStore) Load(account string) (string, error) {
	if account == "" {
		return "", errors.New("account is required")
	}
	tok, err := keyring.Get(keyringService, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("keyring get: %w", err)
	}
	return tok, nil
}

func (keyringStore) Delete(account string) error {
	if account == "" {
		return errors.New("account is required")
	}
	err := keyring.Delete(keyringService, account)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keyring delete: %w", err)
	}
	return nil
}

// fileStore is a no-op signalling sentinel: in fallback mode the token stays
// inline in the metadata file, which Store.save/load manage directly. Load is
// never consulted in file mode (the file round-trip is authoritative).
type fileStore struct{}

func (fileStore) Save(string, string) error   { return nil }
func (fileStore) Load(string) (string, error) { return "", nil }
func (fileStore) Delete(string) error         { return nil }

// Global state, initialized once per process. The keyring is probed at first
// use rather than at import time so tests that call keyring.MockInit() before
// touching the store can control the backend.
var (
	storeOnce       sync.Once
	resolvedStore   tokenStore
	usingKeyring    bool
	keyringProbeErr error
	keyringWarned   sync.Once
)

// resetStoreForTest re-arms the once-guarded probe so a test can switch the
// backend (e.g. keyring.MockInit then re-probe). Test-only.
func resetStoreForTest() {
	storeOnce = sync.Once{}
	resolvedStore = nil
	usingKeyring = false
	keyringProbeErr = nil
	keyringWarned = sync.Once{}
}

// selectStore decides which backend to use. Keyring first (unless disabled via
// env), file fallback otherwise. The probe is a Get of a throwaway account:
// ErrNotFound = keyring is reachable and functional, any other error (or a
// timeout) = keyring is not usable on this system.
func selectStore() tokenStore {
	storeOnce.Do(func() {
		if keyringDisabled() {
			resolvedStore = fileStore{}
			usingKeyring = false
			return
		}
		// Probe in a goroutine with a deadline so a wedged secret-service daemon
		// can't hang the CLI; a timeout falls back to file mode automatically
		// rather than requiring users to know about JUDGE_DISABLE_KEYRING.
		probeErrCh := make(chan error, 1)
		go func() {
			_, err := keyring.Get(keyringService, keyringProbeAccount)
			probeErrCh <- err
		}()
		var probeErr error
		select {
		case probeErr = <-probeErrCh:
		case <-time.After(keyringProbeTimeout):
			probeErr = errKeyringProbeTimeout
		}
		if probeErr == nil || errors.Is(probeErr, keyring.ErrNotFound) {
			resolvedStore = keyringStore{}
			usingKeyring = true
			return
		}
		keyringProbeErr = probeErr
		resolvedStore = fileStore{}
		usingKeyring = false
	})
	return resolvedStore
}

// keyringAvailable returns true iff the currently-selected backend is the OS
// keyring. Callers use this for decisions like "should the token be scrubbed
// from the on-disk metadata file?".
func keyringAvailable() bool {
	_ = selectStore()
	return usingKeyring
}

// warnKeyringUnavailableOnce prints a single warning explaining why the store
// fell back to file storage. Called on first store use per process. Does not log
// the token or credential contents.
func warnKeyringUnavailableOnce(filePath string) {
	if keyringAvailable() {
		return
	}
	// Skip the warning if the user explicitly disabled the keyring — they already
	// know.
	if keyringDisabled() {
		return
	}
	keyringWarned.Do(func() {
		msg := "OS keyring is unavailable — storing tokens in " + filePath + " (0600). "
		msg += "Set " + disableEnvVar + "=1 to silence this warning."
		if keyringProbeErr != nil {
			msg += fmt.Sprintf(" (probe error: %v)", keyringProbeErr)
		}
		fmt.Fprintln(os.Stderr, "judge: "+msg)
	})
}
