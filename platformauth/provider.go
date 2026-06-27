// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

// SourceSharedStore is the storeProvider's Name() and the Source it stamps on a
// resolved credential — a display/diagnostic label, never a trust input.
const SourceSharedStore = "judge-session"

// storeProvider resolves credentials from the keyring-backed shared store. It
// owns the TrustBundleSPKI pin and so declares every capability — it can persist
// a trust-on-first-use pin, carries the identity/scope negotiated at login,
// enforces the credential's expiry, and (for the --token path, via
// TokenCredential) validated the login audience.
type storeProvider struct {
	store *Store
}

// storeCapabilities is what the shared store vouches for. Declared once so the
// per-provider capability set is the single source of truth.
func storeCapabilities() Capabilities {
	return NewCapabilities(
		CapCanPinTrust,
		CapCarriesIdentity,
		CapEnforcesExpiry,
		CapAudienceValidated,
	)
}

func (storeProvider) Name() string { return SourceSharedStore }

// Resolve reads the shared store and applies the filtering for mode:
//
//   - ForBearer: a stored credential matches only with a non-empty Token and a
//     live expiry (callers attach Token as a Bearer).
//   - ForDisplay / IncludingExpired: a stored credential matches when it is not
//     expired, regardless of Token (a token-less workflow-identity marker is a
//     valid display credential).
//
// The IncludingExpired "surface an expired credential as a last resort" behavior
// is NOT done here: it must fall AFTER any fallback provider in precedence, so
// the Resolver applies it once every provider misses.
func (p storeProvider) Resolve(platformURL string, mode ResolveMode) (*Resolved, error) {
	c, err := p.store.Get(platformURL)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}
	switch mode {
	case ForBearer:
		if c.Token == "" || c.Expired() {
			return nil, nil
		}
	case ForDisplay, IncludingExpired:
		if c.Expired() {
			return nil, nil
		}
	}
	return &Resolved{Credential: c, Source: SourceSharedStore, Capabilities: storeCapabilities()}, nil
}

// resolveExpired returns an EXPIRED stored credential for platformURL, or
// (nil, nil) if the store holds none. It is the IncludingExpired last-resort
// fallback applied after every provider misses — surfaced for diagnosis only,
// NEVER for a bearer token. It keeps the store's capability declaration, since
// the expired credential still came from the shared store.
func (p storeProvider) resolveExpired(platformURL string) (*Resolved, error) {
	c, err := p.store.Get(platformURL)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}
	return &Resolved{Credential: c, Source: SourceSharedStore, Capabilities: storeCapabilities()}, nil
}

// Resolver walks credential providers in precedence order and returns the first
// match for a platform URL. The shared store is always first; callers may append
// fallback providers (e.g. a read-through of another tool's legacy store) that
// the shared store takes precedence over.
type Resolver struct {
	store     *Store
	fallbacks []Provider
}

// NewResolver builds a resolver over store with the given fallback providers
// (consulted in order, after the shared store). A nil store uses DefaultStore.
func NewResolver(store *Store, fallbacks ...Provider) (*Resolver, error) {
	if store == nil {
		var err error
		store, err = DefaultStore()
		if err != nil {
			return nil, err
		}
	}
	return &Resolver{store: store, fallbacks: fallbacks}, nil
}

// Store returns the resolver's backing shared store, for callers that need to
// Save/SetScope/SetTrustBundleSPKI through the same store the resolve reads.
func (r *Resolver) Store() *Store { return r.store }

// Resolve walks the shared store then the fallback providers and returns the
// first credential found for platformURL under mode, or (nil, nil) if none holds
// one.
//
// IncludingExpired adds one step the provider walk cannot express on its own:
// after the shared store AND every fallback miss, an EXPIRED shared-store
// credential is surfaced as a last resort (the diagnostic behavior callers rely
// on). That fallback runs after every provider so a stale store entry never masks
// a valid fallback session.
func (r *Resolver) Resolve(platformURL string, mode ResolveMode) (*Resolved, error) {
	sp := storeProvider{store: r.store}
	providers := append([]Provider{sp}, r.fallbacks...)
	for _, p := range providers {
		res, err := p.Resolve(platformURL, mode)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return res, nil
		}
	}
	if mode == IncludingExpired {
		return sp.resolveExpired(platformURL)
	}
	return nil, nil
}
