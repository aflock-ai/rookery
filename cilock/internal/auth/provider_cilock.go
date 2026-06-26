// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

// sourceCilock is the cilockProvider's Name() and the Source it stamps on a
// resolved credential — a display/diagnostic label, never a trust input.
const sourceCilock = "cilock"

// cilockProvider resolves credentials from cilock's OWN store
// (~/.config/cilock/credentials.json). It owns the TrustBundleSPKI pin and so
// declares every capability — it can persist a trust-on-first-use pin, carries
// the identity/scope negotiated at login, enforces the credential's expiry, and
// (for the --token path, via TokenCredential) validated the login audience.
type cilockProvider struct{}

// cilockCapabilities is what the cilock store vouches for. Declared once so the
// per-provider capability set is the single source of truth.
func cilockCapabilities() Capabilities {
	return NewCapabilities(
		CapCanPinTrust,
		CapCarriesIdentity,
		CapEnforcesExpiry,
		CapAudienceValidated,
	)
}

func (cilockProvider) Name() string { return sourceCilock }

// Resolve reads cilock's own store and applies the filtering for mode, mirroring
// the cilock-store branch of the legacy Lookup/LookupAny functions exactly:
//
//   - ForBearer: a stored credential matches only with a non-empty Token and a
//     live expiry (the Lookup contract — callers attach Token as a Bearer).
//   - ForDisplay / IncludingExpired: a stored credential matches when it is not
//     expired, regardless of Token (the LookupAny contract — a token-less
//     workflow-identity marker is a valid display credential).
//
// The IncludingExpired "surface an expired credential as a last resort" behavior
// is NOT done here: it must fall AFTER the jctl provider in precedence (an expired
// cilock entry must never mask a valid jctl fallback), so the top-level
// resolveIncludingExpired applies it once both providers miss.
func (cilockProvider) Resolve(platformURL string, mode ResolveMode) (*Resolved, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	c, ok := s.Credentials[key]
	if !ok {
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
	return &Resolved{Credential: &c, Source: sourceCilock, Capabilities: cilockCapabilities()}, nil
}

// resolveExpiredCilock returns an EXPIRED cilock-store credential for platformURL,
// or (nil, nil) if the store holds none. It is the IncludingExpired last-resort
// fallback the legacy LookupAnyIncludingExpired applies after both a usable cilock
// credential and a jctl fallback miss — surfaced for diagnosis only (`cilock
// doctor`), NEVER for a bearer token. Returning it keeps the cilock capability
// declaration, since the expired credential still came from the cilock store.
func resolveExpiredCilock(platformURL string) (*Resolved, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := s.Credentials[key]; ok {
		return &Resolved{Credential: &c, Source: sourceCilock, Capabilities: cilockCapabilities()}, nil
	}
	return nil, nil
}
