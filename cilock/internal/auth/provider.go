// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import "github.com/aflock-ai/rookery/platformauth"

// The capability seam and session model live in the shared platformauth library
// so cilock and jctl resolve credentials through one model. These aliases keep
// cilock's call sites (`auth.Credential`, `auth.Resolved`, `auth.CapCanPinTrust`,
// `auth.ForBearer`, …) stable while the implementation is shared.

// Capability is a property a credential source declares about the credentials it
// resolves; trust decisions branch on it rather than on the source's name.
type Capability = platformauth.Capability

const (
	// CapCanPinTrust — the source owns a persistent store that can record a
	// trust-on-first-use pin (TrustBundleSPKI) for the platform.
	CapCanPinTrust = platformauth.CapCanPinTrust
	// CapCarriesIdentity — the resolved credential carries an identity binding.
	CapCarriesIdentity = platformauth.CapCarriesIdentity
	// CapEnforcesExpiry — the source enforces the credential's own expiry.
	CapEnforcesExpiry = platformauth.CapEnforcesExpiry
	// CapAudienceValidated — the source validated the token's audience claim.
	CapAudienceValidated = platformauth.CapAudienceValidated
)

// Capabilities is the set of capabilities a source declares (fail-closed: an
// undeclared capability reads as false).
type Capabilities = platformauth.Capabilities

// NewCapabilities builds a capability set from the given capabilities.
func NewCapabilities(caps ...Capability) Capabilities { return platformauth.NewCapabilities(caps...) }

// ResolveMode selects the filtering semantics a resolve uses.
type ResolveMode = platformauth.ResolveMode

const (
	// ForBearer: a stored credential must have a non-empty Token and a live
	// expiry; callers that attach the token as a Bearer use this.
	ForBearer = platformauth.ForBearer
	// ForDisplay: a stored credential must not be expired but may carry an empty
	// Token (a workflow-identity marker). Never use the result for a bearer token.
	ForDisplay = platformauth.ForDisplay
	// IncludingExpired: like ForDisplay, but surfaces an EXPIRED credential as a
	// last resort so diagnostics can tell EXPIRED apart from MISSING.
	IncludingExpired = platformauth.IncludingExpired
)

// Resolved is the outcome of a successful resolve: the credential plus the source
// that vouched for it and the capabilities that source declares.
type Resolved = platformauth.Resolved

// Provider is a credential source.
type Provider = platformauth.Provider

// ErrUnpinnable signals a resolve produced a credential whose source cannot
// persist a trust-on-first-use pin (the jctl gap in GHSA #5988 / #6014).
var ErrUnpinnable = platformauth.ErrUnpinnable

// CapabilityError reports that a required capability was not declared by the
// source that resolved a credential.
type CapabilityError = platformauth.CapabilityError

// Resolve walks the credential sources in precedence order and returns the first
// credential found for platformURL under mode, or (nil, nil) if none holds one.
//
// It routes through the SINGLE useShared() predicate, identical to every mutating
// op, so reads and writes never diverge on which store they consult:
//
//   - useShared() true (flag on AND migration succeeded) → the platformauth
//     keyring-backed store, with the jctl read-through kept as a fallback provider.
//   - useShared() false (flag off, OR migration failed) → the legacy cilock seam
//     (cilock cleartext store first, then the jctl read-through).
//
// Because a migration failure now drops the WHOLE store (read and write) to the
// legacy seam, a Resolve that returns a legacy credential with CapCanPinTrust is
// matched by a SetTrustBundleSPKI that also writes the legacy store — so the pin
// actually persists. A jctl-sourced credential declares nothing either way, so the
// verify trust gate's fail-closed behavior is identical.
func Resolve(platformURL string, mode ResolveMode) (*Resolved, error) {
	if useShared() {
		return resolveShared(platformURL, mode)
	}
	return resolveLegacy(platformURL, mode)
}

// resolveLegacy is the pre-shared-store resolution: the cilock cleartext store
// first, then the jctl read-through, with the IncludingExpired last-resort the
// legacy LookupAnyIncludingExpired applied after both providers miss.
func resolveLegacy(platformURL string, mode ResolveMode) (*Resolved, error) {
	res, err := resolveWith([]Provider{cilockProvider{}, jctlProvider{}}, platformURL, mode)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	if mode == IncludingExpired {
		return resolveExpiredCilock(platformURL)
	}
	return nil, nil
}

// resolveWith walks providers in order, returning the first non-nil resolve. A
// provider's error is propagated immediately (a store I/O failure is not a miss).
func resolveWith(providers []Provider, platformURL string, mode ResolveMode) (*Resolved, error) {
	for _, p := range providers {
		res, err := p.Resolve(platformURL, mode)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return res, nil
		}
	}
	return nil, nil
}
