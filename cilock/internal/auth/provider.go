// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import "errors"

// Capability is a property a credential source DECLARES about the credentials it
// resolves. Trust decisions branch on a declared capability rather than on the
// source's name, so a new source that cannot satisfy a property is fail-closed by
// construction (it simply does not declare the capability) instead of relying on
// a string compare a future source could accidentally pass.
type Capability string

const (
	// CapCanPinTrust — the source owns a persistent store that can record a
	// trust-on-first-use pin (TrustBundleSPKI) for the platform. Only a source
	// that declares this can carry the GHSA #5988 trust-swap protection across
	// resolves; a source without it is un-pinnable and Phase 2 must fail closed
	// rather than silently re-adopt whatever bundle the platform serves.
	CapCanPinTrust Capability = "can-pin-trust"
	// CapCarriesIdentity — the resolved credential carries an identity binding
	// (email / tenant) the source vouches for.
	CapCarriesIdentity Capability = "carries-identity"
	// CapEnforcesExpiry — the source enforces the credential's own expiry (an
	// expired credential is filtered out by the source itself).
	CapEnforcesExpiry Capability = "enforces-expiry"
	// CapAudienceValidated — the source validated the token's audience claim
	// before vouching for it as a login session.
	CapAudienceValidated Capability = "audience-validated"
)

// Capabilities is the set of capabilities a source declares. The zero value (and
// a nil set) declares NOTHING: Has reports false for every capability that was
// not explicitly added. This is the core safety property — an undeclared or
// unknown capability is always false, so a trust branch that gates on Has can
// only proceed when a source affirmatively vouched for the property.
type Capabilities map[Capability]struct{}

// NewCapabilities builds a capability set from the given capabilities.
func NewCapabilities(caps ...Capability) Capabilities {
	set := make(Capabilities, len(caps))
	for _, c := range caps {
		set[c] = struct{}{}
	}
	return set
}

// Has reports whether the capability was explicitly declared. A nil or empty set,
// or any capability not added, returns false (fail-closed by construction).
func (c Capabilities) Has(cap Capability) bool {
	if c == nil {
		return false
	}
	_, ok := c[cap]
	return ok
}

// ResolveMode selects the filtering semantics a resolve uses, mirroring the
// existing Lookup variants exactly. It exists so trust/display/diagnostic callers
// declare WHAT they need from a credential rather than which legacy function to
// call.
type ResolveMode int

const (
	// ForBearer mirrors Lookup: a cilock-store credential must have a non-empty
	// Token and not be expired; otherwise the jctl fallback is tried. Callers that
	// attach the token as a Bearer use this.
	ForBearer ResolveMode = iota
	// ForDisplay mirrors LookupAny: a cilock-store credential must not be expired
	// but MAY carry an empty Token (a workflow-identity marker), so status/display
	// callers (`cilock whoami`) can describe a token-less session. Never use the
	// result to obtain a bearer token.
	ForDisplay
	// IncludingExpired mirrors LookupAnyIncludingExpired: like ForDisplay, but when
	// neither a usable cilock credential nor a jctl fallback exists, an EXPIRED
	// cilock credential is surfaced so diagnostic callers (`cilock doctor`) can tell
	// EXPIRED apart from MISSING. NEVER use the result to obtain a bearer token.
	IncludingExpired
)

// Resolved is the outcome of a successful resolve: the credential plus the source
// that vouched for it and the capabilities that source declares. Phase 1 callers
// read only the embedded *Credential (through the shims); Phase 2 branches trust
// on Capabilities and reads Source only for diagnostics, never as a trust input.
type Resolved struct {
	*Credential
	// Source is the provider Name() that resolved this credential — for display
	// and diagnostics ONLY. Trust decisions MUST branch on Capabilities, never on
	// this string.
	Source string
	// Capabilities is what Source declares about the resolved credential.
	Capabilities Capabilities
}

// Has reports whether the resolving source declared cap. It is the trust-branch
// entry point: a gate writes resolved.Has(CapCanPinTrust) and is fail-closed by
// construction for any source that did not declare it (a nil/empty set returns
// false). Delegates to Capabilities.Has so the safety property lives in one
// place.
func (r *Resolved) Has(cap Capability) bool {
	return r.Capabilities.Has(cap)
}

// Posture renders a one-line, human-readable capability summary for the resolved
// session: its Source plus a yes/no for each capability that matters to an
// operator deciding whether a trust decision will go their way. It is
// DISPLAY-ONLY — whoami/doctor print it so an operator can see WHY a jctl
// session is refused trust-pinning while a cilock-login session is not. No trust
// decision may branch on this string; trust branches gate on Has(cap) directly.
//
// Example (cilock-login):
//
//	cilock-login (trust-pinning: available · expiry-enforced: yes · audience-validated: yes)
//
// Example (jctl):
//
//	jctl (trust-pinning: unavailable · expiry-enforced: no · audience-validated: no)
func (r *Resolved) Posture() string {
	yesNo := func(ok bool) string {
		if ok {
			return "yes"
		}
		return "no"
	}
	// trust-pinning reads available/unavailable rather than yes/no because it
	// describes a CAPABILITY of the session (can it pin at all), not a fact about
	// a single credential — this is the property the GHSA #5988 gate keys on.
	pin := "unavailable"
	if r.Capabilities.Has(CapCanPinTrust) {
		pin = "available"
	}
	source := r.Source
	if source == sourceCilock {
		// Spell out the login provenance so the operator reads "cilock-login"
		// (the pinnable session) rather than the bare provider name.
		source = "cilock-login"
	}
	return source + " (trust-pinning: " + pin +
		" · expiry-enforced: " + yesNo(r.Capabilities.Has(CapEnforcesExpiry)) +
		" · audience-validated: " + yesNo(r.Capabilities.Has(CapAudienceValidated)) + ")"
}

// Provider is a credential source. Each provider declares its own capabilities
// and resolves a credential for a platform URL under a given mode. Resolve returns
// (nil, nil) when this provider has no credential for the platform — the caller
// then falls through to the next provider in precedence order.
type Provider interface {
	// Name identifies the provider for display/diagnostics. It is NOT a trust
	// input — never branch a trust decision on it.
	Name() string
	// Resolve returns the credential this provider holds for platformURL under
	// mode, or (nil, nil) if it holds none. A non-nil error is a real failure
	// (store I/O), not a miss.
	Resolve(platformURL string, mode ResolveMode) (*Resolved, error)
}

// Phase 2 error values. Defined now so the seam's contract is complete; Phase 1
// does not return them (the shims preserve today's nil-on-miss behavior).
var (
	// ErrUnpinnable signals a resolve produced a credential whose source cannot
	// persist a trust-on-first-use pin (does not declare CapCanPinTrust). Phase 2's
	// discovery-trust adoption uses it to fail closed instead of silently
	// re-adopting an un-pinned bundle (the jctl gap in GHSA #5988 / #6014).
	ErrUnpinnable = errors.New("credential source cannot pin trust (un-pinnable session)")
)

// CapabilityError reports that a required capability was not declared by the
// source that resolved a credential. Phase 2 returns it when a trust branch
// demands a capability the resolved source lacks.
type CapabilityError struct {
	Source string
	Want   Capability
}

func (e *CapabilityError) Error() string {
	return "credential from source " + e.Source + " does not declare required capability " + string(e.Want)
}

// defaultProviders is the credential-source precedence the legacy Lookup* path
// uses: cilock's own store first, then the jctl read-through. resolveWith walks
// them in order and returns the first match, preserving today's precedence
// exactly.
func defaultProviders() []Provider {
	return []Provider{cilockProvider{}, jctlProvider{}}
}

// Resolve walks the default providers in precedence order and returns the first
// credential found for platformURL under mode, or (nil, nil) if none holds one.
//
// IncludingExpired adds one legacy step the provider walk cannot express on its
// own: after BOTH a usable cilock credential and a jctl fallback miss, an EXPIRED
// cilock-store credential is surfaced as a last resort (the diagnostic behavior of
// LookupAnyIncludingExpired). That fallback MUST run after the jctl provider so a
// stale cilock entry never masks a valid jctl session — exactly the ordering the
// legacy function encoded inline.
func Resolve(platformURL string, mode ResolveMode) (*Resolved, error) {
	res, err := resolveWith(defaultProviders(), platformURL, mode)
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
