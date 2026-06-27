// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package platformauth is the shared, single-session login library for the
// tools that authenticate to a Judge platform (cilock, jctl). It owns the
// session/credential model, the capability declaration that trust decisions
// gate on, and a keyring-backed on-disk store: the bearer token lives in the OS
// keyring, only non-secret metadata is written to a 0600 file under the user's
// XDG config dir. Both tools log in once and share that session through this
// library; neither reaches into the other's private files. See DESIGN.md.
package platformauth

import (
	"strings"
	"time"
)

// AuthMode records how a stored credential was obtained, so a status command
// can describe the session and a signing command can tell a real session JWT
// apart from a workflow-identity marker that carries no stored token.
const (
	// AuthModeToken — credential is a directly-supplied --token.
	AuthModeToken = "token"
	// AuthModeBrowser — credential came from the interactive browser-loopback flow.
	AuthModeBrowser = "browser"
	// AuthModeDevice — credential came from the RFC 8628 device-code flow.
	AuthModeDevice = "device"
	// AuthModeWorkflowOIDC — CI workflow identity. No long-lived token is stored;
	// the consumer sources a fresh ambient OIDC token per call.
	AuthModeWorkflowOIDC = "workflow-oidc"
)

// Credential is a stored platform session, keyed by platform URL. It also
// carries the working scope (tenant + product) negotiated during login so a
// tool can bind to the product without re-prompting.
//
// The on-disk JSON tags are the wire format of the metadata file. The Token
// field is intentionally tagged so a fallback (keyring-unavailable) store can
// serialize it inline; in keyring mode the token is scrubbed from the file and
// only ever lives in the OS keyring.
type Credential struct {
	PlatformURL string `json:"platform_url"`
	Token       string `json:"token,omitempty"`
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
	// discovery-served policy-signer trust bundle: the SHA-256 (hex) of the raw
	// trust_bundle_pem first adopted for this platform. On later resolves a
	// changed bundle is refused unless the operator re-pins, so a compromised
	// platform cannot silently swap in an attacker CA as the policy-signature
	// trust anchor (GHSA #5988). Empty until the first discovery-trust adoption;
	// omitted from stores that never pinned (an absent pin means "not yet pinned").
	TrustBundleSPKI string `json:"trust_bundle_spki,omitempty"`
}

// Expired reports whether the credential has a known expiry in the past.
func (c Credential) Expired() bool {
	return !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt)
}

// NormalizeURL trims a trailing slash and surrounding whitespace so lookups are
// stable across the slightly different URLs a user may pass.
func NormalizeURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

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
	// resolves; a source without it is un-pinnable and the verify trust gate must
	// fail closed rather than silently re-adopt whatever bundle the platform serves.
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

// ResolveMode selects the filtering semantics a resolve uses. It exists so
// trust/display/diagnostic callers declare WHAT they need from a credential
// rather than which legacy lookup to call.
type ResolveMode int

const (
	// ForBearer: a stored credential matches only with a non-empty Token and a
	// live expiry; callers that attach the token as a Bearer use this.
	ForBearer ResolveMode = iota
	// ForDisplay: a stored credential must not be expired but MAY carry an empty
	// Token (a workflow-identity marker), so status/display callers can describe a
	// token-less session. Never use the result to obtain a bearer token.
	ForDisplay
	// IncludingExpired: like ForDisplay, but when no usable credential exists an
	// EXPIRED stored credential is surfaced so diagnostic callers can tell EXPIRED
	// apart from MISSING. NEVER use the result to obtain a bearer token.
	IncludingExpired
)

// Resolved is the outcome of a successful resolve: the credential plus the source
// that vouched for it and the capabilities that source declares. Callers read the
// embedded *Credential for the bearer/metadata; trust branches gate on
// Capabilities and read Source only for diagnostics, never as a trust input.
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
// false). Delegates to Capabilities.Has so the safety property lives in one place.
func (r *Resolved) Has(cap Capability) bool {
	return r.Capabilities.Has(cap)
}

// sourceLabels maps a provider's bare Source name to the login-provenance label
// an operator reads in a posture line. A source not listed here renders verbatim.
// This is DISPLAY sugar only; no trust decision reads it.
var sourceLabels = map[string]string{
	// the cilock-store provider's Source — spelled out as a login so the operator
	// reads "cilock-login" (the pinnable session) rather than the bare name.
	"cilock": "cilock-login",
}

// sourceLabel returns the operator-facing label for a source name.
func sourceLabel(source string) string {
	if l, ok := sourceLabels[source]; ok {
		return l
	}
	return source
}

// Posture renders a one-line, human-readable capability summary for the resolved
// session: its Source plus a yes/no for each capability that matters to an
// operator deciding whether a trust decision will go their way. It is
// DISPLAY-ONLY — a status/doctor command prints it so an operator can see WHY one
// session is refused trust-pinning while another is not. No trust decision may
// branch on this string; trust branches gate on Has(cap) directly.
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
	return sourceLabel(r.Source) + " (trust-pinning: " + pin +
		" · expiry-enforced: " + yesNo(r.Capabilities.Has(CapEnforcesExpiry)) +
		" · audience-validated: " + yesNo(r.Capabilities.Has(CapAudienceValidated)) + ")"
}

// Provider is a credential source. Each provider declares its own capabilities
// and resolves a credential for a platform URL under a given mode. Resolve returns
// (nil, nil) when this provider has no credential for the platform — the caller
// then falls through to the next provider in precedence order. A non-nil error is
// a real failure (store I/O), not a miss.
type Provider interface {
	// Name identifies the provider for display/diagnostics. It is NOT a trust
	// input — never branch a trust decision on it.
	Name() string
	// Resolve returns the credential this provider holds for platformURL under
	// mode, or (nil, nil) if it holds none.
	Resolve(platformURL string, mode ResolveMode) (*Resolved, error)
}
