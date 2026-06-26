// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

// sourceJctl is the jctlProvider's Name() and the Source it stamps on a resolved
// credential — a display/diagnostic label, never a trust input.
const sourceJctl = "jctl"

// jctlProvider resolves credentials by reading jctl's session
// (~/.jctl/config.yaml + the OS keychain) so a prior `jctl login` works for cilock
// too. It declares NO capabilities: a jctl credential cannot carry cilock's
// trust-on-first-use pin (no cilock store entry to write onto — the GHSA #5988 /
// #6014 gap), cilock did not validate its audience, and it carries no
// cilock-vouched identity binding or expiry enforcement. The empty declaration is
// the fail-closed seam Phase 2 relies on: a trust branch gating on a capability
// will refuse a jctl credential by construction, with no source-string compare.
type jctlProvider struct{}

// jctlCapabilities is empty by design — see the type doc. Kept as a named
// function so the "jctl declares nothing" decision is explicit and testable.
func jctlCapabilities() Capabilities { return NewCapabilities() }

func (jctlProvider) Name() string { return sourceJctl }

// Resolve performs the jctl read-through (lookupJctl). It is mode-independent,
// exactly as the legacy Lookup/LookupAny/LookupAnyIncludingExpired all delegated
// to the same lookupJctl with no per-mode filtering on the jctl branch.
func (jctlProvider) Resolve(platformURL string, _ ResolveMode) (*Resolved, error) {
	key := NormalizeURL(platformURL)
	if c, ok := lookupJctl(key); ok {
		return &Resolved{Credential: c, Source: sourceJctl, Capabilities: jctlCapabilities()}, nil
	}
	return nil, nil
}
