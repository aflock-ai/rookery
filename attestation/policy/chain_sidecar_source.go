// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"context"

	"github.com/aflock-ai/rookery/attestation/chain"
)

// ChainSidecarSource is the pluggable lookup the policy verifier uses
// to fetch a step's chain-of-custody sidecar when one is available.
//
// A chain sidecar binds (downstream step → upstream step) via per-
// material RFC 6962 inclusion proofs against the upstream step's
// signed Merkle root. Without a sidecar source the policy verifier
// falls back to today's path-by-path artifact comparison, which works
// only when the v0.3 attestor's Materials() map was populated in-
// process (single-invocation chains).
//
// Real sources we expect:
//
//   - filesystem: look for "<step-collection>.chain.json" next to the
//     envelope on disk. Air-gapped / offline-friendly.
//   - Archivista: query by envelope digest. Online-friendly, matches
//     existing inclusion-proof attestor flow.
//   - in-memory: testing fixture.
//
// Implementations MUST return (nil, nil) — no error, no sidecar —
// when the step has no chain sidecar. The verifier interprets that
// as "fall back to legacy comparison." Returning a non-nil sidecar
// commits to chain-proof verification semantics; returning an error
// fails the step.
type ChainSidecarSource interface {
	// LookupChainSidecar returns the chain sidecar that downstreamStep
	// published claiming to chain from upstreamStep. Both step names
	// are taken from the policy DAG. The envelopeDigest argument is
	// the upstream step's signed-payload SHA-256 (lowercase hex), used
	// to bind the sidecar to a specific signed attestation rather
	// than just to any tree that happens to share the same Merkle
	// root.
	LookupChainSidecar(ctx context.Context, downstreamStep, upstreamStep, upstreamEnvelopeDigest string) (*chain.ChainSidecar, error)
}

// WithChainSidecarSource installs a ChainSidecarSource on the verify
// options. When set, the verifier will prefer chain-proof verification
// (via VerifyChainSidecar) over the legacy path-by-path comparison
// whenever the source returns a non-nil sidecar.
//
// When NOT set (default), behavior is unchanged: the legacy
// compareArtifacts path runs for every Step.ArtifactsFrom relationship.
// This preserves byte-identical verification semantics for existing
// callers.
func WithChainSidecarSource(src ChainSidecarSource) VerifyOption {
	return func(vo *verifyOptions) {
		vo.chainSidecarSource = src
	}
}

// WithRequireSidecar enables (or disables) strict-chain mode. In
// strict mode, any step whose policy declares ArtifactsFrom MUST
// have a chain sidecar available (via the installed
// ChainSidecarSource) for every upstream edge. Edges without a
// sidecar fail closed instead of falling through to legacy
// compareArtifacts.
//
// Closes the v0.3 vacuous-pass attack surface — without strict
// mode, an attacker can omit the chain sidecar entirely and the
// verifier silently accepts the chain via legacy comparison, which
// trivially passes because v0.3 attestations return empty
// Materials() by design (data lives off-envelope in the sidecar).
//
// In-process default (Go-level): strict mode is OFF unless this
// option is applied. The CLI layer (cilock verify) defaults the
// flag to TRUE in v0.4+, so end users get fail-closed semantics
// by default; the Go default stays permissive to avoid silently
// breaking direct callers that haven't yet updated.
//
// Use `WithRequireSidecar(false)` only when verifying legacy v0.1
// chains for back-compat.
func WithRequireSidecar(require bool) VerifyOption {
	return func(vo *verifyOptions) {
		vo.requireSidecar = require
	}
}
