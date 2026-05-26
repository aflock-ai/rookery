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

	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
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
	LookupChainSidecar(ctx context.Context, downstreamStep, upstreamStep, upstreamEnvelopeDigest string) (*inclusionproof.ChainSidecar, error)
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
