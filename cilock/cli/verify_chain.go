// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// buildChainSidecarSource translates the verify CLI's chain-sidecar
// flags (--chain-sidecar-dir, --chain-sidecar-url) into a
// policy.ChainSidecarSource. Returns nil when neither flag is set —
// the policy verifier then falls back to the legacy path-by-path
// artifact comparison, preserving back-compat for v0.1 attestations.
//
// When both flags are set, the filesystem source is tried first and
// HTTP is the fallback (offline-friendly default).
func buildChainSidecarSource(vo options.VerifyOptions) policy.ChainSidecarSource {
	var sources []policy.ChainSidecarSource
	if vo.ChainSidecarDir != "" {
		sources = append(sources, policy.NewFilesystemChainSidecarSource(vo.ChainSidecarDir))
	}
	if vo.ChainSidecarURL != "" {
		sources = append(sources, policy.NewHTTPChainSidecarSourceWithOptions(
			vo.ChainSidecarURL,
			vo.ChainSidecarHTTPTimeout,
			vo.ChainSidecarHTTPMaxBytes,
		))
	}
	switch len(sources) {
	case 0:
		return nil
	case 1:
		return sources[0]
	default:
		return policy.NewMultiChainSidecarSource(sources...)
	}
}
