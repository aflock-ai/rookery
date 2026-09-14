// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strconv"
)

// Distribution defaults, overridable with -ldflags -X. These never depend on
// login state, platform selection, or runtime environment variables.
var (
	DefaultEvidenceProfile    = "compact"
	DefaultProductInlineBytes = "131072"
)

// EvidenceDefaults validates the compiled profile and product inline budget.
// Zero forces nonempty product inventories off-envelope; legacy retains the
// library constructors' representation. The budget is portable to 32-bit builds.
func EvidenceDefaults() (compact bool, inlineBytes int, err error) {
	switch DefaultEvidenceProfile {
	case "compact", "compact-chain":
		compact = true
	case "legacy":
	default:
		return false, 0, fmt.Errorf("invalid compiled evidence profile %q (want compact, compact-chain, or legacy)", DefaultEvidenceProfile)
	}
	budget, err := strconv.ParseUint(DefaultProductInlineBytes, 10, 31)
	if err != nil {
		return false, 0, fmt.Errorf("invalid compiled product inline byte budget %q: %w", DefaultProductInlineBytes, err)
	}
	return compact, int(budget), nil
}

// EvidenceRetentionDefaults reports build-time consent for chain-producing
// distributions. It does not enable a network destination. Explicit CLI flags
// override these defaults; ordinary compact builds keep both defaults off.
func EvidenceRetentionDefaults() (retainMaterial bool, uploadInventories bool, err error) {
	if _, _, err := EvidenceDefaults(); err != nil {
		return false, false, err
	}
	chain := DefaultEvidenceProfile == "compact-chain"
	return chain, chain, nil
}
