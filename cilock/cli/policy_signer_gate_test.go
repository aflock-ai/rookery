// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Embedded policy-signer identity must be applied ONLY when the operator set
// NO signer-identity flag. Detection is by cobra Changed (not value), so a flag
// with a non-empty default (--policy-fulcio-oidc-issuer) is correctly treated as
// an explicit pin when set — the follow-on bug Codex flagged on PR #5112 after
// the value-based gate was tried.
func TestSignerIdentityPinnedByFlags(t *testing.T) {
	t.Run("nothing set", func(t *testing.T) {
		assert.False(t, signerIdentityPinnedByFlags(VerifyCmd()))
	})

	// Each signer-identity flag, when explicitly set, must register as a pin —
	// including --policy-fulcio-oidc-issuer (which carries a non-empty default).
	for _, name := range signerIdentityFlags {
		t.Run("set "+name, func(t *testing.T) {
			cmd := VerifyCmd()
			require.NoError(t, cmd.Flags().Set(name, "x"))
			assert.True(t, signerIdentityPinnedByFlags(cmd), "%s set explicitly must count as a signer pin", name)
		})
	}

	// A non-signer flag (CA roots) must NOT count — embedded signer still applies.
	t.Run("only ca-roots set", func(t *testing.T) {
		cmd := VerifyCmd()
		require.NoError(t, cmd.Flags().Set("policy-ca-roots", "root.pem"))
		assert.False(t, signerIdentityPinnedByFlags(cmd))
	})
}
