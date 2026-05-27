// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
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

// Drift guard: every registered policy signer-identity flag must appear in
// signerIdentityFlags. The list is maintained by hand and a single omission
// (e.g. --policy-dns-names) silently lets embedded trust overwrite an operator
// pin — the trust-correctness bug class Codex flagged on PR #5112. Trust-source
// flags (policy-ca*, policy-timestamp*) and the deprecated alias are excluded
// because they are NOT signer-identity constraints.
func TestSignerIdentityFlagsCoversAllRegisteredFlags(t *testing.T) {
	notSignerIdentity := map[string]bool{
		"policy-ca":                true, // deprecated alias for policy-ca-roots (trust source)
		"policy-ca-roots":          true, // trust source, not identity
		"policy-ca-intermediates":  true, // trust source, not identity
		"policy-timestamp-servers": true, // trust source, not identity
	}
	known := make(map[string]bool, len(signerIdentityFlags))
	for _, n := range signerIdentityFlags {
		known[n] = true
	}
	VerifyCmd().Flags().VisitAll(func(f *pflag.Flag) {
		if !strings.HasPrefix(f.Name, "policy-") {
			return
		}
		if notSignerIdentity[f.Name] {
			return
		}
		assert.Truef(t, known[f.Name],
			"registered signer-identity flag %q is missing from signerIdentityFlags; "+
				"embedded trust would silently overwrite an operator who pins via this flag alone", f.Name)
	})
}
