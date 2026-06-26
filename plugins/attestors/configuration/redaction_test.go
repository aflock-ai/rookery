package configuration

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttest_RedactsSensitiveFlagValues guards the secret-leak fix: the
// configuration attestor records the CLI flags that drove a run and signs them
// into evidence shipped to Archivista + CI artifacts. Flags whose VALUE is a
// credential (auth headers, tokens, passwords/passphrases) must be redacted
// before they enter the signed predicate; the flag NAME is kept (useful, not
// sensitive). Values below are obviously-fake placeholders (real-looking tokens
// trip secret-scanning push protection).
func TestAttest_RedactsSensitiveFlagValues(t *testing.T) {
	a := New(WithCustomArgs([]string{
		"cilock", "run",
		"--archivista-headers", "FAKE-auth-header-value-001",
		"--signer-fulcio-token=FAKE-token-value-002",
		"--password", "FAKE-pass-value-003",
		"--step", "build", // non-sensitive value must survive verbatim
		"--trace", // boolean flag must survive
	}))

	require.NoError(t, a.Attest(&attestation.AttestationContext{}))

	// Non-sensitive flags are untouched.
	assert.Equal(t, "build", a.Flags["step"])
	assert.Equal(t, "true", a.Flags["trace"])

	secrets := map[string]string{
		"archivista-headers":  "FAKE-auth-header-value-001",
		"signer-fulcio-token": "FAKE-token-value-002",
		"password":            "FAKE-pass-value-003",
	}
	for name, secret := range secrets {
		val, ok := a.Flags[name]
		assert.True(t, ok, "sensitive flag %q should still be recorded (name is not secret)", name)
		assert.NotContains(t, val, secret, "flag %q value must not contain the raw secret", name)
		assert.Equal(t, redactedFlagValue, val, "flag %q value should be redacted", name)
	}
}

// TestAttest_RedactsSensitiveFlagValuesStartingWithDash guards the dash-value
// redaction bypass: a sensitive flag whose VALUE begins with "-" must still be
// redacted. Without consuming the next token for a sensitive flag, parseFlags
// would treat e.g. "--password" as boolean and then record the secret
// ("-secretvalue123" → "secretvalue123" after trimming dashes) as its OWN flag
// NAME with value "true" — leaking the credential into the signed predicate as
// a key, which name-only redaction never inspects.
func TestAttest_RedactsSensitiveFlagValuesStartingWithDash(t *testing.T) {
	a := New(WithCustomArgs([]string{
		"cilock", "run",
		"--password", "-secretvalue123",
		"--archivista-headers", "-Authorization:xyz",
		"--step", "build", // non-sensitive value must survive verbatim
		"--trace", // boolean flag must survive
	}))

	require.NoError(t, a.Attest(&attestation.AttestationContext{}))

	// The secret must NEVER appear as a flag-name key.
	_, leakedPassword := a.Flags["secretvalue123"]
	assert.False(t, leakedPassword, "secret value must not be recorded as a flag name")
	_, leakedHeader := a.Flags["Authorization:xyz"]
	assert.False(t, leakedHeader, "secret header must not be recorded as a flag name")

	// The sensitive flags keep their name (provenance) with a redacted value.
	assert.Equal(t, redactedFlagValue, a.Flags["password"], "password value must be redacted, not boolean")
	assert.Equal(t, redactedFlagValue, a.Flags["archivista-headers"], "header value must be redacted, not boolean")

	// And the secret must not leak verbatim anywhere in the predicate.
	for name, val := range a.Flags {
		assert.NotContains(t, name, "secretvalue123", "no flag name may contain the password secret")
		assert.NotContains(t, val, "secretvalue123", "no flag value may contain the password secret")
		assert.NotContains(t, name, "Authorization:xyz", "no flag name may contain the header secret")
		assert.NotContains(t, val, "Authorization:xyz", "no flag value may contain the header secret")
	}

	// Non-sensitive flags are untouched (no regression).
	assert.Equal(t, "build", a.Flags["step"])
	assert.Equal(t, "true", a.Flags["trace"])
}

// TestAttest_RedactionEdgeShapes is the re-red-team: it exercises the other
// value-shapes that could defeat redaction.
func TestAttest_RedactionEdgeShapes(t *testing.T) {
	t.Run("equals form with dash value", func(t *testing.T) {
		a := New(WithCustomArgs([]string{
			"cilock", "run", "--signer-fulcio-token=-dashvalue",
		}))
		require.NoError(t, a.Attest(&attestation.AttestationContext{}))
		assert.Equal(t, redactedFlagValue, a.Flags["signer-fulcio-token"])
		assertNoSecretAnywhere(t, a.Flags, "-dashvalue")
		assertNoSecretAnywhere(t, a.Flags, "dashvalue")
	})

	// Ambiguous: a sensitive flag followed by what looks like another flag.
	// Chosen behavior: the sensitive flag consumes and redacts the following
	// token unconditionally (safe direction — the value could legitimately be a
	// credential that starts with "-"). Consequence: the following token is NOT
	// separately recorded as its own flag. We bias toward never leaking over
	// preserving provenance of an ambiguous neighbor.
	t.Run("sensitive flag followed by another flag", func(t *testing.T) {
		a := New(WithCustomArgs([]string{
			"cilock", "run", "--password", "--next-real-flag", "--trace",
		}))
		require.NoError(t, a.Attest(&attestation.AttestationContext{}))
		assert.Equal(t, redactedFlagValue, a.Flags["password"], "password value redacted")
		_, recordedNext := a.Flags["next-real-flag"]
		assert.False(t, recordedNext, "consumed-as-value token is not separately recorded (documented tradeoff)")
		assert.Equal(t, "true", a.Flags["trace"], "subsequent boolean flag still parses")
	})

	t.Run("repeated sensitive flag values", func(t *testing.T) {
		a := New(WithCustomArgs([]string{
			"cilock", "run",
			"--archivista-headers", "-Authorization:aaa",
			"--archivista-headers", "Bearer:bbb",
		}))
		require.NoError(t, a.Attest(&attestation.AttestationContext{}))
		assert.Equal(t, redactedFlagValue, a.Flags["archivista-headers"])
		assertNoSecretAnywhere(t, a.Flags, "Authorization:aaa")
		assertNoSecretAnywhere(t, a.Flags, "Bearer:bbb")
	})

	t.Run("sensitive flag at end of argv with dash value", func(t *testing.T) {
		a := New(WithCustomArgs([]string{
			"cilock", "run", "--token", "-trailingsecret",
		}))
		require.NoError(t, a.Attest(&attestation.AttestationContext{}))
		assert.Equal(t, redactedFlagValue, a.Flags["token"])
		assertNoSecretAnywhere(t, a.Flags, "trailingsecret")
	})

	t.Run("sensitive boolean flag at very end has no value to leak", func(t *testing.T) {
		a := New(WithCustomArgs([]string{
			"cilock", "run", "--password",
		}))
		require.NoError(t, a.Attest(&attestation.AttestationContext{}))
		// No following token: recorded as boolean. No secret exists to leak.
		assert.Equal(t, "true", a.Flags["password"])
	})
}

// assertNoSecretAnywhere fails if secret appears in any flag name or value.
func assertNoSecretAnywhere(t *testing.T, flags map[string]string, secret string) {
	t.Helper()
	for name, val := range flags {
		assert.NotContains(t, name, secret, "secret %q must not appear as a flag name", secret)
		assert.NotContains(t, val, secret, "secret %q must not appear as a flag value", secret)
	}
}
