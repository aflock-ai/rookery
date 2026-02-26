//go:build audit

package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// R3-164 (MEDIUM): compareSemver silently treats non-numeric versions as 0
// =============================================================================
// fmt.Sscanf silently fails on non-numeric version components, leaving the
// parsed value as 0. This means:
//   - compareSemver("abc.def.ghi", "0.0.0") == 0 (equal!)
//   - matchSemver(">=0.0.1", "garbage.version") is false
//     but matchSemver(">=0.0.0", "garbage.version") is TRUE
//
// Impact: An agent with a malformed/unresolvable version string will match
// any >=0.0.0 constraint, potentially bypassing model version restrictions.

func TestSecurity_R3_164_CompareSemverMalformedVersion(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected int
	}{
		{
			name:     "normal comparison",
			a:        "1.2.3",
			b:        "1.2.3",
			expected: 0,
		},
		{
			name:     "greater",
			a:        "2.0.0",
			b:        "1.0.0",
			expected: 1,
		},
		{
			name:     "lesser",
			a:        "1.0.0",
			b:        "2.0.0",
			expected: -1,
		},
		{
			name:     "BUG: garbage version equals 0.0.0",
			a:        "garbage.version.string",
			b:        "0.0.0",
			expected: 0, // BUG: should be an error, but returns equal
		},
		{
			name:     "BUG: empty string equals 0.0.0",
			a:        "",
			b:        "0.0.0",
			expected: 0,
		},
		{
			name:     "BUG: mixed valid/invalid",
			a:        "1.abc.3",
			b:        "1.0.3",
			expected: 0, // BUG: abc parsed as 0
		},
		{
			name:     "negative numbers parsed by Sscanf",
			a:        "-1.0.0",
			b:        "0.0.0",
			expected: -1, // Sscanf parses -1 as -1, not 0
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := compareSemver(tc.a, tc.b)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// R3-164b (MEDIUM): matchSemver constraint bypass with garbage versions
// =============================================================================
// Because compareSemver treats garbage versions as 0.0.0, any policy using
// >=0.0.0 (or similar low constraints) will match garbage versions.

func TestSecurity_R3_164b_MatchSemverConstraintBypass(t *testing.T) {
	// A garbage version should NOT match >=0.0.0, but it does
	assert.True(t, matchSemver(">=0.0.0", "garbage"),
		"BUG: garbage version matches >=0.0.0 because Sscanf treats non-numeric as 0")

	// x wildcard also matches anything
	assert.True(t, matchSemver("x", "anything"))
	assert.True(t, matchSemver("*", "anything"))

	// But legitimate constraints still work
	assert.False(t, matchSemver(">=1.0.0", "garbage"),
		"garbage version doesn't match >=1.0.0 (parsed as 0.0.0)")

	assert.True(t, matchSemver(">=1.0.0", "1.2.3"))
	assert.False(t, matchSemver(">=2.0.0", "1.9.9"))
}

// =============================================================================
// R3-167 (LOW): matchGlob only supports trailing wildcard
// =============================================================================
// Users might expect full glob support but matchGlob only handles:
//   - "*" (match everything)
//   - "prefix*" (prefix match)
//   - exact match
// It does NOT handle *suffix, *infix*, or multi-segment patterns.

func TestSecurity_R3_167_MatchGlobLimitedPatterns(t *testing.T) {
	// Working patterns
	assert.True(t, matchGlob("*", "anything"))
	assert.True(t, matchGlob("claude-*", "claude-opus"))
	assert.True(t, matchGlob("claude-opus", "claude-opus"))

	// Non-working patterns that users might expect to work
	assert.False(t, matchGlob("*opus*", "claude-opus-4"),
		"Infix pattern not supported")
	assert.False(t, matchGlob("*opus", "claude-opus"),
		"Suffix pattern not supported")
	assert.False(t, matchGlob("claude-*-4", "claude-opus-4"),
		"Mid-wildcard not supported")
}

// =============================================================================
// R3-168 (LOW): DeriveIdentity hash ambiguity with pipe separator
// =============================================================================
// The canonical representation uses "|" as a separator between components.
// If any component value contains "|", two different identities could produce
// the same hash (collision).

func TestSecurity_R3_168_DeriveIdentityHashAmbiguity(t *testing.T) {
	// Two different agents whose canonical representations could collide
	// if component values contain the separator "|"
	a1 := &AgentIdentity{
		Model:        "claude-opus|tools:Bash",
		ModelVersion: "4.5.0",
	}

	a2 := &AgentIdentity{
		Model:        "claude-opus",
		ModelVersion: "4.5.0",
		Tools:        []string{"Bash"},
	}

	h1 := a1.DeriveIdentity()
	h2 := a2.DeriveIdentity()

	// If the hashes are equal, we have a collision bug
	if h1 == h2 {
		t.Error("BUG: Two different identities produce the same hash due to pipe separator ambiguity")
	}
	// In practice the format "model:X|tools:Y" vs "model:X|tools:Y" would need
	// the model field to contain "|tools:" to collide, which is unlikely but possible
	// with user-controlled model names.
	t.Logf("Hash 1: %s", h1)
	t.Logf("Hash 2: %s", h2)
}

// =============================================================================
// R3-169 (MEDIUM): parseModelVersion regex ordering can give wrong version
// =============================================================================
// The patterns are tried in order. If a model name happens to end with
// a number that matches a simpler pattern, the more specific pattern is skipped.

func TestSecurity_R3_169_ParseModelVersionEdgeCases(t *testing.T) {
	tests := []struct {
		model   string
		version string
	}{
		{"claude-opus-4-5-20251101", "4.5.20251101"},
		{"claude-opus-4-5", "4.5.0"},
		{"claude-opus-4", "4.0.0"},
		{"claude-opus", "0.0.0"},
		{"", "0.0.0"},
		// Edge case: model name with numbers in it
		{"my-model-v2-test-3-1-20250101", "3.1.20250101"},
		// Edge case: version-like suffix
		{"model-1.2.3", "1.2.3"},
	}

	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			result := parseModelVersion(tc.model)
			assert.Equal(t, tc.version, result, "model=%q", tc.model)
		})
	}
}

// =============================================================================
// R3-170 (LOW): sanitizeSPIFFEPath with empty/special inputs
// =============================================================================

func TestSecurity_R3_170_SanitizeSPIFFEPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"claude-opus", "claude-opus"},
		{"Claude Opus 4.5", "claude-opus-4-5"},
		{"", ""},
		{"!!!@@@", "-"},
		{"a/b/c", "a-b-c"},
		{"../../../etc", "-etc"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitizeSPIFFEPath(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// R3-171 (LOW): Matches with empty allowedModels passes
// =============================================================================

func TestSecurity_R3_171_MatchesEmptyConstraints(t *testing.T) {
	identity := &AgentIdentity{
		Model:        "any-model",
		ModelVersion: "1.0.0",
	}

	// Empty allowed lists should pass (no constraints)
	assert.True(t, identity.Matches(nil, nil))
	assert.True(t, identity.Matches([]string{}, nil))
	assert.True(t, identity.Matches(nil, []string{}))

	// With constraints, must match
	assert.False(t, identity.Matches([]string{"different-model"}, nil))
	assert.True(t, identity.Matches([]string{"any-model"}, nil))
	assert.True(t, identity.Matches([]string{"any-*"}, nil))
}

// =============================================================================
// Concurrent access to DeriveIdentity
// =============================================================================

func TestDeriveIdentity_ConcurrentAccess(t *testing.T) {
	identity := &AgentIdentity{
		Model:        "claude-opus",
		ModelVersion: "4.5.0",
		Tools:        []string{"Bash", "Read", "Write"},
	}

	done := make(chan string, 10)
	for i := 0; i < 10; i++ {
		go func() {
			done <- identity.DeriveIdentity()
		}()
	}

	var hashes []string
	for i := 0; i < 10; i++ {
		hashes = append(hashes, <-done)
	}

	// All hashes should be identical (deterministic)
	for _, h := range hashes {
		assert.Equal(t, hashes[0], h, "DeriveIdentity should be deterministic")
	}
}

// =============================================================================
// MatchesFunctionary with various types
// =============================================================================

func TestMatchesFunctionary_EdgeCases(t *testing.T) {
	identity := &AgentIdentity{
		Model:        "claude-opus",
		ModelVersion: "4.5.0",
	}
	identity.DeriveIdentity()

	// Non-spiffe type always returns false
	assert.False(t, identity.MatchesFunctionary(Functionary{Type: "publickey"}))
	assert.False(t, identity.MatchesFunctionary(Functionary{Type: "keyless"}))
	assert.False(t, identity.MatchesFunctionary(Functionary{Type: "x509"}))
	assert.False(t, identity.MatchesFunctionary(Functionary{Type: ""}))

	// SPIFFE type with no constraints matches everything
	assert.True(t, identity.MatchesFunctionary(Functionary{Type: "spiffe"}))

	// SPIFFE type with model constraint
	assert.True(t, identity.MatchesFunctionary(Functionary{
		Type:            "spiffe",
		ModelConstraint: "claude-*",
	}))
	assert.False(t, identity.MatchesFunctionary(Functionary{
		Type:            "spiffe",
		ModelConstraint: "gpt-*",
	}))
}

// =============================================================================
// MatchesAnyFunctionary with non-matching types
// =============================================================================

func TestSecurity_R3_171b_MatchesAnyFunctionary_NonMatchingTypes(t *testing.T) {
	identity := &AgentIdentity{Model: "test"}
	identity.DeriveIdentity()

	// With non-matching functionary types, should fail
	assert.False(t, identity.MatchesAnyFunctionary([]Functionary{
		{Type: "publickey", PublicKeyID: "abc"},
	}))
	assert.False(t, identity.MatchesAnyFunctionary([]Functionary{
		{Type: "x509", Subject: "CN=test"},
		{Type: "keyless", Issuer: "https://example.com"},
	}))
}
