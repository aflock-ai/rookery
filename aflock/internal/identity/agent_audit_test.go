//go:build audit

// Security audit tests for aflock agent identity.
package identity

import (
	"testing"
)

// BUG-IDENTITY-1: DeriveIdentity uses pipe (|) as separator between components.
// If a component value contains |, it could cause collision with another identity.
// Example: model="a|binary:evil" would produce "model:a|binary:evil|binary:real@1.0"
// which splits as components [model:a, binary:evil, binary:real@1.0].
// This is an identity collision / second-preimage attack.
func TestDeriveIdentity_SeparatorInjection(t *testing.T) {
	// Identity A: model contains pipe character
	identityA := &AgentIdentity{
		Model:        "a|binary:evil@9.9",
		ModelVersion: "1.0.0",
		Tools:        []string{"Read"},
	}

	// Identity B: different model but same canonical representation after split
	identityB := &AgentIdentity{
		Model:        "a",
		ModelVersion: "1.0.0",
		Binary: &BinaryIdentity{
			Name:    "evil",
			Version: "9.9",
		},
		Tools: []string{"Read"},
	}

	hashA := identityA.DeriveIdentity()
	hashB := identityB.DeriveIdentity()

	if hashA == hashB {
		t.Fatal("BUG-IDENTITY-1 CRITICAL: Identity hash collision via separator injection!")
		// This would allow an attacker to forge an identity by embedding pipe characters
	}
	t.Logf("Identity A hash: %s", hashA[:16])
	t.Logf("Identity B hash: %s", hashB[:16])
	t.Log("Hashes differ (good), but the canonical format is still fragile - components should be length-prefixed or use a structured serialization format")
}

// BUG-IDENTITY-2: DeriveIdentity does not include SessionID.
// Two different sessions with the same model/binary/tools/policy produce
// the same identity hash. This means session-specific identity binding is not enforced.
func TestDeriveIdentity_SessionIDNotIncluded(t *testing.T) {
	identity1 := &AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
		SessionID:    "session-111",
		Tools:        []string{"Read"},
	}

	identity2 := &AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
		SessionID:    "session-222",
		Tools:        []string{"Read"},
	}

	hash1 := identity1.DeriveIdentity()
	hash2 := identity2.DeriveIdentity()

	if hash1 == hash2 {
		t.Log("BUG-IDENTITY-2 confirmed: Different sessions produce the same identity hash")
		t.Log("SessionID is stored but not included in DeriveIdentity()")
		t.Log("This means identity hash cannot be used to bind to a specific session")
	}
}

// BUG-IDENTITY-3: String() panics if IdentityHash is empty AND DeriveIdentity
// produces an empty hash. Actually DeriveIdentity always produces a 64-char hex string,
// but String() does IdentityHash[:16] which panics if len < 16.
// DeriveIdentity is called first if hash is empty, so this should be safe.
// But what if DeriveIdentity is overridden or the hash is set to a short string manually?
func TestString_ShortIdentityHash(t *testing.T) {
	identity := &AgentIdentity{
		Model:        "test",
		ModelVersion: "1.0.0",
		IdentityHash: "abc", // Short hash set manually
	}

	defer func() {
		if r := recover(); r != nil {
			t.Logf("BUG-IDENTITY-3 confirmed: String() panics on short IdentityHash: %v", r)
		}
	}()

	// String() checks if IdentityHash is empty; if not empty, it does [:16] directly
	// So a non-empty but short hash will panic with slice out of bounds
	s := identity.String()
	t.Logf("String() = %s (did not panic - hash was recalculated)", s)
}

// BUG-IDENTITY-4: parseModelVersion uses fmt.Sscanf which silently fails
// on non-numeric input. A malicious model name could bypass version checks.
func TestParseModelVersion_MaliciousInput(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		// Normal cases
		{"claude-opus-4-5-20251101", "4.5.20251101"},
		{"claude-opus-4-5", "4.5.0"},
		{"claude-opus-4", "4.0.0"},
		// Edge cases
		{"", "0.0.0"},
		{"no-numbers-here", "0.0.0"},
		// Potentially dangerous: very large numbers - regex captures last match
		// The 8-digit pattern (\d+)-(\d+)-(\d{8}) requires exactly 8 digits in the third group
		// so the 14-digit third group doesn't match that pattern.
		// The (\d+)-(\d+)$ pattern matches the last two groups.
		{"model-99999999999999-99999999999999-99999999999999", "99999999999999.99999999999999.0"},
		// Multiple version-like patterns (should match last one due to regex $)
		{"claude-4-5-20251101-beta-1-2", "1.2.0"},
	}

	for _, tc := range testCases {
		result := parseModelVersion(tc.input)
		if result != tc.expected {
			t.Errorf("parseModelVersion(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

// BUG-IDENTITY-5: compareSemver uses fmt.Sscanf to parse version numbers.
// Sscanf returns the number of items scanned but the return value is ignored.
// If a version component is not a number (e.g., "1.x.0"), Sscanf fails silently
// and aval/bval remain 0, making "1.x.0" equivalent to "1.0.0".
func TestCompareSemver_NonNumericComponents(t *testing.T) {
	// "1.x.0" should not equal "1.0.0" but Sscanf fails silently on "x"
	result := compareSemver("1.x.0", "1.0.0")
	if result == 0 {
		t.Log("BUG-IDENTITY-5 confirmed: compareSemver('1.x.0', '1.0.0') returns 0 (equal)")
		t.Log("Non-numeric version components are silently treated as 0")
	}

	// "1.abc.0" vs "1.0.0"
	result2 := compareSemver("1.abc.0", "1.0.0")
	if result2 == 0 {
		t.Log("compareSemver('1.abc.0', '1.0.0') = 0 (treated as equal)")
	}
}

// BUG-IDENTITY-6: matchSemver with "x" wildcard does string comparison on parts.
// The version "1.10.0" with pattern "1.1.x" would NOT match because "10" != "1".
// But "1.1.x" vs "1.1.anything" matches because the third part is "x".
// This is correct behavior but worth documenting.
func TestMatchSemver_WildcardBehavior(t *testing.T) {
	testCases := []struct {
		pattern  string
		version  string
		expected bool
	}{
		{"1.x.x", "1.5.0", true},
		{"1.x.x", "2.0.0", false},
		{"1.2.x", "1.2.3", true},
		{"1.2.x", "1.3.0", false},
		{"*", "anything", true},
		{">=1.0.0", "1.0.0", true},
		{">=1.0.0", "0.9.0", false},
		{">=1.0.0", "2.0.0", true},
	}

	for _, tc := range testCases {
		result := matchSemver(tc.pattern, tc.version)
		if result != tc.expected {
			t.Errorf("matchSemver(%q, %q) = %v, want %v", tc.pattern, tc.version, result, tc.expected)
		}
	}
}

// BUG-IDENTITY-7: matchGlob only supports suffix wildcards (e.g., "claude-*").
// It does NOT support "claude-*-20251101" or "*-opus-*" patterns.
// This limits the expressiveness of model constraints.
func TestMatchGlob_LimitedPatterns(t *testing.T) {
	testCases := []struct {
		pattern  string
		value    string
		expected bool
	}{
		{"claude-*", "claude-opus-4-5", true},
		{"*", "anything", true},
		{"exact-match", "exact-match", true},
		{"exact-match", "exact-mismatch", false},
		// Unsupported patterns
		{"claude-*-20251101", "claude-opus-20251101", false}, // * only at suffix
		{"*-opus", "claude-opus", false},                     // * only at suffix
	}

	for _, tc := range testCases {
		result := matchGlob(tc.pattern, tc.value)
		if result != tc.expected {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.value, result, tc.expected)
		}
	}
}

// BUG-IDENTITY-8: ToSPIFFEID truncates IdentityHash to 16 chars.
// If two identities share the first 16 hex chars of their SHA256 hash
// (probability: 1 in 2^64), they would have the same SPIFFE ID.
// This is an acceptable birthday bound but should be documented.
func TestToSPIFFEID_HashTruncation(t *testing.T) {
	identity := &AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
		Tools:        []string{"Read", "Write"},
	}

	id, err := identity.ToSPIFFEID("aflock.ai")
	if err != nil {
		t.Fatalf("ToSPIFFEID: %v", err)
	}

	t.Logf("SPIFFE ID: %s", id.String())
	t.Logf("Full identity hash: %s", identity.IdentityHash)
	t.Logf("Hash prefix in SPIFFE ID: %s (16 chars = 64 bits)", identity.IdentityHash[:16])

	// Verify the SPIFFE ID contains the truncated hash
	if len(identity.IdentityHash) < 16 {
		t.Fatal("IdentityHash too short")
	}
}

// BUG-IDENTITY-9: sanitizeSPIFFEPath replaces ALL non-alphanumeric chars with dashes.
// This means version "4.5.20251101" becomes "4-5-20251101".
// Two different versions like "4-5" and "4.5" would map to the same path.
func TestSanitizeSPIFFEPath_CollisionRisk(t *testing.T) {
	path1 := sanitizeSPIFFEPath("4.5")
	path2 := sanitizeSPIFFEPath("4-5")
	path3 := sanitizeSPIFFEPath("4_5")

	if path1 == path2 {
		t.Logf("BUG-IDENTITY-9: '4.5' and '4-5' both map to %q - collision risk", path1)
	}
	if path1 == path3 {
		t.Logf("BUG-IDENTITY-9: '4.5' and '4_5' both map to %q - collision risk", path1)
	}
}

// BUG-IDENTITY-10: resolveActualBinary follows exec chains in scripts.
// An attacker who can control a symlinked binary could create a script
// that chains to an arbitrary path, and resolveActualBinary would follow it.
// The depth limit (10) prevents infinite loops but still allows reading
// arbitrary files on the filesystem.
func TestResolveActualBinary_DepthLimit(t *testing.T) {
	// The function has a depth limit of maxResolveDepth (10)
	// and cycle detection via the seen map.
	// Test with a non-existent path
	result := resolveActualBinary("/nonexistent/path")
	if result != "/nonexistent/path" {
		t.Errorf("resolveActualBinary(/nonexistent/path) = %q, want /nonexistent/path", result)
	}

	// Test with actual existing file (this test's own binary)
	result = resolveActualBinary("/bin/sh")
	t.Logf("resolveActualBinary(/bin/sh) = %s", result)
}

// BUG-IDENTITY-11: matchesSPIFFEFunctionary with empty SPIFFEID still matches
// if all constraint fields are empty. This means a Functionary{Type:"spiffe"}
// with no constraints matches any agent identity.
func TestMatchesSPIFFEFunctionary_EmptyConstraints(t *testing.T) {
	identity := &AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
	}

	emptyFunctionary := Functionary{
		Type: "spiffe",
		// All constraint fields are empty
	}

	if identity.matchesSPIFFEFunctionary(emptyFunctionary) {
		t.Log("BUG-IDENTITY-11: Empty SPIFFE functionary matches any identity")
		t.Log("This could allow unintended access if policy has a spiffe functionary with no constraints")
	}
}
