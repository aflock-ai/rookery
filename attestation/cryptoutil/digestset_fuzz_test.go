//go:build audit

package cryptoutil

import (
	"bytes"
	"crypto"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Finding DS-001: DigestSet with duplicate hash algorithms
//
// When CalculateDigestSet receives duplicate DigestValue entries, the
// resulting DigestSet map silently overwrites earlier entries with later
// ones. Since the hashfuncs map is iterated non-deterministically in Go,
// the FINAL value written to the DigestSet for a duplicated key depends
// on map iteration order, which is randomized. In practice, for identical
// DigestValue keys, all writers receive the same data through MultiWriter,
// so the computed hashes should be identical. However, the fact that
// duplicate writers are created is wasteful and the behavior is implicit.
//
// Severity: LOW -- wasteful but not exploitable since identical DigestValue
// keys will produce identical hashes for the same input data.
// ==========================================================================

func TestDigestSet_DS001_DuplicateHashAlgorithms(t *testing.T) {
	data := []byte("duplicate hash algorithm test data")

	// Pass the same DigestValue twice
	hashes := []DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256}, // exact duplicate
	}

	ds, err := CalculateDigestSetFromBytes(data, hashes)
	require.NoError(t, err)

	// DigestSet is a map, so duplicate keys collapse to one entry.
	// But TWO hash.Hash writers were created in CalculateDigestSet,
	// both writing to the same key. The last one to be iterated in
	// the hashfuncs range loop wins.
	assert.Len(t, ds, 1,
		"duplicate DigestValue keys should collapse to single map entry")

	// Verify the digest is correct (matches single-hash computation)
	dsSingle, err := CalculateDigestSetFromBytes(data, []DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	assert.True(t, ds.Equal(dsSingle),
		"duplicate hash should produce same result as single hash")

	// Now test with DigestValues that differ only in flags
	hashesWithFlags := []DigestValue{
		{Hash: crypto.SHA256, GitOID: false},
		{Hash: crypto.SHA256, GitOID: true}, // different DigestValue key
	}

	dsFlags, err := CalculateDigestSetFromBytes(data, hashesWithFlags)
	require.NoError(t, err)
	assert.Len(t, dsFlags, 2,
		"DigestValues differing in GitOID flag should produce separate entries")
}

// ==========================================================================
// Finding DS-002: DigestSet.Equal() with empty and nil DigestSets
//
// The contract of Equal says: "If the two artifacts don't have any digests
// from common hash functions, equal will return false." This means:
// - empty.Equal(empty) == false (no common hashes)
// - empty.Equal(non-empty) == false (no common hashes)
// - nil DigestSet passed as argument works (nil map is valid empty map)
// - nil *DigestSet receiver PANICS (dereferences nil pointer)
//
// The surprising behavior: two empty DigestSets are NOT equal, and a
// DigestSet with entries is NOT equal to itself if iterated differently
// (which can't happen since it uses the same map). But the semantic
// question is: should two empty artifact descriptions be considered equal?
// In supply chain verification, "no digests" means "no evidence," and
// treating that as not-equal is arguably correct.
//
// Severity: LOW -- semantically questionable but not exploitable.
// The nil pointer panic on receiver is a real crash bug.
// ==========================================================================

func TestDigestSet_DS002_EmptyAndNilEquality(t *testing.T) {
	t.Run("empty_vs_empty", func(t *testing.T) {
		ds1 := DigestSet{}
		ds2 := DigestSet{}

		result := ds1.Equal(ds2)
		assert.False(t, result,
			"two empty DigestSets should NOT be equal (no common hash functions)")
	})

	t.Run("nil_argument", func(t *testing.T) {
		ds := DigestSet{
			DigestValue{Hash: crypto.SHA256}: "abc123",
		}

		// nil as argument should work (nil map is empty map)
		result := ds.Equal(nil)
		assert.False(t, result,
			"non-empty vs nil should be false (no common hashes)")
	})

	t.Run("nil_vs_nil", func(t *testing.T) {
		var ds1 DigestSet // nil
		var ds2 DigestSet // nil

		// Calling Equal on nil DigestSet value (not pointer) should work
		// because range over nil map is valid in Go
		result := ds1.Equal(ds2)
		assert.False(t, result,
			"nil vs nil should be false (no common hashes)")
	})

	t.Run("nil_pointer_receiver_panics", func(t *testing.T) {
		var ds *DigestSet // nil pointer
		ds2 := DigestSet{DigestValue{Hash: crypto.SHA256}: "abc"}

		// BUG: calling Equal on nil *DigestSet panics because it
		// dereferences the pointer with range *ds
		assert.Panics(t, func() {
			ds.Equal(ds2)
		}, "nil *DigestSet receiver should panic (dereferences nil pointer)")
	})

	t.Run("empty_value_vs_nil_value", func(t *testing.T) {
		var nilDs DigestSet        // nil map
		emptyDs := DigestSet{}     // empty but non-nil map

		// Both should behave identically with Equal
		assert.Equal(t,
			nilDs.Equal(DigestSet{DigestValue{Hash: crypto.SHA256}: "x"}),
			emptyDs.Equal(DigestSet{DigestValue{Hash: crypto.SHA256}: "x"}),
			"nil and empty DigestSet should behave identically in Equal()")
	})
}

// ==========================================================================
// Finding DS-003: DigestSet with unsupported/unknown hash algorithms
//
// DigestSet is a plain map[DigestValue]string. You can put ANY crypto.Hash
// value into it, including ones not in the hashNames/hashesByName maps.
// The error only surfaces when you try to serialize (MarshalJSON/ToNameMap)
// or create via NewDigestSet with an unknown name string.
//
// This means: code that builds DigestSet directly (not via NewDigestSet)
// can silently include unsupported hashes that will fail at serialization
// time, potentially crashing the attestation pipeline mid-flight.
//
// Additionally, Equal() works fine with unsupported hashes because it
// just compares map keys, not hash names.
//
// Severity: MEDIUM -- silent acceptance of unsupported hashes that only
// fail at serialization time. In a supply chain pipeline, this means
// attestation could be computed successfully but fail to persist.
// ==========================================================================

func TestDigestSet_DS003_UnsupportedHashAlgorithms(t *testing.T) {
	t.Run("unsupported_hash_in_digestset_equal_works", func(t *testing.T) {
		// SHA512 is not in hashNames, but it works as a DigestValue key
		sha512Key := DigestValue{Hash: crypto.SHA512}

		ds1 := DigestSet{sha512Key: "abc123"}
		ds2 := DigestSet{sha512Key: "abc123"}

		// Equal works because it just compares map keys + string values
		assert.True(t, ds1.Equal(ds2),
			"Equal should work with unsupported hash algorithms")
	})

	t.Run("unsupported_hash_marshal_fails", func(t *testing.T) {
		sha512Key := DigestValue{Hash: crypto.SHA512}
		ds := DigestSet{sha512Key: "abc123"}

		// MarshalJSON calls ToNameMap which looks up hashNames
		_, err := ds.MarshalJSON()
		require.Error(t, err,
			"MarshalJSON should fail for unsupported hash algorithm")

		var hashErr ErrUnsupportedHash
		assert.ErrorAs(t, err, &hashErr)
	})

	t.Run("unsupported_hash_to_name_map_fails", func(t *testing.T) {
		sha512Key := DigestValue{Hash: crypto.SHA512}
		ds := DigestSet{sha512Key: "abc123"}

		_, err := ds.ToNameMap()
		require.Error(t, err,
			"ToNameMap should fail for unsupported hash algorithm")
	})

	t.Run("unsupported_hash_via_NewDigestSet", func(t *testing.T) {
		// NewDigestSet rejects unknown hash name strings
		_, err := NewDigestSet(map[string]string{
			"sha512": "abc123",
		})
		require.Error(t, err,
			"NewDigestSet should reject unknown hash name 'sha512'")
	})

	t.Run("mixed_supported_and_unsupported", func(t *testing.T) {
		sha256Key := DigestValue{Hash: crypto.SHA256}
		sha512Key := DigestValue{Hash: crypto.SHA512}

		ds := DigestSet{
			sha256Key: "supported",
			sha512Key: "unsupported",
		}

		// ToNameMap returns partial results before erroring
		nameMap, err := ds.ToNameMap()
		require.Error(t, err,
			"ToNameMap with mixed supported/unsupported should error")

		// BUG: ToNameMap returns a PARTIAL map on error. The caller
		// may not check the error and use the partial results.
		// The map may contain some entries depending on iteration order.
		t.Logf("FINDING DS-003: ToNameMap returned partial map with %d entries "+
			"AND an error. Callers that ignore the error get partial data.",
			len(nameMap))
	})
}

// ==========================================================================
// Finding DS-004: DigestSet.Equal() uses non-constant-time string comparison
//
// The hash digest comparison at digestset.go:137 uses plain `==` operator:
//
//     if digest == otherDigest {
//
// This is NOT constant-time. An attacker observing timing differences in
// Equal() calls can determine how many leading characters of two digests
// match, progressively narrowing down a valid digest value.
//
// In supply chain verification, this matters when:
// 1. An attacker controls one side of the comparison (their attestation)
// 2. They can measure timing of the verification process
// 3. They iterate to find a digest that passes comparison
//
// Go's `==` on strings compares byte-by-byte and short-circuits on first
// mismatch. The crypto/subtle.ConstantTimeCompare function should be used.
//
// Severity: MEDIUM -- timing oracle for digest comparison. While hash
// collision is the real threat, timing leaks make targeted attacks easier.
// ==========================================================================

func TestDigestSet_DS004_NonConstantTimeComparison(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}

	// Create two DigestSets with digests that differ at different positions
	// to demonstrate the non-constant-time behavior exists.
	dsLegit := DigestSet{
		sha256Key: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	// Differs at position 0
	dsEarlyDiff := DigestSet{
		sha256Key: "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	// Differs at position 63 (last char)
	dsLateDiff := DigestSet{
		sha256Key: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854",
	}

	// Both should return false, but timing differs because == short-circuits
	assert.False(t, dsLegit.Equal(dsEarlyDiff))
	assert.False(t, dsLegit.Equal(dsLateDiff))

	// Demonstrate the timing difference with a statistical test.
	// We run each comparison many times and measure wall-clock time.
	// NOTE: This test proves the CODE uses ==, not that the timing
	// difference is reliably measurable (CPU caches, branch prediction,
	// and OS scheduling add noise). The point is the code path.
	const iterations = 100000
	startEarly := time.Now()
	for i := 0; i < iterations; i++ {
		dsLegit.Equal(dsEarlyDiff)
	}
	earlyDuration := time.Since(startEarly)

	startLate := time.Now()
	for i := 0; i < iterations; i++ {
		dsLegit.Equal(dsLateDiff)
	}
	lateDuration := time.Since(startLate)

	// We don't assert timing because it's noisy, but we log for analysis.
	// The real finding is that the source code uses ==, not subtle.ConstantTimeCompare.
	t.Logf("FINDING DS-004: DigestSet.Equal uses '==' for digest comparison, "+
		"not crypto/subtle.ConstantTimeCompare.\n"+
		"  Early-diff timing (%d iterations): %v\n"+
		"  Late-diff timing (%d iterations): %v\n"+
		"  The code at digestset.go:137 should use constant-time comparison "+
		"to prevent timing side-channel attacks on digest values.",
		iterations, earlyDuration, iterations, lateDuration)
}

// ==========================================================================
// Finding DS-005: DigestSet JSON serialization round-trip
//
// All supported hash algorithms survive JSON marshaling/unmarshaling.
// This test verifies round-trip fidelity for every algorithm in the
// hashNames map. The critical property: a DigestSet that is marshaled
// and then unmarshaled must be Equal to the original.
//
// Known sub-finding: non-UTF-8 digest values are silently corrupted
// during JSON round-trip (Go's json.Marshal replaces invalid UTF-8
// with U+FFFD). This is tracked separately.
//
// Severity: N/A -- this is a correctness verification test.
// ==========================================================================

func TestDigestSet_DS005_JSONSerializationRoundTrip(t *testing.T) {
	// Build a DigestSet with ALL supported hash algorithms
	allHashes := DigestSet{
		DigestValue{Hash: crypto.SHA256}:                       "sha256digest",
		DigestValue{Hash: crypto.SHA1}:                         "sha1digest",
		DigestValue{Hash: crypto.SHA256, GitOID: true}:         "gitoid:blob:sha256:abc123",
		DigestValue{Hash: crypto.SHA1, GitOID: true}:           "gitoid:blob:sha1:def456",
		DigestValue{Hash: crypto.SHA256, DirHash: true}:        "dirhashdigest",
	}

	// Marshal to JSON
	jsonBytes, err := allHashes.MarshalJSON()
	require.NoError(t, err, "MarshalJSON should succeed for all supported hashes")

	// Verify the JSON is valid
	assert.True(t, json.Valid(jsonBytes), "should produce valid JSON")

	// Unmarshal back
	var restored DigestSet
	err = restored.UnmarshalJSON(jsonBytes)
	require.NoError(t, err, "UnmarshalJSON should succeed")

	// Verify round-trip equality
	assert.True(t, allHashes.Equal(restored),
		"JSON round-trip should preserve DigestSet equality")
	assert.Equal(t, len(allHashes), len(restored),
		"JSON round-trip should preserve number of entries")

	// Verify each individual digest survived
	for dv, digest := range allHashes {
		restoredDigest, ok := restored[dv]
		assert.True(t, ok, "DigestValue %v should survive round-trip", dv)
		assert.Equal(t, digest, restoredDigest,
			"digest for %v should be preserved", dv)
	}
}

func TestDigestSet_DS005_JSONRoundTrip_NonUTF8Corruption(t *testing.T) {
	// Non-UTF-8 bytes in digest values are silently corrupted by JSON
	sha256Key := DigestValue{Hash: crypto.SHA256}

	// Create a digest with invalid UTF-8 bytes
	invalidUTF8 := "abc\xff\xfe\xfddef"
	ds := DigestSet{sha256Key: invalidUTF8}

	jsonBytes, err := ds.MarshalJSON()
	require.NoError(t, err, "MarshalJSON should succeed even with non-UTF-8")

	var restored DigestSet
	err = restored.UnmarshalJSON(jsonBytes)
	require.NoError(t, err, "UnmarshalJSON should succeed")

	// The digest value was CHANGED by the round-trip because json.Marshal
	// replaces invalid UTF-8 with U+FFFD
	restoredDigest := restored[sha256Key]
	if restoredDigest == invalidUTF8 {
		t.Fatal("expected non-UTF-8 digest to be corrupted during JSON round-trip")
	}
	t.Logf("FINDING DS-005: Non-UTF-8 digest value was silently corrupted:\n"+
		"  Original: %q\n"+
		"  After JSON round-trip: %q\n"+
		"  This means digest values containing non-ASCII bytes can change "+
		"after serialization, potentially causing verification mismatches.",
		invalidUTF8, restoredDigest)
}

// ==========================================================================
// Finding DS-006: Digest computation on zero-byte and nil readers
//
// Computing a digest of empty content is valid and produces the "hash of
// nothing" (e.g., SHA256 of empty string is e3b0c44...). This is correct
// behavior. However, passing a nil io.Reader to CalculateDigestSet causes
// a panic in io.Copy because MultiWriter tries to write to nil.
//
// Severity: LOW for zero-byte (correct behavior), MEDIUM for nil reader
// (panic in production code).
// ==========================================================================

func TestDigestSet_DS006_ZeroByteReader(t *testing.T) {
	hashes := []DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA1},
	}

	// Zero-byte reader should produce valid digests
	ds, err := CalculateDigestSet(bytes.NewReader([]byte{}), hashes)
	require.NoError(t, err, "zero-byte reader should succeed")
	assert.Len(t, ds, 2, "should have entries for each requested hash")

	// Verify the SHA256 of empty content is the well-known value
	sha256Key := DigestValue{Hash: crypto.SHA256}
	expectedSHA256Empty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	assert.Equal(t, expectedSHA256Empty, ds[sha256Key],
		"SHA256 of empty content should match well-known value")

	// SHA1 of empty content
	sha1Key := DigestValue{Hash: crypto.SHA1}
	expectedSHA1Empty := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	assert.Equal(t, expectedSHA1Empty, ds[sha1Key],
		"SHA1 of empty content should match well-known value")
}

func TestDigestSet_DS006_NilReaderPanics(t *testing.T) {
	hashes := []DigestValue{{Hash: crypto.SHA256}}

	// BUG: nil reader causes panic in io.Copy inside CalculateDigestSet.
	// io.Copy tries to read from nil, which panics.
	assert.Panics(t, func() {
		_, _ = CalculateDigestSet(nil, hashes)
	}, "nil reader should panic in CalculateDigestSet (io.Copy to MultiWriter)")
}

func TestDigestSet_DS006_EmptyDigestValues(t *testing.T) {
	// Empty digest values list should produce empty DigestSet with no error
	ds, err := CalculateDigestSet(bytes.NewReader([]byte("some data")), []DigestValue{})
	require.NoError(t, err)
	assert.Len(t, ds, 0, "empty digest values should produce empty DigestSet")
}

func TestDigestSet_DS006_NilDigestValues(t *testing.T) {
	// nil digest values list should also produce empty DigestSet
	ds, err := CalculateDigestSet(bytes.NewReader([]byte("some data")), nil)
	require.NoError(t, err)
	assert.Len(t, ds, 0, "nil digest values should produce empty DigestSet")
}

// ==========================================================================
// Finding DS-007: Concurrent digest computation -- race conditions
//
// CalculateDigestSet creates independent hash.Hash instances per call,
// so concurrent calls with separate readers should be safe. However,
// sharing a single io.Reader across concurrent calls is a data race
// because io.Copy reads from the reader without synchronization.
//
// The DigestSet map itself is not thread-safe for concurrent writes,
// but each CalculateDigestSet call creates its own local map.
//
// Severity: LOW -- the code is safe for typical usage (separate readers).
// Concurrent writes to a shared DigestSet would be a bug, but that's
// the caller's responsibility.
// ==========================================================================

func TestDigestSet_DS007_ConcurrentDigestComputation(t *testing.T) {
	data := []byte("concurrent digest test data that is sufficiently long to exercise the hash")
	hashes := []DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA1},
	}

	// Compute reference digest
	refDS, err := CalculateDigestSetFromBytes(data, hashes)
	require.NoError(t, err)

	const goroutines = 100
	var wg sync.WaitGroup
	results := make([]DigestSet, goroutines)
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each goroutine gets its own reader -- this is the safe pattern
			results[idx], errors[idx] = CalculateDigestSetFromBytes(data, hashes)
		}(i)
	}

	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errors[i], "goroutine %d should succeed", i)
		assert.True(t, refDS.Equal(results[i]),
			"goroutine %d should produce same digest as reference", i)
	}
}

func TestDigestSet_DS007_ConcurrentEqualCalls(t *testing.T) {
	// Concurrent reads from DigestSet via Equal should be safe
	// (map reads are safe from multiple goroutines)
	sha256Key := DigestValue{Hash: crypto.SHA256}
	sha1Key := DigestValue{Hash: crypto.SHA1}

	ds1 := DigestSet{sha256Key: "abc", sha1Key: "def"}
	ds2 := DigestSet{sha256Key: "abc", sha1Key: "def"}
	ds3 := DigestSet{sha256Key: "xyz", sha1Key: "def"}

	const goroutines = 100
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// These are all reads -- should be safe
			_ = ds1.Equal(ds2)
			_ = ds1.Equal(ds3)
			_ = ds2.Equal(ds1)
		}()
	}

	wg.Wait()
	// If we get here without -race detector complaints, concurrent Equal is safe
}

// ==========================================================================
// Finding DS-008: DigestSet.Equal() subset semantics
//
// Equal() has "weakest-common-hash" semantics: if DigestSet A has
// {sha256: X, sha1: Y} and DigestSet B has only {sha256: X}, Equal()
// returns true because the sha256 digests match and sha1 is simply
// skipped (not present in B).
//
// This is the documented behavior ("every digest for hash functions both
// artifacts have in common"), but it enables a hash algorithm downgrade
// attack where an attacker provides only a weak hash that they can
// collide, omitting stronger hashes.
//
// This is the same issue as R3-128 but tested from a different angle:
// subset semantics rather than explicit downgrade.
//
// Severity: MEDIUM -- hash algorithm downgrade via subset selection
// ==========================================================================

func TestDigestSet_DS008_SubsetSemantics(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}
	sha1Key := DigestValue{Hash: crypto.SHA1}
	gitoidKey := DigestValue{Hash: crypto.SHA256, GitOID: true}

	// Full set with multiple algorithms
	fullSet := DigestSet{
		sha256Key: "strong_hash_abc123",
		sha1Key:   "weak_hash_def456",
		gitoidKey: "gitoid:blob:sha256:ghi789",
	}

	t.Run("single_matching_hash_is_subset", func(t *testing.T) {
		// Only sha256, which matches
		subset := DigestSet{sha256Key: "strong_hash_abc123"}

		assert.True(t, fullSet.Equal(subset),
			"subset with matching sha256 is considered Equal")
		assert.True(t, subset.Equal(fullSet),
			"symmetry: fullSet is Equal to subset too")
	})

	t.Run("single_weak_hash_is_subset", func(t *testing.T) {
		// Only sha1 -- the weakest hash -- which matches
		weakSubset := DigestSet{sha1Key: "weak_hash_def456"}

		// BUG: This returns true because sha1 matches.
		// An attacker who can collide sha1 can bypass sha256 verification.
		assert.True(t, fullSet.Equal(weakSubset),
			"BUG: subset with ONLY weak sha1 is considered Equal to full set")
	})

	t.Run("no_overlapping_hashes", func(t *testing.T) {
		// Completely disjoint hash algorithm
		disjoint := DigestSet{
			DigestValue{Hash: crypto.SHA256, DirHash: true}: "dirhash_value",
		}

		assert.False(t, fullSet.Equal(disjoint),
			"disjoint hash algorithms should not be Equal")
	})

	t.Run("overlapping_with_mismatch", func(t *testing.T) {
		// sha256 matches, sha1 differs
		partialMismatch := DigestSet{
			sha256Key: "strong_hash_abc123",
			sha1Key:   "DIFFERENT_weak_hash",
		}

		assert.False(t, fullSet.Equal(partialMismatch),
			"any mismatching common hash should make them not Equal")
	})

	t.Run("gitoid_vs_plain_are_different_keys", func(t *testing.T) {
		// gitoid:sha256 and plain sha256 are different DigestValue keys
		// so they don't conflict
		gitoidOnly := DigestSet{
			gitoidKey: "gitoid:blob:sha256:ghi789",
		}

		assert.True(t, fullSet.Equal(gitoidOnly),
			"gitoid:sha256 key matches in full set")

		// But plain sha256 and gitoid:sha256 do NOT overlap
		plainOnlyWrong := DigestSet{
			sha256Key: "WRONG_VALUE",
			gitoidKey: "gitoid:blob:sha256:ghi789",
		}

		assert.False(t, fullSet.Equal(plainOnlyWrong),
			"mismatching plain sha256 should fail even if gitoid matches")
	})
}

// ==========================================================================
// Finding DS-009: HashToString/HashFromString asymmetry with gitoid/dirHash
//
// HashFromString("sha256") returns crypto.SHA256 (stripping the GitOID
// and DirHash flags). But HashToString(crypto.SHA256) returns "sha256"
// (the plain name). This means the gitoid:sha256 and dirHash names are
// NOT accessible through HashToString -- only through the hashNames map.
//
// This is by design (HashFromString returns crypto.Hash, not DigestValue)
// but it means HashFromString/HashToString is NOT a full round-trip for
// all names. "gitoid:sha256" -> HashFromString -> crypto.SHA256 ->
// HashToString -> "sha256" (LOST the gitoid flag).
//
// Severity: LOW -- documented design limitation, not a bug.
// ==========================================================================

func TestDigestSet_DS009_HashStringRoundTripAsymmetry(t *testing.T) {
	t.Run("plain_sha256_round_trips", func(t *testing.T) {
		h, err := HashFromString("sha256")
		require.NoError(t, err)
		name, err := HashToString(h)
		require.NoError(t, err)
		assert.Equal(t, "sha256", name)
	})

	t.Run("gitoid_sha256_loses_flag", func(t *testing.T) {
		h, err := HashFromString("gitoid:sha256")
		require.NoError(t, err)
		assert.Equal(t, crypto.SHA256, h,
			"HashFromString strips GitOID flag, returns plain crypto.SHA256")

		name, err := HashToString(h)
		require.NoError(t, err)
		assert.Equal(t, "sha256", name,
			"HashToString returns plain name, gitoid flag lost")
		assert.NotEqual(t, "gitoid:sha256", name,
			"gitoid prefix is NOT preserved through HashFromString/HashToString round-trip")
	})

	t.Run("dirHash_loses_flag", func(t *testing.T) {
		h, err := HashFromString("dirHash")
		require.NoError(t, err)
		assert.Equal(t, crypto.SHA256, h,
			"HashFromString strips DirHash flag, returns plain crypto.SHA256")

		name, err := HashToString(h)
		require.NoError(t, err)
		assert.Equal(t, "sha256", name,
			"DirHash flag lost through HashFromString/HashToString")
	})
}

// ==========================================================================
// Finding DS-010: NewDigestSet silently accepts duplicate hash names
//
// If the input map[string]string has colliding hash names (which can't
// happen with a Go map since keys are unique), this is fine. But if
// two different string names map to the same DigestValue, the last one
// iterated wins. Since Go map iteration is random, this is
// non-deterministic.
//
// In practice, the hashesByName map ensures each string name maps to a
// unique DigestValue, so this can't actually happen with the current
// hash name registry. But it documents the behavior.
//
// Severity: N/A -- can't happen with current hash name registry.
// ==========================================================================

func TestDigestSet_DS010_NewDigestSet_Behavior(t *testing.T) {
	t.Run("all_valid_names", func(t *testing.T) {
		ds, err := NewDigestSet(map[string]string{
			"sha256":        "a",
			"sha1":          "b",
			"gitoid:sha256": "c",
			"gitoid:sha1":   "d",
			"dirHash":       "e",
		})
		require.NoError(t, err)
		assert.Len(t, ds, 5, "all 5 supported hash names should produce 5 entries")
	})

	t.Run("empty_digest_value_accepted", func(t *testing.T) {
		// NewDigestSet does not validate that digest values are non-empty
		ds, err := NewDigestSet(map[string]string{
			"sha256": "",
		})
		require.NoError(t, err)
		assert.Equal(t, "", ds[DigestValue{Hash: crypto.SHA256}],
			"empty string digest is silently accepted")
	})

	t.Run("very_long_digest_value_accepted", func(t *testing.T) {
		longValue := strings.Repeat("a", 10*1024*1024) // 10 MB
		ds, err := NewDigestSet(map[string]string{
			"sha256": longValue,
		})
		require.NoError(t, err)
		assert.Equal(t, longValue, ds[DigestValue{Hash: crypto.SHA256}],
			"extremely long digest value is silently accepted without validation")
	})

	t.Run("invalid_hex_digest_accepted", func(t *testing.T) {
		// No validation that the digest looks like hex
		ds, err := NewDigestSet(map[string]string{
			"sha256": "this is not hex at all!!! @#$%",
		})
		require.NoError(t, err)
		assert.Equal(t, "this is not hex at all!!! @#$%",
			ds[DigestValue{Hash: crypto.SHA256}],
			"non-hex digest is silently accepted")
	})
}

// ==========================================================================
// Finding DS-011: CalculateDigestSet with GitOID produces non-hex digest
//
// For normal hashes, CalculateDigestSet hex-encodes the hash output.
// For GitOID hashes, it stores the raw string from gitoid.URI() which
// is a URI like "gitoid:blob:sha256:<hex>". This means the DigestSet
// contains heterogeneous value formats: some are hex strings, some are
// URIs. Equal() treats them all as opaque strings, which is correct,
// but code that assumes all digest values are hex-encoded will break.
//
// Severity: LOW -- documented but surprising heterogeneity.
// ==========================================================================

func TestDigestSet_DS011_GitOIDDigestFormat(t *testing.T) {
	data := []byte("gitoid format test")

	hashes := []DigestValue{
		{Hash: crypto.SHA256},                // plain hash
		{Hash: crypto.SHA256, GitOID: true},  // gitoid
	}

	ds, err := CalculateDigestSetFromBytes(data, hashes)
	require.NoError(t, err)

	plainDigest := ds[DigestValue{Hash: crypto.SHA256}]
	gitoidDigest := ds[DigestValue{Hash: crypto.SHA256, GitOID: true}]

	// Plain digest should be hex-encoded
	assert.NotContains(t, plainDigest, ":",
		"plain digest should be hex only, no colons")

	// GitOID digest should be a URI with "gitoid:" prefix
	assert.True(t, strings.HasPrefix(gitoidDigest, "gitoid:"),
		"gitoid digest should have 'gitoid:' prefix, got %q", gitoidDigest)

	t.Logf("FINDING DS-011: DigestSet contains heterogeneous value formats:\n"+
		"  Plain SHA256: %q (hex-encoded)\n"+
		"  GitOID SHA256: %q (URI format)\n"+
		"  Code that assumes all digest values are hex will break on GitOID entries.",
		plainDigest, gitoidDigest)
}

// ==========================================================================
// Finding DS-012: ToNameMap returns partial results on error
//
// When ToNameMap encounters an unsupported hash, it returns both the
// partially-filled map AND the error. Callers that only check the map
// (ignoring the error) will get incomplete data.
//
// Severity: LOW -- callers should check errors, but the API design
// encourages ignoring the error since a non-nil map is returned.
// ==========================================================================

func TestDigestSet_DS012_ToNameMapPartialResults(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}
	sha512Key := DigestValue{Hash: crypto.SHA512} // unsupported

	ds := DigestSet{
		sha256Key: "supported_hash",
		sha512Key: "unsupported_hash",
	}

	nameMap, err := ds.ToNameMap()
	require.Error(t, err, "should error on unsupported hash")

	// The nameMap is NOT nil -- it contains partial results
	assert.NotNil(t, nameMap,
		"ToNameMap returns non-nil map even on error")

	// Due to random map iteration, the partial map may or may not
	// contain the supported hash entry. Run this multiple times
	// to observe both outcomes.
	t.Logf("FINDING DS-012: ToNameMap returned error AND a map with %d entries. "+
		"Partial data is returned on error, which is a footgun for callers "+
		"that don't check errors.", len(nameMap))
}

// ==========================================================================
// Finding DS-013: CalculateDigestSet with ErrorReader
//
// If the io.Reader returns an error during io.Copy, CalculateDigestSet
// returns the error. But the partial DigestSet is also returned (with
// zero-value hashes for entries that weren't fully computed).
//
// Severity: LOW -- callers should check errors.
// ==========================================================================

type failingReader struct {
	data   []byte
	offset int
	failAt int
}

func (r *failingReader) Read(p []byte) (n int, err error) {
	if r.offset >= r.failAt {
		return 0, io.ErrUnexpectedEOF
	}
	remaining := r.failAt - r.offset
	if remaining > len(p) {
		remaining = len(p)
	}
	if remaining > len(r.data)-r.offset {
		remaining = len(r.data) - r.offset
	}
	n = copy(p[:remaining], r.data[r.offset:r.offset+remaining])
	r.offset += n
	return n, nil
}

func TestDigestSet_DS013_ErrorReaderPropagation(t *testing.T) {
	reader := &failingReader{
		data:   bytes.Repeat([]byte("data"), 1000),
		failAt: 100, // fail after 100 bytes
	}

	hashes := []DigestValue{{Hash: crypto.SHA256}}
	ds, err := CalculateDigestSet(reader, hashes)
	require.Error(t, err, "error from reader should propagate")
	assert.NotNil(t, ds,
		"DigestSet map is returned even on error (empty but non-nil)")
}

// ==========================================================================
// Finding DS-014: Equal() on DigestSet with single matching empty string
//
// If both DigestSets have the same hash algorithm with empty string
// digest values, Equal() returns true. This is technically correct per
// the documented behavior, but semantically meaningless: an empty string
// is not a valid digest for any hash algorithm.
//
// Severity: LOW -- no validation of digest value format.
// ==========================================================================

func TestDigestSet_DS014_EmptyStringDigestMatch(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}

	ds1 := DigestSet{sha256Key: ""}
	ds2 := DigestSet{sha256Key: ""}

	// Empty string matches empty string
	assert.True(t, ds1.Equal(ds2),
		"FINDING DS-014: Two DigestSets with empty-string digest values "+
			"are considered Equal. No validation that digest values are "+
			"well-formed hex or non-empty.")

	// Empty string does NOT match non-empty
	ds3 := DigestSet{sha256Key: "abc"}
	assert.False(t, ds1.Equal(ds3),
		"empty string should not match non-empty digest")
}

// ==========================================================================
// Finding DS-015: CalculateDigestSetFromBytes with nil data
//
// nil []byte is treated the same as empty []byte, which is correct
// Go behavior (bytes.NewReader(nil) creates a reader over 0 bytes).
//
// Severity: N/A -- correct behavior, included for completeness.
// ==========================================================================

func TestDigestSet_DS015_NilBytesInput(t *testing.T) {
	hashes := []DigestValue{{Hash: crypto.SHA256}}

	dsNil, err := CalculateDigestSetFromBytes(nil, hashes)
	require.NoError(t, err)

	dsEmpty, err := CalculateDigestSetFromBytes([]byte{}, hashes)
	require.NoError(t, err)

	assert.True(t, dsNil.Equal(dsEmpty),
		"nil and empty bytes should produce identical digests")
}

// ==========================================================================
// Finding DS-016: DigestSet.Equal is not transitive when subset semantics
// are exploited
//
// Consider: A = {sha256: X, sha1: Y}
//           B = {sha256: X}
//           C = {sha256: X, sha1: Z} where Y != Z
//
// A.Equal(B) == true (sha256 matches, sha1 skipped)
// B.Equal(C) == true (sha256 matches, sha1 not in B so skipped)
// A.Equal(C) == false (sha256 matches but sha1 differs)
//
// This VIOLATES transitivity: A==B and B==C but A!=C.
//
// In supply chain verification with multi-step policies, this means
// intermediate verification steps can create transitive trust gaps.
//
// Severity: MEDIUM -- transitivity violation in equality relation used
// for security-critical artifact comparison.
// ==========================================================================

func TestDigestSet_DS016_TransitivityViolation(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}
	sha1Key := DigestValue{Hash: crypto.SHA1}

	dsA := DigestSet{sha256Key: "X", sha1Key: "Y"}
	dsB := DigestSet{sha256Key: "X"}             // subset of A
	dsC := DigestSet{sha256Key: "X", sha1Key: "Z"} // sha1 differs from A

	ab := dsA.Equal(dsB) // true: sha256 matches, sha1 skipped
	bc := dsB.Equal(dsC) // true: sha256 matches, sha1 not in B
	ac := dsA.Equal(dsC) // false: sha256 matches but sha1 differs

	assert.True(t, ab, "A.Equal(B) should be true (sha256 matches)")
	assert.True(t, bc, "B.Equal(C) should be true (sha256 matches)")
	assert.False(t, ac, "A.Equal(C) should be false (sha1 differs)")

	t.Logf("FINDING DS-016: DigestSet.Equal VIOLATES transitivity:\n"+
		"  A.Equal(B) = %v\n"+
		"  B.Equal(C) = %v\n"+
		"  A.Equal(C) = %v\n"+
		"  A==B and B==C but A!=C. This breaks equivalence relation "+
		"properties and can create transitive trust gaps in multi-step "+
		"policy verification.",
		ab, bc, ac)
}
