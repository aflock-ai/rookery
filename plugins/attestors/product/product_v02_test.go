// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// product_v02_test.go covers the v0.2 tree-subject behavior of the product
// attestor and the v0.1 legacy-mode compatibility shim. The test cases are
// intentionally exhaustive because this is a wire-format change: any drift
// in the merkle computation, the legacy round-trip, or the registry wiring
// will silently break verification of either old or new attestations.

package product

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers
// =============================================================================

// makeProductAttestor builds an Attestor pre-populated with the given files
// (path → content) under a temp dir, runs Attest, and returns the attestor +
// the temp dir. The compiled globs default to "include all".
func makeProductAttestor(t *testing.T, files map[string]string, opts ...Option) (*Attestor, string) {
	t.Helper()
	dir := t.TempDir()
	for relPath, content := range files {
		full := filepath.Join(dir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}

	a := New(opts...)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))
	return a, dir
}

// expectedSha256MerkleRoot recomputes the v0.2 merkle root the same way the
// production code does, but using the standard library directly. The two
// implementations agreeing is the whole point of this helper — if production
// drifts from the documented algorithm, this hand-rolled version will detect
// it.
func expectedSha256MerkleRoot(t *testing.T, products map[string]attestation.Product, included []string) string {
	t.Helper()
	// Sort by the SAME normalization the production path uses.
	normalized := make([]string, 0, len(included))
	for _, n := range included {
		normalized = append(normalized, filepath.ToSlash(n))
	}
	sort.Strings(normalized)

	h := sha256.New()
	for _, name := range normalized {
		// Look up the product by either OS-native or normalized path.
		p, ok := products[name]
		if !ok {
			p, ok = products[filepath.FromSlash(name)]
		}
		require.True(t, ok, "product %q not found in map", name)

		var digest string
		for dv, d := range p.Digest {
			if dv.Hash == crypto.SHA256 && !dv.GitOID && !dv.DirHash {
				digest = d
				break
			}
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(digest))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// =============================================================================
// V02_001: Default mode emits exactly one tree subject
// =============================================================================

func TestV02_001_DefaultModeEmitsSingleTreeSubject(t *testing.T) {
	a, _ := makeProductAttestor(t, map[string]string{
		"a.txt":           "alpha",
		"b.txt":           "bravo",
		"sub/c.txt":       "charlie",
		"sub/deep/d.txt":  "delta",
		"sub/deep/e.json": `{"hi": 1}`,
	})

	subjects := a.Subjects()
	require.Len(t, subjects, 1, "v0.2 must emit exactly one subject")
	root, ok := subjects[TreeSubjectName]
	require.True(t, ok, "subject must be named %q, got keys: %v", TreeSubjectName, keysOf(subjects))
	require.NotEmpty(t, root, "merkle root digest set must be non-empty")

	// Sanity: the root must contain a SHA256 entry because the test files
	// were hashed with SHA256 by RecordArtifacts (default ctx hash).
	hasSha256 := false
	for dv := range root {
		if dv.Hash == crypto.SHA256 {
			hasSha256 = true
		}
	}
	assert.True(t, hasSha256, "merkle root must include sha256 algorithm")
}

// =============================================================================
// V02_002: Merkle root is deterministic and matches an independent computation
// =============================================================================

func TestV02_002_MerkleRootMatchesIndependentRecomputation(t *testing.T) {
	a, _ := makeProductAttestor(t, map[string]string{
		"a":     "1",
		"b":     "2",
		"sub/c": "3",
	})

	// All file names that should be included by the default "*" glob.
	included := []string{"a", "b", "sub/c"}

	expected := expectedSha256MerkleRoot(t, a.products, included)

	subjects := a.Subjects()
	root := subjects[TreeSubjectName]

	var actual string
	for dv, d := range root {
		if dv.Hash == crypto.SHA256 && !dv.GitOID && !dv.DirHash {
			actual = d
			break
		}
	}
	require.NotEmpty(t, actual, "expected sha256 entry in tree subject root")
	assert.Equal(t, expected, actual, "production merkle root must equal hand-computed root")
}

// =============================================================================
// V02_003: Merkle root is order-independent of map iteration
// =============================================================================

func TestV02_003_MerkleRootIsOrderIndependent(t *testing.T) {
	// Build the same product set twice from a fresh tempdir each time.
	// Map iteration order is randomized in Go, so if our sort step were
	// missing or buggy this test would catch it within a few attempts.
	files := map[string]string{
		"alpha":   "1",
		"bravo":   "2",
		"charlie": "3",
		"delta":   "4",
		"echo":    "5",
		"foxtrot": "6",
		"golf":    "7",
		"hotel":   "8",
	}

	first := rootHexFor(t, files)
	for i := 0; i < 20; i++ {
		got := rootHexFor(t, files)
		require.Equal(t, first, got, "merkle root must be deterministic across attempt %d", i)
	}
}

// rootHexFor builds an attestor from `files` and returns the sha256 merkle
// root hex digest of its tree subject.
func rootHexFor(t *testing.T, files map[string]string) string {
	t.Helper()
	a, _ := makeProductAttestor(t, files)
	subjects := a.Subjects()
	root := subjects[TreeSubjectName]
	for dv, d := range root {
		if dv.Hash == crypto.SHA256 && !dv.GitOID && !dv.DirHash {
			return d
		}
	}
	t.Fatalf("no sha256 root found")
	return ""
}

// =============================================================================
// V02_004: Renaming a file changes the merkle root
// =============================================================================

func TestV02_004_RenamingFileChangesRoot(t *testing.T) {
	r1 := rootHexFor(t, map[string]string{"a": "x", "b": "y"})
	r2 := rootHexFor(t, map[string]string{"a": "x", "c": "y"}) // b → c
	assert.NotEqual(t, r1, r2, "renaming a file must change the merkle root")
}

// =============================================================================
// V02_005: Modifying a file's content changes the merkle root
// =============================================================================

func TestV02_005_ModifyingContentChangesRoot(t *testing.T) {
	r1 := rootHexFor(t, map[string]string{"a": "original"})
	r2 := rootHexFor(t, map[string]string{"a": "tampered"})
	assert.NotEqual(t, r1, r2, "changing file content must change the merkle root")
}

// =============================================================================
// V02_006: Adding a file changes the merkle root
// =============================================================================

func TestV02_006_AddingFileChangesRoot(t *testing.T) {
	r1 := rootHexFor(t, map[string]string{"a": "1"})
	r2 := rootHexFor(t, map[string]string{"a": "1", "b": "2"})
	assert.NotEqual(t, r1, r2, "adding a file must change the merkle root")
}

// =============================================================================
// V02_007: Empty workdir produces zero subjects
// =============================================================================

func TestV02_007_EmptyWorkdirProducesNoSubjects(t *testing.T) {
	dir := t.TempDir()
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	subjects := a.Subjects()
	assert.Empty(t, subjects, "empty workdir must produce zero subjects (not a tree of nothing)")
}

// =============================================================================
// V02_008: Exclude-everything glob produces zero subjects
// =============================================================================

func TestV02_008_ExcludeEverythingProducesNoSubjects(t *testing.T) {
	a, _ := makeProductAttestor(t,
		map[string]string{"a.txt": "1", "b.txt": "2"},
		WithExcludeGlob("*"),
	)
	subjects := a.Subjects()
	assert.Empty(t, subjects, "exclude=* must produce zero subjects, not an empty merkle root")
}

// =============================================================================
// V02_009: Subjects() never panics on a stub attestor with nil globs
// =============================================================================

func TestV02_009_NilGlobsDoNotPanic(t *testing.T) {
	a := New()
	// products map populated directly, no Attest() call → globs are nil.
	a.products = map[string]attestation.Product{
		"a.txt": {
			MimeType: "text/plain",
			Digest:   cryptoutil.DigestSet{{Hash: crypto.SHA256}: "abc123"},
		},
	}
	require.NotPanics(t, func() {
		subjects := a.Subjects()
		assert.Len(t, subjects, 1)
	})
}

// =============================================================================
// V02_010: Tree subject is JSON-roundtripable
// =============================================================================

func TestV02_010_TreeSubjectSerializesAsValidIntotoSubject(t *testing.T) {
	a, _ := makeProductAttestor(t, map[string]string{"a": "1", "b": "2"})

	// Marshal predicate (the products map) and verify roundtrip preserves it.
	predicateBytes, err := json.Marshal(a)
	require.NoError(t, err)

	a2 := New()
	require.NoError(t, json.Unmarshal(predicateBytes, a2))
	assert.Equal(t, len(a.products), len(a2.products), "predicate roundtrip must preserve product count")

	// And the unmarshaled attestor must still produce subjects (it's the
	// modern attestor, so it'll emit the tree subject).
	s2 := a2.Subjects()
	assert.Len(t, s2, 1)
	assert.Contains(t, s2, TreeSubjectName)
}

// =============================================================================
// V02_011: A roundtripped predicate produces the SAME merkle root
// =============================================================================

func TestV02_011_RoundtrippedPredicateRecomputesSameRoot(t *testing.T) {
	a, _ := makeProductAttestor(t, map[string]string{
		"a":     "alpha",
		"b":     "bravo",
		"sub/c": "charlie",
	})

	predicateBytes, err := json.Marshal(a)
	require.NoError(t, err)

	a2 := New()
	require.NoError(t, json.Unmarshal(predicateBytes, a2))

	// Both attestors must produce the same tree subject — that's the whole
	// point of the merkle root being derivable from the predicate alone.
	r1 := a.Subjects()[TreeSubjectName]
	r2 := a2.Subjects()[TreeSubjectName]
	require.NotEmpty(t, r1)
	require.NotEmpty(t, r2)
	assert.True(t, r1.Equal(r2), "roundtripped predicate must produce identical merkle root")
}

// =============================================================================
// V02_012: Legacy mode emits per-file subjects (v0.1 shape)
// =============================================================================

func TestV02_012_LegacyModeEmitsPerFileSubjects(t *testing.T) {
	a, _ := makeProductAttestor(t,
		map[string]string{"a.txt": "1", "b.txt": "2", "sub/c.txt": "3"},
		WithLegacyMode(),
	)

	subjects := a.Subjects()
	require.Len(t, subjects, 3, "legacy mode must emit one subject per file")

	// All keys must use the v0.1 "file:" / "dir:" prefix.
	for k := range subjects {
		assert.True(t, strings.HasPrefix(k, "file:") || strings.HasPrefix(k, "dir:"),
			"legacy subject key %q must start with file: or dir:", k)
	}
	assert.Contains(t, subjects, "file:a.txt")
	assert.Contains(t, subjects, "file:b.txt")
	assert.Contains(t, subjects, fmt.Sprintf("file:%s", filepath.Join("sub", "c.txt")))
}

// =============================================================================
// V02_013: Legacy mode digest values match the embedded product digests
// =============================================================================

func TestV02_013_LegacySubjectDigestsMatchProducts(t *testing.T) {
	a, _ := makeProductAttestor(t,
		map[string]string{"a.txt": "hello"},
		WithLegacyMode(),
	)

	subjects := a.Subjects()
	require.Len(t, subjects, 1)
	root := subjects["file:a.txt"]

	// The legacy subject digest must literally be the product digest, not
	// some derivation. v0.1 verification depends on this byte equality.
	expected := a.products["a.txt"].Digest
	assert.True(t, root.Equal(expected), "legacy subject digest must equal product digest")
}

// =============================================================================
// V02_014: Both v0.1 and v0.2 predicate types are registered
// =============================================================================

func TestV02_014_BothPredicateTypesRegistered(t *testing.T) {
	// v0.2 (modern) — must produce a non-legacy attestor.
	modernFactory, ok := attestation.FactoryByType(ProductType)
	require.True(t, ok, "v0.2 predicate type must be registered")
	require.NotNil(t, modernFactory)
	modern, ok := modernFactory().(*Attestor)
	require.True(t, ok, "v0.2 factory must return *Attestor")
	assert.False(t, modern.legacyMode, "v0.2 factory must produce a NON-legacy attestor")

	// v0.1 (legacy) — must produce a legacy-mode attestor.
	legacyFactory, ok := attestation.FactoryByType(LegacyProductType)
	require.True(t, ok, "v0.1 predicate type must be registered for backward compat")
	require.NotNil(t, legacyFactory)
	legacy, ok := legacyFactory().(*Attestor)
	require.True(t, ok, "v0.1 factory must return *Attestor")
	assert.True(t, legacy.legacyMode, "v0.1 factory must produce a LEGACY attestor")
}

// =============================================================================
// V02_015: Lookup by name returns the modern factory
// =============================================================================

func TestV02_015_NameLookupReturnsModernFactory(t *testing.T) {
	// Anything that asks for "product" by name (CLI flag, preset, etc.)
	// must get the modern attestor — never the legacy one.
	factory, ok := attestation.FactoryByName(ProductName)
	require.True(t, ok, "product attestor must be registered by name")
	a, ok := factory().(*Attestor)
	require.True(t, ok)
	assert.False(t, a.legacyMode, "name lookup must return modern attestor, not legacy")
}

// =============================================================================
// V02_016: Version-bump invariants — constants did not regress
// =============================================================================

func TestV02_016_VersionConstants(t *testing.T) {
	// These look trivial but they catch a copy-paste regression where
	// someone "fixes" the duplicate by deleting the modern type.
	assert.Equal(t, "https://aflock.ai/attestations/product/v0.2", ProductType,
		"ProductType must be v0.2")
	assert.Equal(t, "https://aflock.ai/attestations/product/v0.1", LegacyProductType,
		"LegacyProductType must remain v0.1")
	assert.NotEqual(t, ProductType, LegacyProductType,
		"modern and legacy predicate types must differ")
}

// =============================================================================
// V02_017: Big-tree scaling — 5,000 files produce one subject
// =============================================================================

// This is the regression test for the original bug. Without the v0.2 change,
// 5,000 files would emit 5,000 subjects, blow the Archivista MySQL placeholder
// limit, and fail to upload. With the change, the count must be exactly 1.
func TestV02_017_BigTreeProducesSingleSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short mode")
	}
	files := make(map[string]string, 5000)
	for i := 0; i < 5000; i++ {
		// Spread across nested dirs so the test exercises path normalization
		// at scale, not just files in the workdir root.
		files[fmt.Sprintf("dir%03d/file%04d.txt", i/100, i)] = fmt.Sprintf("content-%d", i)
	}

	a, _ := makeProductAttestor(t, files)
	subjects := a.Subjects()
	require.Len(t, subjects, 1, "5000 files must collapse to exactly one tree subject")
	require.NotEmpty(t, subjects[TreeSubjectName])
	assert.Len(t, a.products, 5000, "predicate must still contain all 5000 products")
}

// =============================================================================
// V02_018: Path normalization — backslash and slash must produce the same root
// =============================================================================

// On Windows the walker can produce backslash-separated relative paths.
// Subjects() normalizes them to forward slashes before hashing so the merkle
// root is portable across operating systems. This test fakes a Windows-style
// product map and verifies normalization happens.
func TestV02_018_PathNormalizationIsPortable(t *testing.T) {
	// Two attestors with the same logical files but stored under different
	// path separators in the products map. Both must produce the same root.
	mkAttestor := func(sep string) *Attestor {
		a := New()
		a.products = map[string]attestation.Product{
			"a.txt":               {MimeType: "text/plain", Digest: cryptoutil.DigestSet{{Hash: crypto.SHA256}: "aaa"}},
			"sub" + sep + "b.txt": {MimeType: "text/plain", Digest: cryptoutil.DigestSet{{Hash: crypto.SHA256}: "bbb"}},
		}
		return a
	}

	rSlash := mkAttestor("/").Subjects()[TreeSubjectName]
	rBack := mkAttestor("\\").Subjects()[TreeSubjectName]
	require.NotEmpty(t, rSlash)
	require.NotEmpty(t, rBack)
	assert.True(t, rSlash.Equal(rBack), "merkle root must be the same regardless of OS path separator")
}

// =============================================================================
// V02_019: Legacy mode preserves include/exclude globs
// =============================================================================

func TestV02_019_LegacyModeRespectsIncludeExcludeGlobs(t *testing.T) {
	a, _ := makeProductAttestor(t,
		map[string]string{
			"keep.txt":  "1",
			"drop.exe":  "2",
			"keep2.txt": "3",
		},
		WithLegacyMode(),
		WithExcludeGlob("*.exe"),
	)

	subjects := a.Subjects()
	for k := range subjects {
		assert.False(t, strings.HasSuffix(k, ".exe"), "legacy mode must still apply exclude-glob, found %q", k)
	}
	assert.Contains(t, subjects, "file:keep.txt")
	assert.Contains(t, subjects, "file:keep2.txt")
}

// =============================================================================
// V02_020: keysOf helper — keep test source readable
// =============================================================================

func keysOf(m map[string]cryptoutil.DigestSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
