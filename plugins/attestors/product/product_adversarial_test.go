//go:build audit

// Copyright 2025 The Witness Contributors
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

package product

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Product with symlinks
// =============================================================================

func TestAdversarialProductWithSymlinks(t *testing.T) {
	workingDir := t.TempDir()

	// Create a real file
	realFile := filepath.Join(workingDir, "real.txt")
	require.NoError(t, os.WriteFile(realFile, []byte("real content"), 0644))

	// Create a symlink to the real file
	symlinkFile := filepath.Join(workingDir, "link.txt")
	require.NoError(t, os.Symlink(realFile, symlinkFile))

	// Create a symlink to a directory outside working dir
	outsideDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "outside.txt"), []byte("outside content"), 0644))
	outsideLink := filepath.Join(workingDir, "outside_link")
	require.NoError(t, os.Symlink(outsideDir, outsideLink))

	// Create a dangling symlink (points to nothing)
	danglingLink := filepath.Join(workingDir, "dangling.txt")
	require.NoError(t, os.Symlink(filepath.Join(workingDir, "nonexistent"), danglingLink))

	// Create a self-referential symlink loop
	loopA := filepath.Join(workingDir, "loop_a")
	loopB := filepath.Join(workingDir, "loop_b")
	require.NoError(t, os.Symlink(loopB, loopA))
	require.NoError(t, os.Symlink(loopA, loopB))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	// Attest should not panic or hang on symlinks
	err = a.Attest(ctx)
	// We accept either success or a well-formed error -- no panic, no hang
	if err != nil {
		t.Logf("Attest returned error (acceptable): %v", err)
	} else {
		products := a.Products()
		t.Logf("Products found: %d", len(products))
		for name, prod := range products {
			t.Logf("  %s -> mime=%s", name, prod.MimeType)
		}
	}
}

// =============================================================================
// Product with very long filenames
// =============================================================================

func TestAdversarialProductVeryLongFilename(t *testing.T) {
	workingDir := t.TempDir()

	// Most filesystems limit filenames to 255 bytes.
	// Create the longest filename the OS will accept.
	longName := strings.Repeat("a", 255) // max filename length on most FS
	longFile := filepath.Join(workingDir, longName)
	err := os.WriteFile(longFile, []byte("content"), 0644)
	if err != nil {
		t.Skipf("filesystem does not support 255-byte filenames: %v", err)
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	require.NoError(t, a.Attest(ctx))

	products := a.Products()
	if _, ok := products[longName]; !ok {
		t.Errorf("product with 255-char filename should be recorded, got products: %v", mapKeys(products))
	}
}

func TestAdversarialProductDeeplyNestedPath(t *testing.T) {
	workingDir := t.TempDir()

	// Create a deeply nested directory path
	nested := workingDir
	for i := 0; i < 20; i++ {
		nested = filepath.Join(nested, "d")
		require.NoError(t, os.Mkdir(nested, 0755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(nested, "deep.txt"), []byte("deep"), 0644))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	require.NoError(t, a.Attest(ctx))

	found := false
	for name := range a.Products() {
		if strings.HasSuffix(name, "deep.txt") {
			found = true
			break
		}
	}
	if !found {
		t.Error("deeply nested file should be found as a product")
	}
}

// =============================================================================
// Product with directory that has no read permission
// =============================================================================

func TestAdversarialProductUnreadableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, permission tests are meaningless")
	}

	workingDir := t.TempDir()

	// Create a readable file
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "readable.txt"), []byte("ok"), 0644))

	// Create an unreadable directory
	unreadableDir := filepath.Join(workingDir, "noaccess")
	require.NoError(t, os.Mkdir(unreadableDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(unreadableDir, "hidden.txt"), []byte("hidden"), 0644))
	require.NoError(t, os.Chmod(unreadableDir, 0000))
	t.Cleanup(func() {
		os.Chmod(unreadableDir, 0755) // restore for cleanup
	})

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	// BUG FINDING: RecordArtifacts (via filepath.Walk) returns an error on the first
	// unreadable directory rather than skipping it. This means a single unreadable
	// directory causes the entire product attestation to fail, even if other files
	// are perfectly readable. A more resilient approach would skip unreadable dirs.
	err = a.Attest(ctx)
	if err != nil {
		t.Logf("BUG: Attest failed entirely due to unreadable dir instead of skipping it: %v", err)
		t.Log("This means a single permission-denied directory causes total attestation failure.")
		// This is a real usability/resilience bug. In CI environments, some directories
		// may be temporarily unreadable. The attestor should degrade gracefully.
		return
	}

	products := a.Products()
	// The readable file should still be present
	if _, ok := products["readable.txt"]; !ok {
		t.Errorf("readable.txt should be in products even if sibling dir is unreadable. Products: %v", mapKeys(products))
	}
	// The hidden file should NOT be accessible
	for name := range products {
		if strings.Contains(name, "hidden") {
			t.Errorf("hidden.txt in unreadable dir should not be in products, but found: %s", name)
		}
	}
}

// =============================================================================
// Product with /dev/null and other special files
// =============================================================================

func TestAdversarialProductSpecialFiles(t *testing.T) {
	workingDir := t.TempDir()

	// Create a symlink to /dev/null inside working dir
	devNullLink := filepath.Join(workingDir, "devnull")
	err := os.Symlink("/dev/null", devNullLink)
	if err != nil {
		t.Skipf("cannot create symlink to /dev/null: %v", err)
	}

	// Create a normal file too
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "normal.txt"), []byte("normal"), 0644))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	// Should not panic on special files
	err = a.Attest(ctx)
	if err != nil {
		t.Logf("Attest with /dev/null symlink returned error: %v", err)
	}
}

// =============================================================================
// Product with file that changes during attestation (TOCTOU)
// =============================================================================

func TestAdversarialProductTOCTOU(t *testing.T) {
	workingDir := t.TempDir()

	// Create initial files
	changingFile := filepath.Join(workingDir, "changing.txt")
	require.NoError(t, os.WriteFile(changingFile, []byte("initial content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "stable.txt"), []byte("stable"), 0644))

	// Start a goroutine that continuously modifies the file during attestation
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			content := strings.Repeat("modified ", i+1)
			os.WriteFile(changingFile, []byte(content), 0644)
		}
	}()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	// The attestor reads the file to compute digests. If the file changes
	// mid-read, the digest may be for a partially-written file. This is a
	// fundamental TOCTOU issue that's hard to solve without file locking.
	err = a.Attest(ctx)
	<-done

	if err != nil {
		t.Logf("TOCTOU: Attest returned error (may be acceptable): %v", err)
	} else {
		// Even if it succeeds, the digest may not match what was "intended"
		products := a.Products()
		if prod, ok := products["changing.txt"]; ok {
			t.Logf("TOCTOU: changing.txt was recorded with digest: %v", prod.Digest)
			t.Log("NOTE: The recorded digest may correspond to ANY intermediate state of the file. " +
				"This is a fundamental TOCTOU limitation -- the attestor cannot guarantee the digest " +
				"matches the file as it was at any single point in time if the file is being modified.")
		}
	}
}

// =============================================================================
// Concurrent Attest() calls on same Attestor (race detector target)
// BUG: Attestor.Attest mutates a.compiledIncludeGlob, a.compiledExcludeGlob,
// a.baseArtifacts, and a.products without synchronization.
// =============================================================================

func TestAdversarialProductConcurrentAttest(t *testing.T) {
	workingDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "file2.txt"), []byte("content2"), 0644))

	a := New()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
			if err != nil {
				t.Errorf("NewContext error: %v", err)
				return
			}
			// BUG: This should trigger a data race on a.compiledIncludeGlob,
			// a.compiledExcludeGlob, a.baseArtifacts, and a.products
			_ = a.Attest(ctx)
		}()
	}
	wg.Wait()
}

// =============================================================================
// Product: MarshalJSON / UnmarshalJSON roundtrip
// =============================================================================

func TestAdversarialProductMarshalUnmarshalRoundtrip(t *testing.T) {
	a := New()
	a.products = map[string]attestation.Product{
		"file.txt": {
			MimeType: "text/plain",
			Digest: cryptoutil.DigestSet{
				{Hash: crypto.SHA256}: "abc123",
			},
		},
		"special\nname.bin": {
			MimeType: "application/octet-stream",
			Digest: cryptoutil.DigestSet{
				{Hash: crypto.SHA256}: "def456",
			},
		},
	}

	data, err := json.Marshal(a)
	require.NoError(t, err)

	b := New()
	require.NoError(t, json.Unmarshal(data, b))

	assert.Equal(t, len(a.products), len(b.products))
	for name, prod := range a.products {
		bProd, ok := b.products[name]
		require.True(t, ok, "missing product %q", name)
		assert.Equal(t, prod.MimeType, bProd.MimeType)
	}
}

func TestAdversarialProductUnmarshalMalformedJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty object", "{}"},
		{"null", "null"},
		{"empty string", `""`},
		{"array instead of object", "[]"},
		{"nested garbage", `{"file.txt": {"mimeType": 123}}`},
		{"missing digest", `{"file.txt": {"mimeType": "text/plain"}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := New()
			err := json.Unmarshal([]byte(tc.input), a)
			// We just care that it doesn't panic
			_ = err
		})
	}
}

// =============================================================================
// Product: Subjects() with nil compiled globs
// =============================================================================

func TestAdversarialProductSubjectsNilGlobs(t *testing.T) {
	// If Attest() was never called, compiledIncludeGlob and compiledExcludeGlob
	// are nil. Subjects() should handle this gracefully.
	a := New()
	a.products = map[string]attestation.Product{
		"file.txt": {
			MimeType: "text/plain",
			Digest: cryptoutil.DigestSet{
				{Hash: crypto.SHA256}: "abc123",
			},
		},
	}

	// Should not panic
	subjects := a.Subjects()
	// With nil globs, ALL products should become subjects (no include filter applied)
	if len(subjects) != 1 {
		t.Errorf("with nil globs, expected 1 subject, got %d", len(subjects))
	}
}

// =============================================================================
// Product: fromDigestMap with nonexistent files
// =============================================================================

func TestAdversarialFromDigestMapNonexistentFiles(t *testing.T) {
	digest, err := cryptoutil.CalculateDigestSetFromBytes(
		[]byte("test"),
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
	)
	require.NoError(t, err)

	digestMap := map[string]cryptoutil.DigestSet{
		"nonexistent.txt": digest,
	}

	// fromDigestMap should handle missing files gracefully (mimeType = "unknown")
	products := fromDigestMap("/tmp/nonexistent_dir_xyz", digestMap)
	assert.Len(t, products, 1)
	assert.Equal(t, "unknown", products["nonexistent.txt"].MimeType)
}

// =============================================================================
// Product: Empty working directory
// =============================================================================

func TestAdversarialProductEmptyWorkingDir(t *testing.T) {
	workingDir := t.TempDir()
	// Don't create any files

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	require.NoError(t, a.Attest(ctx))

	if len(a.Products()) != 0 {
		t.Errorf("empty working dir should produce 0 products, got %d", len(a.Products()))
	}
	if len(a.Subjects()) != 0 {
		t.Errorf("empty working dir should produce 0 subjects, got %d", len(a.Subjects()))
	}
}

// =============================================================================
// Product: Invalid include/exclude glob patterns
// =============================================================================

func TestAdversarialProductInvalidGlobs(t *testing.T) {
	workingDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "file.txt"), []byte("content"), 0644))

	t.Run("invalid include glob", func(t *testing.T) {
		a := New(WithIncludeGlob("[invalid"))
		ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
		require.NoError(t, err)
		err = a.Attest(ctx)
		// Should return error, not panic
		assert.Error(t, err, "invalid include glob should cause Attest to return error")
	})

	t.Run("invalid exclude glob", func(t *testing.T) {
		a := New(WithExcludeGlob("[invalid"))
		ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
		require.NoError(t, err)
		err = a.Attest(ctx)
		assert.Error(t, err, "invalid exclude glob should cause Attest to return error")
	})
}

// =============================================================================
// Product: IsSPDXJson / IsCycloneDXJson edge cases
// =============================================================================

func TestAdversarialIsSPDXJsonEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"nil", nil, false},
		{"just the key no version", []byte(`{"spdxVersion":""}`), false},
		{"truncated at exactly 500 bytes", make500BytesSPDX(), true},
		// IsSPDXJson only inspects the first 500 bytes. If the marker starts at
		// offset 490, the 20-byte marker "spdxVersion":"SPDX-" is truncated at 500.
		// This means SPDX files with the marker late in the header will not be detected.
		{"SPDX marker starts at byte 490 - truncated by 500-byte window", makeSPDXAtOffset(490), false},
		// But if it starts early enough to fit within 500 bytes, it should be detected
		{"SPDX marker starts at byte 470 - fits in 500-byte window", makeSPDXAtOffset(470), true},
		{"binary garbage", []byte{0xff, 0xfe, 0xfd, 0x00, 0x01}, false},
		{"very large non-SPDX", make([]byte, 10000), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsSPDXJson(tc.input)
			if result != tc.expected {
				t.Errorf("IsSPDXJson() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestAdversarialIsCycloneDXJsonEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"nil", nil, false},
		{"partial match", []byte(`{"bomFormat":"Cyclo`), false},
		{"wrong format", []byte(`{"bomFormat":"NotCycloneDX"}`), false},
		{"binary garbage", []byte{0xff, 0xfe, 0xfd, 0x00}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsCycloneDXJson(tc.input)
			if result != tc.expected {
				t.Errorf("IsCycloneDXJson() = %v, want %v", result, tc.expected)
			}
		})
	}
}

// =============================================================================
// Product: safeGlobMatch panic recovery
// =============================================================================

func TestAdversarialProductSafeGlobMatchPanicPatterns(t *testing.T) {
	// These patterns are known to cause panics in gobwas/glob
	// The product attestor has its own safeGlobMatch -- test it
	panicPatterns := []string{
		"0*,{*,",
		"*{*,",
		"*{a,b,*",
	}

	for _, pattern := range panicPatterns {
		t.Run(pattern, func(t *testing.T) {
			a := New(WithIncludeGlob(pattern))
			ctx, err := attestation.NewContext("test", []attestation.Attestor{},
				attestation.WithWorkingDir(t.TempDir()))
			require.NoError(t, err)
			// Should error from glob.Compile, not panic
			err = a.Attest(ctx)
			if err != nil {
				t.Logf("Expected error from invalid pattern: %v", err)
			}
		})
	}
}

// =============================================================================
// Product: file with special characters in name
// =============================================================================

func TestAdversarialProductSpecialCharFilenames(t *testing.T) {
	workingDir := t.TempDir()

	specialNames := []string{
		"file with spaces.txt",
		"file\twith\ttabs.txt",
		"file'with'quotes.txt",
		"file\"with\"doublequotes.txt",
		"file(with)parens.txt",
		"file[with]brackets.txt",
		"file{with}braces.txt",
		"file#with#hash.txt",
		"file@with@at.txt",
		"file$with$dollar.txt",
		"file!with!bang.txt",
		// Unicode filenames
		"\u00e9\u00e8\u00ea.txt",
		"\u4e2d\u6587.txt",
	}

	createdCount := 0
	for _, name := range specialNames {
		path := filepath.Join(workingDir, name)
		err := os.WriteFile(path, []byte("content for "+name), 0644)
		if err != nil {
			t.Logf("skipping filename %q: %v", name, err)
			continue
		}
		createdCount++
	}

	if createdCount == 0 {
		t.Skip("could not create any special-character files")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	require.NoError(t, a.Attest(ctx))

	products := a.Products()
	t.Logf("Created %d special-char files, got %d products", createdCount, len(products))
	if len(products) != createdCount {
		t.Errorf("expected %d products, got %d", createdCount, len(products))
	}
}

// =============================================================================
// Product: empty file
// =============================================================================

func TestAdversarialProductEmptyFile(t *testing.T) {
	workingDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "empty.txt"), []byte{}, 0644))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
	require.NoError(t, err)

	a := New()
	require.NoError(t, a.Attest(ctx))

	products := a.Products()
	if _, ok := products["empty.txt"]; !ok {
		t.Error("empty file should still be recorded as a product")
	}
}

// =============================================================================
// Helpers
// =============================================================================

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func make500BytesSPDX() []byte {
	prefix := `{"spdxVersion":"SPDX-2.3","`
	// Pad to exactly 500 bytes
	padding := strings.Repeat("x", 500-len(prefix)-2)
	return []byte(prefix + padding + `"}`)
}

func makeSPDXAtOffset(offset int) []byte {
	padding := strings.Repeat(" ", offset)
	return []byte(padding + `"spdxVersion":"SPDX-2.3"`)
}
