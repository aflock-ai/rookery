// Copyright 2026 TestifySec, Inc.
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
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// Helpers
// =====================================================================

// makeAttestor builds an Attestor against a fresh temp dir populated
// with files (path → content), runs Attest, and returns the attestor.
func makeAttestor(t *testing.T, files map[string]string) *Attestor {
	t.Helper()
	return makeAttestorWithOpts(t, files)
}

func makeAttestorWithOpts(t *testing.T, files map[string]string, opts ...Option) *Attestor {
	t.Helper()
	dir := t.TempDir()
	for relPath, content := range files {
		full := filepath.Join(dir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}

	a := New(opts...)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))
	return a
}

// expectedRootFromLeaves recomputes the v0.3 merkle root the same way
// the production code does but using crypto/sha256 directly — RFC 6962
// §2.1 leaf-prefix then iterative pair hashing. If the in-process
// implementation drifts from the documented algorithm this helper will
// catch it.
func expectedRootFromLeaves(t *testing.T, leaves []ProductLeaf) []byte {
	t.Helper()
	if len(leaves) == 0 {
		// RFC 6962 §2.1: empty tree root is sha256("").
		empty := sha256.Sum256(nil)
		return empty[:]
	}

	// Apply 0x00 leaf prefix to the LeafHash bytes (which are already the
	// path-bound pre-hash). RFC 6962: MTH({d_0}) = H(0x00 || d_0).
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		raw, err := hex.DecodeString(strings.TrimPrefix(l.LeafHash, "sha256:"))
		require.NoError(t, err)
		require.Len(t, raw, sha256.Size)
		h := sha256.New()
		_, _ = h.Write([]byte{0x00})
		_, _ = h.Write(raw)
		hashes[i] = h.Sum(nil)
	}

	// Iteratively reduce: pair adjacent hashes with the 0x01 interior
	// prefix. RFC 6962: MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
	// with k = largest power of two < n. This loop implementation only
	// matches the production tree for perfectly balanced trees and for
	// the n-power-of-2 + remainder cases we exercise; for any n we want
	// to test the production code defines truth, not this helper. We
	// keep the helper for the empty / single-file cases and for direct
	// leaf-encoding inspection.
	if len(hashes) == 1 {
		return hashes[0]
	}
	// Fall through to the production code's root for larger trees.
	return nil
}

func sha256Hex(t *testing.T, content string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// =====================================================================
// Test 1 — deterministic root: same input set, same root
// =====================================================================

func TestDeterministicRoot(t *testing.T) {
	files := map[string]string{
		"a.txt":     "alpha",
		"b/c.txt":   "bravo",
		"d/e/f.txt": "delta",
	}
	a1 := makeAttestor(t, files)
	a2 := makeAttestor(t, files)

	require.NotEmpty(t, a1.MerkleRoot)
	require.Equal(t, a1.MerkleRoot, a2.MerkleRoot, "two attestations over the same file set must produce the same root")
	require.Equal(t, a1.TreeSize, a2.TreeSize)
}

// =====================================================================
// Test 2 — path order does not affect root (deterministic sort)
// =====================================================================

func TestPathOrderInsensitive(t *testing.T) {
	// Two filesystem layouts with the SAME logical file set: walk order
	// from the OS is not stable but the root must be.
	filesA := map[string]string{
		"x.txt":     "X",
		"y.txt":     "Y",
		"z/w.txt":   "W",
		"a/b/c.txt": "C",
	}
	// Same content, written in a different alphabet-mangled order via
	// path prefixes. The walker sees these in whatever order the OS
	// returns; the attestor must normalize.
	filesB := map[string]string{
		"a/b/c.txt": "C",
		"z/w.txt":   "W",
		"y.txt":     "Y",
		"x.txt":     "X",
	}

	a := makeAttestor(t, filesA)
	b := makeAttestor(t, filesB)
	require.Equal(t, a.MerkleRoot, b.MerkleRoot,
		"path ordering of the input must not affect the merkle root")

	// Also confirm leaves are sorted in the attestor's own leaves slice
	// — this is the contract the inclusion-proof attestor relies on.
	leaves := a.Leaves()
	for i := 1; i < len(leaves); i++ {
		assert.True(t, leaves[i-1].Path < leaves[i].Path,
			"leaves must be sorted by path; got %q before %q", leaves[i-1].Path, leaves[i].Path)
	}
}

// =====================================================================
// Test 3 — path-binding: same content, different paths → different roots
// =====================================================================

func TestPathBinding(t *testing.T) {
	const content = "identical content"

	a := makeAttestor(t, map[string]string{"path/one.txt": content})
	b := makeAttestor(t, map[string]string{"path/two.txt": content})

	require.NotEqual(t, a.MerkleRoot, b.MerkleRoot,
		"two files with identical content but different paths must produce different roots")

	// And the leaf-level pre-hashes themselves must differ — that is
	// where the path binding originates.
	require.Len(t, a.Leaves(), 1)
	require.Len(t, b.Leaves(), 1)
	require.NotEqual(t, a.Leaves()[0].LeafHash, b.Leaves()[0].LeafHash)
}

// =====================================================================
// Test 4 — empty product set: size 0, root = sha256("")
// =====================================================================

func TestEmptyProductSet(t *testing.T) {
	a := makeAttestor(t, map[string]string{})

	require.Equal(t, uint64(0), a.TreeSize)

	emptyRoot := sha256.Sum256(nil)
	require.Equal(t, hex.EncodeToString(emptyRoot[:]), a.MerkleRoot,
		"empty tree root must be SHA-256 of the empty string per RFC 6962 §2.1")
}

// =====================================================================
// Test 5 — single-file tree: known root from precomputation
// =====================================================================

func TestSingleFileTree(t *testing.T) {
	const path = "only.txt"
	const content = "hello v0.3"

	a := makeAttestor(t, map[string]string{path: content})
	require.Equal(t, uint64(1), a.TreeSize)

	// Hand-compute the expected root: sha256(0x00 || sha256(path || 0x00 || sha256(content)))
	fileDigest := sha256.Sum256([]byte(content))
	preHashWriter := sha256.New()
	_, _ = preHashWriter.Write([]byte(path))
	_, _ = preHashWriter.Write([]byte{0x00})
	_, _ = preHashWriter.Write(fileDigest[:])
	preHash := preHashWriter.Sum(nil)

	rootWriter := sha256.New()
	_, _ = rootWriter.Write([]byte{0x00}) // RFC 6962 leaf prefix
	_, _ = rootWriter.Write(preHash)
	expectedRoot := rootWriter.Sum(nil)

	require.Equal(t, hex.EncodeToString(expectedRoot), a.MerkleRoot,
		"single-file root must be H(0x00 || H(path || 0x00 || file-digest))")

	// And the cross-check helper for the single-file case.
	expectedRootFromHelper := expectedRootFromLeaves(t, a.Leaves())
	require.Equal(t, expectedRoot, expectedRootFromHelper,
		"helper-derived single-file root must match production")

	// Leaf metadata round-trip.
	leaves := a.Leaves()
	require.Len(t, leaves, 1)
	require.Equal(t, path, leaves[0].Path)
	require.Equal(t, hex.EncodeToString(fileDigest[:]), leaves[0].FileDigest)
	require.Equal(t, hex.EncodeToString(preHash), leaves[0].LeafHash)
}

// =====================================================================
// Test 6 — Subjects() returns only tree:products
// =====================================================================

func TestSubjectsOnlyTreeProducts(t *testing.T) {
	a := makeAttestor(t, map[string]string{
		"x.txt": "X",
		"y.txt": "Y",
	})
	subjects := a.Subjects()
	require.Len(t, subjects, 1, "exactly one subject expected")

	digest, ok := subjects[TreeSubjectName]
	require.True(t, ok, "subject must be named %q", TreeSubjectName)
	require.Len(t, digest, 1, "subject digest set must contain one entry (sha256)")
	// And the digest value must be the hex-encoded root.
	for _, v := range digest {
		require.Equal(t, a.MerkleRoot, v)
	}
}

// =====================================================================
// Test 7 — BackRefs() returns only tree:products
// =====================================================================

func TestBackRefsOnlyTreeProducts(t *testing.T) {
	a := makeAttestor(t, map[string]string{
		"x.txt": "X",
		"y.txt": "Y",
	})

	backRefs := a.BackRefs()
	require.Len(t, backRefs, 1, "BackRefs must mirror Subjects: one tree subject")

	digest, ok := backRefs[TreeSubjectName]
	require.True(t, ok, "BackRefs subject must be named %q", TreeSubjectName)
	require.Equal(t, a.Subjects()[TreeSubjectName], digest,
		"BackRefs digest must equal the Subjects digest")
}

// =====================================================================
// Test 8 — sidecar round-trip
// =====================================================================

func TestSidecarRoundTrip(t *testing.T) {
	files := map[string]string{
		"a/b.txt":   "alpha-bravo",
		"c.txt":     "charlie",
		"d/e/f.txt": "delta-echo-foxtrot",
	}
	a := makeAttestor(t, files)

	// BuildSidecar produces the canonical inclusion-proof sidecar shape.
	// This is the SAME shape `cilock run` writes adjacent to the signed
	// attestation and the SAME shape `cilock prove` reads. No parallel
	// sidecar format exists.
	side, err := a.BuildSidecar()
	require.NoError(t, err)

	require.Equal(t, inclusionproof.SidecarSchemaVersion, side.SchemaVersion)
	require.Equal(t, "product", side.Source)
	require.Equal(t, a.MerkleRoot, side.MerkleRoot,
		"sidecar merkleRoot must equal the signed predicate's root")
	require.Equal(t, a.TreeSize, side.TreeSize)
	require.Equal(t, HashAlgorithm, side.HashAlgorithm)
	require.Equal(t, Construction, side.Construction)
	require.Len(t, side.Leaves, len(files))

	// Round-trip through JSON and reconstruct the tree to verify the
	// sidecar is sufficient to reproduce the signed root. This is the
	// real verifiability handshake.
	buf, err := json.Marshal(side)
	require.NoError(t, err)
	var roundTripped inclusionproof.Sidecar
	require.NoError(t, json.Unmarshal(buf, &roundTripped))

	tree, _, err := roundTripped.Reconstruct()
	require.NoError(t, err, "reconstruct must succeed against the canonical sidecar")
	require.Equal(t, a.MerkleRoot, hex.EncodeToString(tree.Root()),
		"reconstructed root from sidecar must match signed root")

	// Each input file must be present as a leaf with its unprefixed
	// hex sha256.
	got := make(map[string]inclusionproof.SidecarLeaf, len(roundTripped.Leaves))
	for _, l := range roundTripped.Leaves {
		got[l.Path] = l
	}
	for path, content := range files {
		l, ok := got[path]
		require.True(t, ok, "sidecar must contain leaf for %q", path)
		require.Equal(t, sha256Hex(t, content), l.FileDigest,
			"fileDigest mismatch for %q", path)
	}
}

// =====================================================================
// Test 9 — sidecar is NOT signed and NOT in the predicate
// =====================================================================

func TestSidecarNotInPredicate(t *testing.T) {
	a := makeAttestor(t, map[string]string{
		"a.txt": "alpha",
		"b.txt": "bravo",
	})
	require.NotEmpty(t, a.Leaves(), "preconditioning: leaves must be populated")

	data, err := json.Marshal(a)
	require.NoError(t, err)

	// The signed predicate must NOT contain the per-file leaves slice
	// (the whole point of v0.3 is the predicate stays O(1) regardless
	// of product count).
	var generic map[string]any
	require.NoError(t, json.Unmarshal(data, &generic))

	_, hasLeaves := generic["leaves"]
	require.False(t, hasLeaves, "signed predicate must NOT contain 'leaves' field; got %v", generic)

	_, hasProducts := generic["products"]
	require.False(t, hasProducts, "signed predicate must NOT contain 'products' field; got %v", generic)

	// And the predicate MUST contain the four canonical fields.
	require.Contains(t, generic, "merkleRoot")
	require.Contains(t, generic, "treeSize")
	require.Contains(t, generic, "hashAlgorithm")
	require.Contains(t, generic, "construction")
}

// =====================================================================
// Supporting tests — package-level invariants
// =====================================================================

func TestAttestorName(t *testing.T) {
	assert.Equal(t, "product", New().Name())
}

func TestAttestorType(t *testing.T) {
	assert.Equal(t, "https://aflock.ai/attestations/product/v0.3", New().Type())
}

func TestAttestorRunType(t *testing.T) {
	assert.Equal(t, attestation.ProductRunType, New().RunType())
}

func TestSchema(t *testing.T) {
	require.NotNil(t, New().Schema(), "schema must be non-nil")
}

func TestPredicateRoundTripJSON(t *testing.T) {
	a := makeAttestor(t, map[string]string{"a.txt": "a"})
	data, err := json.Marshal(a)
	require.NoError(t, err)

	var b Attestor
	require.NoError(t, json.Unmarshal(data, &b))
	require.Equal(t, a.MerkleRoot, b.MerkleRoot)
	require.Equal(t, a.TreeSize, b.TreeSize)
	require.Equal(t, a.HashAlgorithmField, b.HashAlgorithmField)
	require.Equal(t, a.ConstructionField, b.ConstructionField)
	// Leaves must NOT survive — they are out of band.
	require.Empty(t, b.Leaves())
}

// TestIncludeExcludeGlobs verifies the glob options filter products
// before tree construction and that the resulting root reflects only
// the included file set.
func TestIncludeExcludeGlobs(t *testing.T) {
	files := map[string]string{
		"keep.txt":     "K",
		"drop.bin":     "D",
		"sub/keep.txt": "SK",
		"sub/drop.bin": "SD",
	}

	all := makeAttestor(t, files)
	require.Equal(t, uint64(4), all.TreeSize)

	includeOnly := makeAttestorWithOpts(t, files, WithIncludeGlob("**/*.txt"))
	require.LessOrEqual(t, includeOnly.TreeSize, all.TreeSize)
	require.NotEqual(t, all.MerkleRoot, includeOnly.MerkleRoot,
		"different included sets must produce different roots")

	excludeBins := makeAttestorWithOpts(t, files, WithExcludeGlob("**/*.bin"))
	require.NotEqual(t, all.MerkleRoot, excludeBins.MerkleRoot,
		"excluding files must change the root")
}

// =====================================================================
// MIME helpers — kept from v0.1/v0.2 because sbom relies on them.
// =====================================================================

func TestIsSPDXJson(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"spdx no space", []byte(`{"spdxVersion":"SPDX-2.3","other":"x"}`), true},
		{"spdx with space", []byte(`{"spdxVersion": "SPDX-2.2","other":"x"}`), true},
		{"not spdx", []byte(`{"foo":"bar"}`), false},
		{"empty", []byte{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsSPDXJson(tc.input))
		})
	}
}

func TestIsCycloneDXJson(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"cdx no space", []byte(`{"bomFormat":"CycloneDX","other":"x"}`), true},
		{"cdx with space", []byte(`{"bomFormat": "CycloneDX","other":"x"}`), true},
		{"not cdx", []byte(`{"foo":"bar"}`), false},
		{"empty", []byte{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsCycloneDXJson(tc.input))
		})
	}
}

// =====================================================================
// Issue #152 — traced rename / direct-write capture
// =====================================================================
//
// When `cilock run --trace` is enabled, the product attestor only records
// files that were `open()`'d by traced processes. Atomic-rename builds
// (`go build`: open(out.tmp) → write → rename(out.tmp, out)) never `open()`
// the final destination — it appears via a `rename` syscall instead. The
// product attestor must also consume `FileOps.Renames[].NewPath` and
// `FileOps.Writes[].Path` from each traced ProcessInfo so the post-rename
// destination is included in the capture set. Without this, SBOM (which
// iterates products) fails with `no products to attest` and cilock's own
// release pipeline cannot run with --trace enabled — observed across
// rc1-rc4 of the v1.1.0 release.
//
// These two tests construct a synthetic CommandRun in the completed-
// attestors slice and then run the product attestor against it directly.
// The CommandRun has an empty Cmd, so its Attest() returns early without
// executing anything (the empty-Cmd guard at the top of commandrun.Attest).
// That gets it into ctx.CompletedAttestors() with our pre-populated
// Processes intact — no fork/exec, no ptrace, cross-platform.

// attestWithTracedCommandRun is a helper that:
//  1. builds a temp working dir and writes `out` to it
//  2. constructs a CommandRun with WithTracing(true), no Cmd, and the
//     caller-supplied ProcessInfo
//  3. runs the commandrun attestor through RunAttestors so it ends up in
//     ctx.CompletedAttestors() (Attest returns an empty-Cmd error, which
//     is appended along with the attestor)
//  4. runs the product attestor directly against the populated context
//  5. returns the product attestor (working dir is t.TempDir, auto-cleaned)
//
// The CommandRun's Processes field is set BEFORE RunAttestors. The empty-
// Cmd Attest path does not touch Processes, so our synthetic data survives
// through to product.Attest -> CompletedAttestors() lookup.
func attestWithTracedCommandRun(t *testing.T, proc commandrun.ProcessInfo) *Attestor {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "out"), []byte("simulated go build output"), 0o600))

	cmd := commandrun.New(commandrun.WithTracing(true))
	cmd.Processes = []commandrun.ProcessInfo{proc}

	ctx, err := attestation.NewContext(
		"test",
		[]attestation.Attestor{cmd},
		attestation.WithWorkingDir(dir),
		// t.TempDir() returns paths under /var/folders/** (macOS) or
		// /tmp/** (Linux) — both are in DefaultCachePatterns, so the
		// cache matcher would correctly classify the rename target as
		// "temp" and drop it from the product set. Disable the cache
		// classifier here so the test exercises rename → product
		// classification specifically, not the cache-filter interaction.
		attestation.WithCachePatternOptions(attestation.CachePatternOptions{
			DisableDefaults:    true,
			DisableSystemQuery: true,
		}),
	)
	require.NoError(t, err)

	// commandrun.Attest returns an error on empty Cmd, but the attestor is
	// still appended to completedAttestors with Error set. Product's
	// CompletedAttestors() walk doesn't gate on Error, so our synthetic
	// CommandRun is visible downstream.
	_ = ctx.RunAttestors()

	// Default include glob is "*", which gobwas/glob matches across
	// path separators, so the absolute resolved key (e.g.
	// /var/folders/.../out) is matched. Default products map keys
	// are likewise absolute since ddea2c1 — assertions need to look
	// up the resolved path, not the original relative "out".
	prod := New()
	require.NoError(t, prod.Attest(ctx))
	return prod
}

// productKeyEndingIn finds a product key whose path component ends in
// the relative path the test cares about. Lets the test assert on a
// stable relative anchor while the production code stores absolute
// keys (post-ddea2c1) that vary across t.TempDir() invocations.
func productKeyEndingIn(products map[string]attestation.Product, rel string) bool {
	for k := range products {
		if strings.HasSuffix(k, "/"+rel) || k == rel {
			return true
		}
	}
	return false
}

// TestAttest_TracedRenamedFile_StillCaptured is the regression test for
// issue #152: a build tool that produces its final artifact by renaming a
// temp file (atomic-rename) must still show up in the product set when
// --trace is on. The destination `out` is in FileOps.Renames[0].NewPath
// but NOT in OpenedFiles — exactly the shape `go build` produces.
func TestAttest_TracedRenamedFile_StillCaptured(t *testing.T) {
	prod := attestWithTracedCommandRun(t, commandrun.ProcessInfo{
		OpenedFiles: map[string]cryptoutil.DigestSet{
			"out.tmp": nil, // only the temp file was open()'d
		},
		FileOps: &commandrun.FileActivity{
			Renames: []commandrun.FileRename{
				{OldPath: "out.tmp", NewPath: "out"},
			},
		},
	})

	products := prod.Products()
	ok := productKeyEndingIn(products, "out")
	require.True(t, ok,
		"product ending in `/out` (rename destination, workdir-resolved) must be in capture set under --trace; "+
			"got products = %v", productKeys(products))
}

// TestAttest_TracedDirectlyWrittenFile_StillCaptured covers the sibling
// case where a traced process writes directly to its final destination
// (no rename). The destination shows up in FileOps.Writes[].Path. This
// is the simpler branch of the same fix.
func TestAttest_TracedDirectlyWrittenFile_StillCaptured(t *testing.T) {
	prod := attestWithTracedCommandRun(t, commandrun.ProcessInfo{
		OpenedFiles: map[string]cryptoutil.DigestSet{},
		FileOps: &commandrun.FileActivity{
			Writes: []commandrun.FileWrite{
				{Path: "out", Bytes: 25},
			},
		},
	})

	products := prod.Products()
	ok := productKeyEndingIn(products, "out")
	require.True(t, ok,
		"product ending in `/out` (direct write target, workdir-resolved) must be in capture set under --trace; "+
			"got products = %v", productKeys(products))
}

// productKeys is a tiny helper to make failure messages legible — listing
// the actual captured product set helps diagnose path-format regressions.
func productKeys(m map[string]attestation.Product) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestGetFileContentType(t *testing.T) {
	tempDir := t.TempDir()

	txtFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(txtFile, []byte("This is a test file."), 0o644))

	pdfFile := filepath.Join(tempDir, "test.pdf")
	require.NoError(t, os.WriteFile(pdfFile, []byte{0x25, 0x50, 0x44, 0x46, 0x2D}, 0o644))

	tarFile := filepath.Join(tempDir, "test.tar")
	tarBuffer := new(bytes.Buffer)
	writer := tar.NewWriter(tarBuffer)
	header := &tar.Header{Name: "test.txt", Size: int64(len("This is a test file."))}
	require.NoError(t, writer.WriteHeader(header))
	_, err := writer.Write([]byte("This is a test file."))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, os.WriteFile(tarFile, tarBuffer.Bytes(), 0o644))

	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{"text", txtFile, "text/plain; charset=utf-8"},
		{"pdf", pdfFile, "application/pdf"},
		{"tar", tarFile, "application/x-tar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := getFileContentType(tc.filePath)
			require.NoError(t, err)
			require.Equal(t, tc.expected, ct)
		})
	}
}
