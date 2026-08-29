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

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// --require-products
// =====================================================================
//
// The warning next door tells an operator their envelope has no binary
// subject. These tests cover the enforcing form: a caller that declared the
// step exists to prove an artifact gets a REFUSAL instead of a signed,
// well-formed collection that identifies nothing.
//
// The attestor here is real and walks a real directory — the property under
// test is "did anything the step produced reach the Merkle tree", and a stubbed
// attestor would only restate the answer the test wants.

// productOver runs the product attestor over a directory containing files,
// exactly as a wrapped command's working directory would look afterwards.
func productOver(t *testing.T, glob string, files map[string]string) *product.Attestor {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	a := product.New(product.WithIncludeGlob(glob))
	ctx, err := attestation.NewContext("promote-image-judge-api", []attestation.Attestor{}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))
	return a
}

// The production failure, reduced: the step's pin never wrote its manifest, so
// the working directory is empty when the product attestor walks it. Every
// other attestor still has something to say — the commit, the pipeline, the
// tenant — which is exactly why this has to be refused rather than warned
// about. The envelope would look like a completed promote.
func TestRequireProductsRefusesACollectionThatIdentifiesNoArtifact(t *testing.T) {
	prod := productOver(t, "manifest.json", nil)
	cmd := commandrun.New(commandrun.WithCommand([]string{"promote"}))

	err := requireProductSubject([]attestation.Attestor{prod, cmd, material.New()})

	require.Error(t, err, "a product attestor with no leaves must be refused")
	require.Contains(t, err.Error(), "--require-products")
	require.Contains(t, err.Error(), "no product subject", "the error must name what is missing")
}

// A file that exists but does not match the include-glob is the same failure
// wearing a disguise: the step produced something, and the collection still
// carries no subject for the artifact the caller asked for.
func TestRequireProductsRefusesWhenNothingMatchesTheIncludeGlob(t *testing.T) {
	prod := productOver(t, "manifest.json", map[string]string{"build.log": "no manifest here"})

	err := requireProductSubject([]attestation.Attestor{prod})

	require.Error(t, err, "files outside the include-glob are not the artifact the caller declared")
}

// The passing case, and the reason the check reads LEAVES: a leaf carries the
// path and the content digest the tree root commits to, which is what becomes
// the collection's product subject. For an image manifest that digest is the
// image digest itself.
func TestRequireProductsAcceptsAPinnedArtifactAndTheLeafCarriesItsDigest(t *testing.T) {
	const manifest = "{\n  \"schemaVersion\": 2\n}"
	prod := productOver(t, "manifest.json", map[string]string{"manifest.json": manifest})

	require.NoError(t, requireProductSubject([]attestation.Attestor{prod}))

	leaves := prod.Leaves()
	require.Len(t, leaves, 1)
	sum := sha256.Sum256([]byte(manifest))
	require.Equal(t, hex.EncodeToString(sum[:]), leaves[0].FileDigest,
		"the product subject must be the digest of the bytes on disk, unaltered")
	require.True(t, strings.HasSuffix(leaves[0].Path, "manifest.json"))
}

// A leftover the wrapped command could not delete — the concrete case is a
// stale manifest.json in a workingdir that has become non-writable, so the pin
// refuses and exits non-zero — must never be attested as this run's product.
//
// It cannot be, and this pins WHY, because the reason is not obvious and a
// reader who assumes otherwise will "fix" it by weakening something. The
// product attestor diffs the workingdir against the material snapshot taken
// BEFORE the command ran: a file whose content is unchanged and whose mtime
// predates the command is deduped as a MATERIAL, never promoted to a product
// (attestation/file/file.go, shouldRecord). A file the command could not
// modify is by definition unchanged, so no leaf exists for a products-present
// check to be fooled by — the run is refused for having NO product at all.
//
// Both halves are asserted: the stale file is absent from the products, and
// --require-products still refuses the run.
func TestAStaleFileTheCommandCouldNotTouchIsNeverThisRunsProduct(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "manifest.json")
	require.NoError(t, os.WriteFile(stale, []byte("STALE MANIFEST FROM AN EARLIER RUN"), 0o600))

	prod := product.New(product.WithIncludeGlob("manifest.json"))
	// `false` stands in for a pin that refused: the command exits non-zero
	// having changed nothing, exactly as the pin does when it cannot clear the
	// product path.
	cmd := commandrun.New(commandrun.WithCommand([]string{"false"}))
	ctx, err := attestation.NewContext(
		"promote-image-judge-api",
		[]attestation.Attestor{material.New(), cmd, prod},
		attestation.WithWorkingDir(dir),
	)
	require.NoError(t, err)
	// The wrapped command fails on purpose; the product stage still runs, which
	// is the whole reason a leftover would be dangerous if it were recorded.
	_ = ctx.RunAttestors()

	for _, leaf := range prod.Leaves() {
		require.NotEqual(t, staleDigest(t, stale), leaf.FileDigest,
			"a file this run could not touch was attested as its product")
	}
	require.Empty(t, prod.Leaves(), "an unchanged leftover must not appear in the product tree at all")
	require.Error(t, requireProductSubject([]attestation.Attestor{prod, cmd}),
		"with no product of its own, the run must be refused rather than shipped with a stale leaf")
}

func staleDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Dropping the product attestor is another way to reach a subjectless
// collection, and it must not read as "nothing to check, carry on".
func TestRequireProductsRefusesWhenTheProductAttestorWasDropped(t *testing.T) {
	err := requireProductSubject([]attestation.Attestor{commandrun.New(commandrun.WithCommand([]string{"promote"}))})

	require.Error(t, err)
	require.Contains(t, err.Error(), "no product attestor ran")
}
