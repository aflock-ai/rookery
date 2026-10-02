// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/require"
)

// pushTestsEnvelopeBudget is the done-condition #8410 set for a push-tests
// envelope on a repository of this size: under 100 KiB.
const pushTestsEnvelopeBudget = 100 << 10

// runEnvelopeBytes runs one default-profile `cilock run` over a work tree
// holding n files and returns the size of the signed envelope it wrote.
func runEnvelopeBytes(t *testing.T, n int) int64 {
	t.Helper()
	inventoryProfile(t, "compact", "131072")
	ro, signer, _ := inventoryRunFixture(t)
	for i := 0; i < n; i++ {
		dir := filepath.Join(ro.WorkingDir, fmt.Sprintf("d%03d", i%100))
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d.txt", i)), []byte(fmt.Sprintf("content %d", i)), 0o600))
	}
	stdout, _, err := inventoryCapture(t, func() error {
		return runRun(t.Context(), ro, []string{"sh", "-c", "true"}, nil, nil, signer)
	})
	require.NoError(t, err)
	var summary options.RunSummary
	require.NoError(t, json.Unmarshal(stdout, &summary))
	info, err := os.Stat(summary.OutFile)
	require.NoError(t, err)
	return info.Size()
}

// TestEnvelopeSizeDoesNotGrowWithFileCount is #8410's property: the material
// attestor walks every file in the tree, and the default (compact) profile must
// keep the per-file leaves out of the signed envelope, so the bytes the edge,
// the 4 MiB attestation cap and the Archivista upload deadline see do not scale
// with the repository. The legacy profile measured 4.95 MiB over 17,152 files
// (~226 B/leaf); at 3,000 files that profile alone would be roughly 0.65 MiB,
// so the budget below fails on any regression to inline leaves.
func TestEnvelopeSizeDoesNotGrowWithFileCount(t *testing.T) {
	small := runEnvelopeBytes(t, 1)
	large := runEnvelopeBytes(t, 3000)
	require.Less(t, large, int64(pushTestsEnvelopeBudget), "a push-tests-shaped envelope must stay under 100 KiB")
	// 3,000 more files may move the envelope by the digits in a count and a
	// root hash, never by a per-file amount (226 B x 2,999 = 678 KB).
	require.Less(t, large-small, int64(2<<10), "envelope grew by %d bytes for 2,999 extra files: material leaves are inline again", large-small)
}
