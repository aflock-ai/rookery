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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/stretchr/testify/require"
)

// TestAttest_WalkMode_SameContentRebuildCaptured is the end-to-end regression
// for the walk-mode silent product drop. It exercises the FULL path the file-
// level tests don't: product.go's commandStartTime helper reading the real
// CommandRun.StartedAt(), threaded into file.RecordArtifacts.
//
// Scenario: a file already exists in the workspace (so the material attestor
// snapshots it as an input). The wrapped command rewrites that exact path with
// byte-identical content — a deterministic rebuild. The content digest is
// unchanged, so the legacy digest-only dedup would silently drop it and the
// signed attestation would carry ZERO products. With the mtime signal the
// rewrite (mtime >= command start) is correctly recorded as a product.
//
// The command sleeps ~1.1s before writing so the output's mtime lands a full
// second after the captured command-start instant — deterministic even on
// filesystems with 1-second mtime granularity (no sub-second flake).
func TestAttest_WalkMode_SameContentRebuildCaptured(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh to drive a real command run")
	}

	const content = "deterministic-build-output"
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	require.NoError(t, os.WriteFile(out, []byte(content), 0o600))

	mat := material.New()
	cmd := commandrun.New(
		commandrun.WithCommand([]string{"sh", "-c", "sleep 1.1; printf '%s' '" + content + "' > out"}),
		commandrun.WithSilent(true),
	)
	prod := New()

	ctx, err := attestation.NewContext(
		"build",
		[]attestation.Attestor{mat, cmd, prod},
		attestation.WithWorkingDir(dir),
		// t.TempDir() lives under /tmp or /var/folders, both default cache
		// patterns — disable the cache classifier so this exercises the
		// mtime rule, not the cache filter.
		attestation.WithCachePatternOptions(attestation.CachePatternOptions{
			DisableDefaults:    true,
			DisableSystemQuery: true,
		}),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.True(t, productKeyEndingIn(prod.Products(), "out"),
		"a pre-existing file the build rewrote with identical content must be recorded as a product in walk mode "+
			"(mtime >= command start); got products = %v", productKeys(prod.Products()))
}
