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

package file

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

func sha256Only() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

// TestRecordArtifacts_SameContentRewriteRecordedByMtime is the regression for
// the silent product drop. Walk mode classifies a file as a product only when
// its content digest differs from the pre-command snapshot. A deterministic
// rebuild (or any build that rewrites byte-identical output) produces no
// digest delta, so the real build output silently vanished from the
// attestation. Walk mode can't observe the write syscall the way the eBPF
// tracer can, so mtime >= cmdStart is the signal that the file was produced
// during the run.
func TestRecordArtifacts_SameContentRewriteRecordedByMtime(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hugo-bin")
	require.NoError(t, os.WriteFile(out, []byte("identical-bytes"), 0o644))

	// Pre-command snapshot: the file already exists with this content, so it
	// is a material going in.
	base, err := cryptoutil.CalculateDigestSetFromFile(out, sha256Only())
	require.NoError(t, err)
	baseArtifacts := map[string]cryptoutil.DigestSet{"hugo-bin": base}

	// The command runs and rewrites the SAME bytes (deterministic rebuild).
	cmdStart := time.Now()
	require.NoError(t, os.WriteFile(out, []byte("identical-bytes"), 0o644))
	// Pin mtime unambiguously at/after cmdStart to avoid sub-second flake.
	rewrite := cmdStart.Add(2 * time.Second)
	require.NoError(t, os.Chtimes(out, rewrite, rewrite))

	got, err := RecordArtifacts(dir, baseArtifacts, sha256Only(), map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil, cmdStart)
	require.NoError(t, err)
	_, recorded := got["hugo-bin"]
	require.True(t, recorded,
		"a same-content file rewritten during the command window must be recorded as a product (mtime >= cmdStart)")
}

// TestRecordArtifacts_UntouchedFileStaysMaterial is the inverse guard: a file
// present in the snapshot that the command did NOT touch (mtime < cmdStart)
// must remain a material, not get mis-promoted to a product.
func TestRecordArtifacts_UntouchedFileStaysMaterial(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "go.mod")
	require.NoError(t, os.WriteFile(in, []byte("module example.com/x"), 0o644))

	// Stat the input back in time so its mtime clearly predates the command.
	old := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(in, old, old))

	base, err := cryptoutil.CalculateDigestSetFromFile(in, sha256Only())
	require.NoError(t, err)
	baseArtifacts := map[string]cryptoutil.DigestSet{"go.mod": base}

	cmdStart := time.Now()
	got, err := RecordArtifacts(dir, baseArtifacts, sha256Only(), map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil, cmdStart)
	require.NoError(t, err)
	_, recorded := got["go.mod"]
	require.False(t, recorded,
		"an untouched pre-existing file (mtime < cmdStart) must remain a material, not a product")
}

// TestRecordArtifacts_NoStartTimePreservesLegacyBehavior ensures callers that
// pass no start time (the material attestor, the ~120 existing test call
// sites) keep the exact pre-mtime semantics: a same-digest file in the
// snapshot is skipped regardless of mtime.
func TestRecordArtifacts_NoStartTimePreservesLegacyBehavior(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "artifact")
	require.NoError(t, os.WriteFile(out, []byte("same"), 0o644))

	base, err := cryptoutil.CalculateDigestSetFromFile(out, sha256Only())
	require.NoError(t, err)
	baseArtifacts := map[string]cryptoutil.DigestSet{"artifact": base}

	// Rewrite identical bytes with a fresh (future) mtime, but pass NO
	// cmdStart — legacy callers must not see this promoted to a product.
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(out, future, future))

	got, err := RecordArtifacts(dir, baseArtifacts, sha256Only(), map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)
	_, recorded := got["artifact"]
	require.False(t, recorded,
		"with no cmdStart, a same-digest file must be skipped (legacy behavior preserved)")
}
