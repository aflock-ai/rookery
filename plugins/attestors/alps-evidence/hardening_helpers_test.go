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

package alpsevidence

// Unit tests for the hardening helpers themselves. The end-to-end regressions
// live in hardening_regression_test.go; these pin the mechanics.

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptionArgvTruncatesAtTheFirstTerminator(t *testing.T) {
	assert.Equal(t, []string{"codex", "exec"},
		optionArgv([]string{"codex", "exec", "--", "--sandbox", "read-only"}))

	untouched := []string{"codex", "--model", "m"}
	assert.Equal(t, untouched, optionArgv(untouched), "argv without a terminator passes through whole")

	// Scanners built on the cut stop consuming flags at the terminator...
	_, ok := argvValue([]string{"codex", "--", "--model", "late"}, "--model", "-m")
	assert.False(t, ok)
	_, ok = argvKeyValue([]string{"codex", "--", "-c", "model=late"}, []string{"-c", "--config"}, "model")
	assert.False(t, ok)

	// ...while flags before it still resolve.
	v, ok := argvValue([]string{"codex", "--model", "early", "--", "--model", "late"}, "--model")
	require.True(t, ok)
	assert.Equal(t, "early", v)
}

// TestHashHandleRefusesContentThatDisagreesWithFstat. The digest is bounded by
// the handle's own fstat and refused outright when the bytes read disagree
// with it — a size the digest cannot be paired with must not produce a digest
// at all.
func TestHashHandleRefusesContentThatDisagreesWithFstat(t *testing.T) {
	content := []byte("agent binary bytes")
	path := filepath.Join(t.TempDir(), "bin")
	require.NoError(t, os.WriteFile(path, content, 0o600))

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	require.NoError(t, err)

	sum, err := hashHandle(f, info.Size())
	require.NoError(t, err)
	assert.Equal(t, sha256hex(content), sum)

	// Make the handle yield fewer bytes than the size the digest would be
	// paired with — the shape a mid-read truncation produces.
	_, err = f.Seek(1, io.SeekStart)
	require.NoError(t, err)
	_, err = hashHandle(f, info.Size())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "content changed while hashing")
}

// TestResolvedPathIsRefusedWhenItDoesNotNameTheDigestedFile pins the mechanism
// the end-to-end regression exercises from the outside.
//
// Where no per-process image handle exists (macOS), resolving the recorded
// path is still a second lookup — nothing on that platform avoids it. What
// changed is that its answer is CHECKED against the handle the digest came
// from before it is allowed to be evidence, and a failed check yields no
// resolved path at all rather than one describing other bytes.
func TestResolvedPathIsRefusedWhenItDoesNotNameTheDigestedFile(t *testing.T) {
	dir := t.TempDir()

	digested := filepath.Join(dir, "digested")
	replacement := filepath.Join(dir, "replacement")
	require.NoError(t, os.WriteFile(digested, []byte("the digested binary"), 0o600))
	require.NoError(t, os.WriteFile(replacement, []byte("something else entirely"), 0o600))

	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(digested, link))

	f, err := os.Open(link)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	require.NoError(t, err)

	canonical, err := filepath.EvalSymlinks(digested)
	require.NoError(t, err)

	// Nothing moved: the resolution names the file the handle holds, so it is
	// evidence.
	resolved, warnings := verifyResolutionAgainstHandle(info, link)
	assert.Equal(t, canonical, resolved)
	assert.Empty(t, warnings)

	// The retarget lands after the open — the exact window the old
	// resolve-then-open ordering left. The resolution now names another file,
	// so it is refused outright instead of being paired with this digest.
	require.NoError(t, os.Remove(link))
	require.NoError(t, os.Symlink(replacement, link))
	resolved, warnings = verifyResolutionAgainstHandle(info, link)
	assert.Empty(t, resolved, "a path that does not name the digested file must not be recorded")
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "different file")

	// A path that cannot be resolved at all is likewise not guessed at.
	require.NoError(t, os.Remove(link))
	resolved, warnings = verifyResolutionAgainstHandle(info, link)
	assert.Empty(t, resolved)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "could not be resolved")

	// These warnings reach the signed predicate, so they must name no
	// absolute path (the same rule the unreadable-environment warnings follow).
	_, mismatch := verifyResolutionAgainstHandle(info, digested)
	for _, w := range append(warnings, mismatch...) {
		assert.NotContains(t, w, dir, "a warning in the predicate must not leak a filesystem location")
	}
}
