// jade:ring local

package material

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// #9946: --attestor-material-bind RECORDED=FILE records FILE's digest,
// taken in the material phase (before the wrapped command runs), as a
// material under RECORDED. The release sign step uses it to record the
// unsigned binary under the build step's product path, so artifactsFrom
// compares the two digests at one key.

func writeBindFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cilock")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func runBound(t *testing.T, mode attestation.CaptureMode, trace map[string]attestation.CaptureEntry, binds []string, mutate func()) (*Attestor, error) {
	t.Helper()
	a := New()
	if err := a.SetBindings(binds); err != nil {
		return nil, err
	}
	attestors := []attestation.Attestor{a}
	if mode == attestation.CaptureTrace {
		attestors = append(attestors, &inventoryTraceProbe{inputs: trace})
	}
	wd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(wd, "walked"), []byte("w"), 0o600))
	ctx, err := attestation.NewContext("bind", attestors, attestation.WithWorkingDir(wd), attestation.WithCaptureMode(mode))
	require.NoError(t, err)
	if err := ctx.RunAttestors(); err != nil {
		return a, err
	}
	for _, r := range ctx.CompletedAttestors() {
		if r.Error != nil {
			return a, r.Error
		}
	}
	if mutate != nil {
		mutate()
	}
	if mode == attestation.CaptureTrace {
		if err := a.Finalize(ctx); err != nil {
			return a, err
		}
	}
	return a, nil
}

func TestMaterialBindRecordsFileUnderRecordedPath(t *testing.T) {
	want := digestOf(t, "unsigned-binary")
	for _, mode := range []attestation.CaptureMode{attestation.CaptureWalk, attestation.CaptureTrace} {
		t.Run(string(mode), func(t *testing.T) {
			bin := writeBindFile(t, "unsigned-binary")
			trace := map[string]attestation.CaptureEntry{"/usr/lib/libc.so.6": {Digest: map[string]string{"sha256": digestOf(t, "libc")}}}
			a, err := runBound(t, mode, trace, []string{"/tmp/build/cilock=" + bin}, func() {
				// rcodesign/jsign sign in place AFTER the material phase; the
				// recorded digest must be the pre-signing one.
				require.NoError(t, os.WriteFile(bin, []byte("signed-binary"), 0o600))
			})
			require.NoError(t, err)
			mats := a.Materials()
			got, ok := mats["/tmp/build/cilock"]
			require.True(t, ok, "bound material missing: %v", mats)
			named, err := got.ToNameMap()
			require.NoError(t, err)
			require.Equal(t, want, named["sha256"], "digest must be taken before the command runs")
			if mode == attestation.CaptureWalk {
				require.Contains(t, mats, "walked", "the walk must still run")
			} else {
				require.Contains(t, mats, "/usr/lib/libc.so.6", "trace inputs must be kept")
			}
			require.Equal(t, uint64(len(mats)), a.TreeSize)
		})
	}
}

func TestMaterialBindConflictsFailClosed(t *testing.T) {
	bin := writeBindFile(t, "unsigned-binary")
	// A trace input at the recorded path with DIFFERENT bytes: two answers to
	// "what did this step consume at that path" must not be merged silently.
	trace := map[string]attestation.CaptureEntry{"/tmp/build/cilock": {Digest: map[string]string{"sha256": digestOf(t, "something else")}}}
	_, err := runBound(t, attestation.CaptureTrace, trace, []string{"/tmp/build/cilock=" + bin}, nil)
	require.ErrorContains(t, err, "bind")

	// Same bytes at the same path is consistent, not a conflict.
	same := map[string]attestation.CaptureEntry{"/tmp/build/cilock": {Digest: map[string]string{"sha256": digestOf(t, "unsigned-binary")}}}
	_, err = runBound(t, attestation.CaptureTrace, same, []string{"/tmp/build/cilock=" + bin}, nil)
	require.NoError(t, err)
}

func TestMaterialBindRejectsBadSpecs(t *testing.T) {
	bin := writeBindFile(t, "x")
	for _, spec := range []string{
		"",
		"/tmp/build/cilock",                // no '='
		"=" + bin,                          // empty recorded path
		"/tmp/build/cilock=",               // empty file
		"../escape=" + bin,                 // traversal in the recorded path
		"/tmp/build/../etc/x=" + bin,       // not a clean path
		"/tmp/a=" + bin + ",/tmp/a=" + bin, // not a list syntax; the '=' split makes the file path invalid
	} {
		t.Run(spec, func(t *testing.T) {
			a := New()
			require.Error(t, a.SetBindings([]string{spec}))
		})
	}

	t.Run("duplicate recorded path", func(t *testing.T) {
		a := New()
		require.Error(t, a.SetBindings([]string{"/tmp/a=" + bin, "/tmp/a=" + bin}))
	})

	t.Run("missing file fails at attest time", func(t *testing.T) {
		_, err := runBound(t, attestation.CaptureWalk, nil, []string{"/tmp/build/cilock=" + filepath.Join(t.TempDir(), "absent")}, nil)
		require.Error(t, err)
	})
}

// A relative FILE resolves against the attestation working directory
// (--workingdir), not the process cwd: with different bytes at the same
// relative name in each, the recorded digest is the working directory's.
func TestMaterialBindRelativeFileResolvesAgainstWorkingDir(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cwd, "cilock"), []byte("process-cwd-bytes"), 0o600))
	t.Chdir(cwd)

	wd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(wd, "cilock"), []byte("workingdir-bytes"), 0o600))

	a := New()
	require.NoError(t, a.SetBindings([]string{"/tmp/build/cilock=cilock"}))
	ctx, err := attestation.NewContext("bind", []attestation.Attestor{a}, attestation.WithWorkingDir(wd), attestation.WithCaptureMode(attestation.CaptureWalk))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	for _, r := range ctx.CompletedAttestors() {
		require.NoError(t, r.Error)
	}
	got, ok := a.Materials()["/tmp/build/cilock"]
	require.True(t, ok)
	named, err := got.ToNameMap()
	require.NoError(t, err)
	require.Equal(t, digestOf(t, "workingdir-bytes"), named["sha256"])
}
