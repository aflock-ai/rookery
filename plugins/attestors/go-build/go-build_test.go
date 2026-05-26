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

package gobuild

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalMain is the source for the tiny program tests compile to
// exercise the BuildInfo path. Kept inline so the test is fully
// self-contained — no testdata sources, no fixtures to maintain.
// The init module is required because Go's toolchain refuses to
// embed BuildInfo without a go.mod (GO111MODULE=on is the default).
const minimalMain = `package main

func main() {}
`

const minimalGoMod = `module hellotest

go 1.26
`

// buildHelloBinary compiles a tiny Go program inside dir and returns
// the absolute path to the binary. Skips the calling test if the
// `go` toolchain is unavailable — relevant for cross-compiled CI
// containers that don't ship one.
func buildHelloBinary(t *testing.T, dir, name string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH: %v", err)
	}

	src := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(src, []byte(minimalMain), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(minimalGoMod), 0o600))

	bin := filepath.Join(dir, name)
	// Build the package (not the file) so the toolchain stamps the
	// module path into BuildInfo. `go build path/to/file.go` uses the
	// magic package name "command-line-arguments" and loses module
	// context — that breaks BuildInfo.Path.
	cmd := exec.Command("go", "build", "-o", bin, ".") //nolint:gosec // test-only invocation
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0", // keep the build hermetic across CI environments
		"GOFLAGS=",
	)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build failed: %s", out)
	return bin
}

// TestAttest_GoBinary_WritesSidecar is the headline integration test:
// build a real Go binary, run the attestor against it, and assert the
// sidecar JSON lands on disk next to the binary and round-trips back
// to the BuildInfo we stamped.
//
// This is the load-bearing path users care about — Cole's design
// motivation was "Go has a lot of properties in that they produce.
// We should try to get the output as files in case they strip it
// from the binary." This test proves the file persists with the
// data even after the in-memory predicate is forgotten.
func TestAttest_GoBinary_WritesSidecar(t *testing.T) {
	cwd := t.TempDir()
	binName := "hello"
	if runtime.GOOS == "windows" {
		binName = "hello.exe"
	}
	binAbs := buildHelloBinary(t, cwd, binName)

	a := New()
	p := product.New()

	ctx, err := attestation.NewContext("go-build-test",
		[]attestation.Attestor{p, a},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Len(t, a.Binaries, 1, "expected exactly one Go binary in products")
	bi := a.Binaries[0]

	// We compare against the relative binary name because that's how
	// the product attestor keys its map (paths are workspace-relative).
	assert.Equal(t, binName, bi.Path)

	assert.Truef(t, bi.GoVersion != "", "GoVersion must be populated; got %q", bi.GoVersion)
	assert.Equal(t, "hellotest", bi.MainPath, "main package path mismatch")

	// Settings must include at least one of the well-known keys.
	// `-compiler` is the one Go has emitted forever; we use it as
	// the canary rather than e.g. `vcs.revision` which only appears
	// inside a git workspace.
	require.NotNil(t, bi.Settings, "Settings must be populated")
	_, hasCompiler := bi.Settings["-compiler"]
	assert.True(t, hasCompiler, "expected `-compiler` in Settings; got keys=%v", keysOf(bi.Settings))

	// Sidecar must exist on disk next to the binary.
	sidecarAbs := binAbs + SidecarExt
	body, err := os.ReadFile(sidecarAbs) //nolint:gosec // test-only path
	require.NoErrorf(t, err, "sidecar must be written next to the binary at %s", sidecarAbs)

	var roundtrip BinaryInfo
	require.NoError(t, json.Unmarshal(body, &roundtrip), "sidecar JSON must round-trip cleanly")
	assert.Equal(t, bi.GoVersion, roundtrip.GoVersion)
	assert.Equal(t, bi.MainPath, roundtrip.MainPath)

	// Subject must point at the sidecar (not the binary). The
	// binary's digest is already a product subject; subject-ing the
	// sidecar lets a verifier prove the on-disk JSON matches what
	// was signed.
	subjects := a.Subjects()
	require.Contains(t, subjects, "go-build:"+binName,
		"expected subject keyed by relative binary path")
	require.NotEmpty(t, subjects["go-build:"+binName],
		"subject must have at least one digest")
}

// TestAttest_SkipsNonGoFiles guards the negative path: non-Go
// files in the product set must end up in SkippedNonGo and must
// not produce sidecars or subjects. A noisy product map (text,
// JSON, random binaries) is the common case in real CI steps.
func TestAttest_SkipsNonGoFiles(t *testing.T) {
	cwd := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(cwd, "readme.txt"), []byte("hello"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(cwd, "data.json"), []byte(`{"k":"v"}`), 0o600))

	a := New()
	p := product.New()
	ctx, err := attestation.NewContext("skip-test",
		[]attestation.Attestor{p, a},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	assert.Empty(t, a.Binaries, "no Go binaries → no Binaries entries")
	assert.Empty(t, a.Subjects(), "no Go binaries → no subjects")
	assert.ElementsMatch(t, []string{"readme.txt", "data.json"}, a.SkippedNonGo,
		"both non-Go files must be reported as skipped")
}

// TestAttest_EmptyProductSet is the genuinely-no-products path —
// always-on attestor configurations may include go-build even
// when nothing got built. Should be a clean no-op, not an error.
func TestAttest_EmptyProductSet(t *testing.T) {
	cwd := t.TempDir()

	a := New()
	p := product.New()
	ctx, err := attestation.NewContext("empty-test",
		[]attestation.Attestor{p, a},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	assert.Empty(t, a.Binaries)
	assert.Empty(t, a.SkippedNonGo)
	assert.Empty(t, a.Subjects())
}

// TestConvertModule covers the Replace recursion path. The toolchain
// emits `replace` directives as Module entries with a nested Module
// pointer; we need to copy that across faithfully. A unit test is
// cheaper here than coaxing `go build` to produce a replace-graph.
func TestConvertModule(t *testing.T) {
	// Build a 3-deep replace chain. Real toolchain output rarely
	// goes this deep; if convertModule ever broke recursion this
	// would catch it.
	leaf := debugModuleFixture("leaf.example.com/pkg", "v0.0.1", nil)
	mid := debugModuleFixture("mid.example.com/pkg", "v0.0.2", &leaf)
	top := debugModuleFixture("top.example.com/pkg", "v0.0.3", &mid)

	got := convertModule(top)
	assert.Equal(t, "top.example.com/pkg", got.Path)
	require.NotNil(t, got.Replace)
	assert.Equal(t, "mid.example.com/pkg", got.Replace.Path)
	require.NotNil(t, got.Replace.Replace)
	assert.Equal(t, "leaf.example.com/pkg", got.Replace.Replace.Path)
	assert.Nil(t, got.Replace.Replace.Replace)
}

// debugModuleFixture is a tiny helper to keep the chain construction
// in TestConvertModule readable.
func debugModuleFixture(path, version string, replace *debug.Module) debug.Module {
	return debug.Module{
		Path:    path,
		Version: version,
		Sum:     "h1:fake",
		Replace: replace,
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
