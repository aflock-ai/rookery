// jade:ring local

// Copyright 2026 The Rookery Contributors
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

package secretscan

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// These tests pin the scan scope (#9313): which files the attestor reads and
// whether it reads prior attestations at all. Every default is the behaviour
// before the options existed, so an operator who never touches a flag gets
// the same predicate, byte for byte.

// scopePAT is a classic GitHub PAT shape gitleaks flags without an entropy
// gate, built by concatenation so this file carries no literal.
var scopePAT = "ghp_" + "abcdefghij1234567890" + "KLMNOPQRST654321"

// leakingAttestor is a prior attestor whose JSON carries a secret, standing
// in for command-run stdout or any other attestor whose predicate leaks.
type leakingAttestor struct {
	Note string `json:"note"`
}

func (l *leakingAttestor) Name() string                                   { return "leaky" }
func (l *leakingAttestor) Type() string                                   { return "https://example.test/leaky/v0.1" }
func (l *leakingAttestor) RunType() attestation.RunType                   { return attestation.PreMaterialRunType }
func (l *leakingAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (l *leakingAttestor) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(l) }

func subjectKeys(a *Attestor) []string {
	keys := make([]string, 0, len(a.Subjects()))
	for k := range a.Subjects() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func findingLocations(a *Attestor) []string {
	out := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		out = append(out, f.Location)
	}
	sort.Strings(out)
	return out
}

func hasLocation(a *Attestor, loc string) bool {
	for _, f := range a.Findings {
		if f.Location == loc {
			return true
		}
	}
	return false
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
}

// runScoped runs product + leaky + secretscan over dir. Files written to dir
// BEFORE this call are recorded as products by the walk-mode product attestor
// only if their mtime is at or after the context's start, so callers that
// want products write them via the returned writer inside the run. To keep
// the tests simple every product here is written before the run and picked
// up because the product attestor's walk records the whole tree as products
// when nothing else claims it; that is the existing test convention
// (see report_products_test.go).
func runScoped(t *testing.T, dir string, opts ...Option) *Attestor {
	t.Helper()
	scan := New(opts...)
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{&leakingAttestor{Note: "token=" + scopePAT}, product.New(), scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

// TestScopeDefaultsAreTheOldBehaviour: with no option set the attestor scans
// every product and every prior attestation, and records no scope object, so
// existing predicates do not change shape.
func TestScopeDefaultsAreTheOldBehaviour(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"config.yaml": "github_token: " + scopePAT + "\n",
		"README.md":   "nothing here\n",
	})
	scan := runScoped(t, dir)

	require.True(t, hasLocation(scan, "product:config.yaml"), "findings=%v", findingLocations(scan))
	require.True(t, hasLocation(scan, "attestation:leaky"), "prior attestations are scanned by default; findings=%v", findingLocations(scan))
	require.Nil(t, scan.Scope, "the default scan must not add a scope object to the predicate")
	require.Equal(t, []string{"product:README.md", "product:config.yaml"}, subjectKeys(scan))
}

// TestScanAttestationsOffSkipsPriorAttestors: the material inventory and
// command-run stdout are the expensive, noisy part of a push-gate mint; an
// operator can turn them off and the predicate says so.
func TestScanAttestationsOffSkipsPriorAttestors(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"config.yaml": "github_token: " + scopePAT + "\n"})
	scan := runScoped(t, dir, WithScanAttestations(false))

	require.True(t, hasLocation(scan, "product:config.yaml"), "findings=%v", findingLocations(scan))
	require.False(t, hasLocation(scan, "attestation:leaky"), "attestations must not be scanned when turned off; findings=%v", findingLocations(scan))
	require.NotNil(t, scan.Scope)
	require.False(t, scan.Scope.Attestations)
	require.Equal(t, ScopeProducts, scan.Scope.Files)
}

// TestGlobsRestrictWhichProductsAreScanned: exclude wins over include, and a
// product that is not scanned is not a subject either, so the evidence does
// not claim coverage it did not have.
func TestGlobsRestrictWhichProductsAreScanned(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"src/app.go":            "const token = \"" + scopePAT + "\"\n",
		"vendor/dep/dep.go":     "const token = \"" + scopePAT + "\"\n",
		"vendor/dep/other.go":   "package dep\n",
		"node_modules/x/x.json": "{\"token\":\"" + scopePAT + "\"}\n",
	})

	t.Run("exclude", func(t *testing.T) {
		scan := runScoped(t, dir, WithScanAttestations(false), WithExcludeGlob("{vendor,node_modules}/**"))
		require.Equal(t, []string{"product:src/app.go"}, findingLocations(scan))
		require.Equal(t, []string{"product:src/app.go"}, subjectKeys(scan))
		require.Equal(t, "{vendor,node_modules}/**", scan.Scope.ExcludeGlob)
	})
	t.Run("include", func(t *testing.T) {
		scan := runScoped(t, dir, WithScanAttestations(false), WithIncludeGlob("src/**"))
		require.Equal(t, []string{"product:src/app.go"}, findingLocations(scan))
		require.Equal(t, []string{"product:src/app.go"}, subjectKeys(scan))
	})
	t.Run("exclude beats include", func(t *testing.T) {
		scan := runScoped(t, dir, WithScanAttestations(false), WithIncludeGlob("**/*.go"), WithExcludeGlob("vendor/**"))
		require.Equal(t, []string{"product:src/app.go"}, findingLocations(scan))
		require.Equal(t, []string{"product:src/app.go"}, subjectKeys(scan))
	})
	t.Run("bad glob fails closed", func(t *testing.T) {
		scan := New(WithExcludeGlob("["))
		ctx, err := attestation.NewContext("test", []attestation.Attestor{scan}, attestation.WithWorkingDir(dir))
		require.NoError(t, err)
		require.Error(t, scan.Attest(ctx))
	})
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// TestDiffScopeScansOnlyWhatChangedSinceBase: the push-gate question is "did
// this change introduce a secret". A secret already in the base commit is
// not this push's doing and is not scanned; a modified tracked file, a new
// committed file and a new untracked file are.
func TestDiffScopeScansOnlyWhatChangedSinceBase(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{
		"old-leak.txt": "token=" + scopePAT + "\n",
		"stable.txt":   "unchanged\n",
		"edited.txt":   "clean so far\n",
	})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{
		"edited.txt":       "now leaking " + scopePAT + "\n",
		"added/new.go":     "var token = \"" + scopePAT + "\"\n",
		"untracked.env":    "SECRET=" + scopePAT + "\n",
		"added/binary.bin": "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00" + scopePAT,
	})
	gitRun(t, dir, "add", "edited.txt", "added/new.go", "added/binary.bin")
	gitRun(t, dir, "commit", "-q", "-m", "change")
	// untracked.env is deliberately left untracked.

	scan := New(WithScope("diff:"+base), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Equal(t, []string{"file:added/new.go", "file:edited.txt", "file:untracked.env"}, findingLocations(scan))
	require.Equal(t, []string{"file:added/new.go", "file:edited.txt", "file:untracked.env"}, subjectKeys(scan),
		"every changed text file is a subject; the binary is skipped like a binary product and the base's leak is not this push's")
	sha := scan.Subjects()["file:edited.txt"][cryptoutil.DigestValue{Hash: crypto.SHA256}]
	require.Len(t, sha, 64, "subjects carry the digest of the bytes scanned")

	require.NotNil(t, scan.Scope)
	require.Equal(t, ScopeDiff, scan.Scope.Files)
	require.Equal(t, base, scan.Scope.BaseRef)
	require.Equal(t, base, scan.Scope.BaseCommit)
	require.Equal(t, 3, scan.Scope.FilesScanned)
}

// TestDiffScopeIsRelativeToAWorkingDirBelowTheRepoRoot: cilock may run in
// a subdirectory of the repository. git reports tracked changes relative to
// the root and untracked files relative to the current directory unless told
// otherwise; both must land as paths relative to the working directory, and
// a change outside it is not this step's to scan.
func TestDiffScopeIsRelativeToAWorkingDirBelowTheRepoRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q", "-b", "main", ".")
	writeFiles(t, root, map[string]string{"svc/a.txt": "clean\n", "other/b.txt": "clean\n"})
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "base")

	writeFiles(t, root, map[string]string{
		"svc/a.txt":         "token=" + scopePAT + "\n",
		"svc/new/c.env":     "SECRET=" + scopePAT + "\n", // untracked
		"other/b.txt":       "token=" + scopePAT + "\n",  // changed, outside the working dir
		"other/untracked.t": "token=" + scopePAT + "\n",
	})
	gitRun(t, root, "add", "svc/a.txt", "other/b.txt")
	gitRun(t, root, "commit", "-q", "-m", "change")

	scan := New(WithScope("diff:main~1"), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(filepath.Join(root, "svc")),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Equal(t, []string{"file:a.txt", "file:new/c.env"}, findingLocations(scan))
	require.Equal(t, []string{"file:a.txt", "file:new/c.env"}, subjectKeys(scan))
	require.Equal(t, 2, scan.Scope.FilesScanned)
}

// TestDiffScopeFailsClosedWhenBaseCannotBeResolved: an unknown ref or a
// directory that is not a repository is "could not observe", a plain error
// that keeps the attestor out of the collection. Silently scanning nothing
// would satisfy a no-secrets policy with a scan of nothing.
func TestDiffScopeFailsClosedWhenBaseCannotBeResolved(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "a\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")

	scan := New(WithScope("diff:no-such-ref"))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	err = scan.Attest(ctx)
	require.Error(t, err)
	require.False(t, attestation.IsDetectionError(err), "an unresolvable base is a failure to observe, not a detection")

	notARepo := t.TempDir()
	scan = New(WithScope("diff:HEAD"))
	ctx, err = attestation.NewContext("test", []attestation.Attestor{scan}, attestation.WithWorkingDir(notARepo))
	require.NoError(t, err)
	require.Error(t, scan.Attest(ctx))
}

// TestTreeScopeScansEveryFileUnderTheWorkingDir: "tree" is the explicit
// whole-tree scan the issue assumed was already happening. It skips .git,
// honours the globs and the size limit, and records every file it read.
func TestTreeScopeScansEveryFileUnderTheWorkingDir(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"a/b/c/deep.txt":   "token " + scopePAT + "\n",
		"a/clean.txt":      "clean\n",
		".git/config":      "token " + scopePAT + "\n",
		"vendor/v/leak.go": "token " + scopePAT + "\n",
	})

	scan := New(WithScope(string(ScopeTree)), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.Equal(t, []string{"file:a/b/c/deep.txt", "file:vendor/v/leak.go"}, findingLocations(scan))
	require.Equal(t, []string{"file:a/b/c/deep.txt", "file:a/clean.txt", "file:vendor/v/leak.go"}, subjectKeys(scan), ".git is never scanned")
	require.Equal(t, 3, scan.Scope.FilesScanned)

	scan = New(WithScope(string(ScopeTree)), WithScanAttestations(false), WithExcludeGlob("vendor/**"))
	ctx, err = attestation.NewContext("test", []attestation.Attestor{scan}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.Equal(t, []string{"file:a/b/c/deep.txt"}, findingLocations(scan))
	require.Equal(t, 2, scan.Scope.FilesScanned)
}

// TestScopeOptionRejectsUnknownValues: the flag is parsed when set, so a typo
// fails the run before anything is scanned.
func TestScopeOptionRejectsUnknownValues(t *testing.T) {
	for _, bad := range []string{"", "everything", "diff", "diff:", "tree:x", "products:all"} {
		_, err := parseScope(bad)
		require.Error(t, err, "scope %q must be rejected", bad)
	}
	for in, want := range map[string]scopeSpec{
		"products":         {Files: ScopeProducts},
		"tree":             {Files: ScopeTree},
		"diff:origin/main": {Files: ScopeDiff, BaseRef: "origin/main"},
		"diff:abc123":      {Files: ScopeDiff, BaseRef: "abc123"},
	} {
		got, err := parseScope(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
}

// --- Regressions for PR #9373 review: a scan that reports clean without
// having scanned. Each of these once produced an empty, SUCCESSFUL listing —
// evidence of a clean tree built by reading nothing. They are the same defect
// as the unresolvable base ref above, reached by three other doors.

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
}

// runScanOnly runs secretscan alone over dir, with no product attestor, which
// is the configuration every finding below depends on: with no products, the
// scoped file listing is the ONLY thing that reads anything.
func runScanOnly(t *testing.T, dir string, opts ...Option) *Attestor {
	t.Helper()
	scan := New(opts...)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

// fixedProducts records products whose keys the test chooses, standing in for
// a capture mode that records product keys as absolute paths.
type fixedProducts struct {
	products map[string]attestation.Product
}

func (f *fixedProducts) Name() string                                   { return "fixedproducts" }
func (f *fixedProducts) Type() string                                   { return "https://example.test/fixedproducts/v0.1" }
func (f *fixedProducts) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (f *fixedProducts) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fixedProducts) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(f) }
func (f *fixedProducts) Products() map[string]attestation.Product       { return f.products }

// TestDiffScopeScansATypeChange: replacing a tracked symlink with a regular
// file carrying a secret is a type change — git status T. An ACMR allow-list
// drops it, so the secret rode into the tree past a diff scan that reported
// clean. The filter now names only what it refuses to read (deletions), so no
// present or future class of change is dropped by omission.
func TestDiffScopeScansATypeChange(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"target.txt": "nothing here\n"})
	require.NoError(t, os.Symlink("target.txt", filepath.Join(dir, "creds.env")))
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	require.NoError(t, os.Remove(filepath.Join(dir, "creds.env")))
	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "swap")
	require.Equal(t, "T\tcreds.env", gitRun(t, dir, "diff", "--name-status", "--no-renames", base),
		"the fixture must actually produce a type change, or this test proves nothing")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "file:creds.env"),
		"a tracked symlink replaced by a regular file must be read; findings=%v", findingLocations(scan))
	require.Contains(t, subjectKeys(scan), "file:creds.env")
}

// TestDiffScopeIgnoresDiffRelativeConfig: `git diff --name-only` prints paths
// relative to the CURRENT DIRECTORY when diff.relative is set in the user's or
// the repository's config. The scan joins those paths onto the repository
// root, so under a working directory below the root every changed file lands
// outside it and is skipped — an empty, successful diff. The config is pinned
// on the command line so the scan does not depend on the operator's git.
func TestDiffScopeIgnoresDiffRelativeConfig(t *testing.T) {
	requireGit(t)
	root := t.TempDir()
	gitRun(t, root, "init", "-q", "-b", "main", ".")
	writeFiles(t, root, map[string]string{"svc/a.txt": "clean\n"})
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "base")
	gitRun(t, root, "config", "diff.relative", "true")

	writeFiles(t, root, map[string]string{"svc/a.txt": "token=" + scopePAT + "\n"})
	gitRun(t, root, "commit", "-q", "-am", "leak")

	scan := runScanOnly(t, filepath.Join(root, "svc"), WithScope("diff:main~1"), WithScanAttestations(false))
	require.Equal(t, []string{"file:a.txt"}, findingLocations(scan),
		"diff.relative must not narrow the scan to nothing")
	require.Equal(t, 1, scan.Scope.FilesScanned)
}

// TestTreeScopeResolvesASymlinkedWorkingDir: filepath.WalkDir does not follow
// a symlink handed to it as the root. The callback sees a non-directory,
// non-regular entry, returns nil, and the walk ends with an empty listing and
// no error — clean `tree` evidence over a tree nothing read. CI checkouts
// under a symlinked path (/tmp on macOS, a symlinked workspace) hit this.
func TestTreeScopeResolvesASymlinkedWorkingDir(t *testing.T) {
	real := t.TempDir()
	writeFiles(t, real, map[string]string{"a/leak.txt": "token " + scopePAT + "\n", "a/clean.txt": "clean\n"})
	link := filepath.Join(t.TempDir(), "workdir")
	require.NoError(t, os.Symlink(real, link))

	scan := runScanOnly(t, link, WithScope(string(ScopeTree)), WithScanAttestations(false))
	require.Equal(t, []string{"file:a/leak.txt"}, findingLocations(scan),
		"a symlinked working directory must be resolved, not walked as a leaf; findings=%v", findingLocations(scan))
	require.Equal(t, []string{"file:a/clean.txt", "file:a/leak.txt"}, subjectKeys(scan))
	require.Equal(t, 2, scan.Scope.FilesScanned)
}

// TestTreeScopeFailsClosedWhenTheRootCannotBeWalked: a root that cannot be
// listed at all is "could not observe". Returning an empty list would let a
// no-secrets policy be satisfied by a scan of nothing.
func TestTreeScopeFailsClosedWhenTheRootCannotBeWalked(t *testing.T) {
	for name, root := range map[string]string{
		"dangling symlink": func() string {
			p := filepath.Join(t.TempDir(), "workdir")
			require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "nowhere"), p))
			return p
		}(),
		"missing directory": filepath.Join(t.TempDir(), "absent"),
		"regular file": func() string {
			d := t.TempDir()
			writeFiles(t, d, map[string]string{"notadir": "x\n"})
			return filepath.Join(d, "notadir")
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			scan := New(WithScope(string(ScopeTree)), WithScanAttestations(false))
			ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
				attestation.WithWorkingDir(root))
			require.NoError(t, err)
			require.Error(t, scan.Attest(ctx), "an unwalkable root must fail, not report a clean empty tree")
		})
	}
}

// TestDiffScopeResolvesASymlinkedWorkingDir pins the diff-scope half of the
// same hazard: git reports the resolved root, so an unresolved working
// directory makes every changed path look like it is outside the scan.
func TestDiffScopeResolvesASymlinkedWorkingDir(t *testing.T) {
	requireGit(t)
	real := t.TempDir()
	gitRun(t, real, "init", "-q", "-b", "main", ".")
	writeFiles(t, real, map[string]string{"a.txt": "clean\n"})
	gitRun(t, real, "add", "-A")
	gitRun(t, real, "commit", "-q", "-m", "base")
	writeFiles(t, real, map[string]string{"a.txt": "token=" + scopePAT + "\n"})

	link := filepath.Join(t.TempDir(), "workdir")
	require.NoError(t, os.Symlink(real, link))

	scan := runScanOnly(t, link, WithScope("diff:HEAD"), WithScanAttestations(false))
	require.Equal(t, []string{"file:a.txt"}, findingLocations(scan))
}

// TestProductGlobsAreRelativeToTheWorkingDir: the globs are documented as
// relative to the working directory, but a product key may be absolute. An
// absolute key never matched a relative include glob, so scanProducts dropped
// it — and scanFiles then skipped it too, because it IS a product. The file
// was scanned by neither path and appeared nowhere in the evidence.
func TestProductGlobsAreRelativeToTheWorkingDir(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"src/secret.env":     "SECRET=" + scopePAT + "\n",
		"vendor/dep/leak.go": "const token = \"" + scopePAT + "\"\n",
	})
	abs := func(rel string) string { return filepath.Join(dir, filepath.FromSlash(rel)) }
	newProducts := func() *fixedProducts {
		return &fixedProducts{products: map[string]attestation.Product{
			abs("src/secret.env"):     {MimeType: "text/plain"},
			abs("vendor/dep/leak.go"): {MimeType: "text/plain"},
		}}
	}
	run := func(t *testing.T, opts ...Option) *Attestor {
		t.Helper()
		scan := New(opts...)
		ctx, err := attestation.NewContext("test",
			[]attestation.Attestor{newProducts(), scan},
			attestation.WithWorkingDir(dir),
			attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
		require.NoError(t, err)
		require.NoError(t, ctx.RunAttestors())
		return scan
	}

	t.Run("an include glob reaches an absolute product key", func(t *testing.T) {
		scan := run(t, WithScope(string(ScopeTree)), WithScanAttestations(false), WithIncludeGlob("src/**"))
		require.Equal(t, []string{"product:" + abs("src/secret.env")}, findingLocations(scan),
			"an included product must be scanned exactly once, by the product path")
		require.Equal(t, []string{"product:" + abs("src/secret.env")}, subjectKeys(scan))
	})

	t.Run("an exclude glob reaches an absolute product key", func(t *testing.T) {
		scan := run(t, WithScope(string(ScopeTree)), WithScanAttestations(false), WithExcludeGlob("vendor/**"))
		require.Equal(t, []string{"product:" + abs("src/secret.env")}, findingLocations(scan),
			"an excluded product must stay excluded whatever shape its key has")
		require.Equal(t, []string{"product:" + abs("src/secret.env")}, subjectKeys(scan))
	})

	t.Run("no glob scans every product exactly once", func(t *testing.T) {
		scan := run(t, WithScope(string(ScopeTree)), WithScanAttestations(false))
		require.Equal(t, []string{
			"product:" + abs("src/secret.env"),
			"product:" + abs("vendor/dep/leak.go"),
		}, findingLocations(scan), "a product must never be scanned by both paths")
		require.Equal(t, 2, scan.Scope.FilesScanned)
	})
}

// --- Regressions for PR #9373 review round 2. Same defect class again, one
// layer deeper: the scan reports clean for content it never examined. Round 1
// was about listings that came back empty; these two are about a listing that
// is right and a READ that never happened, and about reading the wrong bytes.

// TestScanErrorIsAnErrorWithoutFailOnDetection: "could not read" is not "read
// and clean". fail-on-detection decides whether a FINDING fails the run; it
// must never decide whether a NON-OBSERVATION does. With the flag off — the
// default — an unreadable file used to produce SIGNED evidence with an empty
// findings list, which downstream is indistinguishable from a clean tree.
func TestScanErrorIsAnErrorWithoutFailOnDetection(t *testing.T) {
	a := New() // defaultFailOnDetection == false
	a.scanErrors = append(a.scanErrors, errors.New("simulated unreadable product"))

	err := a.Attest(&attestation.AttestationContext{})
	require.Error(t, err, "an incomplete scan must never be signed as a clean one")
	require.False(t, attestation.IsDetectionError(err),
		"a file that could not be read is a failure to OBSERVE, not a verdict")
	require.Contains(t, err.Error(), "scan error")
}

// TestUnreadableProductFailsTheScan drives the same contract end to end, with
// no permission games: a product recorded by an earlier attestor whose file is
// not there when secretscan goes to read it.
func TestUnreadableProductFailsTheScan(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "vanished.env")
	scan := New(WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{missing: {MimeType: "text/plain"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Error(t, scan.Attest(ctx), "a product that could not be read must fail the scan, not pass it as clean")
}

// TestUnreadableScopedFileFailsTheScan is the scoped-file half: git lists the
// file, so the evidence would claim to cover it, and the read fails.
func TestUnreadableScopedFileFailsTheScan(t *testing.T) {
	requireGit(t)
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny reads")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")

	locked := filepath.Join(dir, "locked.env")
	writeFiles(t, dir, map[string]string{"locked.env": "SECRET=" + scopePAT + "\n"})
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	scan := New(WithScope("diff:HEAD"), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.Error(t, scan.Attest(ctx),
		"a file in scope that could not be read must fail the scan whatever fail-on-detection says")
}

// TestDiffScopeScansCommittedContentNotJustTheWorkingTree: `git diff <base>`
// compares the base against the WORKING TREE. Commit a secret, then restore
// that path to its base contents without committing, and the path drops out of
// the listing — yet the pushed commit still contains the secret, and the
// evidence is bound to that commit. The committed blob is read out of the
// object store, so working-tree state cannot subtract from what the commit is
// attested to contain.
func TestDiffScopeScansCommittedContentNotJustTheWorkingTree(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"creds.env": "nothing here\n", "other.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n", "other.txt": "still clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")

	// The dodge: put the working tree back the way it was, commit untouched.
	gitRun(t, dir, "checkout", base, "--", "creds.env")
	require.NotContains(t, gitRun(t, dir, "diff", "--name-only", base), "creds.env",
		"the fixture must actually hide the path from the working-tree diff, or this test proves nothing")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"the secret is in the commit being attested; findings=%v", findingLocations(scan))
	require.Contains(t, subjectKeys(scan), "commit:"+introducer+":creds.env",
		"the bytes read out of the object store must be a subject with their own digest")
	// The undirtied path is read once, off disk, exactly as before.
	require.Contains(t, subjectKeys(scan), "file:other.txt")
	require.NotContains(t, subjectKeys(scan), "commit:"+introducer+":other.txt",
		"a path the working tree still represents faithfully must not be read twice")
}

// TestDiffScopeScansCommittedContentWhenTheFileIsDeleted is the same dodge by
// deletion rather than restoration: commit the secret, delete the file. It is
// in no working-tree listing at all.
func TestDiffScopeScansCommittedContentWhenTheFileIsDeleted(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")
	require.NoError(t, os.Remove(filepath.Join(dir, "creds.env")))

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"deleting the file from the working tree must not unsay what the commit contains; findings=%v", findingLocations(scan))
}

// TestDiffScopeSkipsOnlySubmodulesInTheCommit: a gitlink is not a blob at all
// — the object lives in another repository, so cat-file cannot read it and
// every repo with a submodule would become a fatal scan error. It is the only
// mode excluded.
//
// This test previously asserted that SYMLINK blobs were skipped too, and that
// was wrong: `update-index --cacheinfo 120000,<oid>,<path>` puts arbitrary
// bytes behind a symlink mode, so skipping by mode was another way to carry
// content past the scan. A symlink's blob is now read — which dereferences
// nothing, it is just the recorded target string. See
// TestDiffScopeScansASymlinkBlobInTheCommit.
func TestDiffScopeSkipsOnlySubmodulesInTheCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	require.NoError(t, os.Symlink("a.txt", filepath.Join(dir, "link.txt")))
	writeFiles(t, dir, map[string]string{"b.txt": "token " + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "add")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")
	// Dirty every committed path so each one is a blob candidate.
	require.NoError(t, os.Remove(filepath.Join(dir, "link.txt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "b.txt")))

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.Equal(t, []string{"commit:" + introducer + ":b.txt"}, findingLocations(scan))
	require.Contains(t, subjectKeys(scan), "commit:"+introducer+":link.txt",
		"a symlink's recorded target is bytes the commit carries, so it is read and named")
}

// --- Regression for PR #9373 review round 3. The round-2 fix read the
// committed blob only for paths `git diff HEAD` called dirty, reasoning that
// every other committed path is faithfully represented on disk. That premise
// is USER-OVERRIDABLE, and the override is exactly what an attacker reaches
// for: the index flags below tell git to stop comparing a path, so git itself
// reports the tree clean while the disk holds something else entirely.
//
// The principle the whole file now rests on: THE WORKING TREE IS NEVER A PROXY
// FOR THE COMMIT. Not "usually is", not "is unless git says otherwise" —
// git's own answer to "is this dirty" is attacker-controlled input.

// TestDiffScopeScansCommittedBlobWhateverTheIndexSays: commit a secret, tell
// git to assume the path unchanged, then overwrite the disk copy with clean
// text. git omits it from every dirty listing and the file scan reads only the
// replacement, so the pushed commit's secret went unreported.
func TestDiffScopeScansCommittedBlobWhateverTheIndexSays(t *testing.T) {
	requireGit(t)
	for _, flag := range []string{"--assume-unchanged", "--skip-worktree"} {
		t.Run(flag, func(t *testing.T) {
			dir := t.TempDir()
			gitRun(t, dir, "init", "-q", "-b", "main", ".")
			writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
			gitRun(t, dir, "add", "-A")
			gitRun(t, dir, "commit", "-q", "-m", "base")
			base := gitRun(t, dir, "rev-parse", "HEAD")

			writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
			gitRun(t, dir, "add", "-A")
			gitRun(t, dir, "commit", "-q", "-m", "leak")
			introducer := gitRun(t, dir, "rev-parse", "HEAD")

			// Tell git to stop looking, then swap the disk copy for clean text.
			gitRun(t, dir, "update-index", flag, "creds.env")
			writeFiles(t, dir, map[string]string{"creds.env": "nothing to see here\n"})
			require.Empty(t, gitRun(t, dir, "diff", "--name-only", "HEAD"),
				"the fixture must actually make git call the tree clean, or this test proves nothing")

			scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
			require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
				"the commit carries the secret whatever the index says; findings=%v", findingLocations(scan))
			require.Contains(t, subjectKeys(scan), "commit:"+introducer+":creds.env")
		})
	}
}

// TestDiffScopeScansCommittedBlobWhenDiskCopyIsUnreadable: the other way the
// working-tree read can be made to cover nothing. Every reason scanOneFile
// skips a file — not a regular file, over the size limit, unreadable — used to
// be a reason the committed content went unexamined too if git also called the
// path clean. The blob is now read on its own terms, so no working-tree state
// can subtract from it.
func TestDiffScopeScansCommittedBlobWhenDiskCopyIsUnreadable(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")

	// Replace the file with a symlink: scanOneFile skips non-regular files.
	gitRun(t, dir, "update-index", "--assume-unchanged", "creds.env")
	require.NoError(t, os.Remove(filepath.Join(dir, "creds.env")))
	require.NoError(t, os.Symlink("a.txt", filepath.Join(dir, "creds.env")))

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"a skipped working-tree read must not narrow the commit; findings=%v", findingLocations(scan))
}

// TestDiffScopeReadsTheCommittedBlobEvenWhenTheDiskCopyMatches pins that the
// blob is fetched UNCONDITIONALLY, and that the only thing the digest
// comparison suppresses is the redundant second scan of identical bytes — not
// the read, and never the coverage. One subject per path, no duplicate finding.
func TestDiffScopeReadsTheCommittedBlobEvenWhenTheDiskCopyMatches(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.Equal(t, []string{"file:creds.env"}, findingLocations(scan),
		"identical bytes must be reported once, under the working-tree identity")
	require.Equal(t, []string{"file:creds.env"}, subjectKeys(scan))
	require.Equal(t, 1, scan.Scope.FilesScanned)
}

// TestDiffScopeScansASymlinkBlobInTheCommit: a symlink's blob is its target
// string, and a target is attacker-chosen text that a commit carries. Round 2
// skipped it by mode alongside submodule gitlinks; only the gitlink belongs in
// that bucket, because it is not a blob at all and cat-file cannot read it.
// Reading a symlink's blob follows nothing — it is just the recorded string.
func TestDiffScopeScansASymlinkBlobInTheCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	require.NoError(t, os.Symlink("token-"+scopePAT, filepath.Join(dir, "link")))
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "link")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":link"),
		"a symlink target recorded in the commit is content the commit carries; findings=%v", findingLocations(scan))
}

// --- Regressions for PR #9373 review round 4.

// TestDiffScopeIgnoresReplaceRefs: refs/replace/* rewrites what git RETURNS
// for an object. Replace the secret-bearing blob with a clean one and every
// read — cat-file, diff, rev-parse — silently hands back the substitute, while
// an ordinary push still sends the original object to the remote. The scan
// therefore reported clean over a commit whose real bytes carry the secret.
// Object replacement is disabled on every git invocation this package makes.
func TestDiffScopeIgnoresReplaceRefs(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")
	secretOID := gitRun(t, dir, "rev-parse", "HEAD:creds.env")

	// Write the decoy blob from OUTSIDE the work tree so it is not itself a
	// file the scan could find, then point refs/replace at it.
	decoy := filepath.Join(t.TempDir(), "decoy")
	require.NoError(t, os.WriteFile(decoy, []byte("nothing to see here\n"), 0o600))
	cleanOID := gitRun(t, dir, "hash-object", "-w", decoy)
	gitRun(t, dir, "replace", secretOID, cleanOID)

	// Leave the working copy clean too, so the disk read cannot save us.
	writeFiles(t, dir, map[string]string{"creds.env": "nothing to see here\n"})
	gitRun(t, dir, "update-index", "--assume-unchanged", "creds.env")
	require.Equal(t, "nothing to see here", gitRun(t, dir, "cat-file", "blob", secretOID),
		"the fixture must actually make an ordinary git read return the decoy, or this test proves nothing")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"the object a push would carry holds the secret, whatever refs/replace says; findings=%v", findingLocations(scan))
}

// TestDiffScopeDoesNotRescanACommittedProduct: a product is scanned under its
// product identity, and the committed blob for that same path holds the same
// bytes. Deduplication keyed on the working-tree subject only, so the product
// path was read and reported TWICE — duplicate findings, and filesScanned
// counting one file as two. Coverage was never at risk here; the evidence was.
func TestDiffScopeDoesNotRescanACommittedProduct(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")

	abs := filepath.Join(dir, "creds.env")
	scan := New(WithScope("diff:"+base), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "text/plain"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Equal(t, []string{"product:" + abs}, findingLocations(scan),
		"one blob, one scan, one finding — under the identity that read it first")
	require.NotContains(t, subjectKeys(scan), "commit:"+gitRun(t, dir, "rev-parse", "HEAD")+":creds.env",
		"the committed bytes were already covered by the product read")
	require.Equal(t, 1, scan.Scope.FilesScanned, "one file must not be counted as two")
}

// TestDiffScopeStillScansACommittedProductThatDiffersOnDisk is the other half
// of the same dedup: sameness is decided on the BYTES, so a product whose disk
// copy is not what the commit holds still gets its committed content read.
// Dedup must never become a second way to skip coverage.
func TestDiffScopeStillScansACommittedProductThatDiffersOnDisk(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")
	gitRun(t, dir, "update-index", "--assume-unchanged", "creds.env")
	writeFiles(t, dir, map[string]string{"creds.env": "nothing to see here\n"})

	abs := filepath.Join(dir, "creds.env")
	scan := New(WithScope("diff:"+base), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "text/plain"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"the product on disk is not the committed blob, so the blob must still be read; findings=%v", findingLocations(scan))
}

// TestProductDeclaredBinaryIsReportedExactlyOnce: a product's MIME type is
// recorded by another attestor, so it is not this attestor's evidence.
//
// Round 4 asserted the FALLBACK this hole needed — the product read was
// skipped on the label, and the committed blob had to catch the secret, so
// the finding landed at commit:<path>. Round 5 removed the hole itself: the
// product is read and binary-ness decided from its bytes, so the product read
// catches it and the identical committed blob dedups away. The guarantee the
// test exists for is unchanged and is asserted directly here — the label must
// not hide the secret — and it is now met without needing a second reader.
func TestProductDeclaredBinaryIsReportedExactlyOnce(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "leak")

	abs := filepath.Join(dir, "creds.env")
	scan := New(WithScope("diff:"+base), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "application/octet-stream"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Equal(t, []string{"product:" + abs}, findingLocations(scan),
		"a MIME type another attestor recorded must not decide what this one reads, and one file is one finding")
	require.Equal(t, 1, scan.Scope.FilesScanned)
}

// TestDiffScopeReadsManyCommittedBlobs exercises the batch reader over more
// objects than one response fits, mixing sizes across the limit, so the
// streaming rewrite is held to the same results: every eligible blob scanned,
// every oversized one skipped like an oversized file.
func TestDiffScopeReadsManyCommittedBlobs(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"seed.txt": "seed\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	files := map[string]string{}
	var rels []string
	for i := 0; i < 40; i++ {
		rel := fmt.Sprintf("f%02d.env", i)
		files[rel] = fmt.Sprintf("n=%d\nSECRET=%s\n", i, scopePAT)
		rels = append(rels, rel)
	}
	// One blob over the 1 MB limit set below: skipped, exactly as a file is.
	files["huge.env"] = strings.Repeat("x", 1<<20+1) + "\nSECRET=" + scopePAT + "\n"
	writeFiles(t, dir, files)
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "many")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")

	want := make([]string, 0, len(rels))
	for _, rel := range rels {
		want = append(want, "commit:"+introducer+":"+rel)
	}

	// Hide every working copy so the committed blobs are the only reader.
	for rel := range files {
		gitRun(t, dir, "update-index", "--assume-unchanged", rel)
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), []byte("clean\n"), 0o600))
	}

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false), WithMaxFileSize(1))
	sort.Strings(want)
	require.Equal(t, want, findingLocations(scan),
		"every eligible committed blob scanned, the oversized one skipped")
}

// --- Regressions for PR #9373 review round 5. Same family as rounds 3 and 4:
// something other than "this attestor read these bytes" was allowed to stand
// in for coverage.

// TestDiffScopeScansStagedBlobs: a path has up to THREE versions — the commit,
// the index, and the file on disk. The scan read the first and the third, so
// staging a secret and then restoring only the working copy left the secret
// visible to nobody, although `git commit` is about to carry it.
func TestDiffScopeScansStagedBlobs(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	// Stage the secret, then put clean text back on disk. Nothing is committed.
	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "creds.env")
	writeFiles(t, dir, map[string]string{"creds.env": "nothing to see here\n"})
	require.Contains(t, gitRun(t, dir, "diff", "--cached", "--name-only", base), "creds.env",
		"the fixture must actually stage the secret, or this test proves nothing")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "index:creds.env"),
		"the staged bytes are what the next commit carries; findings=%v", findingLocations(scan))
	require.Contains(t, subjectKeys(scan), "index:creds.env")
}

// TestDiffScopeStagedBlobIdenticalToDiskIsScannedOnce: the dedup rule applies
// to the index like every other source — same bytes, one scan, one finding,
// one count, under whichever identity read them first.
func TestDiffScopeStagedBlobIdenticalToDiskIsScannedOnce(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "creds.env")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.Equal(t, []string{"file:creds.env"}, findingLocations(scan),
		"staged, on disk and identical is one set of bytes, not three")
	require.Equal(t, []string{"file:creds.env"}, subjectKeys(scan))
	require.Equal(t, 1, scan.Scope.FilesScanned)
}

// TestTreeScopeReadsAProductDeclaredBinary: the product handoff checked
// INVENTORY MEMBERSHIP, not coverage. Product metadata is another attestor's
// claim, so labelling a text file binary made scanProducts skip reading it
// while scanFiles skipped it too for being "already a product". Nothing read
// it. Binary-ness is decided from the bytes, by whoever actually reads them.
func TestTreeScopeReadsAProductDeclaredBinary(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"src/secret.env": "SECRET=" + scopePAT + "\n"})
	abs := filepath.Join(dir, "src", "secret.env")

	scan := New(WithScope(string(ScopeTree)), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "application/octet-stream"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.NotEmpty(t, scan.Findings,
		"a MIME label from another attestor must not decide what this one reads; findings=%v", findingLocations(scan))
}

// TestProductsScopeReadsAProductDeclaredBinary is the same hole in the DEFAULT
// scope, where there is no second reader to fall back on at all.
func TestProductsScopeReadsAProductDeclaredBinary(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"secret.env": "SECRET=" + scopePAT + "\n"})
	abs := filepath.Join(dir, "secret.env")

	scan := New(WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "application/octet-stream"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Equal(t, []string{"product:" + abs}, findingLocations(scan),
		"the default scope has no second reader, so a MIME label there hides the secret outright")
}

// TestGenuinelyBinaryProductIsStillSkipped: reading the bytes must not turn
// every binary artefact into a subject. Content decides, and content says no.
func TestGenuinelyBinaryProductIsStillSkipped(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "app.bin")
	require.NoError(t, os.WriteFile(bin, append([]byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00"), []byte(scopePAT)...), 0o600))

	scan := New(WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{bin: {MimeType: "text/plain"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Empty(t, findingLocations(scan), "binary content is skipped on its own evidence")
	require.Empty(t, subjectKeys(scan), "a file that was not scanned is not a subject")
}

// TestDirectoryProductIsSkippedWithoutError: a directory cannot be read, and
// reading one would become a fatal scan error. It is skipped on this
// attestor's own lstat, not on a mime-type label.
func TestDirectoryProductIsSkippedWithoutError(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"sub/a.txt": "clean\n"})
	sub := filepath.Join(dir, "sub")

	scan := New(WithScanAttestations(false))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{sub: {MimeType: "text/plain"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.NoError(t, scan.Attest(ctx), "a directory product must be skipped, not turned into a scan error")
}

// --- Regression for PR #9373 review round 6. A signed claim binds to the
// bytes THIS attestor observed, never to a name or another attestor's record.

// TestProductSubjectCarriesTheBytesWeRead: the product: subject published the
// digest the PRODUCT ATTESTOR recorded, not the digest of what secretscan
// actually read. When the file changed between the product snapshot and the
// scan, the subject named bytes nobody scanned — the findings were real and
// the digest beside them was someone else's. The subject now carries what was
// read, and the disagreement is stated in the predicate instead of being
// correlated away, because "the file changed between snapshot and scan" is
// evidence a policy may want to deny on.
func TestProductSubjectCarriesTheBytesWeRead(t *testing.T) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	dir := t.TempDir()
	abs := filepath.Join(dir, "config.yaml")

	// What the product attestor saw.
	require.NoError(t, os.WriteFile(abs, []byte("clean\n"), 0o600))
	recorded, err := cryptoutil.CalculateDigestSetFromFile(abs, hashes)
	require.NoError(t, err)

	// What is there when secretscan reads it.
	require.NoError(t, os.WriteFile(abs, []byte("token: "+scopePAT+"\n"), 0o600))
	scannedDigest, err := cryptoutil.CalculateDigestSetFromFile(abs, hashes)
	require.NoError(t, err)
	require.NotEqual(t, recorded, scannedDigest, "the fixture must actually change the bytes")

	scan := New() // a genuinely default scan: no option is set
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.True(t, hasLocation(scan, "product:"+abs), "findings=%v", findingLocations(scan))
	require.Equal(t, scannedDigest, scan.Subjects()["product:"+abs],
		"the subject must be the digest of the bytes that were scanned")

	require.NotNil(t, scan.Scope, "a disagreement is recorded even when every scope option is default")
	require.Len(t, scan.Scope.ProductDigestMismatches, 1)
	got := scan.Scope.ProductDigestMismatches[0]
	require.Equal(t, abs, got.Path)
	require.Equal(t, recorded, got.Recorded, "what the product attestor said")
	require.Equal(t, scannedDigest, got.Scanned, "what we read")
}

// TestProductSubjectUnchangedWhenDigestsAgree is the other half, and the one
// that matters for everybody already using this: when the bytes are the bytes
// the product attestor recorded, the subject is identical to what it always
// was, no disagreement is recorded, and a default scan still adds no scope
// object to the predicate.
func TestProductSubjectUnchangedWhenDigestsAgree(t *testing.T) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	dir := t.TempDir()
	abs := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(abs, []byte("token: "+scopePAT+"\n"), 0o600))
	recorded, err := cryptoutil.CalculateDigestSetFromFile(abs, hashes)
	require.NoError(t, err)

	scan := New() // a genuinely default scan: no option is set
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Equal(t, recorded, scan.Subjects()["product:"+abs])
	require.Nil(t, scan.Scope, "agreement is not news; the default predicate keeps its shape")
}

// TestProductWithNoRecordedDigestIsNotADisagreement: a witness-only product
// carries no digest at all. There is no claim to disagree with, so nothing is
// recorded as a mismatch — but the subject still gets the digest of the bytes
// read, where it used to publish nothing.
func TestProductWithNoRecordedDigestIsNotADisagreement(t *testing.T) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	dir := t.TempDir()
	abs := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(abs, []byte("token: "+scopePAT+"\n"), 0o600))
	want, err := cryptoutil.CalculateDigestSetFromFile(abs, hashes)
	require.NoError(t, err)

	scan := New() // a genuinely default scan: no option is set
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{abs: {MimeType: "text/plain"}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.Equal(t, want, scan.Subjects()["product:"+abs],
		"a product recorded without a digest still gets one for the bytes we read")
	require.Nil(t, scan.Scope, "nothing was claimed, so nothing disagrees")
}

// TestRealProductAttestorSubjectsAreUnchanged is the guarantee for everybody
// already using this, checked against the REAL product attestor rather than a
// fake: when the bytes are the bytes it recorded, every product: subject is
// exactly the digest it published, and no disagreement is manufactured by the
// two attestors having computed their digests by different routes.
func TestRealProductAttestorSubjectsAreUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"config.yaml": "github_token: " + scopePAT + "\n",
		"README.md":   "nothing here\n",
	})
	scan := New()
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{product.New(), scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	products := ctx.Products()
	require.NotEmpty(t, products)
	for path, p := range products {
		require.Equal(t, p.Digest, scan.Subjects()["product:"+path],
			"subject for %s must equal what the product attestor recorded when the bytes agree", path)
	}
	require.Nil(t, scan.Scope, "agreeing digests are not news and must not add a scope object")
}

// --- Regressions for PR #9373 review round 7. The unit of coverage for a push
// is the newly reachable COMMIT SET, not the endpoint diff.

// TestDiffScopeScansASecretAddedThenDeletedInALaterCommit: a push publishes
// every commit newly reachable from HEAD, not just HEAD's tree. Add a secret,
// delete it in the next commit, and base->HEAD is clean, the index is clean
// and the working tree is clean — while the objects the push sends still carry
// it, and anyone who fetches can read it out of the first commit forever.
func TestDiffScopeScansASecretAddedThenDeletedInALaterCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "oops")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")

	gitRun(t, dir, "rm", "-q", "creds.env")
	writeFiles(t, dir, map[string]string{"a.txt": "an unrelated clean change\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "tidy up")

	endpoint := gitRun(t, dir, "diff", "--name-only", base, "HEAD")
	require.NotContains(t, endpoint, "creds.env",
		"the fixture must hide the secret from the endpoint diff, or this test proves nothing")
	require.Contains(t, endpoint, "a.txt", "and must still carry an unrelated clean change")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"the secret is in a commit this push publishes, attributed to the commit that introduced it; findings=%v",
		findingLocations(scan))
}

// TestDiffScopeScansASecretOnAMergedSideBranch: the secret is added AND deleted
// on a side branch before the merge, so it is in no tree on the first-parent
// path and in no tree at HEAD. Walking first-parent only would miss it
// entirely; every parent of every newly reachable commit has to be read.
func TestDiffScopeScansASecretOnAMergedSideBranch(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	gitRun(t, dir, "checkout", "-q", "-b", "side")
	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "side: oops")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")
	gitRun(t, dir, "rm", "-q", "creds.env")
	gitRun(t, dir, "commit", "-q", "-m", "side: tidy up")

	gitRun(t, dir, "checkout", "-q", "main")
	writeFiles(t, dir, map[string]string{"b.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "main: unrelated")
	gitRun(t, dir, "merge", "-q", "--no-ff", "-m", "merge side", "side")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"a secret on a merged side branch is published by the push; findings=%v", findingLocations(scan))
}

// TestDiffScopeIgnoresSecretsAlreadyReachableFromTheBase: the other edge of
// the same rule. History scanning must not widen the scan to the whole
// repository — a secret the base already published is not this push's doing,
// and reporting it would make every gate fail forever on old history.
func TestDiffScopeIgnoresSecretsAlreadyReachableFromTheBase(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"old-leak.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "ancient history")
	gitRun(t, dir, "rm", "-q", "old-leak.env")
	gitRun(t, dir, "commit", "-q", "-m", "removed long ago")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"new.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "this push")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.Empty(t, findingLocations(scan),
		"only what this push newly publishes is in scope; the base's history is not")
}

// --- Regressions for PR #9373 review round 8. Both defects are in the round-7
// history walk: it trusted git's VIEW of history instead of the objects.

// TestDiffScopeScansANestedSecretInARootCommit: `git diff-tree` is plumbing,
// so it is NOT recursive by default. A root commit's subdirectories came back
// as TREE objects rather than the blobs inside them, so a secret nested one
// directory down in a root commit — an unrelated history merged in and the
// directory deleted afterwards — was never read.
func TestDiffScopeScansANestedSecretInARootCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	// An unrelated history whose root commit hides the secret in a subdirectory.
	gitRun(t, dir, "checkout", "-q", "--orphan", "other")
	gitRun(t, dir, "rm", "-rq", "--cached", ".")
	require.NoError(t, os.Remove(filepath.Join(dir, "a.txt")))
	writeFiles(t, dir, map[string]string{"dir/creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "unrelated root")
	root := gitRun(t, dir, "rev-parse", "HEAD")

	gitRun(t, dir, "checkout", "-q", "main")
	gitRun(t, dir, "merge", "-q", "--no-ff", "--allow-unrelated-histories", "-m", "merge unrelated", "other")
	gitRun(t, dir, "rm", "-rq", "dir")
	gitRun(t, dir, "commit", "-q", "-m", "drop dir")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+root+":dir/creds.env"),
		"a nested blob in a root commit is content the push publishes; findings=%v", findingLocations(scan))
}

// TestParseDiffRawRejectsATree: once the listing is recursive a tree can never
// appear, so one showing up means the listing was built wrong. That is a bug,
// not a path to skip — skipping it is exactly how the nested secret above went
// unread, quietly.
func TestParseDiffRawRejectsATree(t *testing.T) {
	raw := []byte(":000000 040000 " + strings.Repeat("0", 40) + " " + strings.Repeat("a", 40) + " A\x00dir\x00")
	_, err := parseDiffRaw(raw, blobFromCommit, "deadbeef")
	require.Error(t, err, "a tree in the listing must be an error, not a silently skipped path")
	require.Contains(t, err.Error(), "040000")
}

// graftRepo builds base -> A(secret) -> B(clean), then writes a graft file
// joining B straight to base so git's own walk cannot see A.
func graftRepo(t *testing.T) (dir, base, introducer string) {
	t.Helper()
	dir = t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base = gitRun(t, dir, "rev-parse", "HEAD")

	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "oops")
	introducer = gitRun(t, dir, "rev-parse", "HEAD")

	gitRun(t, dir, "rm", "-q", "creds.env")
	writeFiles(t, dir, map[string]string{"a.txt": "clean and tidy\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "tidy")
	head := gitRun(t, dir, "rev-parse", "HEAD")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git", "info"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "info", "grafts"),
		[]byte(head+" "+base+"\n"), 0o600))
	return dir, base, introducer
}

// TestDiffScopeWalksObjectParentsNotGitsView: .git/info/grafts rewrites what
// git REPORTS for a commit's parents, and --no-replace-objects does not touch
// it. rev-list then omits the secret-bearing commit entirely; remove the graft
// before pushing and the pushed history is unchanged while the evidence was
// clean. Ancestry is read from the commit objects, which a graft cannot alter.
//
// This drives the listing directly, below the refusal, because the refusal
// (see the next test) is what an operator actually hits. The walk has to be
// right on its own — the refusal is the fallback for graft mechanisms we
// cannot detect, not the only line of defence.
func TestDiffScopeWalksObjectParentsNotGitsView(t *testing.T) {
	requireGit(t)
	dir, base, introducer := graftRepo(t)

	require.NotContains(t, gitRun(t, dir, "rev-list", base+"..HEAD"), introducer,
		"the fixture must actually hide the commit from git's own walk")

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	scan, err := diffFiles(ctx, dir, base)
	require.NoError(t, err)

	got := make([]string, 0, len(scan.Blobs))
	for _, b := range scan.Blobs {
		got = append(got, b.Commit+":"+b.Rel)
	}
	require.Contains(t, got, introducer+":creds.env",
		"the commit objects still name the real parent, so the blob is still published; blobs=%v", got)
}

// TestDiffScopeRefusesAGraftedRepository: the loud refusal is the fallback for
// whatever else a graft can do. A view of history this attestor cannot trust
// produces no evidence at all rather than evidence that quietly covers less.
func TestDiffScopeRefusesAGraftedRepository(t *testing.T) {
	requireGit(t)
	dir, base, _ := graftRepo(t)

	scan := New(WithScope("diff:"+base), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)

	err = scan.Attest(ctx)
	require.Error(t, err)
	require.True(t, errors.Is(err, commandrun.ErrNotAttestable),
		"a grafted history must refuse with the sentinel, got: %v", err)
}

// TestDiffScopeRefusesAShallowRepository: a shallow clone's boundary commits
// lie about their parents by construction, so the newly reachable set cannot
// be computed. Same refusal, same reason.
func TestDiffScopeRefusesAShallowRepository(t *testing.T) {
	requireGit(t)
	origin := t.TempDir()
	gitRun(t, origin, "init", "-q", "-b", "main", ".")
	writeFiles(t, origin, map[string]string{"a.txt": "one\n"})
	gitRun(t, origin, "add", "-A")
	gitRun(t, origin, "commit", "-q", "-m", "one")
	writeFiles(t, origin, map[string]string{"a.txt": "two\n"})
	gitRun(t, origin, "add", "-A")
	gitRun(t, origin, "commit", "-q", "-m", "two")

	shallow := filepath.Join(t.TempDir(), "shallow")
	gitRun(t, origin, "clone", "-q", "--depth=1", "file://"+origin, shallow)
	require.Equal(t, "true", gitRun(t, shallow, "rev-parse", "--is-shallow-repository"),
		"the fixture must actually be shallow")

	scan := New(WithScope("diff:HEAD"), WithScanAttestations(false))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(shallow),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)

	err = scan.Attest(ctx)
	require.Error(t, err)
	require.True(t, errors.Is(err, commandrun.ErrNotAttestable),
		"a shallow history must refuse with the sentinel, got: %v", err)
}

// --- Regression for PR #9373 review round 9. Commit dates are not ancestry.

// gitRunAt commits with an explicit author/committer date, so a fixture can
// give history the skew that real repositories get from rebases, cherry-picks,
// imports and wrong clocks.
func gitRunAt(t *testing.T, dir string, epoch int, args ...string) string {
	t.Helper()
	// "@<epoch> +0000" is git's raw format; a bare number is not a date.
	stamp := fmt.Sprintf("@%d +0000", epoch)
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_DATE="+stamp, "GIT_COMMITTER_DATE="+stamp)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// TestDiffScopeIgnoresABasePublishedCommitDatedAfterTheBase is the shape the
// review named. R is the parent of both B and S; H merges B and S; the dates
// are skewed so R is NEWER than B:
//
//	B=100   R=200   S=300   H=400        base = B, HEAD = H
//
// R is reachable from the base, so the push does not publish it. A walk
// ordered by date stops once only B is left queued and reports R as new — so a
// secret introduced in R and deleted on both branches blocks a clean push
// forever, blaming this push for history the base already carried.
func TestDiffScopeIgnoresABasePublishedCommitDatedAfterTheBase(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")

	// R: the root, carrying the secret.
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n", "creds.env": "SECRET=" + scopePAT + "\n"})
	gitRunAt(t, dir, 200, "add", "-A")
	gitRunAt(t, dir, 200, "commit", "-q", "-m", "R: root with the secret")

	// B: deletes it, and is DATED BEFORE its own parent.
	gitRun(t, dir, "checkout", "-q", "-b", "b1")
	gitRun(t, dir, "rm", "-q", "creds.env")
	gitRunAt(t, dir, 100, "commit", "-q", "-m", "B: drop the secret")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	// S: the other child of R, also deletes it.
	gitRun(t, dir, "checkout", "-q", "-b", "b2", "HEAD~1")
	gitRun(t, dir, "rm", "-q", "creds.env")
	gitRunAt(t, dir, 300, "commit", "-q", "-m", "S: drop the secret too")

	// H: the merge, newest of all.
	gitRun(t, dir, "checkout", "-q", "b1")
	gitRunAt(t, dir, 400, "merge", "-q", "--no-ff", "-m", "H: merge", "b2")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.Empty(t, findingLocations(scan),
		"R is already published by the base whatever its date says; this push introduces nothing")
}

// TestDiffScopeScansASideBranchCommitDatedBeforeItsParent is the mirror: the
// commit that DOES belong to the push is dated earlier than its own parent.
// It must still be found, and still be attributed to itself.
func TestDiffScopeScansASideBranchCommitDatedBeforeItsParent(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")

	// R: clean root, dated LATE.
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	gitRunAt(t, dir, 300, "add", "-A")
	gitRunAt(t, dir, 300, "commit", "-q", "-m", "R: clean root")

	// B: the base, dated earliest.
	gitRun(t, dir, "checkout", "-q", "-b", "b1")
	writeFiles(t, dir, map[string]string{"a.txt": "clean and edited\n"})
	gitRunAt(t, dir, 100, "add", "-A")
	gitRunAt(t, dir, 100, "commit", "-q", "-m", "B: unrelated change")
	base := gitRun(t, dir, "rev-parse", "HEAD")

	// S: introduces the secret, dated BEFORE its parent R.
	gitRun(t, dir, "checkout", "-q", "-b", "b2", "HEAD~1")
	writeFiles(t, dir, map[string]string{"creds.env": "SECRET=" + scopePAT + "\n"})
	gitRunAt(t, dir, 200, "add", "-A")
	gitRunAt(t, dir, 200, "commit", "-q", "-m", "S: oops")
	introducer := gitRun(t, dir, "rev-parse", "HEAD")

	gitRun(t, dir, "checkout", "-q", "b1")
	gitRunAt(t, dir, 400, "merge", "-q", "--no-ff", "-m", "H: merge", "b2")
	gitRun(t, dir, "rm", "-q", "creds.env")
	gitRunAt(t, dir, 500, "commit", "-q", "-m", "D: drop it again")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasLocation(scan, "commit:"+introducer+":creds.env"),
		"a commit dated before its parent is still this push's to answer for; findings=%v", findingLocations(scan))
}
