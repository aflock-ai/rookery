// jade:ring local
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

package policy

import (
	"context"
	"path"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #9815: Step.AllowedUntracked was documented as strict chain-of-custody
// ("Empty (the default) means strict mode") but nothing read it, and
// compareArtifacts silently skipped any downstream material the upstream step
// never produced. These tests pin the enforced contract:
//
//   - in a step with artifactsFrom, every material must match an upstream
//     artifact (by path, digests equal) OR match an AllowedUntracked glob;
//   - an allow-listed path that IS present upstream still has to match its
//     digest (the glob exempts absence, never a mismatch);
//   - the >=1 overlap rule (GHSA-vmvj-p3hw-39q3) is unchanged.

// untrackedChainPolicy builds source -> build (artifactsFrom=[source]) where
// source produces app.bin=D and build consumed buildMats.
func untrackedChainPolicy(t *testing.T, allowed []string, srcProducts map[string]cryptoutil.DigestSet, buildMats map[string]cryptoutil.DigestSet) (Policy, *lazySource) {
	t.Helper()
	verifier, keyID := earlyExitVerifier(t)

	products := make(map[string]attestation.Product, len(srcProducts))
	for p, d := range srcProducts {
		products[p] = attestation.Product{Digest: d}
	}
	src := lazyCollection(verifier, "source-1", "source", "",
		&lazyAttestor{AttName: "source-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "source-1-prod", AttType: lazyChainAttType, products: products, inline: true})
	build := lazyCollection(verifier, "build-1", "build", "",
		&lazyAttestor{AttName: "build-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "build-1-mat", AttType: lazyChainAttType, materials: buildMats, inline: true})

	buildStep := lazyStep("build", keyID)
	buildStep.ArtifactsFrom = []string{"source"}
	buildStep.AllowedUntracked = allowed

	return lazyPolicy(keyID, buildStep, lazyStep("source", keyID)),
		newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": {build, src}})
}

func verifyUntrackedChain(t *testing.T, p Policy, src *lazySource) (bool, map[string]StepResult) {
	t.Helper()
	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:seed"}),
	)
	require.NoError(t, err)
	return pass, results
}

func buildRejections(results map[string]StepResult) string {
	var b strings.Builder
	for _, r := range results["build"].Rejected {
		if r.Reason != nil {
			b.WriteString(r.Reason.Error())
			b.WriteString("\n")
		}
	}
	return b.String()
}

func TestAllowedUntracked_ChainEnforcement(t *testing.T) {
	d := lazyDigest("d0d0")
	x := lazyDigest("e1e1")
	injected := map[string]cryptoutil.DigestSet{"app.bin": d, "/tmp/injected.sh": x}
	upstream := map[string]cryptoutil.DigestSet{"app.bin": d}

	cases := []struct {
		name      string
		allowed   []string
		products  map[string]cryptoutil.DigestSet
		materials map[string]cryptoutil.DigestSet
		wantPass  bool
		wantInErr string
	}{
		{
			// The #9815 repro: an untracked material with no allow-list.
			name: "strict default rejects untracked material", allowed: nil,
			products: upstream, materials: injected,
			wantPass: false, wantInErr: "/tmp/injected.sh",
		},
		{
			// An allow-list that does not cover the injected path.
			name: "non-matching glob still rejects", allowed: []string{"/usr/lib/**"},
			products: upstream, materials: injected,
			wantPass: false, wantInErr: "/tmp/injected.sh",
		},
		{
			name: "matching glob admits the untracked path", allowed: []string{"/tmp/**"},
			products: upstream, materials: injected,
			wantPass: true,
		},
		{
			name: "exact path pattern admits", allowed: []string{"/tmp/injected.sh"},
			products: upstream, materials: injected,
			wantPass: true,
		},
		{
			name: "fully tracked materials pass with no allow-list", allowed: nil,
			products: upstream, materials: upstream,
			wantPass: true,
		},
		{
			// The glob exempts ABSENCE upstream, never a digest mismatch on
			// a path upstream did produce.
			name: "allow-listed path present upstream must still match digest", allowed: []string{"**"},
			products: upstream, materials: map[string]cryptoutil.DigestSet{"app.bin": x},
			wantPass: false, wantInErr: "mismatched digests for app.bin",
		},
		{
			// An alternate spelling of an upstream path skips compareArtifacts'
			// raw-key digest compare; a glob must not admit it.
			name: "aliased spelling of upstream path is never glob-admitted", allowed: []string{"*.bin", "**"},
			products: upstream, materials: map[string]cryptoutil.DigestSet{"app.bin": d, "./app.bin": x},
			wantPass: false, wantInErr: "./app.bin",
		},
		{
			// GHSA-vmvj-p3hw-39q3 overlap rule is unchanged: materials that
			// are ALL allow-listed but share nothing with upstream still fail.
			name: "overlap rule still rejects zero shared paths", allowed: []string{"/tmp/**"},
			products: upstream, materials: map[string]cryptoutil.DigestSet{"/tmp/injected.sh": x},
			wantPass: false, wantInErr: "no artifacts in common",
		},
		{
			// A signed, inline, EMPTY material set remains a legitimate
			// "consumed nothing" claim.
			name: "empty signed material set still passes", allowed: nil,
			products: upstream, materials: map[string]cryptoutil.DigestSet{},
			wantPass: true,
		},
	}
	withHardening(t, HardeningOptions{EnforceAllowedUntracked: true})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, src := untrackedChainPolicy(t, tc.allowed, tc.products, tc.materials)
			pass, results := verifyUntrackedChain(t, p, src)
			assert.Equal(t, tc.wantPass, pass, "rejections: %s", buildRejections(results))
			if tc.wantInErr != "" {
				assert.Contains(t, buildRejections(results), tc.wantInErr)
			}
		})
	}
}

// TestAllowedUntracked_WarnOnlyWithoutHardening pins the backward-compatible
// library zero value: with EnforceAllowedUntracked off (any embedder
// that never calls SetHardening) the #9815 repro keeps verifying exactly as it
// did before, so existing policies do not start failing on upgrade. The
// overlap and digest-mismatch rules still apply in this mode.
func TestAllowedUntracked_WarnOnlyWithoutHardening(t *testing.T) {
	withHardening(t, HardeningOptions{})
	d := lazyDigest("d0d0")
	x := lazyDigest("e1e1")
	upstream := map[string]cryptoutil.DigestSet{"app.bin": d}

	p, src := untrackedChainPolicy(t, nil, upstream, map[string]cryptoutil.DigestSet{"app.bin": d, "/tmp/injected.sh": x})
	pass, results := verifyUntrackedChain(t, p, src)
	assert.True(t, pass, "warn-only default must keep pre-#9815 behavior: %s", buildRejections(results))

	p, src = untrackedChainPolicy(t, nil, upstream, map[string]cryptoutil.DigestSet{"app.bin": x})
	pass, _ = verifyUntrackedChain(t, p, src)
	assert.False(t, pass, "digest mismatch must still fail without hardening")
}

func TestErrUntrackedMaterials_BoundsMessage(t *testing.T) {
	paths := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		paths = append(paths, strings.Repeat("p", i+1))
	}
	msg := ErrUntrackedMaterials{Step: "build", Paths: paths}.Error()
	assert.Contains(t, msg, "25 material(s)")
	assert.Contains(t, msg, "... and 5 more")
	assert.NotContains(t, msg, strings.Repeat("p", 21))
}

// TestAllowedUntracked_MultipleArtifactsFrom pins that coverage is the UNION of
// every artifactsFrom edge: a build consuming source files AND dependency files
// is fully tracked when each edge covers its own share, even though no single
// edge covers everything.
func TestAllowedUntracked_MultipleArtifactsFrom(t *testing.T) {
	withHardening(t, HardeningOptions{EnforceAllowedUntracked: true})
	verifier, keyID := earlyExitVerifier(t)
	a := lazyDigest("aaaa")
	b := lazyDigest("bbbb")
	x := lazyDigest("cccc")

	src := lazyCollection(verifier, "source-1", "source", "",
		&lazyAttestor{AttName: "source-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "source-1-prod", AttType: lazyChainAttType,
			products: map[string]attestation.Product{"main.go": {Digest: a}}, inline: true})
	deps := lazyCollection(verifier, "deps-1", "deps", "",
		&lazyAttestor{AttName: "deps-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "deps-1-prod", AttType: lazyChainAttType,
			products: map[string]attestation.Product{"vendor/lib.go": {Digest: b}}, inline: true})

	for _, tc := range []struct {
		name     string
		mats     map[string]cryptoutil.DigestSet
		wantPass bool
	}{
		{"union of edges covers every material", map[string]cryptoutil.DigestSet{"main.go": a, "vendor/lib.go": b}, true},
		{"material covered by neither edge fails", map[string]cryptoutil.DigestSet{"main.go": a, "vendor/lib.go": b, "evil.go": x}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := lazyCollection(verifier, "build-1", "build", "",
				&lazyAttestor{AttName: "build-1", AttType: lazyAttType},
				&lazyAttestor{AttName: "build-1-mat", AttType: lazyChainAttType, materials: tc.mats, inline: true})
			buildStep := lazyStep("build", keyID)
			buildStep.ArtifactsFrom = []string{"source", "deps"}
			p := lazyPolicy(keyID, buildStep, lazyStep("source", keyID), lazyStep("deps", keyID))
			ls := newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": {build, src, deps}})
			pass, results := verifyUntrackedChain(t, p, ls)
			assert.Equal(t, tc.wantPass, pass, "rejections: %s", buildRejections(results))
			if !tc.wantPass {
				assert.Contains(t, buildRejections(results), "evil.go")
			}
		})
	}
}

// TestMatchAllowedUntracked pins the glob semantics documented on
// Step.AllowedUntracked: gobwas/glob with '/' as the separator, matched
// against the material path exactly as the material attestor recorded it
// (lexically cleaned; no absolute/relative normalization).
func TestMatchAllowedUntracked(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// ** crosses separators; * does not.
		{"/usr/lib/**", "/usr/lib/x86_64/libc.so", true},
		{"/usr/lib/**", "/usr/lib/libc.so", true},
		{"/usr/lib/*", "/usr/lib/libc.so", true},
		{"/usr/lib/*", "/usr/lib/x86_64/libc.so", false},
		// Prefix must be a whole path segment.
		{"/usr/lib/**", "/usr/lib64/libc.so", false},
		{"/usr/lib/**", "/usr/lib", false},
		// Absolute and relative paths are distinct; no implicit rooting.
		{"/vendor/**", "vendor/a.go", false},
		{"vendor/**", "/vendor/a.go", false},
		{"vendor/**", "vendor/a/b.go", true},
		{"*.go", "main.go", true},
		{"*.go", "cmd/main.go", false},
		{"**.go", "cmd/main.go", true},
		// Traversal cannot climb out of an allow-listed prefix: the path is
		// lexically cleaned before matching.
		{"vendor/**", "vendor/../../etc/passwd", false},
		{"/usr/lib/**", "/usr/lib/../../etc/shadow", false},
		{"/etc/**", "/usr/lib/../../etc/shadow", true},
		// Cleaning also normalizes harmless redundancy.
		{"vendor/**", "./vendor/a.go", true},
		{"vendor/**", "vendor//a.go", true},
		// Character classes / alternation behave as gobwas documents.
		{"/opt/{a,b}/**", "/opt/b/tool", true},
		{"/opt/{a,b}/**", "/opt/c/tool", false},
		// The literals on either side of '**' never share bytes. gobwas let
		// them overlap, so "a**a" admitted "a" and "vendor/**/x.go" admitted
		// "vendor/x.go" (while "vendor/**/*.go" refused "vendor/a.go").
		{"a**a", "a", false},
		{"a**a", "aa", true},
		{"/**/", "/", false},
		{"vendor/**/x.go", "vendor/x.go", false},
		{"vendor/**/x.go", "vendor/a/x.go", true},
		{"vendor/**/*.go", "vendor/a.go", false},
		{"vendor/**x.go", "vendor/x.go", true},
		// '?' is one rune and never the separator.
		{"?", "é", true},
		{"a?b", "a/b", false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"|"+tc.path, func(t *testing.T) {
			m, err := compileAllowedUntracked([]string{tc.pattern})
			require.NoError(t, err)
			assert.Equal(t, tc.want, m.matches(tc.path))
		})
	}

	t.Run("empty allow-list matches nothing", func(t *testing.T) {
		m, err := compileAllowedUntracked(nil)
		require.NoError(t, err)
		assert.False(t, m.matches("anything"))
		assert.False(t, m.matches(""))
	})
}

// refUntrackedGlob is the allowedUntracked glob semantics written as a direct
// recursive definition (the cilock-policy Lean model's untrackedAllowed): '**'
// is any run of runes, '*' any run without '/', '?' one rune other than '/',
// anything else itself. Tokens are read left to right, "**" before "*".
func refUntrackedGlob(pat, v []rune) bool {
	if len(pat) == 0 {
		return len(v) == 0
	}
	switch {
	case len(pat) >= 2 && pat[0] == '*' && pat[1] == '*':
		for i := 0; i <= len(v); i++ {
			if refUntrackedGlob(pat[2:], v[i:]) {
				return true
			}
		}
		return false
	case pat[0] == '*':
		for i := 0; i <= len(v); i++ {
			if refUntrackedGlob(pat[1:], v[i:]) {
				return true
			}
			if i < len(v) && v[i] == '/' {
				return false
			}
		}
		return false
	case pat[0] == '?':
		return len(v) > 0 && v[0] != '/' && refUntrackedGlob(pat[1:], v[1:])
	default:
		return len(v) > 0 && v[0] == pat[0] && refUntrackedGlob(pat[1:], v[1:])
	}
}

// TestAllowedUntrackedMatchesReference enumerates every pattern of up to four
// tokens over {a, b, *, **, ?, /} against every clean path of up to five
// characters over {a, b, /} and holds the matcher to refUntrackedGlob. It is
// the adversarial form of the overlap cases above: gobwas failed it on "a**a"
// against "a" and on "/**/" against "/", both admitting a path the pattern
// does not describe.
func TestAllowedUntrackedMatchesReference(t *testing.T) {
	tokens := []string{"a", "b", "*", "**", "?", "/"}
	var pats []string
	seen := map[string]bool{}
	var grow func(prefix string, n int)
	grow = func(prefix string, n int) {
		if prefix != "" && !seen[prefix] {
			seen[prefix] = true
			pats = append(pats, prefix)
		}
		if n == 0 {
			return
		}
		for _, tok := range tokens {
			grow(prefix+tok, n-1)
		}
	}
	grow("", 4)
	var vals []string
	var grow2 func(prefix string, n int)
	grow2 = func(prefix string, n int) {
		if prefix != "" && path.Clean(prefix) == prefix {
			vals = append(vals, prefix)
		}
		if n == 0 {
			return
		}
		for _, c := range []string{"a", "b", "/"} {
			grow2(prefix+c, n-1)
		}
	}
	grow2("", 5)

	mismatches := 0
	for _, p := range pats {
		m, err := compileAllowedUntracked([]string{p})
		require.NoError(t, err, p)
		for _, v := range vals {
			want := refUntrackedGlob([]rune(p), []rune(v))
			if got := m.matches(v); got != want {
				mismatches++
				if mismatches <= 20 {
					t.Errorf("pattern %q path %q: matcher %v, reference %v", p, v, got, want)
				}
			}
		}
	}
	t.Logf("%d patterns x %d paths, %d mismatches", len(pats), len(vals), mismatches)
}

// TestStepAllowsUntracked pins the exported probe to the verifier's matcher.
func TestStepAllowsUntracked(t *testing.T) {
	s := Step{AllowedUntracked: []string{"/usr/lib/*.so*"}}
	ok, err := s.AllowsUntracked("/usr/lib/libc.so.6")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = s.AllowsUntracked("/usr/lib/x/libc.so.6")
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = Step{}.AllowsUntracked("/usr/lib/libc.so.6")
	require.NoError(t, err)
	assert.False(t, ok, "an empty allow-list admits nothing")

	_, err = Step{AllowedUntracked: []string{"/usr/lib/["}}.AllowsUntracked("/usr/lib/x")
	require.Error(t, err)
}

// TestAllowedUntracked_InvalidGlobRejectedAtValidate pins that a malformed
// pattern fails policy load instead of silently matching nothing (or
// everything) at verify time.
func TestAllowedUntracked_InvalidGlobRejectedAtValidate(t *testing.T) {
	_, keyID := earlyExitVerifier(t)
	for _, bad := range []string{"/usr/lib/[", "/opt/[a-", ""} {
		t.Run(bad, func(t *testing.T) {
			build := lazyStep("build", keyID)
			build.ArtifactsFrom = []string{"source"}
			build.AllowedUntracked = []string{bad}
			p := lazyPolicy(keyID, build, lazyStep("source", keyID))
			err := p.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "allowedUntracked")
		})
	}
}
