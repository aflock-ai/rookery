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
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// Precedence table — Bug 1 from the blind Linux UX test
// =====================================================================
//
// Argo CD test surfaced a silent-failure: `cilock run --trace --
// go build -o /tmp/out/argocd ./cmd` produced an empty product set
// because /tmp/** is a default cache pattern AND the cache classifier
// ran inside commandrun.TraceOutputs BEFORE the user's
// --attestor-product-include-glob got a chance to express intent.
//
// Fix: move cache classification into product.Attest's precedence
// table. These tests pin the table cell-by-cell so a regression that
// reorders the precedence is caught at unit-test time.

func mustGlob(t *testing.T, p string) glob.Glob {
	t.Helper()
	g, err := glob.Compile(p)
	require.NoError(t, err, "compile glob %q", p)
	return g
}

func mustCacheMatcher(t *testing.T, patterns []string) *attestation.CachePathMatcher {
	t.Helper()
	m, errs := attestation.NewCachePathMatcher(patterns)
	require.Empty(t, errs, "cache matcher compile errors: %v", errs)
	return m
}

// TestPrecedence_UserIncludeWinsOverDefaultCache: this is the
// regression. The operator passes --attestor-product-include-glob
// '/tmp/**' (user-set, NOT the default "*"), and even though /tmp/**
// is in the default cache patterns, the path must be classified as a
// PRODUCT.
func TestPrecedence_UserIncludeWinsOverDefaultCache(t *testing.T) {
	cache := mustCacheMatcher(t, []string{"/tmp/**", "**/.cache/**"})
	cacheAllow := mustCacheMatcher(t, nil)
	includeGlob := mustGlob(t, "/tmp/**")

	got := classifyTracePath(
		"/tmp/build/argocd",
		includeGlob, true, // user-set: this is the rescue signal
		nil, // no exclude
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyProduct, got,
		"user-set include-glob must rescue /tmp/build/argocd from the /tmp/** default cache pattern")
}

// TestPrecedence_UserExcludeWinsOverInclude: include and exclude both
// fire. Exclude wins.
func TestPrecedence_UserExcludeWinsOverInclude(t *testing.T) {
	cache := mustCacheMatcher(t, []string{"/tmp/**"})
	cacheAllow := mustCacheMatcher(t, nil)
	includeGlob := mustGlob(t, "/tmp/**")
	excludeGlob := mustGlob(t, "**/argocd")

	got := classifyTracePath(
		"/tmp/build/argocd",
		includeGlob, true,
		excludeGlob,
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyDrop, got,
		"exclude-glob must drop a path even when include-glob also matches")
}

// TestPrecedence_CacheAllowExemptsFromDefaultCache: no include flag,
// but --cache-allow-pattern '/tmp/build/**' rescues the build output.
func TestPrecedence_CacheAllowExemptsFromDefaultCache(t *testing.T) {
	cache := mustCacheMatcher(t, []string{"/tmp/**"})
	cacheAllow := mustCacheMatcher(t, []string{"/tmp/build/**"})
	// Include glob is the default "*" — NOT user-set.
	includeGlob := mustGlob(t, "*")

	got := classifyTracePath(
		"/tmp/build/argocd",
		includeGlob, false, // default include glob, NO user intent
		nil, // no exclude
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyProduct, got,
		"cache-allow pattern must exempt a path from the default cache classifier")
}

// TestPrecedence_DefaultCacheDropsWhenNoUserIntent: the silent-drop
// path from before the fix — no user flags, /tmp output → CACHE
// bucket (not a product). Codifies that the cache classifier still
// works when the operator hasn't expressed intent.
func TestPrecedence_DefaultCacheDropsWhenNoUserIntent(t *testing.T) {
	cache := mustCacheMatcher(t, []string{"/tmp/**"})
	cacheAllow := mustCacheMatcher(t, nil)
	includeGlob := mustGlob(t, "*")

	got := classifyTracePath(
		"/tmp/argocd",
		includeGlob, false,
		nil,
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyCache, got,
		"with no user flags, /tmp/argocd must land in the cache bucket")
}

// TestPrecedence_NoFiltersKeepsEverything: nothing fires; path lands
// as a product. The "default include='*', empty exclude, no cache
// pattern matches" baseline.
func TestPrecedence_NoFiltersKeepsEverything(t *testing.T) {
	cache := mustCacheMatcher(t, []string{"/tmp/**"})
	cacheAllow := mustCacheMatcher(t, nil)
	includeGlob := mustGlob(t, "*")

	got := classifyTracePath(
		"/build/argocd",
		includeGlob, false,
		nil,
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyProduct, got,
		"/build/argocd with no user flags and no cache match must be a product")
}

// TestPrecedence_UserIncludeNarrowsButCacheStillCatchesOthers: when
// the user passes a NARROW include-glob (e.g. '/build/**'), paths
// that don't match it AND ARE cache must still land in CACHE — not
// DROP. The exclude semantics is only for paths the user explicitly
// excluded; un-matched cache paths flow to the cache bucket.
//
// However when the path is NEITHER in include NOR in cache, the
// user's narrowing intent dominates: we drop it. The precedence
// table's step 5 covers this.
func TestPrecedence_UserIncludeNarrowsCacheStillCatches(t *testing.T) {
	cache := mustCacheMatcher(t, []string{"/tmp/**"})
	cacheAllow := mustCacheMatcher(t, nil)
	includeGlob := mustGlob(t, "/build/**")

	// /tmp/scratch.txt: doesn't match user include, IS in cache → CACHE.
	gotCache := classifyTracePath(
		"/tmp/scratch.txt",
		includeGlob, true,
		nil,
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyCache, gotCache,
		"a path the user's narrow include didn't claim, and that IS in the cache, must land in cache")

	// /random/elsewhere.txt: doesn't match include, ISN'T in cache → DROP
	// (operator narrowed include, so we trust they don't want this).
	gotDrop := classifyTracePath(
		"/random/elsewhere.txt",
		includeGlob, true,
		nil,
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyDrop, gotDrop,
		"a path outside the user's narrow include and outside cache must be dropped")
}

// TestPrecedence_DefaultIncludeStarDoesNotOverrideCache: the default
// include="*" is the most-common case. Without the user-intent flag,
// it must NOT rescue every path from cache (which would defeat the
// classifier entirely). The cache classifier still wins.
func TestPrecedence_DefaultIncludeStarDoesNotOverrideCache(t *testing.T) {
	cache := mustCacheMatcher(t, []string{"/tmp/**"})
	cacheAllow := mustCacheMatcher(t, nil)
	includeGlob := mustGlob(t, "*")

	got := classifyTracePath(
		"/tmp/scratch",
		includeGlob, false, // default — NOT user intent
		nil,
		cacheAllow,
		cache,
	)
	assert.Equal(t, classifyCache, got,
		"default include='*' must not rescue cache paths; the cache classifier owns them")
}
