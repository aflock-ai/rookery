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

package attestation

import "testing"

// TestCacheMatcher_GoModuleCache asserts the WHOLE Go module cache is
// classified as build-internal, not just the download cache. A cold
// `go build` extracts module source into $GOMODCACHE/<mod>@<ver>/… and
// those write events were being captured as products before the pattern
// was broadened from **/go/pkg/mod/cache/** to **/go/pkg/mod/**.
func TestCacheMatcher_GoModuleCache(t *testing.T) {
	m, errs := NewCachePathMatcher(ResolveCachePatterns(CachePatternOptions{
		DisableSystemQuery: true, // exercise the hardcoded defaults only
	}))
	if len(errs) != 0 {
		t.Fatalf("pattern compile errors: %v", errs)
	}

	cache := []string{
		// download cache (matched before AND after the fix)
		"/home/runner/go/pkg/mod/cache/download/github.com/foo/bar/@v/v1.2.3.zip",
		// extracted module SOURCE — the regression: these were captured as products
		"/home/runner/go/pkg/mod/github.com/foo/bar@v1.2.3/.cirrus.yml",
		"/home/runner/go/pkg/mod/github.com/foo/bar@v1.2.3/internal/x/y.go",
		"/home/runner/go/pkg/mod/golang.org/x/text@v0.14.0/LICENSE",
	}
	for _, p := range cache {
		if !m.Matches(p) {
			t.Errorf("expected %q to be classified as cache, but it was not", p)
		}
	}

	// A real product must NOT be swept up by the broadened pattern.
	products := []string{
		"/home/runner/work/hugo/hugo/hugo-bin",
		"/home/runner/work/hugo/hugo/hugo-bin.cdx.json",
	}
	for _, p := range products {
		if m.Matches(p) {
			t.Errorf("expected %q to be a product, but it was classified as cache", p)
		}
	}
}

// TestCacheMatcher_GOMODCACHEEnv asserts the env-derived GOMODCACHE
// pattern covers the whole tree (extracted source included), not just
// the /cache subdir.
func TestCacheMatcher_GOMODCACHEEnv(t *testing.T) {
	orig := getEnvForCachePath
	getEnvForCachePath = func(k string) string {
		if k == "GOMODCACHE" {
			return "/custom/modcache"
		}
		return ""
	}
	defer func() { getEnvForCachePath = orig }()

	m, errs := NewCachePathMatcher(ResolveCachePatterns(CachePatternOptions{
		DisableDefaults: true, // isolate the env-derived pattern
	}))
	if len(errs) != 0 {
		t.Fatalf("pattern compile errors: %v", errs)
	}

	if !m.Matches("/custom/modcache/github.com/foo/bar@v1.2.3/main.go") {
		t.Error("extracted module source under GOMODCACHE should be cache")
	}
	if !m.Matches("/custom/modcache/cache/download/x.zip") {
		t.Error("download cache under GOMODCACHE should still be cache")
	}
}
