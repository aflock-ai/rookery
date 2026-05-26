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

import "os"

// DefaultCachePatterns returns the well-known glob patterns that
// identify build-internal cache + temp storage across common
// languages and tools. Files matching these patterns get classified
// as cache/temp artifacts (semantically build-internal storage that
// may persist between builds but is NOT a user-facing product).
//
// Patterns use shell-style globs:
//   - matches any sequence except /
//     ** matches any sequence including /
//     ?  matches a single character
//
// Operators can:
//   - ADD entries via CILOCK_CACHE_ADD_PATTERN env / --cache-add-pattern
//   - REMOVE entries (treat as products instead) via
//     CILOCK_CACHE_ALLOW_PATTERN / --cache-allow-pattern
//   - DISABLE the defaults entirely via
//     CILOCK_CACHE_DISABLE_DEFAULTS / --cache-disable-defaults
//
// Source-of-truth list is here in code rather than a config file so
// the attestation framework remains self-contained and the defaults
// ship signed alongside the binary.
//
// Path-only classification — no per-process metadata, no MIME-type
// inspection. Glob matching is intentionally cheap so this runs
// on every product candidate during attestation finalization.
func DefaultCachePatterns() map[string]struct{} {
	return map[string]struct{}{
		// ─── Generic OS temp + cache roots ───
		"/tmp/**":                  {}, // Linux/BSD scratch
		"/var/tmp/**":              {}, // Linux long-lived temp
		"/var/folders/**":          {}, // macOS TMPDIR root (per-user)
		"**/.cache/**":             {}, // XDG cache spec (~/.cache, project-local .cache)
		"**/Library/Caches/**":     {}, // macOS user caches
		"**/AppData/Local/Temp/**": {}, // Windows TEMP
		"**/AppData/Local/Microsoft/Windows/INetCache/**": {}, // IE/Edge

		// ─── Go ───
		"**/go-build*/**":        {}, // GOCACHE (default ~/.cache/go-build; also /tmp/go-build*)
		"**/go/pkg/mod/cache/**": {}, // module download cache
		"**/go/pkg/sumdb/**":     {}, // checksum database cache

		// ─── Python ───
		"**/__pycache__/**":   {},
		"**/*.pyc":            {},
		"**/*.pyo":            {},
		"**/.pytest_cache/**": {},
		"**/.mypy_cache/**":   {},
		"**/.ruff_cache/**":   {},
		"**/.tox/**":          {},
		"**/.coverage":        {},
		"**/.coverage.*":      {},
		"**/htmlcov/**":       {},
		"**/.pip/cache/**":    {},
		"**/pip/cache/**":     {}, // $PIP_CACHE_DIR override locations

		// ─── Node.js / JavaScript ecosystem ───
		"**/node_modules/.cache/**": {},
		"**/.next/cache/**":         {}, // Next.js
		"**/.nuxt/cache/**":         {}, // Nuxt
		"**/.svelte-kit/**":         {},
		"**/.turbo/**":              {}, // Turborepo
		"**/.parcel-cache/**":       {},
		"**/.npm/_cacache/**":       {},
		"**/.yarn/cache/**":         {},
		"**/.yarn/install-state.gz": {},
		"**/.pnpm-store/**":         {},
		"**/.vite/**":               {},

		// ─── Rust / Cargo ───
		// target/debug/<binary> (no extension, in the debug/ root) is the
		// user-facing OUTPUT for `cargo build`. Treat target/debug/{deps,
		// build, .fingerprint, incremental} as cache; let the actual
		// binary in target/debug/ fall through to product classification.
		"**/target/debug/deps/**":           {}, // intermediate .rlib + .o
		"**/target/debug/build/**":          {}, // build-script artifacts
		"**/target/debug/.fingerprint/**":   {}, // cargo's fingerprint markers
		"**/target/debug/incremental/**":    {}, // incremental compile state
		"**/target/release/deps/**":         {},
		"**/target/release/build/**":        {},
		"**/target/release/.fingerprint/**": {},
		"**/target/release/incremental/**":  {},
		"**/target/.rustc_info.json":        {}, // cargo's rustc-version cache
		"**/target/CACHEDIR.TAG":            {}, // cargo's cache marker
		"**/.cargo/registry/cache/**":       {},
		"**/.cargo/registry/src/**":         {},
		"**/.cargo/git/checkouts/**":        {},

		// ─── Java / Maven / Gradle ───
		// .m2/repository is INPUTS not cache — Maven local repo is a
		// dependency source; we deliberately don't classify it here.
		"**/.gradle/caches/**":          {},
		"**/.gradle/daemon/**":          {},
		"**/.gradle/native/**":          {},
		"**/build/tmp/**":               {}, // Gradle build temp
		"**/.idea/caches/**":            {}, // IntelliJ caches
		"**/.idea/shelf/**":             {},
		"**/.idea/usage.statistics.xml": {},

		// ─── C / C++ / Make / CMake / ccache ───
		"**/.ccache/**":       {},
		"**/ccache/**":        {},
		"**/CMakeFiles/**":    {},
		"**/CMakeCache.txt":   {},
		"**/cmake-build-*/**": {},
		"**/.deps/**":         {}, // automake dependency tracking

		// ─── Kbuild (Linux kernel build) ───
		// .cmd files are Kbuild's per-object dependency tracking
		// (one per .o); a defconfig produces ~25,000 of them, all
		// write-once-never-read in a clean build. Currently the
		// dominant source of misclassified "products" — without
		// this rule defconfig reports ~5,700 products, of which
		// ~5,000+ are these .cmd files.
		"**/.*.cmd":      {}, // .foo.o.cmd, .built-in.a.cmd, .modules.order.cmd, ...
		"**/.tmp_*/**":   {}, // Kbuild per-link-stage temp dirs (modpost, vmlinux.tmp)
		"**/.tmp_*.[oa]": {}, // Kbuild temp .o / .a (e.g. .tmp_kallsyms1.o)
		"**/.*.d":        {}, // gcc -MD per-file dependency files (raw form)
		"**/.config.old": {}, // Kbuild's previous-config backup

		// ─── Container / Docker / Bazel ───
		"**/.docker/buildx/cache/**": {},
		"**/bazel-out/**":            {},
		"**/bazel-bin/**":            {},
		"**/bazel-testlogs/**":       {},

		// ─── Git working state (not source) ───
		"**/.git/index":               {},
		"**/.git/HEAD.lock":           {},
		"**/.git/objects/pack/.tmp-*": {},

		// ─── Editor / IDE volatile state ───
		"**/.vscode/.ropeproject/**": {},
		"**/.history/**":             {},
		"**/.swp":                    {}, // vim swap
		"**/*.swp":                   {},

		// ─── Misc lock + state files ───
		"**/*.lock-info": {},
		"**/.DS_Store":   {}, // macOS finder metadata
	}
}

// SystemCachePathsFromEnv probes the runtime environment for
// cache + temp paths set via environment variable. Each found
// variable contributes a glob matching its value's entire subtree.
// Returns paths as glob patterns; merge into the configured cache
// pattern set.
//
// Why query the environment:
//
//	The hardcoded defaults catch common LOCATIONS (~/.cache/...,
//	/tmp/...), but operators routinely point their toolchains at
//	custom roots via env vars — e.g., GOCACHE=/mnt/fast/go-build on
//	build farms, CARGO_HOME on shared NFS, PIP_CACHE_DIR for
//	container builds. Without env-driven discovery a build that
//	moves its cache to /opt/build/cache would have those entries
//	show up as products. This function closes that gap.
//
// Returns absolute-path globs (one /** per env entry). Skips vars
// that are unset, empty, or "/" (which would match everything).
//
// Coverage rationale: include only env vars whose semantics are
// unambiguously "cache" or "temp" — not e.g. GOPATH (source root,
// not cache) or M2_HOME (Maven install location, not cache).
//
//nolint:funlen // explicit enumeration is the entire point
func SystemCachePathsFromEnv() []string {
	type envEntry struct {
		key    string
		suffix string // appended after env value (e.g., "/cache/**" for sub-cache)
	}
	entries := []envEntry{
		// ─── Generic POSIX / XDG ───
		{"XDG_CACHE_HOME", "/**"},
		{"XDG_RUNTIME_DIR", "/**"},
		{"TMPDIR", "/**"},
		{"TMP", "/**"}, // Windows
		{"TEMP", "/**"},

		// ─── Go ───
		{"GOCACHE", "/**"},
		{"GOMODCACHE", "/cache/**"},
		{"GOTMPDIR", "/**"},

		// ─── Rust / Cargo ───
		{"CARGO_HOME", "/registry/cache/**"},
		{"CARGO_HOME", "/registry/src/**"},
		{"CARGO_TARGET_DIR", "/**"},

		// ─── Python ───
		{"PIP_CACHE_DIR", "/**"},
		{"PYTHONPYCACHEPREFIX", "/**"},
		{"POETRY_CACHE_DIR", "/**"},

		// ─── Node.js ecosystem ───
		{"NPM_CONFIG_CACHE", "/**"},
		{"YARN_CACHE_FOLDER", "/**"},
		{"PNPM_HOME", "/store/**"},
		{"BUN_INSTALL_CACHE_DIR", "/**"},

		// ─── Java / Gradle ───
		{"GRADLE_USER_HOME", "/caches/**"},
		{"GRADLE_USER_HOME", "/daemon/**"},

		// ─── C / C++ ───
		{"CCACHE_DIR", "/**"},
		{"SCCACHE_DIR", "/**"},

		// ─── Container / image build ───
		{"DOCKER_BUILDKIT_CACHE_DIR", "/**"},
		{"BUILDAH_CACHE_DIR", "/**"},

		// ─── Ruby ───
		{"BUNDLE_CACHE_PATH", "/**"},
		{"GEM_HOME", "/cache/**"},
	}
	seen := make(map[string]bool, len(entries))
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		v := getEnvForCachePath(e.key)
		if v == "" || v == "/" {
			continue
		}
		// Strip trailing slash so we don't end up with "//**".
		for len(v) > 1 && v[len(v)-1] == '/' {
			v = v[:len(v)-1]
		}
		pattern := v + e.suffix
		if seen[pattern] {
			continue
		}
		seen[pattern] = true
		out = append(out, pattern)
	}
	return out
}

// getEnvForCachePath reads an env var. Indirected through a package
// var so tests can stub it without monkey-patching os.Getenv.
//
//nolint:gochecknoglobals // intentional indirection for test stubbing
var getEnvForCachePath = os.Getenv
