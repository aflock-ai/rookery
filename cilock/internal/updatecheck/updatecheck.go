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

// Package updatecheck performs a best-effort new-release check against the
// cilock.dev download manifest.
//
// Design constraints (a version check must be unable to break anything):
//   - It NEVER runs for unstamped, dirty, or pre-release builds.
//   - The fetch runs in a background goroutine, concurrently with the real
//     command, under a hard deadline (default 2s). If the result isn't in by
//     the time the command finishes + deadline, nothing is printed.
//   - Every error — network, HTTP status, JSON, cache I/O — is silently
//     swallowed. There is no retry.
//   - Results (including failed attempts) are cached for 24h in the user
//     cache dir, so repeated CI invocations neither hammer the endpoint nor
//     pay the fetch latency.
//   - It only ever produces a string for the caller to print to stderr; it
//     never prompts and never affects exit codes.
package updatecheck

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	// DefaultManifestURL is the public release manifest on cilock.dev. Its
	// top-level "latest" field is only ever moved by GA releases (the
	// publisher skips it for pre-releases), so it is safe to nag against.
	DefaultManifestURL = "https://cilock.dev/dl/manifest.json"

	// defaultTimeout is the hard deadline for the whole check.
	defaultTimeout = 2 * time.Second

	// cacheTTL is how long a fetched (or failed) result is reused.
	cacheTTL = 24 * time.Hour

	// cacheFileName is the file written under Config.CacheDir.
	cacheFileName = "update-check.json"

	// noticeGrace caps how long Notice() will wait AFTER the command has
	// finished. The fetch overlaps the command's real work; this is only the
	// residual window for a result that is almost in. Keeping it small means
	// a cache-miss day adds at most ~this much latency to a fast command —
	// the overall deadline (Timeout) still bounds the slow-command case.
	noticeGrace = 250 * time.Millisecond

	// maxManifestBytes caps the response read (the live manifest is ~200KB).
	maxManifestBytes = 4 << 20
)

// Config parameterizes a check. The caller resolves all environment inputs
// (opt-out env var, CI detection, TTY detection) so this package stays free
// of process-global reads and fully testable.
type Config struct {
	Tool          string        // binary name, e.g. "cilock"
	Current       string        // stamped version, e.g. "4.1.3" (or "dev")
	ManifestURL   string        // defaults to DefaultManifestURL
	CacheDir      string        // "" disables caching
	Timeout       time.Duration // hard deadline; defaults to 2s
	UpdateCommand string        // exact command to print, e.g. the install one-liner
	SkipEnvVar    string        // opt-out env var name, mentioned in the notice
	IsTTY         bool          // stderr is a terminal
	InCI          bool          // the CI env var is set
}

// cacheEntry is the on-disk cache format. Latest is empty when the last
// attempt failed — that failure is cached too, so broken networks aren't
// re-probed on every invocation within the TTL.
type cacheEntry struct {
	Schema      int       `json:"schema"`
	ManifestURL string    `json:"manifest_url"`
	Latest      string    `json:"latest"`
	CheckedAt   time.Time `json:"checked_at"`
}

// Check is an in-flight (or cache-resolved) version check.
type Check struct {
	cfg       Config
	deadline  time.Time
	ch        chan string // receives the fetched latest tag ("" on failure)
	cached    string      // resolved synchronously from a fresh cache entry
	fromCache bool
}

// Start begins the check. It returns nil — meaning "never notify" — when the
// running build should not be compared at all: unstamped dev builds, dirty or
// pre-release versions, or anything that is not a plain semver release. When
// the cache is fresh it resolves synchronously with no goroutine and no
// network; otherwise it kicks off a background fetch bounded by cfg.Timeout.
func Start(cfg Config) *Check {
	if canonicalRelease(cfg.Current) == "" {
		return nil
	}
	if cfg.ManifestURL == "" {
		cfg.ManifestURL = DefaultManifestURL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	c := &Check{cfg: cfg}
	if latest, ok := readCache(cfg.CacheDir, cfg.ManifestURL); ok {
		c.cached = latest
		c.fromCache = true
		return c
	}

	// Record the attempt BEFORE the fetch starts — synchronously, not in the
	// goroutine and not deferred: when the endpoint hangs, Notice() gives up
	// at its deadline, the CLI exits, and the fetch goroutine dies before
	// client.Get() ever returns, so nothing later in the goroutine (including
	// fetchLatest's deferred write) is guaranteed to run. This pre-write is
	// what makes even a killed/timed-out attempt count against the TTL, so a
	// CI fleet against a broken endpoint pays the wait once, not per run.
	// A fetch that completes overwrites this marker with the real result.
	writeCache(cfg.CacheDir, cfg.ManifestURL, "")

	c.deadline = time.Now().Add(cfg.Timeout)
	c.ch = make(chan string, 1)
	go func() { c.ch <- fetchLatest(cfg) }()
	return c
}

// Notice returns the message to print to stderr, or "" when there is nothing
// to say. It blocks at most until the deadline set at Start — typically not
// at all, because the fetch ran concurrently with the real command.
func (c *Check) Notice() string {
	if c == nil {
		return ""
	}
	latest := c.cached
	if !c.fromCache {
		// A ready result always wins: when the command ran longer than the
		// deadline, both the recv and the (immediately-firing) timer would be
		// ready and select would pick randomly — so try non-blocking first.
		// Otherwise wait only the small residual grace (never beyond the
		// overall deadline): the fetch overlapped the command's real work, so
		// a fast command on a cache-miss day pays at most ~noticeGrace, and a
		// still-unfinished fetch is simply dropped (the attempt is already
		// recorded in the cache by Start's pre-write).
		wait := time.Until(c.deadline)
		if wait > noticeGrace {
			wait = noticeGrace
		}
		select {
		case latest = <-c.ch:
		default:
			select {
			case latest = <-c.ch:
			case <-time.After(wait):
				return "" // still in flight — drop it
			}
		}
	}

	latest = ensureV(strings.TrimSpace(latest))
	// Only plain semver releases may nag; the manifest's "latest" is GA-only
	// by construction, but stay defensive against a malformed manifest.
	if !semver.IsValid(latest) || semver.Prerelease(latest) != "" {
		return ""
	}
	current := canonicalRelease(c.cfg.Current)
	if current == "" || semver.Compare(latest, current) <= 0 {
		return ""
	}

	curDisp := strings.TrimPrefix(current, "v")
	latestDisp := strings.TrimPrefix(latest, "v")
	if c.cfg.IsTTY && !c.cfg.InCI {
		return fmt.Sprintf("A new version of %s is available: %s -> %s\nUpdate: %s  (set %s=1 to disable this check)",
			c.cfg.Tool, curDisp, latestDisp, c.cfg.UpdateCommand, c.cfg.SkipEnvVar)
	}
	// CI / non-TTY: exactly one warning line.
	return fmt.Sprintf("warning: %s %s is outdated; latest is %s — update: %s (set %s=1 to silence)",
		c.cfg.Tool, curDisp, latestDisp, c.cfg.UpdateCommand, c.cfg.SkipEnvVar)
}

// canonicalRelease returns the v-prefixed canonical semver for a plain
// release version, or "" for anything that must never be compared: empty,
// "dev"/"unknown" stamps, invalid semver, pre-release, or build metadata.
func canonicalRelease(v string) string {
	v = ensureV(strings.TrimSpace(v))
	if !semver.IsValid(v) {
		return ""
	}
	if semver.Prerelease(v) != "" || semver.Build(v) != "" {
		return ""
	}
	return semver.Canonical(v)
}

// ensureV normalizes a version to the "vX.Y.Z" form x/mod/semver expects.
func ensureV(v string) string {
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// fetchLatest downloads the manifest and returns its "latest" tag, or "" on
// any error. It records a completed attempt's result in the cache
// (best-effort); the attempt itself was already recorded by Start.
func fetchLatest(cfg Config) string {
	latest := ""
	defer func() { writeCache(cfg.CacheDir, cfg.ManifestURL, latest) }()

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Get(cfg.ManifestURL)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var manifest struct {
		Latest string `json:"latest"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifestBytes)).Decode(&manifest); err != nil {
		return ""
	}
	latest = manifest.Latest
	return latest
}

// readCache returns the cached latest tag when the entry is fresh AND was
// recorded against the same manifest URL — switching distribution origins
// (e.g. CILOCK_DIST_BASE) must never reuse another origin's cached result.
// The tag may be "" (a cached failure) — that still counts as fresh.
func readCache(dir, manifestURL string) (string, bool) {
	if dir == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(dir, cacheFileName)) //nolint:gosec // G304: dir is our own user-cache directory joined with a constant file name
	if err != nil {
		return "", false
	}
	var e cacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return "", false
	}
	if e.ManifestURL != manifestURL {
		return "", false
	}
	if e.CheckedAt.IsZero() || time.Since(e.CheckedAt) > cacheTTL {
		return "", false
	}
	return e.Latest, true
}

// writeCache records an attempt. All errors are swallowed.
func writeCache(dir, manifestURL, latest string) {
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	b, err := json.Marshal(cacheEntry{Schema: 1, ManifestURL: manifestURL, Latest: latest, CheckedAt: time.Now()})
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, cacheFileName), b, 0o600)
}
