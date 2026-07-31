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

package updatecheck

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// manifestServer serves a cilock.dev-style /dl/manifest.json with the given
// latest tag and counts hits so tests can assert cache behavior.
func manifestServer(t *testing.T, latest string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintf(w, `{"schema":1,"latest":%q,"versions":[],"updated":"2026-07-31T00:00:00Z"}`, latest)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConfig(url, cacheDir, current string) Config {
	return Config{
		Tool:          "cilock",
		Current:       current,
		ManifestURL:   url,
		CacheDir:      cacheDir,
		Timeout:       2 * time.Second,
		UpdateCommand: "curl -fsSL https://cilock.dev/install.sh | bash",
		SkipEnvVar:    "CILOCK_SKIP_VERSION_CHECK",
		IsTTY:         true,
		InCI:          false,
	}
}

func TestStartSkipsUnreleasedBuilds(t *testing.T) {
	var hits atomic.Int64
	srv := manifestServer(t, "v99.0.0", &hits)
	for _, current := range []string{
		"",              // unset
		"dev",           // default stamp for plain `go build`
		"unknown",       // defensive
		"4.1.3-rc.1",    // pre-release must never nag
		"v4.1.3-rc.1",   // pre-release, v-prefixed
		"4.1.3-dirty",   // dirty build
		"4.1.3+abcdef1", // build metadata
		"not-a-version", // garbage
	} {
		cfg := testConfig(srv.URL, t.TempDir(), current)
		if c := Start(cfg); c != nil {
			t.Errorf("Start(current=%q) = %v, want nil", current, c)
		}
	}
	// No skip path may touch the network.
	if got := hits.Load(); got != 0 {
		t.Errorf("manifest fetched %d times for skipped builds, want 0", got)
	}
}

func TestNoticeWhenNewerTTY(t *testing.T) {
	var hits atomic.Int64
	srv := manifestServer(t, "v9.9.9", &hits)
	c := Start(testConfig(srv.URL, t.TempDir(), "4.1.3"))
	if c == nil {
		t.Fatal("Start returned nil for a release build")
	}
	n := c.Notice()
	for _, want := range []string{"4.1.3", "9.9.9", "curl -fsSL https://cilock.dev/install.sh | bash"} {
		if !strings.Contains(n, want) {
			t.Errorf("notice %q missing %q", n, want)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("manifest hits = %d, want 1", hits.Load())
	}
}

func TestNoNoticeWhenCurrentOrOlderLatest(t *testing.T) {
	for _, latest := range []string{"v4.1.3", "v4.0.0", "v9.9.9-rc.1", "garbage", ""} {
		var hits atomic.Int64
		srv := manifestServer(t, latest, &hits)
		c := Start(testConfig(srv.URL, t.TempDir(), "4.1.3"))
		if c == nil {
			t.Fatal("Start returned nil for a release build")
		}
		if n := c.Notice(); n != "" {
			t.Errorf("latest=%q: notice = %q, want empty", latest, n)
		}
	}
}

func TestCIModeIsSingleWarningLine(t *testing.T) {
	var hits atomic.Int64
	srv := manifestServer(t, "v9.9.9", &hits)
	for name, mutate := range map[string]func(*Config){
		"ci-env-set": func(c *Config) { c.InCI = true },
		"not-a-tty":  func(c *Config) { c.IsTTY = false },
	} {
		cfg := testConfig(srv.URL, t.TempDir(), "4.1.3")
		mutate(&cfg)
		c := Start(cfg)
		if c == nil {
			t.Fatalf("%s: Start returned nil", name)
		}
		n := c.Notice()
		if n == "" {
			t.Fatalf("%s: expected a warning line", name)
		}
		if strings.Contains(n, "\n") {
			t.Errorf("%s: CI warning must be a single line, got %q", name, n)
		}
		if !strings.Contains(n, "CILOCK_SKIP_VERSION_CHECK") {
			t.Errorf("%s: CI warning should name the opt-out env var, got %q", name, n)
		}
	}
}

func TestVPrefixNormalization(t *testing.T) {
	var hits atomic.Int64
	srv := manifestServer(t, "4.2.0", &hits) // no leading v in the manifest
	cfg := testConfig(srv.URL, t.TempDir(), "v4.1.3")
	c := Start(cfg)
	if c == nil {
		t.Fatal("Start returned nil for v-prefixed release build")
	}
	if n := c.Notice(); !strings.Contains(n, "4.2.0") {
		t.Errorf("notice = %q, want it to mention 4.2.0", n)
	}
}

func TestCacheHitSkipsNetwork(t *testing.T) {
	var hits atomic.Int64
	srv := manifestServer(t, "v9.9.9", &hits)
	dir := t.TempDir()

	c1 := Start(testConfig(srv.URL, dir, "4.1.3"))
	if n := c1.Notice(); n == "" {
		t.Fatal("first run: expected a notice")
	}
	if hits.Load() != 1 {
		t.Fatalf("first run: hits = %d, want 1", hits.Load())
	}

	// Second invocation inside the TTL must serve from cache: no new hit,
	// same conclusion.
	c2 := Start(testConfig(srv.URL, dir, "4.1.3"))
	if n := c2.Notice(); n == "" {
		t.Error("second run: expected a notice from cache")
	}
	if hits.Load() != 1 {
		t.Errorf("second run: hits = %d, want 1 (cache must prevent refetch)", hits.Load())
	}
}

func TestExpiredCacheRefetches(t *testing.T) {
	var hits atomic.Int64
	srv := manifestServer(t, "v9.9.9", &hits)
	dir := t.TempDir()
	stale := cacheEntry{Schema: 1, ManifestURL: srv.URL, Latest: "v9.9.8", CheckedAt: time.Now().Add(-25 * time.Hour)}
	b, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cacheFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}

	c := Start(testConfig(srv.URL, dir, "4.1.3"))
	if n := c.Notice(); !strings.Contains(n, "9.9.9") {
		t.Errorf("notice = %q, want refreshed 9.9.9", n)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1 (expired cache must refetch)", hits.Load())
	}
}

func TestCacheNotReusedAcrossManifestURLs(t *testing.T) {
	// A cached result is keyed by the manifest URL: switching distribution
	// origins (e.g. CILOCK_DIST_BASE) must trigger a fresh fetch, never
	// reuse another origin's cached "latest" for the rest of the TTL.
	var hitsA, hitsB atomic.Int64
	srvA := manifestServer(t, "v9.9.9", &hitsA)
	srvB := manifestServer(t, "v8.8.8", &hitsB)
	dir := t.TempDir()

	if n := Start(testConfig(srvA.URL, dir, "4.1.3")).Notice(); !strings.Contains(n, "9.9.9") {
		t.Fatalf("origin A: notice = %q, want 9.9.9", n)
	}
	if n := Start(testConfig(srvB.URL, dir, "4.1.3")).Notice(); !strings.Contains(n, "8.8.8") {
		t.Errorf("origin B: notice = %q, want a fresh 8.8.8 (not A's cached 9.9.9)", n)
	}
	if hitsA.Load() != 1 || hitsB.Load() != 1 {
		t.Errorf("hits = A:%d B:%d, want 1 each", hitsA.Load(), hitsB.Load())
	}
}

func TestFetchFailureIsCachedAndSilent(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()

	c1 := Start(testConfig(srv.URL, dir, "4.1.3"))
	if n := c1.Notice(); n != "" {
		t.Errorf("failure run: notice = %q, want empty", n)
	}
	// The failed attempt must be cached too, so a fleet of CI invocations
	// doesn't hammer a broken endpoint.
	c2 := Start(testConfig(srv.URL, dir, "4.1.3"))
	if c2 != nil {
		if n := c2.Notice(); n != "" {
			t.Errorf("second failure run: notice = %q, want empty", n)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1 (failure must be cached within TTL)", hits.Load())
	}
}

func TestBadJSONAndUnreachableAreSwallowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json {")
	}))
	t.Cleanup(srv.Close)
	if n := Start(testConfig(srv.URL, t.TempDir(), "4.1.3")).Notice(); n != "" {
		t.Errorf("bad json: notice = %q, want empty", n)
	}
	// Unreachable endpoint (closed immediately).
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close()
	if n := Start(testConfig(dead.URL, t.TempDir(), "4.1.3")).Notice(); n != "" {
		t.Errorf("unreachable: notice = %q, want empty", n)
	}
}

func TestHangingServerBoundedByTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hang until test cleanup
	}))
	t.Cleanup(srv.Close) // registered first so it runs LAST (LIFO) ...
	// ... because Close blocks until the handler returns, the hung handler
	// must be released BEFORE Close runs.
	t.Cleanup(func() { close(release) })

	cfg := testConfig(srv.URL, t.TempDir(), "4.1.3")
	cfg.Timeout = 300 * time.Millisecond
	start := time.Now()
	c := Start(cfg)
	n := c.Notice()
	elapsed := time.Since(start)
	if n != "" {
		t.Errorf("hanging server: notice = %q, want empty", n)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Notice blocked %v; must stay within the ~%v deadline", elapsed, cfg.Timeout)
	}

	// Drain the goroutine before TempDir cleanup: its HTTP client gives up
	// at cfg.Timeout and performs a final cache write, which must not race
	// the test directory removal.
	select {
	case <-c.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch goroutine never finished")
	}
}

func TestTimedOutFetchIsCachedAcrossInvocations(t *testing.T) {
	// When the endpoint hangs, the CLI exits at the deadline and the fetch
	// goroutine dies before it can record the failure. The attempt must
	// still land in the cache (pre-written at Start) so the NEXT invocation
	// inside the TTL resolves from cache without contacting the endpoint —
	// a CI fleet against a broken endpoint pays the deadline once, not per run.
	var hits atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release // hang until test cleanup
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // LIFO: release the handler before Close waits on it

	dir := t.TempDir()
	cfg := testConfig(srv.URL, dir, "4.1.3")
	cfg.Timeout = 200 * time.Millisecond

	c1 := Start(cfg)
	if n := c1.Notice(); n != "" {
		t.Fatalf("hanging endpoint: notice = %q, want empty", n)
	}

	// Second invocation within the TTL: must resolve from the cached attempt
	// with no new request, even though the first fetch never completed.
	c2 := Start(cfg)
	if c2 == nil {
		t.Fatal("second invocation: Start = nil, want a cache-resolved check")
	}
	if n := c2.Notice(); n != "" {
		t.Errorf("second invocation: notice = %q, want empty", n)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("endpoint hit %d times, want 1 (timed-out attempt must be cached)", got)
	}

	// Drain the first invocation's goroutine before TempDir cleanup: its
	// HTTP client gives up at cfg.Timeout and performs a final cache write,
	// which must not race the test directory removal.
	select {
	case <-c1.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("first goroutine never finished")
	}
}

func TestReadyResultWinsOverExpiredDeadline(t *testing.T) {
	// A command that runs longer than the check's deadline must still get
	// the notice when the fetch finished in time: with both the result and
	// the (immediately-firing) deadline timer ready, select alone would pick
	// randomly, so this would flake ~50% per iteration without the
	// non-blocking first receive.
	var hits atomic.Int64
	srv := manifestServer(t, "v9.9.9", &hits)
	for i := 0; i < 10; i++ {
		cfg := testConfig(srv.URL, t.TempDir(), "4.1.3")
		cfg.Timeout = 100 * time.Millisecond
		c := Start(cfg)
		time.Sleep(250 * time.Millisecond) // outlive the deadline; fetch is local and fast
		if n := c.Notice(); n == "" {
			t.Fatalf("iteration %d: ready result must win over the expired deadline", i)
		}
	}
}

func TestNilCheckNoticeIsSafe(t *testing.T) {
	var c *Check
	if n := c.Notice(); n != "" {
		t.Errorf("nil check: notice = %q, want empty", n)
	}
}
