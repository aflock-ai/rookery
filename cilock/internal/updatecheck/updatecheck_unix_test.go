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

// The `unix` build constraint is standard since Go 1.19 (it matches every
// GOOS that go's syscall package treats as Unix-like) — see the Go 1.19
// release notes. These tests use mkfifo/symlink-to-devices, which only exist
// there; ordinary `go test` runs on linux/darwin CI include this file.
//go:build unix

package updatecheck

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestBlockedCacheAccessDoesNotBlockCommand(t *testing.T) {
	// A FIFO planted as the cache file makes os.ReadFile block forever on
	// open (no writer). All cache I/O runs in the background goroutine, so
	// the command must still return within the bounded Notice wait.
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, cacheFileName), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	cfg := testConfig("http://127.0.0.1:1/manifest.json", dir, "4.1.3") // never reached: the cache read blocks first
	cfg.Timeout = 300 * time.Millisecond

	start := time.Now()
	n := Start(cfg).Notice()
	elapsed := time.Since(start)
	if n != "" {
		t.Errorf("blocked cache: notice = %q, want empty", n)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Notice blocked %v on a stalled cache; must stay within the bounded wait", elapsed)
	}
}

func TestNonRegularCacheFileIsRejected(t *testing.T) {
	// A cache path symlinked to a device file must be rejected by the
	// regular-file check (and the capped read) instead of being slurped —
	// /dev/zero would otherwise mean unbounded allocation.
	var hits atomic.Int64
	srv := manifestServer(t, "v9.9.9", &hits)
	dir := t.TempDir()
	if err := os.Symlink("/dev/zero", filepath.Join(dir, cacheFileName)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	cfg := testConfig(srv.URL, dir, "4.1.3")
	start := time.Now()
	n := Start(cfg).Notice()
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("Notice took %v on a device-file cache; the read must be capped", elapsed)
	}
	// The device-backed cache is a miss; the fetch proceeds and still nags.
	if !strings.Contains(n, "9.9.9") {
		t.Errorf("notice = %q, want a fresh 9.9.9 after rejecting the non-regular cache file", n)
	}
}
