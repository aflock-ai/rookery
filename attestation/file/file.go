// Copyright 2021 The Witness Contributors
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

package file

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
)

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob library
// can panic on certain patterns that compile successfully but trigger out-of-bounds
// access during matching. We treat panics as non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}

// fileJob represents a file to be hashed by the worker pool.
type fileJob struct {
	relPath string
	// openName is the path opened by the worker, relative to the os.Root rooted
	// at rootDir. It usually equals relPath, but when basePath is itself a
	// regular file (the symlink-to-file recursion) the root is the parent dir
	// and openName is the file's base name while relPath stays ".".
	openName string
	// mtime is the file's modification time captured at walk time. It lets
	// shouldRecord distinguish a same-content file the command rewrote during
	// its run (mtime >= cmdStart → product) from a pre-existing input the
	// command never touched (mtime < cmdStart → material). Zero for dir-hash
	// and symlinked results, where the legacy digest-only rule applies.
	mtime time.Time
	// info is the walk's own lstat of the file; the digest cache keys on it
	// (device, inode, size, mtime, ctime) so a hit costs no extra syscall.
	info fs.FileInfo
}

// fileResult represents the result of hashing a file.
type fileResult struct {
	relPath string
	digest  cryptoutil.DigestSet
	mtime   time.Time
	err     error
}

// RecordArtifacts walks basePath and records the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
// includeGlob/excludeGlob filter which files are recorded: exclude is checked first (excluded files are
// never recorded), then include (only matching files are recorded). Pass nil for either to skip that filter.
//
// cmdStartTime is optional. When provided (non-zero), a file present in
// baseArtifacts with an UNCHANGED content digest is still recorded as an
// artifact if its mtime is at/after cmdStartTime — i.e. the command rewrote
// it during the run. This closes the walk-mode silent product drop: a
// deterministic rebuild that re-emits byte-identical output produces no digest
// delta, and without the mtime signal the real build output vanished from the
// attestation. Omit it (or pass the zero time) for pure input snapshots — e.g.
// the material attestor — to keep the legacy digest-only dedup behavior.
// Mirrors the trace path's commandrun.traceStartTime handling.
//
// Symlink handling: RecordArtifacts REFUSES symlinks whose resolved target
// escapes basePath — the safe default (GHSA-v6px-jqx8-8xwj). The dir hash fails
// closed (race-free via os.Root) and per-file escapes are skipped, so
// out-of-tree content can never be pulled into an attestation of an untrusted
// tree. In-tree symlinks are still followed. Use RecordArtifactsFollowingSymlinks
// to deliberately follow out-of-tree symlinks (e.g. recording toolchains or
// dependency caches symlinked into a TRUSTED build tree). Symlink-cycle
// detection and non-regular-file (FIFO/device) skipping apply in both modes.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob, includeGlob glob.Glob, excludeGlob glob.Glob, cmdStartTime ...time.Time) (map[string]cryptoutil.DigestSet, error) {
	return recordArtifactsTop(basePath, true, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob, includeGlob, excludeGlob, cmdStartTime...)
}

// RecordArtifactsFollowingSymlinks is like RecordArtifacts but FOLLOWS symlinks
// even when they resolve outside basePath, so the attestor faithfully records
// what a build actually consumed — out-of-tree inputs (toolchains, module/
// dependency caches symlinked into the working dir) included. Use it ONLY when
// attesting a TRUSTED tree: an escaping symlink in an untrusted tree would pull
// out-of-tree content into the signed attestation (GHSA-v6px-jqx8-8xwj). The
// default RecordArtifacts is fail-closed and should be preferred unless the
// build environment is trusted and out-of-tree fidelity is required.
func RecordArtifactsFollowingSymlinks(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob, includeGlob glob.Glob, excludeGlob glob.Glob, cmdStartTime ...time.Time) (map[string]cryptoutil.DigestSet, error) {
	return recordArtifactsTop(basePath, false, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob, includeGlob, excludeGlob, cmdStartTime...)
}

func recordArtifactsTop(basePath string, restrictSymlinks bool, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob, includeGlob glob.Glob, excludeGlob glob.Glob, cmdStartTime ...time.Time) (map[string]cryptoutil.DigestSet, error) {
	var cmdStart time.Time
	if len(cmdStartTime) > 0 {
		cmdStart = cmdStartTime[0]
	}

	// The escape boundary (used only in restricted mode) is pinned to the
	// original attestation root and threaded unchanged through symlink recursion,
	// so a chained in-tree symlink cannot widen it (GHSA-v6px-jqx8-8xwj).
	return recordArtifacts(basePath, basePath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob, includeGlob, excludeGlob, restrictSymlinks, cmdStart)
}

func recordArtifacts(basePath, root string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob, includeGlob glob.Glob, excludeGlob glob.Glob, restrictSymlinks bool, cmdStart time.Time) (map[string]cryptoutil.DigestSet, error) { //nolint:gocognit,gocyclo,funlen
	artifacts := make(map[string]cryptoutil.DigestSet)

	// Open a root so worker opens resolve beneath it. This refuses a
	// final-component (or any-component) symlink that escapes the root at open
	// time, closing the per-file symlink TOCTOU (#5994): the walk classifies
	// entries with Lstat, but a regular file swapped for an out-of-tree symlink
	// before the worker opens it would otherwise be followed. Legitimate
	// in-tree symlinks are resolved and recursed by the walk below before any
	// worker open, so the only symlink a worker can hit here is a malicious
	// post-Lstat swap.
	//
	// os.OpenRoot requires a directory. When basePath is itself a regular file
	// (the symlink-to-file recursion below passes the resolved file as the new
	// basePath) we root at its parent dir and open the file by base name.
	rootDir := basePath
	if fi, statErr := os.Lstat(basePath); statErr == nil && !fi.IsDir() {
		rootDir = filepath.Dir(basePath)
	}
	rootHandle, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rootHandle.Close() }()

	// Files are opened beneath a handle on their own directory, opened once
	// beneath rootHandle, so each open resolves one path component instead
	// of the whole relative path. Measured on a 62k-file tree: open+fstat
	// 3.9 s -> 2.9 s. Every escape refusal still holds: the directory handle
	// is itself opened beneath the root, and the final component is opened
	// with the same symlink-refusing open as before.

	numWorkers := max(runtime.GOMAXPROCS(0), 1)
	jobs := make(chan fileJob, numWorkers*2)
	results := make(chan fileResult, numWorkers*2)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				digest, err := hashInRoot(rootHandle, job.openName, job.info, hashes)
				results <- fileResult{relPath: job.relPath, digest: digest, mtime: job.mtime, err: err}
			}
		}()
	}

	walkDone := make(chan error, 1)
	go func() {
		walkErr := parallelWalk(basePath, func(path string, info fs.FileInfo) error {
			relPath, err := filepath.Rel(basePath, path)
			if err != nil {
				return err
			}

			if info.IsDir() { //nolint:nestif
				dirHashMatch := false
				for _, globItem := range dirHashGlob {
					if !dirHashMatch {
						if matched, err := safeGlobMatch(globItem, relPath); err != nil {
							log.Debugf("glob match error for path %q: %v", relPath, err)
						} else if matched {
							dirHashMatch = true
						}
					}
				}

				if dirHashMatch {
					// Restricted (default): refuse a symlink whose target escapes the
					// attestation root, race-free via os.Root, so no out-of-tree
					// content enters the hash (GHSA-v6px-jqx8-8xwj). Unrestricted
					// (opt-in): follow symlinks (incl. out-of-tree) so the dir hash
					// faithfully records what a trusted build consumed. Either way the
					// hash is byte-identical to the legacy dirhash for an equivalent
					// tree.
					var (
						dir  cryptoutil.DigestSet
						derr error
					)
					if restrictSymlinks {
						dir, derr = cryptoutil.CalculateDigestSetFromDirWithinRoot(path, root, hashes)
					} else {
						dir, derr = cryptoutil.CalculateDigestSetFromDir(path, hashes)
					}
					if derr != nil {
						return derr
					}

					results <- fileResult{relPath: relPath + string(os.PathSeparator), digest: dir}
					return filepath.SkipDir
				}

				return nil
			}

			if info.Mode()&fs.ModeSymlink != 0 { //nolint:nestif
				linkedPath, err := filepath.EvalSymlinks(path)
				if os.IsNotExist(err) {
					log.Debugf("(file) broken symlink detected: %v", path)
					return nil
				} else if err != nil {
					return err
				}

				// RESTRICTED mode (the default): skip a symlink whose target escapes
				// the attestation ROOT boundary — the original root threaded through
				// recursion, NOT the per-call basePath, so a chained in-tree symlink
				// cannot move it (GHSA-v6px-jqx8-8xwj). In the opt-in unrestricted
				// mode the symlink is followed so the attestor records what a trusted
				// build actually used (out-of-tree toolchains / dependency caches
				// included). EvalSymlinks both paths so they share the same prefix
				// where temp/working dirs are themselves symlinked (macOS /var).
				if restrictSymlinks {
					absRoot, err := filepath.Abs(root)
					if err != nil {
						return fmt.Errorf("failed to resolve attestation root: %w", err)
					}
					absRoot, err = filepath.EvalSymlinks(absRoot)
					if err != nil {
						return fmt.Errorf("failed to resolve attestation root symlinks: %w", err)
					}
					absLinked, err := filepath.Abs(linkedPath)
					if err != nil {
						return fmt.Errorf("failed to resolve symlink target: %w", err)
					}
					if !withinRoot(absLinked, absRoot) {
						log.Debugf("(file) symlink %v points outside attestation root %v, skipping (restricted mode)", path, root)
						return nil
					}
				}

				if _, ok := visitedSymlinks[linkedPath]; ok {
					return nil
				}

				visitedSymlinks[linkedPath] = struct{}{}
				// Recursive call handles its own parallelization. Thread the
				// original root and the restrict flag unchanged.
				symlinkedArtifacts, err := recordArtifacts(linkedPath, root, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob, includeGlob, excludeGlob, restrictSymlinks, cmdStart)
				if err != nil {
					return err
				}

				for artifactPath, artifact := range symlinkedArtifacts {
					joinedPath := filepath.Join(relPath, artifactPath)
					results <- fileResult{relPath: joinedPath, digest: artifact}
				}

				return nil
			}

			// Only record regular files. Skip FIFOs (named pipes), device files,
			// sockets, and other special files. Opening a FIFO blocks until a
			// writer connects, which is a DoS vector if an attacker can place
			// a FIFO in the scanned directory.
			if !info.Mode().IsRegular() {
				log.Debugf("(file) skipping non-regular file: %v (mode: %v)", path, info.Mode())
				return nil
			}

			openName := relPath
			if rootDir != basePath {
				// basePath is a regular file; root is its parent, so open by
				// base name. The walk visits only basePath here (relPath ".").
				openName = filepath.Base(basePath)
			}
			jobs <- fileJob{relPath: relPath, openName: openName, mtime: info.ModTime(), info: info}
			return nil
		})
		close(jobs)
		walkDone <- walkErr
	}()

	// Wait for all workers to finish, then close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results (single goroutine, no mutex needed).
	// We must drain the entire results channel to prevent goroutine leaks
	// in the walk goroutine and workers.
	var firstErr error
	for result := range results {
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}

		if firstErr == nil && shouldRecord(result.relPath, result.digest, baseArtifacts, processWasTraced, openedFiles, includeGlob, excludeGlob, result.mtime, cmdStart) {
			artifacts[result.relPath] = result.digest
		}
	}

	if err := <-walkDone; err != nil {
		return nil, err
	}

	if firstErr != nil {
		return nil, firstErr
	}

	return artifacts, nil
}

// shouldRecord determines whether artifact should be recorded.
// Exclude glob is checked first (excluded files are never recorded), then include glob
// (only matching files are recorded). After glob filtering, tracing and deduplication
// checks are applied.
//
// mtime is the file's modification time (zero for dir-hash / symlinked
// results). cmdStart is the command-start instant (zero when the caller didn't
// supply one). When a file's content digest matches the pre-command snapshot
// it is normally deduped as a material — UNLESS it was rewritten during the
// command window (mtime >= cmdStart), in which case it is a product the build
// produced with byte-identical content. Without this, walk mode silently drops
// deterministic-rebuild outputs because it can't observe the write syscall the
// way the eBPF tracer can.
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet, processWasTraced bool, openedFiles map[string]bool, includeGlob glob.Glob, excludeGlob glob.Glob, mtime time.Time, cmdStart time.Time) bool {
	normalizedPath := filepath.ToSlash(path)
	if excludeGlob != nil {
		if matched, err := safeGlobMatch(excludeGlob, normalizedPath); err != nil {
			log.Debugf("exclude glob match error for path %q: %v", normalizedPath, err)
		} else if matched {
			return false
		}
	}
	if includeGlob != nil {
		if matched, err := safeGlobMatch(includeGlob, normalizedPath); err != nil {
			log.Debugf("include glob match error for path %q: %v", normalizedPath, err)
		} else if !matched {
			return false
		}
	}
	if _, ok := openedFiles[path]; !ok && processWasTraced {
		return false
	}
	if previous, ok := baseArtifacts[path]; ok && artifact.Equal(previous) {
		// Same content as the pre-command snapshot. Dedup as a material
		// UNLESS the command rewrote it during its run: mtime >= cmdStart
		// means the build produced this file even though the bytes are
		// identical (deterministic rebuild, same-content overwrite). Walk
		// mode has no syscall view, so mtime is the signal. Inclusive
		// comparison mirrors the trace path (commandrun ModTime().Before).
		if cmdStart.IsZero() || mtime.Before(cmdStart) {
			return false
		}
	}
	return true
}

// withinRoot reports whether absPath is the attestation root itself or a
// descendant of it. It uses filepath.Rel so the filesystem-root edge case
// (absRoot == "/", where a naive prefix check would compare against "//" and
// reject legitimate descendants) is handled correctly, and so a sibling-prefix
// bypass (e.g. "/root-evil" inside "/root") is rejected. Both arguments are
// expected to be absolute, symlink-resolved paths.
func withinRoot(absPath, absRoot string) bool {
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// hashInRoot opens name beneath its directory's handle, hashes the descriptor
// and returns the digests together with fstat of that same descriptor. One
// fstat serves both the hashability check and the identity comparison.
//
// walked is the walker's lstat of the path. When the descriptor is not that
// file, hashing it would record one file's bytes under another file's name —
// exactly what happens if a directory is renamed and replaced between the
// walk and the open, since a cached directory handle still points at the old
// inode. That is EVIDENCE_UNBOUND, so it is refused rather than recorded: the
// walk fails and the caller re-runs against a settled tree. Cache rejection
// is not enough, because the digest is emitted whether it was cached or not.
func hashInRoot(top *os.Root, name string, walked fs.FileInfo, hashes []cryptoutil.DigestValue) (cryptoutil.DigestSet, error) {
	// Resolve the WHOLE relative path from the top root on every open, rather
	// than reusing a cached handle for the containing directory.
	//
	// A per-directory handle is an inode, and a path is not. Prime the handle
	// for d, let the walk lstat d/f, then replace d wholesale: the cached
	// handle still opens the OLD d/f, and os.SameFile(walked, hashed) SUCCEEDS
	// because both describe the old inode. The guard passes and the old file's
	// digest is published under a path that now names a different file
	// (Codex, #9436). Resolving from the top binds the open to the path as it
	// stands now, so the same race produces a refusal instead of a substitution.
	f, err := cryptoutil.OpenRegularInRoot(top, name)
	if err != nil {
		return cryptoutil.DigestSet{}, err
	}
	defer func() { _ = f.Close() }()

	hashed, err := f.Stat()
	if err != nil {
		return cryptoutil.DigestSet{}, err
	}
	if !sameFile(walked, hashed) {
		return cryptoutil.DigestSet{}, fmt.Errorf(
			"%s changed identity between the walk and the open (the tree moved under the walk); refusing to record another file's digest under this path", name)
	}

	digest, err := cryptoutil.CalculateDigestSetFromOpenFileInfo(f, hashed, name, hashes)
	return digest, err
}

// sameFile reports whether two FileInfos name the same file. os.SameFile is
// the platform's own answer (device and inode), and it is exactly the question
// asked here; size and timestamps are deliberately NOT compared, since a
// writer appending to the same file is the walk's ordinary race and is handled
// by the digest cache's racy-clean margin, not by refusing the walk.
func sameFile(a, b fs.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	return os.SameFile(a, b)
}

// parallelWalk visits every entry beneath root with its lstat, like
// filepath.Walk, but reads directories concurrently: the single-threaded scan
// was 1.7 s of a 3.8 s walk on a 62k-file tree while fifteen cores idled.
//
// Two of Walk's properties are kept on purpose:
//
//   - fn returning filepath.SkipDir for a directory skips its contents (the
//     dir-hash globs rely on it), and the first other error stops the walk.
//   - fn IS CALLED CONCURRENTLY, on the pool's workers. The caller in this
//     package only sends to channels from it, which is why that is safe;
//     any other caller owns its own synchronisation.
//   - SYMLINKS ARE VISITED IN WALK'S ORDER, AFTER THE PARALLEL SCAN. The
//     caller records a symlink's target only the first time it is met, so
//     if two links to one target were visited in scheduling order the
//     recorded path would change from run to run and with it the material
//     tree's root. They are collected during the scan and visited afterwards
//     sorted the way Walk would have reached them (depth-first, lexical per
//     path component), which keeps the record identical to the old walker.
func parallelWalk(root string, fn func(path string, info fs.FileInfo) error) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if err := fn(root, info); err != nil {
		if errors.Is(err, filepath.SkipDir) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}
	w := &parallelWalker{fn: fn}
	w.cond = sync.NewCond(&w.mu)
	w.push(root)
	w.run(max(runtime.GOMAXPROCS(0), 1))
	if w.firstErr != nil {
		return w.firstErr
	}
	return w.visitLinksInWalkOrder()
}

// parallelWalker is the state of one parallelWalk: a bounded set of directory
// readers, the first error any of them met, and the symlinks deferred to the
// end.
type parallelWalker struct {
	fn func(path string, info fs.FileInfo) error

	// Directories are held in a queue drained by a FIXED pool, not a
	// goroutine per directory gated by a semaphore: the semaphore bounded
	// how many ran at once but not how many existed, so a wide tree parked
	// a goroutine and its stack on every directory it had discovered.
	mu      sync.Mutex
	cond    *sync.Cond
	queue   []string
	pending int  // queued plus in flight; the walk is done at zero
	done    bool // set once, to release every worker

	stop     atomic.Bool
	errOnce  sync.Once
	firstErr error

	linksMu sync.Mutex
	links   []walkEntry
}

// push queues a directory for the pool.
func (w *parallelWalker) push(dir string) {
	w.mu.Lock()
	w.queue = append(w.queue, dir)
	w.pending++
	w.mu.Unlock()
	w.cond.Signal()
}

// next returns the next directory to scan, or false once the walk is over.
// A worker blocks here while others still hold work, since that work can
// queue more directories.
func (w *parallelWalker) next() (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.queue) == 0 && !w.done {
		w.cond.Wait()
	}
	if w.done {
		return "", false
	}
	dir := w.queue[len(w.queue)-1]
	w.queue = w.queue[:len(w.queue)-1]
	return dir, true
}

// finish marks one directory complete and ends the walk when none remain.
func (w *parallelWalker) finish() {
	w.mu.Lock()
	w.pending--
	if w.pending == 0 {
		w.done = true
		w.mu.Unlock()
		w.cond.Broadcast()
		return
	}
	w.mu.Unlock()
}

// run drains the queue with exactly n workers and returns when the walk is
// over.
func (w *parallelWalker) run(n int) {
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				dir, ok := w.next()
				if !ok {
					return
				}
				w.scanDir(dir)
				w.finish()
			}
		}()
	}
	wg.Wait()
}

func (w *parallelWalker) fail(err error) {
	w.errOnce.Do(func() {
		w.firstErr = err
		w.stop.Store(true)
		w.abandon()
	})
}

// abandon releases every worker after a failure, including any blocked
// waiting for work that will never come.
func (w *parallelWalker) abandon() {
	w.mu.Lock()
	w.done = true
	w.mu.Unlock()
	w.cond.Broadcast()
}

// scanDir lists one directory and visits its entries; subdirectories are
// spawned, symlinks are deferred.
func (w *parallelWalker) scanDir(dir string) {
	if w.stop.Load() {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.fail(err)
		return
	}
	for _, e := range entries {
		if w.stop.Load() {
			return
		}
		if !w.visitEntry(filepath.Join(dir, e.Name()), e) {
			return
		}
	}
}

// visitEntry handles one directory entry and reports whether the scan of
// its directory should continue.
func (w *parallelWalker) visitEntry(path string, e fs.DirEntry) bool {
	info, err := e.Info()
	if err != nil {
		// Including fs.ErrNotExist. A file that vanished between readdir
		// and lstat is a DETECTED inconsistency in the tree being attested,
		// and swallowing it puts a silent hole in signed evidence: remove a
		// file after enumeration and recreate it, and it is simply absent
		// from a successful inventory. filepath.Walk handed this error to
		// the callback, which returned it, so the walk this replaced
		// aborted; matching that is the conservative reading.
		w.fail(err)
		return false
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		w.linksMu.Lock()
		w.links = append(w.links, walkEntry{path: path, info: info})
		w.linksMu.Unlock()
		return true
	}
	if err := w.fn(path, info); err != nil {
		if errors.Is(err, filepath.SkipDir) {
			return true
		}
		w.fail(err)
		return false
	}
	if info.IsDir() {
		w.push(path)
	}
	return true
}

// visitLinksInWalkOrder visits the deferred symlinks in filepath.Walk's
// order, so first-wins recording of a shared target is deterministic.
func (w *parallelWalker) visitLinksInWalkOrder() error {
	sort.Slice(w.links, func(i, j int) bool { return walkOrderLess(w.links[i].path, w.links[j].path) })
	for _, l := range w.links {
		if err := w.fn(l.path, l.info); err != nil && !errors.Is(err, filepath.SkipDir) {
			return err
		}
	}
	return nil
}

type walkEntry struct {
	path string
	info fs.FileInfo
}

// walkOrderLess orders paths as filepath.Walk reaches them: depth-first,
// lexical within each directory, which is lexical order per path component.
func walkOrderLess(a, b string) bool {
	as, bs := strings.Split(a, string(os.PathSeparator)), strings.Split(b, string(os.PathSeparator))
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}
