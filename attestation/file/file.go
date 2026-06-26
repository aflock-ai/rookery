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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob, includeGlob glob.Glob, excludeGlob glob.Glob, cmdStartTime ...time.Time) (map[string]cryptoutil.DigestSet, error) { //nolint:gocognit,gocyclo,funlen
	var cmdStart time.Time
	if len(cmdStartTime) > 0 {
		cmdStart = cmdStartTime[0]
	}

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
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	numWorkers := max(runtime.GOMAXPROCS(0), 1)
	jobs := make(chan fileJob, numWorkers*2)
	results := make(chan fileResult, numWorkers*2)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				digest, err := cryptoutil.CalculateDigestSetFromFileInRoot(root, job.openName, hashes)
				results <- fileResult{relPath: job.relPath, digest: digest, mtime: job.mtime, err: err}
			}
		}()
	}

	walkDone := make(chan error, 1)
	go func() {
		walkErr := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

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
					dir, err := cryptoutil.CalculateDigestSetFromDir(path, hashes)
					if err != nil {
						return err
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

				// Security: ensure the symlink target is within the basePath boundary.
				// Use EvalSymlinks for both paths so they share the same prefix
				// on systems where temp/working dirs are themselves symlinked
				// (e.g. macOS: /var → /private/var).
				absBase, err := filepath.Abs(basePath)
				if err != nil {
					return fmt.Errorf("failed to resolve base path: %w", err)
				}
				absBase, err = filepath.EvalSymlinks(absBase)
				if err != nil {
					return fmt.Errorf("failed to resolve base path symlinks: %w", err)
				}
				absLinked, err := filepath.Abs(linkedPath)
				if err != nil {
					return fmt.Errorf("failed to resolve symlink target: %w", err)
				}
				if !strings.HasPrefix(absLinked, absBase+string(os.PathSeparator)) && absLinked != absBase {
					log.Debugf("(file) symlink %v points outside base path %v, skipping", path, basePath)
					return nil
				}

				if _, ok := visitedSymlinks[linkedPath]; ok {
					return nil
				}

				visitedSymlinks[linkedPath] = struct{}{}
				// Recursive call handles its own parallelization
				symlinkedArtifacts, err := RecordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob, includeGlob, excludeGlob, cmdStart)
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
			jobs <- fileJob{relPath: relPath, openName: openName, mtime: info.ModTime()}
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
