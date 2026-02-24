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
	path    string
	relPath string
}

// fileResult represents the result of hashing a file.
type fileResult struct {
	relPath string
	digest  cryptoutil.DigestSet
	err     error
}

// RecordArtifacts walks basePath and records the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
// includeGlob/excludeGlob filter which files are recorded: exclude is checked first (excluded files are
// never recorded), then include (only matching files are recorded). Pass nil for either to skip that filter.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob, includeGlob glob.Glob, excludeGlob glob.Glob) (map[string]cryptoutil.DigestSet, error) { //nolint:gocognit,gocyclo,funlen
	artifacts := make(map[string]cryptoutil.DigestSet)

	numWorkers := max(runtime.GOMAXPROCS(0), 1)
	jobs := make(chan fileJob, numWorkers*2)
	results := make(chan fileResult, numWorkers*2)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				digest, err := cryptoutil.CalculateDigestSetFromFile(job.path, hashes)
				results <- fileResult{relPath: job.relPath, digest: digest, err: err}
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
				symlinkedArtifacts, err := RecordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob, includeGlob, excludeGlob)
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

			jobs <- fileJob{path: path, relPath: relPath}
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

		if firstErr == nil && shouldRecord(result.relPath, result.digest, baseArtifacts, processWasTraced, openedFiles, includeGlob, excludeGlob) {
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
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet, processWasTraced bool, openedFiles map[string]bool, includeGlob glob.Glob, excludeGlob glob.Glob) bool {
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
		return false
	}
	return true
}
