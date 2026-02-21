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

	"github.com/gobwas/glob"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
)

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

// recordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob) (map[string]cryptoutil.DigestSet, error) {
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

			if info.IsDir() {
				dirHashMatch := false
				for _, globItem := range dirHashGlob {
					if !dirHashMatch && globItem.Match(relPath) {
						dirHashMatch = true
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

			if info.Mode()&fs.ModeSymlink != 0 {
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
				symlinkedArtifacts, err := RecordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob)
				if err != nil {
					return err
				}

				for artifactPath, artifact := range symlinkedArtifacts {
					joinedPath := filepath.Join(relPath, artifactPath)
					results <- fileResult{relPath: joinedPath, digest: artifact}
				}

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

		if firstErr == nil && shouldRecord(result.relPath, result.digest, baseArtifacts, processWasTraced, openedFiles) {
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
// if the process was traced and the artifact was not one of the opened files, return false
// if the artifact is already in baseArtifacts, check if it's changed
// if it is not equal to the existing artifact, return true, otherwise return false
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet, processWasTraced bool, openedFiles map[string]bool) bool {
	if _, ok := openedFiles[path]; !ok && processWasTraced {
		return false
	}
	if previous, ok := baseArtifacts[path]; ok && artifact.Equal(previous) {
		return false
	}
	return true
}
