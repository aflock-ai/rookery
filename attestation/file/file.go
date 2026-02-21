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
	"strings"

	"github.com/gobwas/glob"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
)

// RecordArtifacts walks basePath and records the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
// includeGlob/excludeGlob filter which files are recorded: exclude is checked first (excluded files are
// never recorded), then include (only matching files are recorded). Pass nil for either to skip that filter.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob, includeGlob glob.Glob, excludeGlob glob.Glob) (map[string]cryptoutil.DigestSet, error) {
	artifacts := make(map[string]cryptoutil.DigestSet)
	err := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
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

				artifacts[relPath+string(os.PathSeparator)] = dir
				return filepath.SkipDir
			}

			return nil
		}

		if info.Mode()&fs.ModeSymlink != 0 {
			// if this is a symlink, eval the true path and eval any artifacts in the symlink. we record every symlink we've visited to prevent infinite loops
			linkedPath, err := filepath.EvalSymlinks(path)
			if os.IsNotExist(err) {
				log.Debugf("(file) broken symlink detected: %v", path)
				return nil
			} else if err != nil {
				return err
			}

			// Security: ensure the symlink target is within the basePath boundary.
			// Without this check, a symlink pointing outside the working directory
			// (e.g. /etc/shadow) would be followed and its contents hashed into
			// the attestation, enabling path traversal attacks.
			absBase, err := filepath.Abs(basePath)
			if err != nil {
				return fmt.Errorf("failed to resolve base path: %w", err)
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
			symlinkedArtifacts, err := RecordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob, includeGlob, excludeGlob)
			if err != nil {
				return err
			}

			for artifactPath, artifact := range symlinkedArtifacts {
				// all artifacts in the symlink should be recorded relative to our basepath
				joinedPath := filepath.Join(relPath, artifactPath)
				if shouldRecord(joinedPath, artifact, baseArtifacts, processWasTraced, openedFiles, includeGlob, excludeGlob) {
					artifacts[filepath.Join(relPath, artifactPath)] = artifact
				}
			}

			return nil
		}

		artifact, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
		if err != nil {
			return err
		}

		if shouldRecord(relPath, artifact, baseArtifacts, processWasTraced, openedFiles, includeGlob, excludeGlob) {
			artifacts[relPath] = artifact
		}

		return nil
	})

	return artifacts, err
}

// shouldRecord determines whether artifact should be recorded.
// Exclude glob is checked first (excluded files are never recorded), then include glob
// (only matching files are recorded). After glob filtering, tracing and deduplication
// checks are applied.
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet, processWasTraced bool, openedFiles map[string]bool, includeGlob glob.Glob, excludeGlob glob.Glob) bool {
	normalizedPath := filepath.ToSlash(path)
	if excludeGlob != nil && excludeGlob.Match(normalizedPath) {
		return false
	}
	if includeGlob != nil && !includeGlob.Match(normalizedPath) {
		return false
	}
	if _, ok := openedFiles[path]; !ok && processWasTraced {
		return false
	}
	if previous, ok := baseArtifacts[path]; ok && artifact.Equal(previous) {
		return false
	}
	return true
}
