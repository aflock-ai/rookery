// Copyright 2024 The Witness Contributors
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

package lockfiles

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

const (
	Name    = "lockfiles"
	Type    = "https://aflock.ai/attestations/lockfiles/v0.1"
	RunType = attestation.PreMaterialRunType
)

// ignoredDirs lists directories to skip during recursive search.
var ignoredDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	".svn":         true,
	".hg":          true,
	"__pycache__":  true,
	"venv":         true,
	".venv":        true,
	"target":       true,
	"build":        true,
	"dist":         true,
}

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewLockfilesAttestor()
	})
}

func NewLockfilesAttestor() attestation.Attestor {
	return &Attestor{
		Lockfiles:   []LockfileInfo{},
		SearchPaths: os.Getenv("WITNESS_LOCKFILES_SEARCH_PATHS"),
	}
}

// Attestor implements the lockfiles attestation type
type Attestor struct {
	Lockfiles   []LockfileInfo `json:"lockfiles"`
	SearchPaths string         `json:"-"`
}

// LockfileInfo stores information about a lockfile
type LockfileInfo struct {
	Filename string               `json:"filename"`
	Content  string               `json:"content"`
	Digest   cryptoutil.DigestSet `json:"digest"`
}

// Name returns the name of the attestation type
func (a *Attestor) Name() string {
	return "lockfiles"
}

// lockfilePatterns returns the list of known lockfile names.
func lockfilePatterns() []string {
	return []string{
		"Gemfile.lock",      // Ruby
		"package-lock.json", // Node.js (npm)
		"yarn.lock",         // Node.js (Yarn)
		"Cargo.lock",        // Rust
		"poetry.lock",       // Python (Poetry)
		"Pipfile.lock",      // Python (Pipenv)
		"requirements.txt",  // Python (pip)
		"composer.lock",     // PHP
		"go.sum",            // Go
		"Podfile.lock",      // iOS/macOS (CocoaPods)
		"gradle.lockfile",   // Gradle
		"pnpm-lock.yaml",    // Node.js (pnpm)
	}
}

// Attest captures the contents of common lockfiles.
//
// Three modes based on SearchPaths:
//   - Empty (default): search current directory only (backward compatible)
//   - "recursive": recursively search the entire tree, ignoring dependency dirs
//   - Colon-separated paths: search only the specified directories
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	patterns := lockfilePatterns()
	a.Lockfiles = []LockfileInfo{}

	if a.SearchPaths == "" {
		return a.searchInDirectory(".", patterns)
	}

	if a.SearchPaths == "recursive" {
		return a.searchRecursive(".", patterns)
	}

	for _, dir := range parseSearchPaths(a.SearchPaths) {
		if err := a.searchInDirectory(dir, patterns); err != nil {
			return err
		}
	}
	return nil
}

// parseSearchPaths splits a colon-separated (or OS-specific separator) path list.
func parseSearchPaths(paths string) []string {
	var result []string
	for _, p := range filepath.SplitList(paths) {
		trimmed := filepath.Clean(strings.TrimSpace(p))
		if trimmed != "" && trimmed != "." {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return []string{"."}
	}
	return result
}

// searchInDirectory searches a single directory for lockfile patterns.
func (a *Attestor) searchInDirectory(dir string, patterns []string) error {
	for _, pattern := range patterns {
		searchPattern := filepath.Join(dir, pattern)
		matches, err := filepath.Glob(searchPattern)
		if err != nil {
			return fmt.Errorf("error searching for %s: %w", searchPattern, err)
		}
		for _, match := range matches {
			if err := a.addLockfile(match); err != nil {
				return err
			}
		}
	}
	return nil
}

// searchRecursive walks the directory tree looking for lockfiles, skipping ignored dirs.
func (a *Attestor) searchRecursive(root string, patterns []string) error {
	patternSet := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		patternSet[p] = true
	}

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			name := info.Name()
			if ignoredDirs[name] || (name != "." && strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}

		if patternSet[info.Name()] {
			return a.addLockfile(path)
		}
		return nil
	})
}

// addLockfile reads a lockfile, computes its digest, and appends it to the attestor.
func (a *Attestor) addLockfile(path string) error {
	content, err := os.ReadFile(path) //nolint:gosec // G304: lockfile path from attestation context
	if err != nil {
		return fmt.Errorf("error reading %s: %w", path, err)
	}

	digest, err := cryptoutil.CalculateDigestSetFromBytes(content, []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
	})
	if err != nil {
		return fmt.Errorf("error computing digest of %s: %w", path, err)
	}

	a.Lockfiles = append(a.Lockfiles, LockfileInfo{
		Filename: path,
		Content:  string(content),
		Digest:   digest,
	})
	return nil
}

// RunType implements attestation.Attestor.
func (o *Attestor) RunType() attestation.RunType {
	return RunType
}

// Schema implements attestation.Attestor.
func (o *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&o)
}

// Type implements attestation.Attestor.
func (o *Attestor) Type() string {
	return Type
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for _, lockfile := range a.Lockfiles {
		subjectName := fmt.Sprintf("file:%s", lockfile.Filename)
		subjects[subjectName] = lockfile.Digest
	}
	return subjects
}
