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

// Pins the point-at-the-artifact UX: `cilock verify ./my-binary` adopts a bare
// positional path as the artifact (its sha256 subject is computed for the
// operator — no digest to extract or paste), directories route to the tree
// subject, conflicts and misses fail closed with actionable errors.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// TestAdoptPositionalArtifact_FileBecomesArtifactFile: the headline UX — a
// regular file path is adopted as --artifactfile.
func TestAdoptPositionalArtifact_FileBecomesArtifactFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(f, []byte("artifact-bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vo := &options.VerifyOptions{}
	if err := adoptPositionalArtifact(vo, f); err != nil {
		t.Fatalf("adoptPositionalArtifact: %v", err)
	}
	if vo.ArtifactFilePath != f {
		t.Fatalf("ArtifactFilePath = %q, want %q", vo.ArtifactFilePath, f)
	}
	if vo.ArtifactDirectoryPath != "" {
		t.Fatal("a file must not set the directory path")
	}
}

// TestAdoptPositionalArtifact_DirectoryBecomesDirectoryPath: a directory arg
// routes to --directory-path (the tree subject) — existing behavior, pinned.
func TestAdoptPositionalArtifact_DirectoryBecomesDirectoryPath(t *testing.T) {
	d := t.TempDir()
	vo := &options.VerifyOptions{}
	if err := adoptPositionalArtifact(vo, d); err != nil {
		t.Fatalf("adoptPositionalArtifact: %v", err)
	}
	if vo.ArtifactDirectoryPath != d {
		t.Fatalf("ArtifactDirectoryPath = %q, want %q", vo.ArtifactDirectoryPath, d)
	}
	if vo.ArtifactFilePath != "" {
		t.Fatal("a directory must not set the file path")
	}
}

// TestAdoptPositionalArtifact_ConflictWithExplicitFlagErrors: explicit
// --artifactfile / --directory-path plus a positional arg is a usage error —
// never silently prefer one.
func TestAdoptPositionalArtifact_ConflictWithExplicitFlagErrors(t *testing.T) {
	f := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, vo := range []*options.VerifyOptions{
		{ArtifactFilePath: "already.bin"},
		{ArtifactDirectoryPath: "already-dir"},
	} {
		err := adoptPositionalArtifact(vo, f)
		if err == nil {
			t.Fatal("want a usage error when positional and flag artifacts are both given")
		}
		if !strings.Contains(err.Error(), "use one") {
			t.Fatalf("error %q should tell the operator to use one form", err.Error())
		}
	}
}

// TestAdoptPositionalArtifact_MissingPathErrors: a nonexistent path fails
// immediately (no fallback interpretation).
func TestAdoptPositionalArtifact_MissingPathErrors(t *testing.T) {
	vo := &options.VerifyOptions{}
	err := adoptPositionalArtifact(vo, filepath.Join(t.TempDir(), "nope.bin"))
	if err == nil {
		t.Fatal("want an error for a missing path")
	}
	if vo.ArtifactFilePath != "" || vo.ArtifactDirectoryPath != "" {
		t.Fatal("a failed adoption must not set any artifact path")
	}
}

// TestAdoptPositionalArtifact_DigestLookingArgPointsAtSubjects: digests are
// never accepted positionally; a digest-shaped miss names the --subjects fix.
func TestAdoptPositionalArtifact_DigestLookingArgPointsAtSubjects(t *testing.T) {
	vo := &options.VerifyOptions{}
	err := adoptPositionalArtifact(vo, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if err == nil {
		t.Fatal("want an error for a digest-shaped positional arg")
	}
	if !strings.Contains(err.Error(), "--subjects") {
		t.Fatalf("error %q should point the operator at --subjects", err.Error())
	}
}

// TestAdoptPositionalArtifact_FileNamedLikeDigestStillAdopts: an EXISTING file
// whose name is 64 hex chars is a file, not a digest — stat wins, no ambiguity.
func TestAdoptPositionalArtifact_FileNamedLikeDigestStillAdopts(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	vo := &options.VerifyOptions{}
	if err := adoptPositionalArtifact(vo, f); err != nil {
		t.Fatalf("adoptPositionalArtifact: %v", err)
	}
	if vo.ArtifactFilePath != f {
		t.Fatalf("ArtifactFilePath = %q, want the existing file adopted", vo.ArtifactFilePath)
	}
}
