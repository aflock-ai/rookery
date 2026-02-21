// Copyright 2025 The Witness Contributors
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
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

func setupBenchFiles(b *testing.B, dir string, count int, sizeBytes int) {
	b.Helper()
	data := make([]byte, sizeBytes)
	for i := range count {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%05d.bin", i)), data, 0644); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecordArtifacts_100x1KB(b *testing.B) {
	dir := b.TempDir()
	setupBenchFiles(b, dir, 100, 1024)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	b.ResetTimer()
	for range b.N {
		_, err := RecordArtifacts(dir, nil, hashes, map[string]struct{}{}, false, map[string]bool{}, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecordArtifacts_100x1MB(b *testing.B) {
	dir := b.TempDir()
	setupBenchFiles(b, dir, 100, 1024*1024)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	b.ResetTimer()
	for range b.N {
		_, err := RecordArtifacts(dir, nil, hashes, map[string]struct{}{}, false, map[string]bool{}, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecordArtifacts_1000x1KB(b *testing.B) {
	dir := b.TempDir()
	setupBenchFiles(b, dir, 1000, 1024)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	b.ResetTimer()
	for range b.N {
		_, err := RecordArtifacts(dir, nil, hashes, map[string]struct{}{}, false, map[string]bool{}, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
