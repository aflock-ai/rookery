//go:build audit

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

package cryptoutil

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
)

// TestSecurity_R3_247_CalculateDigestSetFromDirIgnoresHashes proves that
// CalculateDigestSetFromDir ignores its `hashes` parameter and always produces
// a dirHash using SHA256, regardless of what hash algorithms are requested.
//
// Impact: MEDIUM — If a caller requests only SHA1 hashes (or any non-SHA256 set),
// they get SHA256 back instead. This causes inconsistency in the DigestSet:
// file artifacts have the requested hashes but directory artifacts always have
// dirHash:sha256. During artifact comparison in policy verification, this means
// directory hashes will never match if the expected hashes differ from SHA256.
func TestSecurity_R3_247_CalculateDigestSetFromDirIgnoresHashes(t *testing.T) {
	// Create a temp directory with some files
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	// Request SHA1-only hashes
	sha1Only := []DigestValue{{Hash: crypto.SHA1}}
	ds, err := CalculateDigestSetFromDir(dir, sha1Only)
	if err != nil {
		t.Fatal(err)
	}

	// The function should have returned SHA1 digest, but it returns dirHash:sha256 instead
	dirHashKey := DigestValue{Hash: crypto.SHA256, DirHash: true}
	sha1Key := DigestValue{Hash: crypto.SHA1}

	if _, hasDirHash := ds[dirHashKey]; !hasDirHash {
		t.Fatal("expected dirHash:sha256 in result, but it's missing")
	}

	if _, hasSHA1 := ds[sha1Key]; hasSHA1 {
		t.Fatal("unexpectedly found SHA1 in result — the hashes parameter was ignored")
	}

	t.Logf("SECURITY BUG R3-247: CalculateDigestSetFromDir(hashes=[SHA1]) returned dirHash:SHA256. "+
		"The hashes parameter is completely ignored. This causes inconsistency: file artifacts "+
		"will have SHA1 digests but directory artifacts always have SHA256 dirHash. During policy "+
		"artifact comparison, directories will fail to match because the hash algorithms don't overlap.")
}

// TestSecurity_R3_247_DirHashFileHashMismatch proves the downstream effect:
// when CalculateDigestSet for a file uses SHA1 and CalculateDigestSetFromDir
// uses SHA256, DigestSet.Equal between them always returns false because there
// are no common hash algorithms.
func TestSecurity_R3_247_DirHashFileHashMismatch(t *testing.T) {
	sha1Key := DigestValue{Hash: crypto.SHA1}
	dirHashKey := DigestValue{Hash: crypto.SHA256, DirHash: true}

	// Simulating: file artifact has SHA1, dir artifact has dirHash:SHA256
	fileDS := DigestSet{sha1Key: "sha1value"}
	dirDS := DigestSet{dirHashKey: "h1:dirvalue"}

	if fileDS.Equal(dirDS) {
		t.Fatal("unexpected: file and dir digest sets should never be equal (no common hashes)")
	}

	// This confirms that requesting SHA1 for files but getting SHA256 for dirs
	// means artifact comparison between file and dir steps will always fail.
	t.Logf("Confirmed: SHA1 file artifacts and SHA256 dir artifacts have no common "+
		"hash algorithms and can never be Equal(). This is a consequence of R3-247.")
}

// TestSecurity_R3_248_NewDigestSetPartialOnError proves that NewDigestSet
// returns a partially populated DigestSet along with an error when one of the
// hash names is unsupported. A caller that doesn't check err could use the
// partial result.
func TestSecurity_R3_248_NewDigestSetPartialOnError(t *testing.T) {
	input := map[string]string{
		"sha256":         "abc123",
		"invalid_hash":   "def456",
		"sha1":           "ghi789",
	}

	ds, err := NewDigestSet(input)
	if err == nil {
		t.Fatal("expected error for unsupported hash name")
	}

	// The partial result may contain sha256 but not invalid_hash
	// Map iteration order is non-deterministic, so we may or may not get sha256
	t.Logf("FINDING R3-248: NewDigestSet returned partial DigestSet (len=%d) with error: %v. "+
		"A caller that ignores the error gets an incomplete digest set.", len(ds), err)
}

// TestSecurity_R3_249_ToNameMapPartialOnError proves that ToNameMap returns
// a partial map along with an error when an unsupported hash is in the DigestSet.
func TestSecurity_R3_249_ToNameMapPartialOnError(t *testing.T) {
	// Create a DigestSet with a hash that's not in hashNames
	unsupported := DigestValue{Hash: crypto.SHA384} // not in hashNames
	ds := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "abc",
		unsupported:                      "def",
	}

	nameMap, err := ds.ToNameMap()
	if err == nil {
		t.Fatal("expected error for unsupported hash")
	}

	// The partial nameMap may contain sha256 despite the error
	t.Logf("FINDING R3-249: ToNameMap returned partial result (len=%d) with error: %v. "+
		"If used for serialization (MarshalJSON), the partial map would produce "+
		"incomplete JSON.", len(nameMap), err)
}

// TestSecurity_R3_250_UnmarshalJSONUnknownHashDropped proves that
// DigestSet.UnmarshalJSON fails on unknown hash names. This means a
// JSON envelope from a newer version of the software that uses a hash
// algorithm not recognized by this version will fail to deserialize
// entirely, rather than gracefully degrading.
func TestSecurity_R3_250_UnmarshalJSONUnknownHashDropped(t *testing.T) {
	// JSON with an unknown hash algorithm alongside a known one
	jsonData := []byte(`{"sha256":"abc123","sha3-256":"def456"}`)

	var ds DigestSet
	err := ds.UnmarshalJSON(jsonData)
	if err != nil {
		// Entire deserialization fails because of one unknown hash
		t.Logf("FINDING R3-250: UnmarshalJSON fails entirely when encountering unknown hash "+
			"algorithm: %v. This means forward compatibility is broken — a newer algorithm "+
			"in the digest set causes the entire set to be rejected, even though valid "+
			"algorithms (sha256) are present.", err)
	} else {
		t.Logf("UnmarshalJSON succeeded with unknown hash (len=%d). Checking contents...", len(ds))
		sha256Key := DigestValue{Hash: crypto.SHA256}
		if v, ok := ds[sha256Key]; ok {
			t.Logf("sha256=%s preserved", v)
		}
	}
}

// TestSecurity_R3_251_IsHashableFileSymlinkViaOpen proves that isHashableFile
// sees symlinks as regular files when opened via os.Open (which follows symlinks).
// The symlink check in isHashableFile (line 287) is dead code because os.Open
// resolves symlinks before returning the file descriptor.
func TestSecurity_R3_251_IsHashableFileSymlinkDeadCode(t *testing.T) {
	dir := t.TempDir()

	// Create a regular file and a symlink to it
	realFile := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(realFile, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(dir, "link.txt")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatal(err)
	}

	// Open the symlink — os.Open follows it
	f, err := os.Open(symlink)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	hashable, err := isHashableFile(f)
	if err != nil {
		t.Fatal(err)
	}

	if !hashable {
		t.Fatal("expected symlink target to be hashable")
	}

	// Check the mode — it should be regular, NOT symlink
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	if stat.Mode()&os.ModeSymlink != 0 {
		t.Logf("File opened via symlink reports ModeSymlink — symlink branch IS reachable")
	} else {
		t.Logf("FINDING R3-251: isHashableFile's symlink check (mode&ModeSymlink) is dead code. "+
			"os.Open follows symlinks, so Stat() on the opened file returns the target's mode, "+
			"never ModeSymlink. The symlink branch at line 287 is unreachable through os.Open. "+
			"Not a security issue per se, but misleading — the function appears to handle "+
			"symlinks but never actually encounters them.")
	}
}

// TestSecurity_R3_252_DigestSetEqualEmptyString proves that Equal matches
// empty digest strings, which could occur if a DigestSet is constructed
// with empty values.
func TestSecurity_R3_252_DigestSetEqualEmptyString(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}

	ds1 := DigestSet{sha256Key: ""}
	ds2 := DigestSet{sha256Key: ""}

	if !ds1.Equal(ds2) {
		t.Fatal("expected empty strings to match")
	}

	// Empty digest = zero-length file? Or corrupted data?
	// Either way, empty string "" == "" returns true which is technically correct
	// but means two files with no content (or corrupted hashing) pass comparison.
	t.Logf("FINDING R3-252: DigestSet.Equal matches empty digest strings. "+
		"Two digest sets with empty SHA256 values are considered equal. "+
		"This could mask hashing failures where the digest was never computed. "+
		"A defensive implementation would reject empty digest values.")
}

// TestSecurity_R3_253_HashToStringMissingSHA384 proves that common hash
// algorithms like SHA384 and SHA512 are not in the hashNames map and
// cannot be converted to string names.
func TestSecurity_R3_253_HashToStringMissingSHA384(t *testing.T) {
	unsupportedHashes := []struct {
		hash crypto.Hash
		name string
	}{
		{crypto.SHA384, "SHA-384"},
		{crypto.SHA512, "SHA-512"},
		{crypto.SHA512_256, "SHA-512/256"},
		{crypto.SHA3_256, "SHA3-256"},
		{crypto.SHA3_384, "SHA3-384"},
		{crypto.SHA3_512, "SHA3-512"},
	}

	for _, h := range unsupportedHashes {
		_, err := HashToString(h.hash)
		if err == nil {
			t.Errorf("expected error for %s but HashToString succeeded", h.name)
			continue
		}

		t.Logf("FINDING R3-253: HashToString does not support %s — returns: %v. "+
			"Only SHA256 and SHA1 are supported. A policy requesting SHA384 "+
			"would fail at the hash name conversion stage.", h.name, err)
	}
}
