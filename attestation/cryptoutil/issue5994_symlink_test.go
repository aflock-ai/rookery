// Copyright 2022 The Witness Contributors
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

//go:build !windows

package cryptoutil

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
)

// Issue #5994 — per-file symlink TOCTOU in materials/products collection.
//
// attestation/file.RecordArtifacts classifies entries with Lstat during the
// walk, then a worker opens each "regular file" entry via
// CalculateDigestSetFromFile, which uses os.Open and therefore follows
// symlinks at open time with no boundary recheck. An attacker who swaps a
// regular file for a symlink to an out-of-tree secret AFTER the walk saw it
// as a regular file gets the foreign content hashed into the attestation.
//
// The fix is the root-aware open path CalculateDigestSetFromFileInRoot, which
// opens names relative to an os.Root rooted at the attestation basePath. A
// final-component (or any-component) symlink that escapes the root is refused
// at open time, closing the TOCTOU window without breaking the walker's own
// in-tree symlink handling (the walker resolves and recurses in-tree symlinks
// before any worker open, so the only symlink a worker can ever encounter is a
// post-Lstat swap).
//
// These tests assert the SECURE behavior: an open that escapes the root is
// refused and the foreign content is never hashed.

// TestSecurity_Issue5994_PerFileSymlinkOpenFollows: opening a symlink whose
// target is an out-of-tree secret through the root-aware path must be refused.
func TestSecurity_Issue5994_PerFileSymlinkOpenFollows(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()

	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("OUT-OF-TREE SECRET"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	// A symlink inside the attestation root pointing at the out-of-tree secret.
	link := filepath.Join(base, "innocent.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() { _ = root.Close() }()

	hashes := []DigestValue{{Hash: crypto.SHA256}}
	_, err = CalculateDigestSetFromFileInRoot(root, "innocent.txt", hashes)
	if err == nil {
		t.Fatal("SECURITY: open of an out-of-tree symlink target was NOT refused; " +
			"the foreign secret would be hashed into the attestation")
	}
	t.Logf("refused out-of-tree symlink open as expected: %v", err)
}

// TestSecurity_Issue5994_ToctouClassifyThenSwap: classify a regular file with
// Lstat, then swap it for an out-of-tree symlink before the worker opens it.
// The swapped target must not be hashed.
func TestSecurity_Issue5994_ToctouClassifyThenSwap(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()

	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("OUT-OF-TREE SECRET"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	// Step 1: a real regular file, as the walk's Lstat would classify it.
	victim := filepath.Join(base, "product.bin")
	benign := []byte("benign product bytes")
	if err := os.WriteFile(victim, benign, 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	info, err := os.Lstat(victim)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("expected regular file at classify time, got %v", info.Mode())
	}

	// Compute the digest of the benign content so we can prove the swapped
	// secret was never substituted.
	hashes := []DigestValue{{Hash: crypto.SHA256}}
	benignDS, err := CalculateDigestSetFromBytes(benign, hashes)
	if err != nil {
		t.Fatalf("benign digest: %v", err)
	}

	// Step 2: the attacker swaps the regular file for a symlink to the secret
	// after the walk classified it but before the worker opens it.
	if err := os.Remove(victim); err != nil {
		t.Fatalf("remove victim: %v", err)
	}
	if err := os.Symlink(secret, victim); err != nil {
		t.Fatalf("swap symlink: %v", err)
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() { _ = root.Close() }()

	// Step 3: the worker's open must refuse the escaped target. It must NOT
	// return the secret's digest.
	gotDS, err := CalculateDigestSetFromFileInRoot(root, "product.bin", hashes)
	if err == nil {
		secretDS, derr := CalculateDigestSetFromBytes([]byte("OUT-OF-TREE SECRET"), hashes)
		if derr != nil {
			t.Fatalf("secret digest: %v", derr)
		}
		if gotDS.Equal(secretDS) {
			t.Fatal("SECURITY: TOCTOU swap caused the out-of-tree secret to be hashed")
		}
		if gotDS.Equal(benignDS) {
			t.Fatal("SECURITY: open silently followed the swapped symlink (matched benign? " +
				"unexpected) — should have been refused")
		}
		t.Fatalf("SECURITY: swapped symlink open was not refused (digest=%v)", gotDS)
	}
	t.Logf("refused TOCTOU-swapped symlink open as expected: %v", err)
}

// TestSecurity_Issue5994_ToctouInRootSwap: classify a regular file with Lstat,
// then swap it for an IN-ROOT symlink (target stays inside the root) before the
// worker opens it. os.Root.Open would FOLLOW this link because the target is
// in-root, recording the sibling's content under the victim's relPath and
// bypassing the walk's classification/filtering. The worker open must refuse it
// anyway — the walker only ever dispatches Lstat-classified regular files, so
// any symlink at open time is a malicious post-classification swap regardless of
// where it points. This is the non-escaping case the prior fix missed.
func TestSecurity_Issue5994_ToctouInRootSwap(t *testing.T) {
	base := t.TempDir()

	// An in-root sibling whose content an attacker wants substituted under the
	// victim's recorded relPath.
	sibling := filepath.Join(base, "sibling.txt")
	siblingBytes := []byte("IN-ROOT SIBLING CONTENT")
	if err := os.WriteFile(sibling, siblingBytes, 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}

	// Step 1: a real regular file, as the walk's Lstat would classify it.
	victim := filepath.Join(base, "product.bin")
	benign := []byte("benign product bytes")
	if err := os.WriteFile(victim, benign, 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	info, err := os.Lstat(victim)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("expected regular file at classify time, got %v", info.Mode())
	}

	hashes := []DigestValue{{Hash: crypto.SHA256}}
	siblingDS, err := CalculateDigestSetFromBytes(siblingBytes, hashes)
	if err != nil {
		t.Fatalf("sibling digest: %v", err)
	}
	benignDS, err := CalculateDigestSetFromBytes(benign, hashes)
	if err != nil {
		t.Fatalf("benign digest: %v", err)
	}

	// Step 2: swap the regular file for an IN-ROOT symlink to the sibling. This
	// target does NOT escape the root, so os.Root.Open would follow it.
	if err := os.Remove(victim); err != nil {
		t.Fatalf("remove victim: %v", err)
	}
	if err := os.Symlink("sibling.txt", victim); err != nil {
		t.Fatalf("swap in-root symlink: %v", err)
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() { _ = root.Close() }()

	// Step 3: the worker open must refuse the in-root symlink leaf. It must NOT
	// return the sibling's digest (the substitution the attacker wanted) and it
	// must NOT silently succeed.
	gotDS, err := CalculateDigestSetFromFileInRoot(root, "product.bin", hashes)
	if err == nil {
		if gotDS.Equal(siblingDS) {
			t.Fatal("SECURITY: in-root TOCTOU swap caused the sibling's content to be " +
				"recorded under the victim's relPath (the non-escaping symlink gap)")
		}
		if gotDS.Equal(benignDS) {
			t.Fatal("SECURITY: open returned the pre-swap content despite the swap — " +
				"unexpected; the swapped symlink should have been refused")
		}
		t.Fatalf("SECURITY: in-root swapped symlink open was not refused (digest=%v)", gotDS)
	}
	t.Logf("refused in-root TOCTOU-swapped symlink open as expected: %v", err)
}
