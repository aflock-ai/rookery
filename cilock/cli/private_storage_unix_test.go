//go:build !windows

// jade:ring local

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func assertPrivateStorage(t *testing.T, path string, directory bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o600)
	if directory {
		want |= os.ModeDir | 0o100
	}
	if info.Mode() != want {
		t.Fatalf("%s: mode %v, want %v", path, info.Mode(), want)
	}
}

func privateStorageDirectoryLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateStorageUnixModes(t *testing.T) {
	base := t.TempDir()
	evidence := filepath.Join(base, "evidence")
	if err := os.Mkdir(evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newPrivateRunDir(evidence); err == nil {
		t.Fatal("accepted public directory")
	}
	if err := os.Chmod(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := newPrivateRunDir(evidence)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle")
	if err := writePrivateRunEnvelope(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	assertPrivateStorage(t, evidence, true)
	assertPrivateStorage(t, dir, true)
	assertPrivateStorage(t, path, false)
}
