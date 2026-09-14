// jade:ring local

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateStorageRoundTrip(t *testing.T) {
	dir, err := newPrivateRunDir(filepath.Join(t.TempDir(), "state", "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence.json")
	if err := writePrivateRunEnvelope(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	assertPrivateStorage(t, filepath.Dir(dir), true)
	assertPrivateStorage(t, dir, true)
	assertPrivateStorage(t, path, false)
	if err := writePrivateRunEnvelope(path, []byte("overwrite")); err == nil {
		t.Fatal("accepted existing file")
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "private" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	other, err := newPrivateRunDir(filepath.Dir(dir))
	if err != nil || other == dir {
		t.Fatalf("second directory=%q err=%v", other, err)
	}
}

func TestPrivateStorageRejectsDirectorySymlink(t *testing.T) {
	base := t.TempDir()
	link := filepath.Join(base, "evidence")
	privateStorageDirectoryLink(t, t.TempDir(), link)
	if _, err := newPrivateRunDir(link); err == nil {
		t.Fatal("accepted directory symlink")
	}
}
