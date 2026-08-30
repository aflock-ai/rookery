//go:build unix

package instructionfile

import (
	"os"
	"path/filepath"
	"testing"
)

// A SYMLINKED SEARCH ROOT must enumerate the real tree (Codex, #8408).
//
// os.Stat and os.OpenRoot follow a symlinked root, but filepath.WalkDir
// lstats it: without resolving the root first, the walk visited only the
// symlink entry, found nothing, and the attestor signed `status: complete`
// over an empty file list. macOS's /tmp (a symlink to /private/tmp) makes
// this the DEFAULT shape of a temp-dir working directory, not an edge case.
func TestScan_SymlinkedRootEnumeratesTheRealTree(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "CLAUDE.md"), []byte("# rules\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(t.TempDir(), "workspace")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	files, warnings, err := scan(link)
	if err != nil {
		t.Fatalf("scan through a symlinked root: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if len(files) != 1 || files[0].Path != "CLAUDE.md" {
		t.Fatalf("a symlinked root must yield the real tree's files; got %+v", files)
	}
	if len(files[0].Digest) == 0 {
		t.Fatal("the file found through a symlinked root must still be digested")
	}
}
