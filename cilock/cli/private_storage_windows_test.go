// jade:ring local

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func assertPrivateStorage(t *testing.T, path string, directory bool) {
	t.Helper()
	_, sid, err := privateRunSecurity()
	if err != nil {
		t.Fatal(err)
	}
	h, err := openRunHandle(0, path, nil, directory, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.CloseHandle(h); err != nil {
			t.Error(err)
		}
	})
	if err := checkPrivateRunHandle(h, sid); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func privateStorageDirectoryLink(t *testing.T, target, link string) {
	t.Helper()
	// Junctions do not require the symlink privilege or Developer Mode.
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		t.Fatalf("junction is not a reparse point: attributes=%x err=%v", attrs, err)
	}
	linked, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(linked, dest) {
		t.Fatal("junction does not resolve to its target")
	}
}

func TestPrivateStorageWindowsDACL(t *testing.T) {
	sd, sid, err := privateRunSecurity()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateRunSecurity(sd, sid); err != nil {
		t.Fatal(err)
	}
	for _, sddl := range []string{
		"O:" + sid.String() + "D:(A;;FA;;;" + sid.String() + ")",
		"O:" + sid.String() + "D:P(A;;FA;;;WD)",
		"O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")(A;;FR;;;WD)",
		"O:WDD:P(A;;FA;;;" + sid.String() + ")",
		"O:" + sid.String() + "D:P",
		"O:" + sid.String() + "D:NO_ACCESS_CONTROL",
	} {
		bad, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkPrivateRunSecurity(bad, sid); err == nil {
			t.Fatalf("accepted %s", sddl)
		}
	}
}

func TestPrivateStorageWindowsRejectsPublicExistingDirectory(t *testing.T) {
	dir, err := newPrivateRunDir(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Dir(dir)
	public, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := public.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(evidence, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := newPrivateRunDir(evidence); err == nil {
		t.Fatal("accepted Everyone DACL")
	}
}

func TestPrivateStorageWindowsFileACLAndAncestorReparse(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "bundle")
	if err := writePrivateRunEnvelope(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	assertPrivateStorage(t, path, false)
	link := filepath.Join(t.TempDir(), "link")
	privateStorageDirectoryLink(t, base, link)
	if err := writePrivateRunEnvelope(filepath.Join(link, "escaped"), []byte("private")); err == nil {
		t.Fatal("followed ancestor reparse point")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("created through reparse point: %v", err)
	}
}
