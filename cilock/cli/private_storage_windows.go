package cli

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows os.Mkdir/Chmod mode bits do not enforce Unix privacy. Supply a
// protected DACL at creation, not after potentially exposing evidence bytes.
func privateRunSecurity() (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	sid := user.User.Sid
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")")
	return sd, sid, err
}

func checkPrivateRunHandle(h windows.Handle, sid *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkPrivateRunSecurity(sd, sid)
}

func checkPrivateRunSecurity(sd *windows.SECURITY_DESCRIPTOR, sid *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if owner == nil || !windows.EqualSid(owner, sid) || control&windows.SE_DACL_PROTECTED == 0 || acl == nil || acl.AceCount != 1 {
		return fmt.Errorf("evidence requires a protected current-user-only DACL and owner")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		return err
	}
	const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	// GetAce returns the OS-validated ACE; ACCESS_ALLOWED_ACE stores its SID at SidStart.
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != fileAllAccess || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), sid) { // #nosec G103 -- native SID layout, after checking the ACE type
		return fmt.Errorf("evidence DACL is not current-user-only full access")
	}
	return nil
}

// OBJ_DONT_REPARSE rejects reparse points anywhere in an absolute path.
// Relative child creation uses a pinned parent handle; no path-based ACL edits.
func openRunHandle(parent windows.Handle, name string, sd *windows.SECURITY_DESCRIPTOR, directory, create bool) (windows.Handle, error) {
	if parent == 0 {
		abs, err := filepath.Abs(name)
		if err != nil {
			return 0, err
		}
		if strings.HasPrefix(abs, `\\`) {
			abs = `UNC\` + strings.TrimPrefix(abs, `\\`)
		}
		name = `\??\` + abs
	} else if name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return 0, fmt.Errorf("invalid evidence basename %q", name)
	}
	ntName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: ntName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd}
	oa.Length = uint32(unsafe.Sizeof(oa))
	options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	access := uint32(windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_ATTRIBUTES)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	disposition := uint32(windows.FILE_OPEN)
	if create {
		disposition = windows.FILE_CREATE
		access |= windows.GENERIC_WRITE
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition, options, 0, 0)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return 0, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return 0, fmt.Errorf("evidence path is a reparse point")
	}
	return h, nil
}

func ensureRunParent(path string, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	h, err := openRunHandle(0, path, nil, true, false)
	if err == nil {
		return h, nil
	}
	if !errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) && !errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
		return 0, err
	}
	parentPath := filepath.Dir(path)
	if parentPath == path {
		return 0, err
	}
	parent, err := ensureRunParent(parentPath, sd)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(parent) }()
	h, err = openRunHandle(parent, filepath.Base(path), sd, true, true)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
		return openRunHandle(parent, filepath.Base(path), nil, true, false)
	}
	return h, err
}

func newPrivateRunDir(dir string) (string, error) {
	sd, sid, err := privateRunSecurity()
	if err != nil {
		return "", err
	}
	parent, err := ensureRunParent(filepath.Dir(dir), sd)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(parent) }()
	h, err := openRunHandle(parent, filepath.Base(dir), sd, true, true)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
		h, err = openRunHandle(parent, filepath.Base(dir), nil, true, false)
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := checkPrivateRunHandle(h, sid); err != nil {
		return "", err
	}
	name := "run-" + rand.Text()
	run, err := openRunHandle(h, name, sd, true, true)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(run) }()
	if err := checkPrivateRunHandle(run, sid); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func writePrivateRunEnvelope(path string, body []byte) error {
	sd, sid, err := privateRunSecurity()
	if err != nil {
		return err
	}
	parent, err := openRunHandle(0, filepath.Dir(path), nil, true, false)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(parent) }()
	h, err := openRunHandle(parent, filepath.Base(path), sd, false, true)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	if err := checkPrivateRunHandle(h, sid); err != nil {
		_ = f.Close()
		return err
	}
	_, writeErr := f.Write(body)
	return errors.Join(writeErr, f.Sync(), f.Close())
}
