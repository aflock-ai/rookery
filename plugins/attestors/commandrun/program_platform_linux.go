// Copyright 2021 The Witness Contributors
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

//go:build linux

package commandrun

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// platformFDRealPath reads the descriptor's path from /proc/self/fd/N. That is
// the kernel's own name for the open file object, so it cannot disagree with
// the bytes read through the same descriptor.
func platformFDRealPath(f *os.File) (string, string, error) {
	p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd()))) //nolint:gosec // G115: a descriptor number fits in int
	if err != nil {
		return "", "", err
	}
	if strings.HasSuffix(p, " (deleted)") {
		return "", "", errors.New("the program was unlinked after it was opened")
	}
	return p, RealPathFromProcFD, nil
}

// Seams over the capability lookup. Nothing in production assigns to them.
var (
	fgetxattr = unix.Fgetxattr
	getxattr  = unix.Getxattr
)

const capabilityXattr = "security.capability"

// programFileFacts is the identity of the descriptor: device, inode, link
// count, set-id (mode bits or a security.capability xattr) and file system.
// With no descriptor (f nil) the capability cannot be asked, so set-id is
// established only by a mode bit and is otherwise unknown.
func programFileFacts(f *os.File, fi os.FileInfo) *ProgramFile {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	pf := &ProgramFile{
		Device: uint64(sys.Dev),   //nolint:unconvert,gosec // Stat_t field widths differ across GOARCH
		Inode:  uint64(sys.Ino),   //nolint:unconvert // Stat_t field widths differ across GOARCH
		Links:  uint64(sys.Nlink), //nolint:unconvert // Stat_t field widths differ across GOARCH
	}
	switch {
	case fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0:
		pf.SetID = boolRef(true)
	case f == nil:
		pf.SetIDReason = "no descriptor to read the " + capabilityXattr + " attribute through"
	default:
		pf.SetID, pf.SetIDReason = fileCapabilityOf(f)
	}
	if f == nil {
		return pf
	}
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &sfs); err == nil { //nolint:gosec // G115: a descriptor number fits in int
		pf.FSType = linuxFSTypeName(int64(sfs.Type)) //nolint:unconvert // Statfs_t.Type width differs across GOARCH
	}
	return pf
}

// fileCapabilityOf asks the descriptor itself whether the file carries a
// capability, so the answer describes the file that was hashed and needs no
// /proc. Only ENODATA (no such attribute) and EOPNOTSUPP (a file system that
// cannot carry one; the kernel's exec-time lookup gets the same answer and
// grants nothing) establish absence. Every other error, ENOENT, EIO, EACCES
// from a security module, EOVERFLOW for a capability owned outside this user
// namespace, leaves set-id unknown.
func fileCapabilityOf(f *os.File) (*bool, string) {
	fd := int(f.Fd()) //nolint:gosec // G115: a descriptor number fits in int
	_, err := fgetxattr(fd, capabilityXattr, nil)
	if errors.Is(err, unix.EBADF) {
		// An O_PATH descriptor (an unreadable program) refuses fgetxattr.
		// The kernel's link to the same open file can still be asked.
		_, err = getxattr("/proc/self/fd/"+strconv.Itoa(fd), capabilityXattr, nil)
	}
	switch {
	case err == nil:
		return boolRef(true), ""
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.EOPNOTSUPP):
		return boolRef(false), ""
	default:
		return nil, "the " + capabilityXattr + " attribute could not be read: " + err.Error()
	}
}

// pathOnlyFacts identifies a program that cannot be opened for reading. On
// Linux an O_PATH descriptor needs no read permission and still yields the
// kernel's path and identity, so an execute-only program keeps both.
func pathOnlyFacts(path string) (string, string, *ProgramFile) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nameOnlyFacts(path)
	}
	f := os.NewFile(uintptr(fd), path) //nolint:gosec // G115: a descriptor from open(2) is non-negative
	defer func() { _ = f.Close() }()
	rp, source, err := platformFDRealPath(f)
	if err != nil {
		return nameOnlyFacts(path)
	}
	var pf *ProgramFile
	if fi, err := f.Stat(); err == nil {
		pf = programFileFacts(f, fi)
	}
	return rp, source, pf
}

// cilockWrapperOf: after P0 (docs/design/command-program-pinning.md 3.3) no
// Linux path rewrites c.Path. Until then the sudo privilege drop wraps the
// command in setpriv, which searches PATH again as another user, so it is
// deliberately NOT a recognised wrapper: the guard reports the exec target as
// changed, which is the truth.
func cilockWrapperOf(programSnapshot, *exec.Cmd) (string, string, bool) {
	return "", "", false
}

func linuxFSTypeName(magic int64) string {
	switch magic {
	case 0xEF53:
		return "ext4"
	case 0x58465342:
		return "xfs"
	case 0x9123683E:
		return "btrfs"
	case 0x01021994:
		return "tmpfs"
	case 0x794c7630:
		return "overlayfs"
	case 0x73717368:
		return "squashfs"
	case 0x6969:
		return "nfs"
	case 0x65735546:
		return "fuse"
	case 0x2fc12fc1:
		return "zfs"
	case 0x01021997:
		return "9p"
	case 0x858458f6:
		return "ramfs"
	case 0x5346414f:
		return "afs"
	default:
		return fmt.Sprintf("0x%x", magic)
	}
}
