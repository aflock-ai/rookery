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

//go:build darwin

package commandrun

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// darwinMaxPathLen is MAXPATHLEN, the buffer F_GETPATH writes into.
const darwinMaxPathLen = 1024

// platformFDRealPath asks the kernel for the descriptor's path with
// fcntl(F_GETPATH): the path of the vnode already open, not a new walk.
func platformFDRealPath(f *os.File) (string, string, error) {
	// Heap-allocated, so the address handed to the kernel cannot move.
	buf := make([]byte, darwinMaxPathLen)
	_, err := unix.FcntlInt(f.Fd(), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&buf[0])))) //nolint:gosec // G103,G115: F_GETPATH takes a buffer address
	runtime.KeepAlive(buf)
	if err != nil {
		return "", "", err
	}
	n := bytes.IndexByte(buf, 0)
	if n <= 0 {
		return "", "", errors.New("F_GETPATH returned no path")
	}
	return string(buf[:n]), RealPathFromFGetPath, nil
}

// programFileFacts is the identity of the descriptor. macOS has no file
// capabilities, so the setuid and setgid bits of the stat establish set-id.
func programFileFacts(f *os.File, fi os.FileInfo) *ProgramFile {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	pf := &ProgramFile{
		Device: uint64(uint32(sys.Dev)), //nolint:gosec // G115: dev_t is a 32-bit bit pattern on darwin
		Inode:  sys.Ino,
		Links:  uint64(sys.Nlink),
		SetID:  boolRef(fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0),
	}
	if f == nil {
		return pf
	}
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &sfs); err == nil { //nolint:gosec // G115: a descriptor number fits in int
		name := make([]byte, 0, len(sfs.Fstypename))
		for _, c := range sfs.Fstypename {
			if c == 0 {
				break
			}
			name = append(name, byte(c))
		}
		pf.FSType = string(name)
	}
	return pf
}

// pathOnlyFacts: macOS has no descriptor that opens without read permission,
// so an unreadable program's path and identity come from the name.
func pathOnlyFacts(path string) (string, string, *ProgramFile) {
	return nameOnlyFacts(path)
}

// cilockWrapperOf recognises the one wrapper cilock itself puts in front of
// the program on macOS: sandbox-exec under --trace (sandbox_trace_darwin.go
// wrap). It is recognised only in the exact shape wrap writes, with the
// recorded c.Path as sandbox-exec's target and the recorded arguments after
// it, so a wrapper that changed the target is still reported as a change.
func cilockWrapperOf(snap programSnapshot, c *exec.Cmd) (string, string, bool) {
	if c.Path != sandboxExecPath || len(c.Args) < 5 {
		return "", "", false
	}
	if c.Args[0] != sandboxExecPath || c.Args[1] != "-p" || c.Args[3] != "--" || c.Args[4] != snap.path {
		return "", "", false
	}
	var rest []string
	if len(snap.args) > 1 {
		rest = snap.args[1:]
	}
	if !slices.Equal(c.Args[5:], rest) {
		return "", "", false
	}
	return "sandbox-exec", "cilock started the program through sandbox-exec", true
}
