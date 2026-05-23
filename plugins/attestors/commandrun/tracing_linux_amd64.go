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

//go:build linux && amd64

package commandrun

import (
	"os"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"golang.org/x/sys/unix"
)

func getSyscallId(regs unix.PtraceRegs) uint64 {
	return regs.Orig_rax
}

// getSyscallRetVal returns the syscall return value at a syscall-exit stop.
// On amd64 the kernel places the return value in rax. orig_rax retains the
// syscall number for the duration of the syscall (the value used at entry).
// A negative value (interpreted as int64) is the negated errno per the
// syscall ABI; callers must check for that before treating it as a fd.
func getSyscallRetVal(regs unix.PtraceRegs) int64 {
	return int64(regs.Rax) //nolint:gosec // signed interpretation required by the syscall ABI
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return []uintptr{
		uintptr(regs.Rdi),
		uintptr(regs.Rsi),
		uintptr(regs.Rdx),
		uintptr(regs.R10),
		uintptr(regs.R8),
		uintptr(regs.R9),
	}
}

func getNativeUint(n int) uint64 {
	return uint64(n) //nolint:gosec
}

// amd64-only legacy syscall numbers. arm64 was designed without these
// (it has only the *at variants); they're per-arch by build tag so the
// shared handler in tracing_linux.go can dispatch via the per-arch
// handleArchLegacySyscall hook.
const (
	amd64SysOpen    = 2
	amd64SysCreat   = 85
	amd64SysLink    = 86
	amd64SysUnlink  = 87
	amd64SysSymlink = 88
	amd64SysChmod   = 90
	amd64SysFchmod  = 91
	amd64SysRename  = 82
	amd64SysMkdir   = 83
	amd64SysRmdir   = 84
)

// handleArchLegacySyscall handles amd64-only syscalls that have no arm64
// equivalent. A build running on amd64 could use a legacy variant (chmod,
// rename, unlink, etc.) and bypass our otherwise-equivalent *at hook
// without this dispatch.
func (p *ptraceContext) handleArchLegacySyscall(pid int, syscallId uint64, args []uintptr) error { //nolint:gocyclo // flat switch over legacy variants
	switch syscallId {
	case unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD:
		// kexec — load a kernel for replacement. Extremely rare in builds.
		// Defined on amd64; not present on every Linux arch so handled here.
		name := "kexec_load"
		if syscallId == unix.SYS_KEXEC_FILE_LOAD {
			name = "kexec_file_load"
		}
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   name,
			Detail:    name + " — kernel replacement attempt inside build",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case amd64SysOpen, amd64SysCreat:
		// open(pathname, flags[, mode]) / creat(pathname, mode) — record like openat.
		file, err := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		if err != nil {
			return nil //nolint:nilerr // matches openat's path-error tolerance
		}
		// Register exit pairing for the fd→path cache. The exit handler
		// reuses the SYS_OPENAT branch by reading the syscall ID we pass
		// here — for legacy open/creat we tag it as openat so the same
		// "store fd→path on success" logic applies.
		p.pendingSyscalls[pid] = &pendingSyscall{
			syscallID: unix.SYS_OPENAT,
			path:      file,
		}
		procInfo := p.getProcInfo(pid)
		digestSet, derr := cryptoutil.CalculateDigestSetFromFile(file, p.hash)
		if derr != nil {
			if _, isPathErr := derr.(*os.PathError); isPathErr {
				procInfo.OpenedFiles[file] = nil
			}
			return nil //nolint:nilerr
		}
		procInfo.OpenedFiles[file] = digestSet

	case amd64SysUnlink:
		// unlink(pathname) — arg 0 is pathname.
		path, err := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		if err == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Deletes = append(procInfo.FileOps.Deletes, FileDelete{
				Path:      path,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case amd64SysRename:
		// rename(oldpath, newpath) — args 0 and 1.
		oldPath, e1 := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		newPath, e2 := p.readSyscallReg(pid, args[1], MAX_PATH_LEN)
		if e1 == nil && e2 == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Renames = append(procInfo.FileOps.Renames, FileRename{
				OldPath:   oldPath,
				NewPath:   newPath,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case amd64SysChmod:
		// chmod(pathname, mode) — args 0 and 1.
		path, err := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		if err == nil {
			mode := uint32(args[1])
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.PermChanges = append(procInfo.FileOps.PermChanges, FilePermChange{
				Path:      path,
				Mode:      mode,
				SetExec:   mode&0111 != 0,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case amd64SysFchmod:
		// fchmod(fd, mode) — resolve fd to path.
		fd := int(args[0])
		path := p.resolveFD(pid, fd)
		if path != "" && !strings.HasPrefix(path, "pipe:") && !strings.HasPrefix(path, "socket:") && !strings.HasPrefix(path, "anon_inode:") {
			mode := uint32(args[1])
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.PermChanges = append(procInfo.FileOps.PermChanges, FilePermChange{
				Path:      path,
				Mode:      mode,
				SetExec:   mode&0111 != 0,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case amd64SysLink:
		// link(oldpath, newpath) — args 0 and 1.
		oldPath, e1 := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		newPath, e2 := p.readSyscallReg(pid, args[1], MAX_PATH_LEN)
		if e1 == nil && e2 == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Links = append(procInfo.FileOps.Links, FileLink{
				SourcePath: oldPath,
				LinkPath:   newPath,
				IsSymlink:  false,
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case amd64SysSymlink:
		// symlink(target, linkpath) — args 0 and 1.
		target, e1 := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		linkPath, e2 := p.readSyscallReg(pid, args[1], MAX_PATH_LEN)
		if e1 == nil && e2 == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Links = append(procInfo.FileOps.Links, FileLink{
				SourcePath: target,
				LinkPath:   linkPath,
				IsSymlink:  true,
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case amd64SysMkdir:
		// mkdir(pathname, mode) — args 0 and 1.
		path, err := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		if err == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.DirOps = append(procInfo.FileOps.DirOps, DirOp{
				Path:      path,
				Op:        "mkdir",
				Mode:      uint32(args[1]),
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case amd64SysRmdir:
		// rmdir(pathname) — arg 0.
		path, err := p.readSyscallReg(pid, args[0], MAX_PATH_LEN)
		if err == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.DirOps = append(procInfo.FileOps.DirOps, DirOp{
				Path:      path,
				Op:        "rmdir",
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
	}
	return nil
}
