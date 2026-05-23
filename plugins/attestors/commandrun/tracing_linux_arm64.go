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

//go:build linux && arm64

package commandrun

import (
	"time"

	"golang.org/x/sys/unix"
)

func getSyscallId(regs unix.PtraceRegs) uint64 {
	return regs.Regs[8]
}

// getSyscallRetVal returns the syscall return value at a syscall-exit stop.
// On arm64 the kernel places the return value in x0 (Regs[0]); the syscall
// number stays in x8 across the call. A negative value (interpreted as
// int64) is the negated errno per the syscall ABI; callers must check for
// that before treating it as a fd.
func getSyscallRetVal(regs unix.PtraceRegs) int64 {
	return int64(regs.Regs[0]) //nolint:gosec // signed interpretation required by the syscall ABI
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return []uintptr{
		uintptr(regs.Regs[0]),
		uintptr(regs.Regs[1]),
		uintptr(regs.Regs[2]),
		uintptr(regs.Regs[3]),
		uintptr(regs.Regs[4]),
		uintptr(regs.Regs[5]),
	}
}

func getNativeUint(n int) uint64 {
	return uint64(n) //nolint:gosec // syscall register value, non-negative by contract
}

// handleArchLegacySyscall on arm64 handles the rare syscalls whose
// constants are not defined on every Linux arch (e.g. SYS_KEXEC_FILE_LOAD
// is missing on 386). The non-*at file syscalls (open, chmod, rename,
// unlink, mkdir, etc.) never existed on arm64; those are handled in the
// amd64-only sibling file.
func (p *ptraceContext) handleArchLegacySyscall(pid int, syscallId uint64, _ []uintptr) error {
	switch syscallId {
	case unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD:
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
	}
	return nil
}
