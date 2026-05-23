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

//go:build linux && arm

package commandrun

import (
	"golang.org/x/sys/unix"
)

func getSyscallId(regs unix.PtraceRegs) uint32 {
	// arm32 has some nuance here with OABI vs EABI... punting for now and just using R7
	return regs.Uregs[7]
}

// getSyscallRetVal returns the syscall return value at a syscall-exit stop.
// On arm the return value sits in r0 (Uregs[0]); the syscall number lives in
// r7. Returned as int64 for cross-arch signature parity — arm r0 is only
// 32 bits so the upper word is sign-extended.
func getSyscallRetVal(regs unix.PtraceRegs) int64 {
	return int64(int32(regs.Uregs[0])) //nolint:gosec // signed interpretation required by the syscall ABI
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return []uintptr{
		uintptr(regs.Uregs[0]),
		uintptr(regs.Uregs[1]),
		uintptr(regs.Uregs[2]),
		uintptr(regs.Uregs[3]),
		uintptr(regs.Uregs[4]),
		uintptr(regs.Uregs[5]),
	}
}

func getNativeUint(n int) uint32 {
	return uint32(n)
}

// handleArchLegacySyscall is currently a no-op on arm. arm has legacy
// non-*at variants but cilock release artifacts do not target arm32 —
// stub exists so the shared tracing_linux.go compiles for this arch.
func (p *ptraceContext) handleArchLegacySyscall(_ int, _ uint32, _ []uintptr) error {
	return nil
}
