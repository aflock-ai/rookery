// Copyright 2026 The Rookery Contributors
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

// Syscall-number helpers for the fd-cache unit tests. Kept in a
// dedicated file because unix.SYS_DUP2 / SYS_DUP3 are defined on some
// arches and missing on others (notably arm64 has no SYS_DUP2 — dup2
// uses syscall number 23 on amd64, defined in tracing_linux_amd64.go's
// `33 = SYS_DUP2` pattern).

package commandrun

import "golang.org/x/sys/unix"

// openatSyscallNumber returns SYS_OPENAT for the current arch.
func openatSyscallNumber() uint64 { return uint64(unix.SYS_OPENAT) }

// openatAltSyscallNumber returns SYS_OPENAT2 — the alt openat used by
// glibc on recent kernels.
func openatAltSyscallNumber() uint64 { return uint64(unix.SYS_OPENAT2) }

// closeSyscallNumber returns SYS_CLOSE for the current arch.
func closeSyscallNumber() uint64 { return uint64(unix.SYS_CLOSE) }

// dupSyscallNumber returns SYS_DUP for the current arch.
func dupSyscallNumber() uint64 { return uint64(unix.SYS_DUP) }

// dup3SyscallNumber returns SYS_DUP3 for the current arch.
func dup3SyscallNumber() uint64 { return uint64(unix.SYS_DUP3) }

// dup2SyscallNumber returns the syscall number the production code uses
// for dup2. Production dispatches on the literal 33 (amd64's SYS_DUP2) so
// the tests use the same literal. On arm64 there is no dup2 — the value
// here is purely the case-label used for test-only routing of dup2-like
// behavior.
func dup2SyscallNumber() uint64 { return 33 }
