//go:build linux

// Copyright 2026 TestifySec, Inc.
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

package commandrun

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// readHardening reads back the live anti-tamper state of THIS process (cilock,
// the signer) at attestation time and returns it as the non-forgeability
// evidence carried in `_meta.keyGuard`. It never asserts protection it didn't
// observe: every field is a kernel read-back.
//
// cilock clears PR_SET_DUMPABLE at process start, long before the command-run
// attestor runs; because the attestor executes in that same process,
// PR_GET_DUMPABLE here reflects the signer's real state. The value is frozen
// into the signed predicate so a verifier reads it from the envelope rather
// than re-probing (which would read the verifier's process).
//
// NOTE: only the dumpable bit is signed as key protection. mlock is deliberately
// NOT reported as keyGuard evidence — cilock locks pages resident at startup,
// which does not cover the signing key allocated later, so an mlock claim here
// would over-state protection of the key.
func readHardening() *V02KeyGuard {
	kg := &V02KeyGuard{YamaPtraceScope: -1}

	// PR_GET_DUMPABLE: 0 means cleared (protected) — a same-UID ptrace /
	// process_vm_readv / /proc/<pid>/mem read is denied and the process is
	// excluded from core dumps. Default to "dumpable" if the read fails so we
	// never over-claim protection.
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err == nil {
		kg.Dumpable = d != 0
	} else {
		kg.Dumpable = true
	}
	kg.Applied = !kg.Dumpable
	kg.YamaPtraceScope = readYamaPtraceScope()
	if kg.Dumpable {
		kg.Note = "process is dumpable; signing key may be readable by a same-UID attacker"
	}
	return kg
}

// readYamaPtraceScope returns /proc/sys/kernel/yama/ptrace_scope, or -1 when
// the Yama LSM isn't present. >=1 means the host additionally restricts
// cross-process ptrace (defense in depth on top of the dumpable bit).
func readYamaPtraceScope() int {
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return n
}
