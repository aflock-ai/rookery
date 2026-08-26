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

//go:build darwin

package alpsevidence

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// TestKinfoProcCommDecodesThroughNulTerminated is an executable rebuttal.
//
// Codex review round 2 on PR #8209 claimed unix.KinfoProc.Proc.P_comm is an
// int8 array on Darwin, which would make nulTerminated(ki.Proc.P_comm[:])
// fail to compile and break the advertised macOS support. It is [17]byte on
// BOTH darwin/arm64 and darwin/amd64 in the pinned golang.org/x/sys v0.45.0
// (ztypes_darwin_arm64.go:801, ztypes_darwin_amd64.go:801), and both arches
// build clean. This test references P_comm through the exact expression
// ReadProcess uses, so if a future x/sys bump changes the element type, the
// module stops compiling here — loudly, on every darwin arch — instead of
// macOS support silently rotting.
func TestKinfoProcCommDecodesThroughNulTerminated(t *testing.T) {
	var ki unix.KinfoProc

	copy(ki.Proc.P_comm[:], "codex\x00garbage")
	assert.Equal(t, "codex", nulTerminated(ki.Proc.P_comm[:]),
		"comm must decode up to the first NUL")

	// A comm that fills the array without a terminating NUL comes back whole.
	full := "0123456789abcdef!"
	copy(ki.Proc.P_comm[:], full)
	assert.Equal(t, full, nulTerminated(ki.Proc.P_comm[:]),
		"an unterminated comm must come back whole")
}

func TestSameDarwinProcessSlotBindsStartTimeAndParent(t *testing.T) {
	var before, after unix.KinfoProc
	before.Eproc.Ppid = 7
	before.Proc.P_starttime.Sec = 100
	before.Proc.P_starttime.Usec = 200
	after = before
	assert.True(t, sameDarwinProcessSlot(&before, &after))

	after.Proc.P_starttime.Usec++
	assert.False(t, sameDarwinProcessSlot(&before, &after),
		"a recycled PID with the same comm must not reuse the earlier ancestry")
	after = before
	after.Eproc.Ppid++
	assert.False(t, sameDarwinProcessSlot(&before, &after),
		"a reparent during capture leaves no coherent ancestry edge")
}
