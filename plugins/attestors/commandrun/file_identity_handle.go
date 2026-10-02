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

package commandrun

import (
	"os"
	"time"
)

// handleInfo is a stat whose identity was read through the open handle rather
// than derived from a name or from modification time. Windows is the only
// producer; the type lives in a portable file so the identity arithmetic is
// tested on every host.
type handleInfo struct {
	os.FileInfo
	id fileIdentity
}

// windowsEpochToUnix is the number of 100ns ticks between 1601-01-01 and
// 1970-01-01, the two epochs Windows file times and Go times count from.
const windowsEpochToUnix = 116444736000000000

// windowsFileIdentity builds the bracket's identity from what a handle
// reports: the volume serial number, the 128-bit file id and the ChangeTime.
// ChangeTime moves on every data or metadata change and, unlike
// LastWriteTime, is not settable through SetFileTime, which is why it
// replaces modification time as the compared stamp (issue #10571). A missing
// ChangeTime or an all-zero file id is "not reported" and yields no identity:
// an absent stamp is not a stamp that did not move.
func windowsFileIdentity(volume uint64, fileID [16]byte, changeTime, size int64) (fileIdentity, bool) {
	if changeTime <= 0 {
		return fileIdentity{}, false
	}
	var lo, hi uint64
	for i := 0; i < 8; i++ {
		lo |= uint64(fileID[i]) << (8 * i)
		hi |= uint64(fileID[8+i]) << (8 * i)
	}
	if lo == 0 && hi == 0 {
		return fileIdentity{}, false
	}
	// Whole seconds and the sub-second remainder are split before scaling so
	// a year-30000 stamp cannot overflow the nanosecond product.
	ticks := changeTime - windowsEpochToUnix
	sec := ticks / 10_000_000
	nsec := (ticks % 10_000_000) * 100
	if nsec < 0 {
		sec--
		nsec += int64(time.Second)
	}
	return fileIdentity{
		dev:       volume,
		ino:       lo,
		inoHi:     hi,
		ctimeSec:  sec,
		ctimeNsec: nsec,
		size:      size,
	}, true
}
