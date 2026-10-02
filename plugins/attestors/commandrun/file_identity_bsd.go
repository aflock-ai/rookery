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

//go:build freebsd || netbsd

package commandrun

import (
	"os"
	"syscall"
)

// identityFromInfo reads device, inode and change time from the stat of the
// open descriptor, as on Linux and macOS (issue #10571).
//
//nolint:unconvert // Stat_t field widths differ across GOARCH and OS.
func identityFromInfo(st os.FileInfo) (fileIdentity, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	return fileIdentity{
		dev:       uint64(sys.Dev),
		ino:       uint64(sys.Ino),
		ctimeSec:  int64(sys.Ctimespec.Sec),
		ctimeNsec: int64(sys.Ctimespec.Nsec),
		size:      st.Size(),
	}, true
}
