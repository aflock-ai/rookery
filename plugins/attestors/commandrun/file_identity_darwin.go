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
	"os"
	"syscall"
)

// identityFromInfo extracts the kernel identity from a stat result. Callers
// that mean to bind a digest to bytes must pass an fstat of the descriptor
// the bytes were read through, never a fresh resolution of a name: statting
// a path and then opening it are two resolutions, and a symlink flipped
// between them describes one file with another file's stat (Codex review of
// judge#9044, round 4).
func identityFromInfo(st os.FileInfo) (fileIdentity, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	//nolint:unconvert // Stat_t field widths differ across GOARCH; the conversions are load-bearing on 32-bit targets.
	return fileIdentity{
		dev:       uint64(sys.Dev),
		ino:       uint64(sys.Ino),
		ctimeSec:  int64(sys.Ctimespec.Sec),
		ctimeNsec: int64(sys.Ctimespec.Nsec),
		size:      st.Size(),
	}, true
}
