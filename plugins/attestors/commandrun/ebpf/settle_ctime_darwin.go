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

//go:build darwin

package ebpf

import (
	"os"
	"syscall"
	"time"
)

// changeTime is the inode change time (st_ctimespec) of an fstat result.
func changeTime(fi os.FileInfo) (time.Time, bool) {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	//nolint:unconvert // Stat_t field widths differ across GOARCH.
	return time.Unix(int64(sys.Ctimespec.Sec), int64(sys.Ctimespec.Nsec)), true
}
