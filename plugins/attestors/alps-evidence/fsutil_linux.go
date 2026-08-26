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

//go:build linux

package alpsevidence

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// deletedSuffix is how the kernel renders a /proc/<pid>/fd/<n> link whose
// target has been unlinked. It is a description, not a path, so it must never
// be recorded as one.
const deletedSuffix = " (deleted)"

// resolveOpenedImage asks the KERNEL what file the descriptor holds, rather
// than looking a path up a second time.
//
// /proc/self/fd/<n> is a kernel-maintained link to the exact inode the open
// handle refers to, so the answer is derived from the handle itself: there is
// no path lookup for a concurrent retarget to race against, and the resolved
// path cannot possibly name a different file than the one this snapshot
// fstat'd and digested. This is the atomic resolution the "path" binding on
// macOS cannot offer, and it is why digestBindingProcessImage is a genuinely
// stronger claim on Linux rather than a cosmetic difference.
//
// Two answers are refused rather than recorded. An unlinked image reads back
// as "<path> (deleted)", which is prose about a path and not a path; and a
// non-absolute answer is not a path this predicate can publish. Both fall
// through to the verified resolution, which will either bind a real path to
// this handle or record none at all.
func resolveOpenedImage(f *os.File, info os.FileInfo, recorded string) (string, []string) {
	// FormatUint on the widened uintptr, not Itoa on a narrowed int: a
	// descriptor number is unsigned and narrowing it would be a conversion
	// that can, in principle, lose the value.
	fd := strconv.FormatUint(uint64(f.Fd()), 10)
	target, err := os.Readlink(filepath.Join("/proc", "self", "fd", fd))
	if err == nil && filepath.IsAbs(target) && !strings.HasSuffix(target, deletedSuffix) {
		return target, nil
	}
	return verifyResolutionAgainstHandle(info, recorded)
}
