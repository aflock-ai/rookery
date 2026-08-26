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

//go:build unix

package alpsevidence

import (
	"errors"
	"syscall"
)

// platformOpenFlags keeps the non-blocking FIFO defense and refuses a symlink
// at the final component on Unix. These constants must not appear in an
// untagged file: non-Unix targets do not share this open(2) vocabulary.
const platformOpenFlags = syscall.O_NONBLOCK | syscall.O_NOFOLLOW

// isSymlinkRefusal reports O_NOFOLLOW rejecting a symlink. POSIX specifies
// ELOOP; FreeBSD-lineage kernels (macOS included) document EMLINK.
func isSymlinkRefusal(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}
