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

//go:build !linux

package alpsevidence

import "os"

// resolveOpenedImage on a platform with no way to ask a descriptor for its own
// path.
//
// macOS is the measured case: there is no /proc, and no per-process image
// handle either, so both the digest binding and the path resolution top out at
// "this path, opened once". The handle still governs — the resolution below is
// only accepted when it names the file this snapshot fstat'd — but the
// resolution itself remains a second lookup, which is exactly what
// digestBindingPath tells a reader.
func resolveOpenedImage(_ *os.File, info os.FileInfo, recorded string) (string, []string) {
	return verifyResolutionAgainstHandle(info, recorded)
}
