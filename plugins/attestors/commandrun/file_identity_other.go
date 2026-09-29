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

//go:build !linux && !darwin

package commandrun

import "os"

// identityFromInfo on a platform with no (device, inode) in its stat result.
// The bracket then compares only size and modification time, which is weaker
// than the change time and file id the other platforms compare: modification
// time can be set by anyone who can write the file. Windows gets its volume
// serial, FileId and ChangeTime through a handle in lane P1b
// (docs/design/command-program-pinning.md section 4.3). Until then the digest
// is still taken, because the only permitted absence of a program digest is a
// program cilock cannot read.
func identityFromInfo(st os.FileInfo) (fileIdentity, bool) {
	mt := st.ModTime()
	return fileIdentity{
		ctimeSec:  mt.Unix(),
		ctimeNsec: int64(mt.Nanosecond()),
		size:      st.Size(),
	}, true
}
