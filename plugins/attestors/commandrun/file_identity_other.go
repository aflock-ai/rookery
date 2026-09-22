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

// identityFromInfo on a platform where this package reads no kernel identity
// from the stat result. With no identity a bracket cannot be compared, so
// observedUnchanged refuses every read here: the answer the Linux and darwin
// versions give for a stat that carries no *syscall.Stat_t. Nothing on these
// platforms hashes through the bracket.
func identityFromInfo(os.FileInfo) (fileIdentity, bool) {
	return fileIdentity{}, false
}
