// Copyright 2026 The Witness Contributors
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

//go:build !unix

package cryptoutil

import "os"

// openRegularInRoot opens name relative to root. On non-unix platforms (notably
// Windows) os.Root.Open already refuses ALL symlinks — there is no in-root
// symlink-following behavior to defeat — so the plain root open is sufficient
// to refuse a post-classification symlink swap. See the unix build for the
// O_NOFOLLOW rationale.
func openRegularInRoot(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
