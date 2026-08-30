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

//go:build unix

package instructionfile

import (
	"path/filepath"
	"syscall"
	"testing"
)

// unixSkipFixtures adds the non-regular-entry refusal, which needs mkfifo.
func unixSkipFixtures() []skipFixture {
	return []skipFixture{
		{
			name:       "not-a-regular-file",
			wantReason: "regular file",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := syscall.Mkfifo(filepath.Join(root, "CLAUDE.md"), 0o600); err != nil {
					t.Skipf("mkfifo unavailable on this filesystem: %v", err)
				}
			},
		},
	}
}
