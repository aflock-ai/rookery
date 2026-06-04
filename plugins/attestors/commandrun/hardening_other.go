//go:build !linux

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

package commandrun

// readHardening reports "no hardening" on platforms without the Linux
// process-protection primitives (e.g. macOS dev machines, which do not
// produce trusted provenance). Applied stays false and Dumpable true so a
// verifier never mistakes an unhardened dev run for a protected one.
func readHardening() *V02KeyGuard {
	return &V02KeyGuard{
		Applied:         false,
		Dumpable:        true,
		YamaPtraceScope: -1,
		Note:            "memory-hardening unsupported on this platform (non-Linux)",
	}
}
