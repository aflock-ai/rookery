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

// SetExitCodeForTesting injects a value into the exported ExitCode
// field on a CommandRun. Strictly speaking the field is already
// public, but this helper documents the intent (test-only seam) and
// keeps the call sites consistent with the product-package helpers.
//
// Production code never calls this. ExitCode is set by runCmd from
// the wait status of the traced process.
func SetExitCodeForTesting(rc *CommandRun, code int) {
	if rc == nil {
		return
	}
	rc.ExitCode = code
}
