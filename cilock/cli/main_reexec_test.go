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

// jade:ring local

package cli

import (
	"fmt"
	"os"
	"testing"
)

// cliReexecEnv makes this test binary act as `cilock` when it is started
// again as a child process. `cilock policy prove` records evidence by
// running its own executable (proveSelfExecutable); under `go test` that
// executable is this binary, so the child must run the CLI instead of the
// tests. Everything else in the package is untouched: without the variable
// TestMain only runs the tests.
const cliReexecEnv = "CILOCK_CLI_TEST_REEXEC"

func TestMain(m *testing.M) {
	if os.Getenv(cliReexecEnv) == "1" {
		if err := New().Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
