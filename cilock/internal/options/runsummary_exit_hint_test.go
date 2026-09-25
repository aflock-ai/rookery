// Copyright 2026 The Aflock Authors
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

package options

import (
	"strings"
	"testing"
)

// mx-monorepo-tag-expressions-l12: the agent's `npm --prefix javascript run
// build` exited 127 because the package's dependencies were never installed,
// and the run summary said only "command exit: 127". The shell's two
// could-not-run codes now say what they mean and what to check.
func TestRunSummaryExplainsShellCouldNotRunExitCodes(t *testing.T) {
	cases := []struct {
		code int
		want []string
	}{
		{127, []string{"command exit: 127", "not found", "installed", "PATH"}},
		{126, []string{"command exit: 126", "not executable"}},
	}
	for _, c := range cases {
		s := &RunSummary{WrappedCommand: &WrappedCommand{Args: []string{"npm", "run", "build"}, ExitCode: c.code}}
		var b strings.Builder
		s.WriteHuman(&b)
		out := b.String()
		for _, want := range c.want {
			if !strings.Contains(out, want) {
				t.Errorf("exit %d: summary missing %q:\n%s", c.code, want, out)
			}
		}
	}
	for _, code := range []int{0, 1, 2} {
		s := &RunSummary{WrappedCommand: &WrappedCommand{Args: []string{"go", "test"}, ExitCode: code}}
		var b strings.Builder
		s.WriteHuman(&b)
		if strings.Contains(b.String(), "not found") || strings.Contains(b.String(), "not executable") {
			t.Errorf("exit %d must not carry a could-not-run hint:\n%s", code, b.String())
		}
	}
}
