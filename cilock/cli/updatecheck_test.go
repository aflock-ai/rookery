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

package cli

import "testing"

func TestSkipUpdateCheckForArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"bare invocation", nil, true},
		{"help word", []string{"help"}, true},
		{"help flag only", []string{"--help"}, true},
		{"completion", []string{"completion", "bash"}, true},
		// Cobra allows persistent flags before the subcommand — the guard
		// must not be defeated by a flag-prefixed invocation.
		{"completion after flags", []string{"--log-level", "debug", "completion", "bash"}, true},
		{"hidden complete after flags", []string{"--log-level", "debug", "__complete", "run", ""}, true},
		{"hidden complete", []string{"__complete", "run", ""}, true},
		{"hidden complete nodesc", []string{"__completeNoDesc", "run", ""}, true},
		{"normal command", []string{"verify", "artifact"}, false},
		// --help/-h anywhere before "--" is help rendering, not real work.
		{"subcommand help flag", []string{"verify", "--help"}, true},
		{"subcommand short help", []string{"verify", "-h"}, true},
		{"subcommand advanced help", []string{"run", "--help-advanced"}, true},
		{"normal command after flags", []string{"--log-level", "debug", "verify"}, false},
		// Tokens after "--" are the wrapped command's argv, not subcommands.
		{"run wrapping sensitive word", []string{"run", "--", "help"}, false},
		{"run wrapping completion", []string{"run", "-s", "build", "--", "make", "completion"}, false},
	}
	for _, tc := range cases {
		if got := skipUpdateCheckForArgs(tc.args); got != tc.want {
			t.Errorf("%s: skipUpdateCheckForArgs(%v) = %v, want %v", tc.name, tc.args, got, tc.want)
		}
	}
}
