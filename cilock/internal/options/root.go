// Copyright 2025 The Aflock Authors
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

package options

import (
	"github.com/spf13/cobra"
)

type RootOptions struct {
	LogLevel        string
	CpuProfileFile  string
	MemProfileFile  string
	PolicyHardening string
}

func (ro *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&ro.LogLevel, "log-level", "l", "info", "Level of logging to output (debug, info, warn, error)")
	cmd.PersistentFlags().StringVar(&ro.CpuProfileFile, "debug-cpu-profile-file", "", "Path to store the CPU profile. Profiling will be enabled if this is non-empty")
	cmd.PersistentFlags().StringVar(&ro.MemProfileFile, "debug-mem-profile-file", "", "Path to store the Memory profile. Profiling will be enabled if this is non-empty")
	cmd.PersistentFlags().StringVar(&ro.PolicyHardening, "policy-hardening", "enforce",
		"Policy-verification hardening mode (#6266). 'enforce' (default) rejects dangerous policy configurations: vacuous empty cert constraints, certConstraint ignored on key-ID match, duplicate rego packages, incoherent step names. 'warn' downgrades them to loud warnings for legacy policies that cannot be re-signed yet. Also settable via CILOCK_POLICY_HARDENING")
}
