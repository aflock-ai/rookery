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

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Build-time provenance, injected via -ldflags -X. Mirrors the judge-api/jctl
// version package so a cilock binary traces back to its exact source revision,
// not just a semver. Defaults make an unstamped (plain `go build`) binary obvious.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func VersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "version",
		Short:             "Prints out the cilock version",
		Long:              `Prints out the cilock version`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			// First line MUST stay exactly "cilock <Version>": the release-fanout
			// and ci.yml cilock-version-stamp-guard both match it (via head -n1).
			fmt.Printf("cilock %s\n", Version)
			fmt.Printf("  Commit: %s\n", GitCommit)
			fmt.Printf("  Built:  %s\n", BuildTime)
		},
	}
}
