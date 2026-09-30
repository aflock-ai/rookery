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

	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
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
	var asJSON bool
	cmd := &cobra.Command{
		Use:               "version",
		Short:             "Prints out the cilock version",
		Long:              `Prints out the cilock version`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if asJSON {
				_ = writeVersionJSON(cmd.OutOrStdout())
				return
			}
			// First line MUST stay exactly "cilock <Version>": the release-fanout
			// and ci.yml cilock-version-stamp-guard both match it. Both extract it
			// IN-SHELL (`got="${ver_out%%$'\n'*}"`); do NOT reintroduce `| head -n1`.
			// Once this output outgrows head's single read, head exits first and our
			// next write takes SIGPIPE (Go raises it on fd 1 rather than returning
			// EPIPE), so the guard dies with 141 under `set -o pipefail` before it
			// asserts. Adding lines here is what makes that pipe fatal, and it is
			// how the whole public v3.0.1 distribution was lost; see #5551.
			fmt.Printf("cilock %s\n", Version)
			fmt.Printf("  Commit: %s\n", GitCommit)
			fmt.Printf("  Built:  %s\n", BuildTime)

			// Embedded policy trust: state explicitly which platform's signing trust
			// (if any) this binary verifies policies against, so it is auditable and
			// never silently in effect. A stock/dev build embeds nothing.
			switch lines, err := embeddedtrust.Summary(); {
			case err != nil:
				fmt.Printf("  Embedded policy trust: ERROR (%v)\n", err)
			case len(lines) == 0:
				fmt.Println("  Embedded policy trust: none (flagless verify disabled; supply --policy-ca-roots / --policy-*)")
			default:
				fmt.Println("  Embedded policy trust:")
				for _, l := range lines {
					fmt.Printf("    %s\n", l)
				}
				fmt.Println("    (ignore at verify time with --no-embedded-trust)")
			}
		},
	}
	cmd.Flags().BoolVar(&asJSON, jsonFlag, false, jsonFlagUsage)
	return cmd
}
