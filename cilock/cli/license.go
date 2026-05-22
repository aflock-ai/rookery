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

// CustomerID and TenantID are ldflag-injected at build time for
// branded distribution. Both default to empty so the stock binary's
// `license` output is the plain Apache 2.0 statement.
//
//	go build -ldflags "-X github.com/aflock-ai/rookery/cilock/cli.CustomerID=acme \
//	                   -X github.com/aflock-ai/rookery/cilock/cli.TenantID=acme-prod" \
//	  ./cmd/cilock/
//
// The rookery-builder injects these via the same `-X` mechanism when
// the operator passes `--customer` and `--tenant`.
var (
	CustomerID string
	TenantID   string
)

func LicenseCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "license",
		Short:         "Show license information",
		Long:          `Show the Apache 2.0 license under which cilock is distributed, plus any customer / tenant branding metadata baked in at build time.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Apache License 2.0")
			fmt.Fprintln(out, "========================================")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Copyright 2025 The Aflock Authors")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Licensed under the Apache License, Version 2.0 (the \"License\");")
			fmt.Fprintln(out, "you may not use this file except in compliance with the License.")
			fmt.Fprintln(out, "You may obtain a copy of the License at")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "    http://www.apache.org/licenses/LICENSE-2.0")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Unless required by applicable law or agreed to in writing, software")
			fmt.Fprintln(out, "distributed under the License is distributed on an \"AS IS\" BASIS,")
			fmt.Fprintln(out, "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.")
			fmt.Fprintln(out, "See the License for the specific language governing permissions and")
			fmt.Fprintln(out, "limitations under the License.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Source: https://github.com/aflock-ai/rookery")
			if CustomerID != "" {
				fmt.Fprintln(out)
				fmt.Fprintf(out, "Built for: %s\n", CustomerID)
			}
			if TenantID != "" {
				fmt.Fprintf(out, "Tenant:    %s\n", TenantID)
			}
			return nil
		},
	}
}
