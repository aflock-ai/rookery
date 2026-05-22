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
	"io"
	"strings"

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

const licenseText = `Apache License 2.0
========================================

Copyright 2025 The Aflock Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Source: https://github.com/aflock-ai/rookery
`

// renderLicense assembles the static license text plus the optional
// ldflag-injected CustomerID/TenantID branding into a single string.
// Centralizing the build here gives the RunE callback a single
// error-returning io.WriteString call instead of N unchecked fmt.Fprintln
// returns (errcheck linter fail).
func renderLicense() string {
	var b strings.Builder
	b.WriteString(licenseText)
	if CustomerID != "" {
		b.WriteByte('\n')
		_, _ = fmt.Fprintf(&b, "Built for: %s\n", CustomerID)
	}
	if TenantID != "" {
		_, _ = fmt.Fprintf(&b, "Tenant:    %s\n", TenantID)
	}
	return b.String()
}

func LicenseCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "license",
		Short:         "Show license information",
		Long:          `Show the Apache 2.0 license under which cilock is distributed, plus any customer / tenant branding metadata baked in at build time.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), renderLicense())
			return err
		},
	}
}
