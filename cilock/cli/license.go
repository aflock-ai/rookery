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
	_ "embed"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// License texts are embedded from files (not inlined as Go string constants)
// so the source stays readable and the text has a single canonical home.
//
//go:embed licenses/apache.txt
var apacheLicense string

//go:embed licenses/busl.txt
var buslLicense string

// Edition selects which license this binary reports. Empty — the default for a
// stock `go build` — is the open-source Apache 2.0 CLI. The rookery builder
// injects `-X github.com/aflock-ai/rookery/cilock/cli.Edition=busl`, because
// the builder, its derivative works, and the binaries it produces are licensed
// under the Business Source License 1.1.
var Edition string

// CustomerID and TenantID are ldflag-injected at build time for
// branded distribution. Both default to empty so the stock binary's
// `license` output carries no branding.
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

// renderLicense assembles the license text for this edition (Apache 2.0 by
// default, BUSL 1.1 for builder-produced binaries) plus the optional
// ldflag-injected CustomerID/TenantID branding into a single string.
func renderLicense() string {
	var b strings.Builder
	if Edition == "busl" {
		b.WriteString(buslLicense)
	} else {
		b.WriteString(apacheLicense)
	}
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
		Use:   "license",
		Short: "Show license information",
		Long: `Show the license under which this binary is distributed — Apache 2.0 for the
stock cilock CLI, or the Business Source License 1.1 for binaries produced by the
rookery builder — plus any customer / tenant branding baked in at build time.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), renderLicense())
			return err
		},
	}
}
