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

import (
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

// AttestCmd is `cilock attest` — a thin wrapper over `cilock run`
// for consultative / state-snapshot attestors that don't need a
// wrapped command. Examples:
//
//	cilock attest -a github-review -k key.pem -o review.bundle.json -s review
//	cilock attest -a aws-iid       -k key.pem -o iid.bundle.json    -s iid
//
// Internally we synthesize argv `["true"]` (or `["cmd","/c","exit"]`
// on Windows) and call runRun. Every other flag (-a, -k, -o, -s,
// --attestor-*) accepts the same shape as `cilock run`.
//
// The wrapped command_run attestor still records the no-op exec —
// that's intentional: it stamps the moment of attestation. If you
// want to ignore command_run entirely, use `-a <attestor>` selectively
// and `--ignore-command-exit-code`.
//
// Cobra positional args: attest takes no positional args. If you want
// a wrapped command, use `cilock run` instead.
func AttestCmd() *cobra.Command {
	o := options.RunOptions{
		AttestorOptSetters:       make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Record attestations without wrapping a command",
		Long: `attest records one or more attestations against the current context,
without wrapping a child command. Use it for consultative attestors that
snapshot at-rest state — like github-review (PR review state for a commit),
aws-iid (EC2 identity), or any plugin that fires during the prematerial
stage and doesn't depend on a wrapped command's outputs.

Behind the scenes this is sugar for ` + "`cilock run -- true`" + ` — every
flag accepted by ` + "`cilock run`" + ` works identically here.`,
		Example: `  # Snapshot PR review state for HEAD in the current repo
  cilock attest -a github-review -k key.pem -o review.bundle.json -s review-head

  # Snapshot EC2 instance identity (when on an EC2 host)
  cilock attest -a aws-iid -k key.pem -o iid.bundle.json -s iid

  # Snapshot a specific PR's review state from any working dir
  cilock attest -a github-review --attestor-github-review-repo aflock-ai/rookery --attestor-github-review-pr 153 -k key.pem -o review-pr153.bundle.json -s review-pr153`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.ResolvePlatformDefaults(cmd)

			signerProviders := providersFromFlags("signer", cmd.Flags())
			signers, err := loadSigners(cmd.Context(),
				o.SignerOptions,
				o.KMSSignerProviderOptions,
				signerProviders)
			if err != nil {
				return fmt.Errorf("failed to load signers: %w", err)
			}

			// Synthesize a no-op wrapped command. `true` exists on every
			// POSIX system and on Windows under Git Bash / WSL. On native
			// Windows powershell users can run `cilock attest` and the
			// runRun path will exec the local `true` if available, or
			// fall back to whatever the shell resolves.
			userSetFlags := map[string]bool{
				"attestor-product-include-glob": cmd.Flags().Changed("attestor-product-include-glob"),
			}
			return runRun(cmd.Context(), o, []string{"true"}, userSetFlags, signerProviders, signers...)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
