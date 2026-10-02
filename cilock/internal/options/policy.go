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

type PolicyValidateOptions struct {
	PolicyFilePath string
	PublicKeyPath  string
	OutputFormat   string
	// RequireSigned makes an unsigned policy a validation failure instead of
	// an accepted input. Off by default: validate-then-sign is the documented
	// flow, so the raw policy is the normal input and gets no signature
	// warning. Set it (or pass -k) when a signature is expected (#9311).
	RequireSigned bool
	// Strict refuses the empty platform trust placeholders a `cilock policy
	// template` draft carries (fulcio-root, platform-tsa). Off by default:
	// those placeholders are expected in an unsigned draft, because the
	// platform fills them when a human signs. Set it where the policy must
	// already be the complete form that gets signed.
	Strict bool
}

var RequiredPolicyValidateFlags = []string{
	"policy",
}

func (pvo *PolicyValidateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&pvo.PolicyFilePath, "policy", "p", "", "Path to policy file to validate (required)")
	cmd.Flags().StringVarP(&pvo.PublicKeyPath, "publickey", "k", "", "Path to public key for signature verification (optional)")
	cmd.Flags().StringVar(&pvo.OutputFormat, "format", "text", "Output format: text or json")
	// --output / -o used to be this format flag. -o is an output PATH on every
	// other command that binds it (#9311), so the old spellings stay as
	// deprecated aliases of --format: they still work, print a one-line
	// notice, and are hidden from --help.
	// MarkDeprecated alone: pflag prints the flag notice on the shorthand path
	// too, so marking the shorthand as well would print two lines for `-o`.
	cmd.Flags().StringVarP(&pvo.OutputFormat, "output", "o", "text", "Deprecated alias for --format")
	_ = cmd.Flags().MarkDeprecated("output", "use --format")
	cmd.Flags().BoolVar(&pvo.RequireSigned, "require-signed", false,
		"Fail unless the policy is a DSSE envelope carrying at least one signature (the form `cilock sign` "+
			"produces). Presence only; pass -k/--publickey to verify the signature.")

	cmd.Flags().BoolVar(&pvo.Strict, "strict", false,
		"Also fail on the empty platform trust placeholders (roots.fulcio-root, timestampauthorities.platform-tsa) "+
			"an unsigned draft carries until the platform fills them when a human signs.")

	cmd.MarkFlagsRequiredTogether(RequiredPolicyValidateFlags...)
}
