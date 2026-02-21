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
}

var RequiredPolicyValidateFlags = []string{
	"policy",
}

func (pvo *PolicyValidateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&pvo.PolicyFilePath, "policy", "p", "", "Path to policy file to validate (required)")
	cmd.Flags().StringVarP(&pvo.PublicKeyPath, "publickey", "k", "", "Path to public key for signature verification (optional)")
	cmd.Flags().StringVarP(&pvo.OutputFormat, "output", "o", "text", "Output format: text or json")

	cmd.MarkFlagsRequiredTogether(RequiredPolicyValidateFlags...)
}
