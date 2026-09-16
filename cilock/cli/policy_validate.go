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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/cilock/internal/policy"
	"github.com/spf13/cobra"
)

func PolicyValidateCmd() *cobra.Command {
	pvo := options.PolicyValidateOptions{}

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a Witness policy file",
		Long:  "Validates a Witness policy file for correct schema, structure, and optionally verifies signatures",
		Example: `  # Validate a policy's schema and structure (unsigned input is the normal case)
  cilock policy validate -p policy.json

  # Also verify the policy signature against a public key, as JSON
  cilock policy validate -p policy.json -k policy-pub.pem --format json

  # Refuse a policy that was never signed
  cilock policy validate -p policy.signed.json --require-signed`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidatePolicy(cmd.Context(), pvo, cmd.OutOrStdout())
		},
	}

	pvo.AddFlags(cmd)
	return cmd
}

func runValidatePolicy(ctx context.Context, pvo options.PolicyValidateOptions, out io.Writer) error {
	policyBytes, err := os.ReadFile(pvo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var verifier cryptoutil.Verifier
	if pvo.PublicKeyPath != "" {
		keyBytes, err := os.ReadFile(pvo.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}

		verifier, err = cryptoutil.NewVerifierFromReader(bytes.NewReader(keyBytes))
		if err != nil {
			return fmt.Errorf("failed to create verifier from public key: %w", err)
		}
	}

	result, err := validatePolicyInput(ctx, pvo, policyBytes, verifier)
	if err != nil {
		return err
	}

	if pvo.OutputFormat == formatJSON {
		return outputJSON(out, result)
	}

	return outputText(out, result)
}

// validatePolicyInput validates either form of input. A signature is expected
// only when the caller says so (-k, --require-signed) or the input is already
// in the signed form (a DSSE envelope, which ValidatePolicy warns about when it
// carries no signatures). A raw policy is the documented validate-then-sign
// input and gets no warning (#9311).
func validatePolicyInput(ctx context.Context, pvo options.PolicyValidateOptions, policyBytes []byte, verifier cryptoutil.Verifier) (*policy.ValidationResult, error) {
	policyEnvelope, err := policy.LoadPolicy(ctx, pvo.PolicyFilePath, nil)
	if err != nil || len(policyEnvelope.Payload) == 0 {
		if pvo.RequireSigned {
			return nil, fmt.Errorf("--require-signed: the policy is not signed (not a DSSE envelope); sign it with `cilock sign -f %s -o policy.signed.json`", pvo.PolicyFilePath)
		}
		if pvo.PublicKeyPath != "" {
			return nil, fmt.Errorf("cannot verify signature on raw (non-DSSE) policy file - policy must be wrapped in DSSE envelope for signature verification")
		}
		return policy.ValidateRawPolicy(ctx, policyBytes), nil
	}
	if pvo.RequireSigned && len(policyEnvelope.Signatures) == 0 {
		return nil, fmt.Errorf("--require-signed: the DSSE envelope carries no signatures; sign it with `cilock sign -f policy.json -o policy.signed.json`")
	}
	return policy.ValidatePolicy(ctx, policyEnvelope, verifier), nil
}

func outputJSON(out io.Writer, result *policy.ValidationResult) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode JSON output: %w", err)
	}

	if !result.Valid {
		return fmt.Errorf("policy validation failed")
	}
	return nil
}

func outputText(out io.Writer, result *policy.ValidationResult) error {
	if result.Valid {
		_, _ = fmt.Fprintln(out, "Policy validation: PASSED")
		_, _ = fmt.Fprintf(out, "  signature: %s\n", result.Signature)

		if len(result.Warnings) > 0 {
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(out, "Warnings:")
			for i, warn := range result.Warnings {
				_, _ = fmt.Fprintf(out, "  %d. %s\n", i+1, warn)
			}
		}
		return nil
	}

	_, _ = fmt.Fprintln(out, "Policy validation: FAILED")
	_, _ = fmt.Fprintln(out)

	if len(result.Errors) > 0 {
		_, _ = fmt.Fprintln(out, "Validation errors:")
		for i, err := range result.Errors {
			_, _ = fmt.Fprintf(out, "  %d. %q\n", i+1, err)
		}
	}

	if len(result.Warnings) > 0 {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "Warnings:")
		for i, warn := range result.Warnings {
			_, _ = fmt.Fprintf(out, "  %d. %q\n", i+1, warn)
		}
	}

	return fmt.Errorf("policy validation failed")
}
