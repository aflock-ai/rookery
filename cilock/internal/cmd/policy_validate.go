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

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/cilock/internal/policy"
	"github.com/spf13/cobra"
)

func PolicyValidateCmd() *cobra.Command {
	pvo := options.PolicyValidateOptions{}

	cmd := &cobra.Command{
		Use:           "validate",
		Short:         "Validate a Witness policy file",
		Long:          "Validates a Witness policy file for correct schema, structure, and optionally verifies signatures",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidatePolicy(cmd.Context(), pvo)
		},
	}

	pvo.AddFlags(cmd)
	return cmd
}

func runValidatePolicy(ctx context.Context, pvo options.PolicyValidateOptions) error {
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

	var result *policy.ValidationResult

	policyEnvelope, err := policy.LoadPolicy(ctx, pvo.PolicyFilePath)
	if err == nil && len(policyEnvelope.Payload) > 0 {
		result = policy.ValidatePolicy(ctx, policyEnvelope, verifier)
	} else {
		if pvo.PublicKeyPath != "" {
			return fmt.Errorf("cannot verify signature on raw (non-DSSE) policy file - policy must be wrapped in DSSE envelope for signature verification")
		}
		result = policy.ValidateRawPolicy(ctx, policyBytes)
	}

	if pvo.OutputFormat == "json" {
		return outputJSON(result)
	}

	return outputText(result)
}

func outputJSON(result *policy.ValidationResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode JSON output: %w", err)
	}

	if !result.Valid {
		os.Exit(1)
	}
	return nil
}

func outputText(result *policy.ValidationResult) error {
	if result.Valid {
		fmt.Println("Policy validation: PASSED")

		if len(result.Warnings) > 0 {
			fmt.Println()
			fmt.Println("Warnings:")
			for i, warn := range result.Warnings {
				fmt.Printf("  %d. %s\n", i+1, warn)
			}
		}
		return nil
	}

	fmt.Println("Policy validation: FAILED")
	fmt.Println()

	if len(result.Errors) > 0 {
		fmt.Println("Validation errors:")
		for i, err := range result.Errors {
			fmt.Printf("  %d. %s\n", i+1, err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println()
		fmt.Println("Warnings:")
		for i, warn := range result.Warnings {
			fmt.Printf("  %d. %s\n", i+1, warn)
		}
	}

	os.Exit(1)
	return nil
}
