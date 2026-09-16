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
	"os"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	witnesspolicy "github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

func SignCmd() *cobra.Command {
	so := options.SignOptions{
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}

	cmd := &cobra.Command{
		Use:   "sign [file]",
		Short: "Signs a file",
		Long:  "Signs a file with the provided key source and outputs the signed file to the specified destination",
		Example: `  # Sign a policy file with a local key, write the signed envelope
  cilock sign -k cosign.key -f policy.json -o policy.signed.json`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read the input ONCE. The same bytes are classified (is this a
			// policy?) and then signed, so nothing between the two reads can
			// swap the file or the symlink and have different bytes signed than
			// the ones the refusal below looked at.
			data, err := os.ReadFile(so.InFilePath) //nolint:gosec // user-supplied signing input
			if err != nil {
				return fmt.Errorf("failed to read file to sign: %w", err)
			}
			if err := refuseOfflineWithoutLocalSigner(cmd, so); err != nil {
				return err
			}
			if err := refuseAgentPolicySigning(cmd, so, data); err != nil {
				return err
			}
			limit, err := resolveMaxAttestationBytes(cmd, so.MaxAttestationBytes)
			if err != nil {
				return err
			}
			so.MaxAttestationBytes = options.ByteSize(limit)
			// Refuse an oversized input here, before a signer is loaded or a
			// platform session is exchanged: the size of the bytes is already
			// known, and an operator who is over the limit should learn it
			// without first being told their key is missing.
			if err := checkAttestationSize(data, so.DataType, limit); err != nil {
				return err
			}
			// Derive Fulcio/TSA from --platform-url and, if logged in, exchange the
			// stored session for a short-lived Fulcio token — so `cilock sign` can
			// sign a policy keyless after `cilock login`, with minimal flags.
			so.ResolvePlatformDefaults(cmd)

			signers, err := loadSigners(cmd.Context(), so.SignerOptions, so.KMSSignerProviderOptions, providersFromFlags("signer", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signer: %w", err)
			}

			return signBytes(cmd.Context(), so, data, signers...)
		},
	}

	so.AddFlags(cmd)
	return cmd
}

// refuseOfflineWithoutLocalSigner names the reason an offline sign cannot
// proceed when no --signer-* flag was given: the only signer that needs no
// flag is the platform's keyless Fulcio path, and --offline is precisely the
// promise not to use the platform. Without this the run died later with the
// generic "no signers found".
func refuseOfflineWithoutLocalSigner(cmd *cobra.Command, so options.SignOptions) error {
	if !so.Offline || len(providersFromFlags("signer", cmd.Flags())) > 0 {
		return nil
	}
	return fmt.Errorf("--offline needs a local signer: pass -k/--signer-file-key-path <key> (or a --signer-kms-*/--signer-vault-*/--signer-spiffe-* provider); keyless signing exchanges a platform session for a Fulcio certificate, which is what --offline opts out of")
}

// refuseAgentPolicySigning classifies the exact bytes that will be signed. It
// must never re-read the path: the caller signs `data`, not whatever the path
// holds by the time the signer runs.
func refuseAgentPolicySigning(cmd *cobra.Command, so options.SignOptions, data []byte) error {
	if !isWitnessPolicyInput(data, so.DataType) {
		return nil
	}
	// Any explicitly selected signer wins over platform identity resolution.
	// In particular, -k is the offline proof path used by the validator harness.
	if len(providersFromFlags("signer", cmd.Flags())) > 0 || so.PlatformURL == "" {
		return nil
	}
	active, err := auth.LookupAgent(so.PlatformURL)
	if err != nil {
		return fmt.Errorf("resolve enrolled agent before policy signing: %w", err)
	}
	pending, err := auth.LookupPendingAgent(so.PlatformURL)
	if err != nil {
		return fmt.Errorf("resolve pending agent before policy signing: %w", err)
	}
	if active != nil || pending != nil {
		return fmt.Errorf("humans sign policies, agents sign attestations: this policy would use the enrolled agent for %s; have a human sign this policy", auth.NormalizeURL(so.PlatformURL))
	}
	return nil
}

// isWitnessPolicyInput reports whether the bytes about to be signed are a
// witness policy: either the caller declared a policy payload type, or the
// document is a JSON object carrying both `steps` and `expires`. Bytes that are
// not a JSON object are simply not a policy.
func isWitnessPolicyInput(data []byte, payloadType string) bool {
	if payloadType == witnesspolicy.PolicyPredicate || payloadType == witnesspolicy.LegacyPolicyPredicate {
		return true
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(data, &document) != nil {
		return false
	}
	_, hasSteps := document["steps"]
	_, hasExpires := document["expires"]
	return hasSteps && hasExpires
}

// runSign reads the input file and signs it. Callers that have already read
// the input (and classified it) use signBytes directly so the signed bytes are
// the classified bytes.
func runSign(ctx context.Context, so options.SignOptions, signers ...cryptoutil.Signer) error {
	data, err := os.ReadFile(so.InFilePath) //nolint:gosec // user-supplied signing input
	if err != nil {
		return fmt.Errorf("failed to read file to sign: %w", err)
	}
	return signBytes(ctx, so, data, signers...)
}

func signBytes(_ context.Context, so options.SignOptions, data []byte, signers ...cryptoutil.Signer) error {
	// The input IS the statement payload here (sign frames nothing), so the
	// limit is measured on the bytes read, before a signer is consulted or
	// the output is opened. Direct callers that leave the field zero are
	// unlimited, matching the workflow library's default.
	if err := checkAttestationSize(data, so.DataType, int(so.MaxAttestationBytes)); err != nil {
		return err
	}
	if len(signers) > 1 {
		return onlyOneSignerError()
	}

	if len(signers) == 0 {
		return fmt.Errorf("no signers found")
	}

	timestampers := []timestamp.Timestamper{}
	for _, url := range so.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	outFile, err := loadOutfile(so.OutFilePath)
	if err != nil {
		return err
	}
	defer closeOutfile(outFile)

	return workflow.Sign(bytes.NewReader(data), so.DataType, outFile, dsse.SignWithSigners(signers[0]), dsse.SignWithTimestampers(timestampers...))
}
