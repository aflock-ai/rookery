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
	"context"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/attestation/signer/kms"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/pflag"
)

func providersFromFlags(prefix string, flags *pflag.FlagSet) map[string]struct{} {
	providers := make(map[string]struct{})
	flags.Visit(func(flag *pflag.Flag) {
		if !strings.HasPrefix(flag.Name, fmt.Sprintf("%s-", prefix)) {
			return
		}

		parts := strings.Split(flag.Name, "-")
		if len(parts) < 2 {
			return
		}

		providers[parts[1]] = struct{}{}
	})

	return providers
}

// loadSigners creates signers from the provided flags. Returns an error immediately
// on any failure rather than silently continuing, preventing partial trust decisions
// from being made with an incomplete set of signers. (Security: silent signer loading
// failures could cause an operation to proceed with fewer signers than intended.)
func loadSigners(ctx context.Context, so options.SignerOptions, ko options.KMSSignerProviderOptions, signerProviders map[string]struct{}) ([]cryptoutil.Signer, error) {
	signers := make([]cryptoutil.Signer, 0)
	for signerProvider := range signerProviders {
		setters := so[signerProvider]
		sp, err := signer.NewSignerProvider(signerProvider, setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v signer provider: %w", signerProvider, err)
		}

		if ksp, ok := sp.(*kms.KMSSignerProvider); ok {
			for _, opt := range ksp.Options {
				for _, setter := range ko[opt.ProviderName()] {
					sp, err = setter(ksp)
					if err != nil {
						return nil, fmt.Errorf("failed to configure KMS signer provider %v: %w", signerProvider, err)
					}
				}
			}
		}

		s, err := sp.Signer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v signer: %w", signerProvider, err)
		}

		signers = append(signers, s)
	}

	if len(signers) == 0 {
		return signers, fmt.Errorf("failed to load any signers")
	}

	return signers, nil
}

// loadVerifiers creates verifiers from the provided flags. Returns an error immediately
// on any failure rather than silently continuing, preventing verification from proceeding
// with an incomplete trust set. (Security: silent verifier loading failures could allow
// artifacts signed by an expected-but-missing verifier to bypass policy checks.)
func loadVerifiers(ctx context.Context, so options.VerifierOptions, ko options.KMSVerifierProviderOptions, verifierProviders map[string]struct{}) ([]cryptoutil.Verifier, error) { //nolint:gocognit
	verifiers := make([]cryptoutil.Verifier, 0)
	for verifierProvider := range verifierProviders {
		setters := so[verifierProvider]
		sp, err := signer.NewVerifierProvider(verifierProvider, setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v verifier provider: %w", verifierProvider, err)
		}

		if ksp, ok := sp.(*kms.KMSSignerProvider); ok {
			for _, opt := range ksp.Options {
				pn := opt.ProviderName()
				for _, setter := range ko[pn] {
					vp, err := setter(ksp)
					if err != nil {
						return nil, fmt.Errorf("failed to configure KMS verifier provider %v: %w", verifierProvider, err)
					}

					kspv, ok := vp.(*kms.KMSSignerProvider)
					if !ok {
						return nil, fmt.Errorf("provided verifier provider is not a KMS verifier provider")
					}

					sp = kspv
				}
			}
		}

		s, err := sp.Verifier(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v verifier: %w", verifierProvider, err)
		}

		verifiers = append(verifiers, s)
	}

	return verifiers, nil
}
