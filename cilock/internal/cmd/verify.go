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
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/cilock/internal/policy"
	"github.com/spf13/cobra"
)

func VerifyCmd() *cobra.Command {
	vo := options.VerifyOptions{
		ArchivistaOptions:          options.ArchivistaOptions{},
		KMSVerifierProviderOptions: options.KMSVerifierProviderOptions{},
		VerifierOptions:            options.VerifierOptions{},
	}
	cmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies a witness policy",
		Long:              "Verifies a policy provided key source and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Lookup("policy-ca").Changed {
				log.Warn("The flag `--policy-ca` is deprecated and will be removed in a future release. Please use `--policy-ca-root` and `--policy-ca-intermediate` instead.")
			}

			verifiers, err := loadVerifiers(cmd.Context(), vo.VerifierOptions, vo.KMSVerifierProviderOptions, providersFromFlags("verifier", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signer: %w", err)
			}
			return runVerify(cmd.Context(), vo, verifiers...)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

func runVerify(ctx context.Context, vo options.VerifyOptions, verifiers ...cryptoutil.Verifier) error {
	memSource := source.NewMemorySource()
	var collectionSource source.Sourcer = memSource

	if vo.ArchivistaOptions.Enable {
		return fmt.Errorf("archivista integration is not yet supported in cilock; use --attestations flag to provide attestation files directly")
	}

	if vo.KeyPath == "" && len(vo.PolicyCARootPaths) == 0 && len(verifiers) == 0 {
		return fmt.Errorf("must supply either a public key, CA certificates or a verifier")
	}

	if !vo.ArchivistaOptions.Enable && len(vo.AttestationFilePaths) == 0 {
		return fmt.Errorf("must either specify attestation file paths or enable archivista as an attestation source")
	}

	if vo.KeyPath != "" {
		keyFile, err := os.Open(vo.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to open key file: %w", err)
		}

		defer func() {
			if err := keyFile.Close(); err != nil {
				log.Errorf("failed to close key file: %v", err)
			}
		}()

		v, err := cryptoutil.NewVerifierFromReader(keyFile)
		if err != nil {
			return fmt.Errorf("failed to create verifier: %w", err)
		}

		verifiers = append(verifiers, v)
	}

	var policyRoots []*x509.Certificate
	if len(vo.PolicyCARootPaths) > 0 {
		for _, caPath := range vo.PolicyCARootPaths {
			caFile, err := os.ReadFile(caPath)
			if err != nil {
				return fmt.Errorf("failed to read root CA certificate file: %w", err)
			}

			cert, err := cryptoutil.TryParseCertificate(caFile)
			if err != nil {
				return fmt.Errorf("failed to parse root CA certificate: %w", err)
			}

			policyRoots = append(policyRoots, cert)
		}
	}

	var policyIntermediates []*x509.Certificate
	if len(vo.PolicyCAIntermediatePaths) > 0 {
		for _, caPath := range vo.PolicyCAIntermediatePaths {
			caFile, err := os.ReadFile(caPath)
			if err != nil {
				return fmt.Errorf("failed to read intermediate CA certificate file: %w", err)
			}

			cert, err := cryptoutil.TryParseCertificate(caFile)
			if err != nil {
				return fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
			}

			policyIntermediates = append(policyIntermediates, cert)
		}
	}

	ptsVerifiers := make([]timestamp.TimestampVerifier, 0)
	if len(vo.PolicyTimestampServers) > 0 {
		for _, server := range vo.PolicyTimestampServers {
			f, err := os.ReadFile(server)
			if err != nil {
				return fmt.Errorf("failed to open Timestamp Server CA certificate file: %w", err)
			}

			cert, err := cryptoutil.TryParseCertificate(f)
			if err != nil {
				return fmt.Errorf("failed to parse Timestamp Server CA certificate: %w", err)
			}

			ptsVerifiers = append(ptsVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts([]*x509.Certificate{cert})))
		}
	}

	policyEnvelope, err := policy.LoadPolicy(ctx, vo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open policy file: %w", err)
	}

	subjects := []cryptoutil.DigestSet{}
	if len(vo.ArtifactDirectoryPath) > 0 {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromDir(vo.ArtifactDirectoryPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if err != nil {
			return fmt.Errorf("failed to calculate dir digest: %w", err)
		}

		subjects = append(subjects, artifactDigestSet)
	}

	if len(vo.ArtifactFilePath) > 0 {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact digest: %w", err)
		}

		subjects = append(subjects, artifactDigestSet)
	}

	for _, subDigest := range vo.AdditionalSubjects {
		subjects = append(subjects, cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: subDigest})
	}

	if len(subjects) == 0 {
		return errors.New("at least one subject is required, provide an artifact file or subject")
	}

	for _, path := range vo.AttestationFilePaths {
		if err := memSource.LoadFile(path); err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
	}

	verifiedEvidence, err := workflow.Verify(
		ctx,
		policyEnvelope,
		verifiers,
		workflow.VerifyWithSubjectDigests(subjects),
		workflow.VerifyWithCollectionSource(collectionSource),
		workflow.VerifyWithPolicyTimestampAuthorities(ptsVerifiers),
		workflow.VerifyWithPolicyCARoots(policyRoots),
		workflow.VerifyWithPolicyCAIntermediates(policyIntermediates),
		workflow.VerifyWithPolicyCertConstraints(vo.PolicyCommonName, vo.PolicyDNSNames, vo.PolicyEmails, vo.PolicyOrganizations, vo.PolicyURIs),
		workflow.VerifyWithPolicyFulcioCertExtensions(vo.PolicyFulcioCertExtensions),
	)
	if err != nil {
		if verifiedEvidence.StepResults != nil {
			log.Error("Verification failed")
			log.Error("Evidence:")
			for step, result := range verifiedEvidence.StepResults {
				log.Error("Step: ", step)
				if len(result.Passed) > 0 {
					log.Infof("Passed with evidence: %s", result.Passed[0].Collection.Reference)
					continue
				}
				for _, p := range result.Rejected {
					if p.Collection.Collection.Name != "" {
						log.Errorf("collection rejected: %s, Reason: %s ", p.Collection.Collection.Name, p.Reason)
					} else {
						log.Errorf("verification failure: Reason: %s", p.Reason)
					}
				}
			}
		}
		return fmt.Errorf("failed to verify policy: %w", err)
	}

	log.Info("Verification succeeded")
	log.Info("Evidence:")
	num := 0
	for step, result := range verifiedEvidence.StepResults {
		log.Info("Step: ", step)
		for _, p := range result.Passed {
			log.Info(fmt.Sprintf("%d: %s", num, p.Collection.Reference))
			num++
		}
	}
	return nil
}
