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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/slsa"
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
		SignerOptions:              options.SignerOptions{},
		KMSSignerProviderOptions:   options.KMSSignerProviderOptions{},
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
				return fmt.Errorf("failed to load verifier: %w", err)
			}

			// Signers are optional on `verify` — they are only used to sign the
			// VSA emitted via --vsa-outfile. If no --signer-* flags were set we
			// skip loading entirely and the VSA (if requested) will be written
			// as an unsigned in-toto Statement.
			var signers []cryptoutil.Signer
			signerProviders := providersFromFlags("signer", cmd.Flags())
			if len(signerProviders) > 0 {
				signers, err = loadSigners(cmd.Context(), vo.SignerOptions, vo.KMSSignerProviderOptions, signerProviders)
				if err != nil {
					return fmt.Errorf("failed to load signer: %w", err)
				}
			}

			return runVerify(cmd.Context(), vo, verifiers, signers)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

func runVerify(ctx context.Context, vo options.VerifyOptions, verifiers []cryptoutil.Verifier, signers []cryptoutil.Signer) error { //nolint:gocognit,gocyclo,funlen
	var (
		collectionSource source.Sourcer
		archivistaClient *archivista.Client
	)
	memSource := source.NewMemorySource()
	collectionSource = memSource

	if vo.ArchivistaOptions.Enable {
		var err error
		archivistaClient, err = vo.ArchivistaOptions.Client()
		if err != nil {
			return fmt.Errorf("failed to create archivista client: %w", err)
		}
		collectionSource = source.NewMultiSource(collectionSource, source.NewArchivistaSource(archivistaClient))
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
			caFile, err := os.ReadFile(caPath) //nolint:gosec // G304: caPath is from CLI flags
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
			caFile, err := os.ReadFile(caPath) //nolint:gosec // G304: caPath is from CLI flags
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
			f, err := os.ReadFile(server) //nolint:gosec // G304: server path is from CLI flags
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

	policyEnvelope, err := policy.LoadPolicy(ctx, vo.PolicyFilePath, archivistaClient)
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
		// Security: validate that subject digests look like hex-encoded hashes.
		// Accepting arbitrary strings could cause false positive or negative
		// matches against artifact digest sets during policy verification.
		if !isValidHexDigest(subDigest) {
			return fmt.Errorf("invalid subject digest %q: must be a hex-encoded hash (e.g. sha256:abc123...)", subDigest)
		}
		// Strip optional algorithm prefix (e.g. "sha256:") before storing.
		// The prefix is accepted by isValidHexDigest for convenience, but DigestSet
		// values must be raw hex to match computed digests from CalculateDigestSet.
		digestHex := subDigest
		if idx := strings.Index(subDigest, ":"); idx != -1 {
			digestHex = subDigest[idx+1:]
		}
		subjects = append(subjects, cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: digestHex})
	}

	if len(subjects) == 0 {
		return errors.New("at least one subject is required, provide an artifact file or subject")
	}

	for _, path := range vo.AttestationFilePaths {
		if err := memSource.LoadFile(path); err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
	}

	verifyOpts := []workflow.VerifyOption{
		workflow.VerifyWithSubjectDigests(subjects),
		workflow.VerifyWithCollectionSource(collectionSource),
		workflow.VerifyWithPolicyTimestampAuthorities(ptsVerifiers),
		workflow.VerifyWithPolicyCARoots(policyRoots),
		workflow.VerifyWithPolicyCAIntermediates(policyIntermediates),
		workflow.VerifyWithPolicyCertConstraints(vo.PolicyCommonName, vo.PolicyDNSNames, vo.PolicyEmails, vo.PolicyOrganizations, vo.PolicyURIs),
		workflow.VerifyWithPolicyFulcioCertExtensions(vo.PolicyFulcioCertExtensions),
	}
	if len(signers) > 0 {
		verifyOpts = append(verifyOpts, workflow.VerifyWithSigners(signers...))
	}

	verifiedEvidence, verifyErr := workflow.Verify(ctx, policyEnvelope, verifiers, verifyOpts...)

	// Write the VSA to disk BEFORE returning — on both pass and fail. A failed
	// VSA is still valuable diagnostic evidence and can legitimately be the
	// input to a downstream policy that must know the previous stage failed.
	if vo.VSAOutFilePath != "" {
		if writeErr := writeVSAOutfile(vo.VSAOutFilePath, verifiedEvidence, signers, vo.VSATimestampServers); writeErr != nil {
			// Prefer reporting the verification failure (the more important
			// signal) but always surface the write failure as well so it is
			// never silently swallowed.
			if verifyErr != nil {
				return fmt.Errorf("failed to verify policy: %w (additionally, failed to write VSA outfile: %v)", verifyErr, writeErr)
			}
			return fmt.Errorf("failed to write VSA outfile: %w", writeErr)
		}
	}

	if verifyErr != nil { //nolint:nestif
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
		return fmt.Errorf("failed to verify policy: %w", verifyErr)
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

// writeVSAOutfile writes the Verification Summary Attestation to disk.
//
// When signers are supplied, it signs the VSA as a DSSE envelope (same format
// stored in Archivista). Without signers, it emits an unsigned in-toto
// Statement JSON — still consumable by downstream policies that don't require
// a functionary-signed VSA, but logged with a warning so users know chaining
// policies that require signatures will reject it.
//
// A failed VSA is legitimately useful — policies may want to inspect that a
// previous verification FAILED — so this function writes regardless of
// verification outcome.
func writeVSAOutfile(path string, evidence workflow.VerifyResult, signers []cryptoutil.Signer, timestampServers []string) error {
	subjects := map[string]cryptoutil.DigestSet{}
	for _, sub := range evidence.VerificationSummary.InputAttestations {
		if sub.URI == "" || len(sub.Digest) == 0 {
			continue
		}
		subjects[sub.URI] = sub.Digest
	}

	predicateBytes, err := json.Marshal(evidence.VerificationSummary)
	if err != nil {
		return fmt.Errorf("failed to marshal VSA predicate: %w", err)
	}

	if len(signers) == 0 {
		log.Warn("VSA written without a signer — downstream policies that require a functionary-signed VSA will reject this file. Pass --signer-* flags to produce a signed DSSE envelope.")
		stmt, sErr := intoto.NewStatement(slsa.VerificationSummaryPredicate, predicateBytes, subjects)
		if sErr != nil {
			return fmt.Errorf("failed to build unsigned VSA statement: %w", sErr)
		}
		stmtBytes, sErr := json.Marshal(stmt)
		if sErr != nil {
			return fmt.Errorf("failed to marshal unsigned VSA statement: %w", sErr)
		}
		if wErr := os.WriteFile(path, stmtBytes, 0o600); wErr != nil { //nolint:gosec // G304/G703: path is from --vsa-outfile CLI flag
			return fmt.Errorf("failed to write VSA outfile: %w", wErr)
		}
		return nil
	}

	timestampers := make([]timestamp.Timestamper, 0, len(timestampServers))
	for _, url := range timestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	stmt, err := intoto.NewStatement(slsa.VerificationSummaryPredicate, predicateBytes, subjects)
	if err != nil {
		return fmt.Errorf("failed to build VSA statement: %w", err)
	}
	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		return fmt.Errorf("failed to marshal VSA statement: %w", err)
	}
	envelope, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(stmtBytes),
		dsse.SignWithSigners(signers...),
		dsse.SignWithTimestampers(timestampers...),
	)
	if err != nil {
		return fmt.Errorf("failed to sign VSA envelope: %w", err)
	}
	envBytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal VSA envelope: %w", err)
	}
	if err := os.WriteFile(path, envBytes, 0o600); err != nil { //nolint:gosec // G304/G703: path is from --vsa-outfile CLI flag
		return fmt.Errorf("failed to write VSA outfile: %w", err)
	}
	return nil
}

// isValidHexDigest checks whether s looks like a hex-encoded digest, optionally
// prefixed with an algorithm (e.g. "sha256:abcdef0123456789..."). This is a
// lenient check—it accepts any even-length hex string of at least 32 characters
// (128 bits), with or without an algorithm prefix.
func isValidHexDigest(s string) bool {
	hex := s
	if idx := strings.Index(s, ":"); idx != -1 {
		hex = s[idx+1:]
	}
	if len(hex) < 32 || len(hex)%2 != 0 {
		return false
	}
	for _, c := range hex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
