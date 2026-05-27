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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/bundle"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
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
		Use:   "verify [artifact-path]",
		Short: "Verifies a witness policy",
		Long: "Verifies a policy provided key source and exits with code 0 if verification succeeds.\n\n" +
			"The artifact to verify may be given as a positional argument — `cilock verify ./app -p policy.json` —\n" +
			"as a shorthand for --artifactfile (a regular file) or --directory-path (a directory).",
		Example: `  # Verify a binary against a signed policy (positional artifact)
  cilock verify ./judge-api -p policy.json.signed --policy-ca-roots fulcio-root.pem

  # Verify a policy against local attestation files
  cilock verify -p policy.json -k policy-pub.pem -a build.att.json -a test.att.json

  # Verify a subject artifact, pulling evidence from Archivista
  cilock verify ./dist/app.tar.gz -p policy.json -k policy-pub.pem --enable-archivista

  # Fully offline verify from a bundle (no platform lookup)
  cilock verify -p policy.json -k policy-pub.pem --bundle evidence.tar.gz --platform-url ""`,
		Args:              cobra.MaximumNArgs(1),
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Lookup("policy-ca").Changed {
				log.Warn("The flag `--policy-ca` is deprecated and will be removed in a future release. Please use `--policy-ca-roots` and `--policy-ca-intermediates` instead.")
			}

			// Positional artifact path is shorthand for --artifactfile (file)
			// or --directory-path (directory). Explicit flags win; a positional
			// arg alongside a conflicting flag is a usage error.
			if len(args) == 1 {
				if vo.ArtifactFilePath != "" || vo.ArtifactDirectoryPath != "" {
					return fmt.Errorf("artifact given both positionally (%q) and via --artifactfile/--directory-path; use one", args[0])
				}
				info, statErr := os.Stat(args[0])
				switch {
				case statErr != nil:
					return fmt.Errorf("artifact path %q: %w", args[0], statErr)
				case info.IsDir():
					vo.ArtifactDirectoryPath = args[0]
				default:
					vo.ArtifactFilePath = args[0]
				}
			}

			// Resolve platform-derived defaults the same way `cilock run`
			// does so verify-side endpoint defaults match the run-side
			// of the workflow. `--platform-url ""` opts out for fully
			// offline verify.
			vo.ResolvePlatformDefaults(cmd)

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

			return runVerify(cmd.Context(), vo, verifiers, signers, signerIdentityPinnedByFlags(cmd))
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

func runVerify(ctx context.Context, vo options.VerifyOptions, verifiers []cryptoutil.Verifier, signers []cryptoutil.Signer, signerPinnedByFlags bool) error { //nolint:gocognit,gocyclo,funlen
	var (
		collectionSource source.Sourcer
		archivistaClient *archivista.Client
		archivistaRec    *source.RecordingSource
	)
	memSource := source.NewMemorySource()
	collectionSource = memSource

	if vo.ArchivistaOptions.Enable {
		var err error
		archivistaClient, err = vo.ArchivistaOptions.Client()
		if err != nil {
			return fmt.Errorf("failed to create archivista client: %w", err)
		}
		archivistaSrc := source.NewArchivistaSource(archivistaClient)
		if vo.OutputBundlePath != "" {
			archivistaRec = source.NewRecordingSource(archivistaSrc)
			collectionSource = source.NewMultiSource(collectionSource, archivistaRec)
		} else {
			collectionSource = source.NewMultiSource(collectionSource, archivistaSrc)
		}
	}

	// Embedded policy trust: roots + signer identity compiled into this cilock
	// build for verifying the POLICY signature only. Attestation trust always
	// comes from the policy itself, never from here.
	embTrust, err := embeddedtrust.Load()
	if err != nil {
		return fmt.Errorf("load embedded policy trust: %w", err)
	}
	var embFulcioRoots, embTSARoots []*x509.Certificate
	if embTrust != nil {
		if embFulcioRoots, err = embTrust.FulcioRoots(); err != nil {
			return err
		}
		if embTSARoots, err = embTrust.TSARoots(); err != nil {
			return err
		}
	}

	if vo.KeyPath == "" && len(vo.PolicyCARootPaths) == 0 && len(verifiers) == 0 && len(embFulcioRoots) == 0 {
		return fmt.Errorf("must supply a public key, CA certificates, a verifier, or a cilock built with embedded policy trust")
	}

	if !vo.ArchivistaOptions.Enable && len(vo.AttestationFilePaths) == 0 && len(vo.BundlePaths) == 0 {
		return fmt.Errorf("must specify attestation file paths, attestation bundles, or enable archivista as an attestation source")
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
	var tsaRootCerts []*x509.Certificate // tracked only so we can display them
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
			tsaRootCerts = append(tsaRootCerts, cert)
		}
	}

	// Fill any policy-trust dimension the operator did not pass on the command
	// line from embedded trust. Flags win wholesale per dimension; embedded
	// fills the gaps. Covers ONLY policy-signature trust — attestation trust is
	// untouched. Signer identity is applied ONLY when the operator set NO
	// signer-identity constraint at all (CN/DNS/email/org/URIs/Fulcio
	// extensions). Gating on --policy-uris alone would silently overwrite an
	// operator who pinned the signer via --policy-emails / --policy-fulcio-*
	// without --policy-uris, verifying under unintended trust.
	if embTrust != nil { //nolint:nestif // per-dimension flag-vs-embedded precedence (ca-roots / tsa-roots / signer-identity); flattening obscures which dimension wins
		applied := make([]string, 0, 3)
		if len(vo.PolicyCARootPaths) == 0 && len(embFulcioRoots) > 0 {
			policyRoots = append(policyRoots, embFulcioRoots...)
			applied = append(applied, "ca-roots")
		}
		if len(vo.PolicyTimestampServers) == 0 && len(embTSARoots) > 0 {
			for _, c := range embTSARoots {
				ptsVerifiers = append(ptsVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts([]*x509.Certificate{c})))
				tsaRootCerts = append(tsaRootCerts, c)
			}
			applied = append(applied, "timestamp-roots")
		}
		if !signerPinnedByFlags && len(embTrust.PolicySigners) > 0 {
			if len(embTrust.PolicySigners) > 1 {
				return fmt.Errorf("embedded trust defines %d policy signers; selecting among multiple embedded signers is not yet supported — pass --policy-uris / --policy-fulcio-* to choose", len(embTrust.PolicySigners))
			}
			cc := embTrust.PolicySigners[0].CertConstraint
			vo.PolicyCommonName = cc.CommonName
			vo.PolicyDNSNames = cc.DNSNames
			vo.PolicyEmails = cc.Emails
			vo.PolicyOrganizations = cc.Organizations
			vo.PolicyURIs = cc.URIs
			vo.PolicyFulcioCertExtensions = cc.Extensions
			applied = append(applied, "signer-identity")
		}
		if len(applied) > 0 {
			log.Infof("using embedded policy trust (%s); pass the corresponding --policy-* flags to override", strings.Join(applied, ", "))
		}
	}

	logPolicyTrust(policyRoots, tsaRootCerts, vo)

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

	var artifactFileDigestHex string
	if len(vo.ArtifactFilePath) > 0 {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact digest: %w", err)
		}

		artifactFileDigestHex = artifactDigestSet[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}]
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
		return buildNoSubjectError(vo)
	}

	// Track every envelope we explicitly load so --output-bundle can emit a
	// portable replay artifact at the end. Archivista-fetched envelopes are
	// captured separately via the RecordingSource wrapper above.
	var loadedEnvelopes []dsse.Envelope

	for _, path := range vo.AttestationFilePaths {
		env, err := loadEnvelopeFromFile(path)
		if err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
		if err := memSource.LoadEnvelope(path, env); err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
		loadedEnvelopes = append(loadedEnvelopes, env)
	}

	for _, path := range vo.BundlePaths {
		envs, err := loadEnvelopesFromBundle(path, memSource)
		if err != nil {
			return fmt.Errorf("failed to load bundle %q: %w", path, err)
		}
		loadedEnvelopes = append(loadedEnvelopes, envs...)
	}

	// Bridge a primary artifact (plain file digest) to a Merkle-tree product
	// collection so the collection matches by subject. Resolved from the
	// collection's inline leaves (default), a single-leaf reconstruct, or a
	// signed inclusion-proof envelope — whichever applies. Trust is still
	// enforced by the engine's downstream functionary/signature checks. See
	// expandSubjectsWithInclusionProofs for the CVE-2026-22703 / RFC 6962 notes.
	subjects = expandSubjectsWithInclusionProofs(subjects, loadedEnvelopes, vo.ArtifactFilePath, artifactFileDigestHex)

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
	if chainSrc := buildChainSidecarSource(vo); chainSrc != nil {
		verifyOpts = append(verifyOpts, workflow.VerifyWithChainSidecarSource(chainSrc))
	}
	if vo.RequireSidecar {
		verifyOpts = append(verifyOpts, workflow.VerifyWithRequireSidecar(true))
	}

	verifiedEvidence, verifyErr := workflow.Verify(ctx, policyEnvelope, verifiers, verifyOpts...)

	// Write the bundle BEFORE the VSA so a single verify can emit both even on
	// failure. Like the VSA, a bundle is useful on a FAILED verify — it lets
	// an operator replay the exact evidence set offline to triage why the
	// policy rejected it.
	if writeErr := maybeWriteOutputBundle(vo, subjects, loadedEnvelopes, archivistaRec); writeErr != nil {
		if verifyErr != nil {
			return fmt.Errorf("failed to verify policy: %w (additionally, failed to write output bundle: %v)", verifyErr, writeErr)
		}
		return fmt.Errorf("failed to write output bundle: %w", writeErr)
	}

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

// logPolicyTrust prints the trust anchors that will gate policy-signature
// verification — the CA root(s), timestamp root(s), and signer identity
// constraint — so an operator can see exactly what this run trusts, whether it
// came from --policy-* flags or from trust compiled into the binary. Trust
// should never be invisible.
func logPolicyTrust(policyRoots, tsaRootCerts []*x509.Certificate, vo options.VerifyOptions) {
	if len(policyRoots) == 0 && len(tsaRootCerts) == 0 && len(vo.PolicyURIs) == 0 {
		return // key-based verify with no x509 policy trust; nothing to show
	}
	log.Infof("policy trust anchors (%d CA root(s), %d timestamp root(s)):", len(policyRoots), len(tsaRootCerts))
	for _, c := range policyRoots {
		log.Infof("  policy CA root: %s [sha256:%s]", certSubject(c), certFingerprint(c))
	}
	for _, c := range tsaRootCerts {
		log.Infof("  policy timestamp root: %s [sha256:%s]", certSubject(c), certFingerprint(c))
	}
	ext := vo.PolicyFulcioCertExtensions
	log.Infof("  policy signer: uris=%v issuer=%q sourceRepositoryURI=%q buildConfigURI=%q",
		vo.PolicyURIs, ext.Issuer, ext.SourceRepositoryURI, ext.BuildConfigURI)
}

// signerIdentityFlags are the policy signer-identity flags. If the operator set
// ANY of them, embedded trust must NOT supply the signer identity (flags win).
var signerIdentityFlags = []string{
	"policy-commonname",
	"policy-dns-names",
	"policy-emails",
	"policy-organizations",
	"policy-uris",
	"policy-fulcio-oidc-issuer",
	"policy-fulcio-source-repository-uri",
	"policy-fulcio-build-config-uri",
	"policy-fulcio-runner-environment",
	"policy-fulcio-build-trigger",
	"policy-fulcio-source-repository-digest",
	"policy-fulcio-source-repository-identifier",
	"policy-fulcio-source-repository-ref",
	"policy-fulcio-run-invocation-uri",
}

// signerIdentityPinnedByFlags reports whether the operator explicitly set any
// policy signer-identity flag. Detection is by cobra's Changed (not by value)
// so a flag with a non-empty default — notably --policy-fulcio-oidc-issuer —
// is correctly recognized when set explicitly. When true, embedded trust must
// not overwrite the operator's signer constraint (flags override embedded).
func signerIdentityPinnedByFlags(cmd *cobra.Command) bool {
	for _, name := range signerIdentityFlags {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return true
		}
	}
	return false
}

func certSubject(c *x509.Certificate) string {
	if s := c.Subject.String(); s != "" {
		return s
	}
	return "(no subject)"
}

func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
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

// maybeWriteOutputBundle materialises --output-bundle when set, combining
// explicitly loaded envelopes with anything the Archivista RecordingSource
// captured during verify. Returns nil when --output-bundle is empty.
func maybeWriteOutputBundle(vo options.VerifyOptions, subjects []cryptoutil.DigestSet, loaded []dsse.Envelope, rec *source.RecordingSource) error {
	if vo.OutputBundlePath == "" {
		return nil
	}
	bundleSubjects := make([]string, 0, len(subjects))
	for _, ds := range subjects {
		for _, digest := range ds {
			bundleSubjects = append(bundleSubjects, digest)
		}
	}
	var archivistaEnvs []dsse.Envelope
	if rec != nil {
		archivistaEnvs = rec.Envelopes()
	}
	bundleSource := bundle.SourceFile
	if vo.ArchivistaOptions.Enable {
		bundleSource = bundle.SourceVerifyExport
	}
	return writeOutputBundle(vo.OutputBundlePath, bundleSubjects, bundleSource, vo.ArchivistaOptions.Url, loaded, archivistaEnvs)
}

// buildNoSubjectError returns the operator-facing error when verify is
// invoked without --artifactfile / --directory-path / --subjects. It
// best-effort scans any supplied --attestations / --bundle files for
// in-toto subjects and pastes the first few sha256 digests into the
// error message so the operator can copy them straight into --subjects
// without cracking the DSSE payload with jq.
//
// Black-box UX test follow-up: cobra's MarkFlagsOneRequired was firing
// before this code could run, so the helpful candidate-listing was
// invisible. The flag-group constraint has been removed in favour of
// this custom error.
func buildNoSubjectError(vo options.VerifyOptions) error {
	const baseMsg = "at least one subject is required (cilock verifies an attestation AGAINST an artifact — " +
		"the subject is the entry point into the attestation graph).\n" +
		"  Provide one of:\n" +
		"    --artifactfile <path>     hash the file you're verifying\n" +
		"    --directory-path <dir>    hash the directory you're verifying\n" +
		"    --subjects <sha256:hex>   pass a digest directly (repeatable)"

	candidates := candidateSubjectsFromEnvelopes(append([]string(nil), append(vo.AttestationFilePaths, vo.BundlePaths...)...))
	if len(candidates) == 0 {
		return fmt.Errorf("%s", baseMsg)
	}
	return fmt.Errorf("%s\n  Candidates found in the supplied envelope(s):\n    --subjects %s",
		baseMsg, strings.Join(candidates, "\n    --subjects "))
}

// candidateSubjectsFromEnvelopes scans the supplied attestation/bundle
// paths and returns up to 5 unique sha256 subject digests, prefixed
// with "sha256:" so they can be pasted directly into --subjects.
// Best-effort: unreadable paths are silently skipped (the caller falls
// back to the no-candidates error variant).
func candidateSubjectsFromEnvelopes(paths []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, path := range paths {
		envs, err := loadEnvelopesBestEffort(path)
		if err != nil {
			continue
		}
		for _, env := range envs {
			for s := range extractSubjectDigests(env) {
				key := "sha256:" + s
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, key)
				if len(out) >= 5 {
					return out
				}
			}
		}
	}
	return out
}

// loadEnvelopesBestEffort attempts to read DSSE envelopes from a path,
// trying first as a bundle (tar.gz) and falling back to a single
// envelope JSON. Returns nil + no error if neither shape parses —
// callers use this for hint-extraction and shouldn't treat unreadable
// inputs as fatal. Used by the no-subjects error path to surface
// candidate subjects to the operator without requiring jq surgery.
func loadEnvelopesBestEffort(path string) ([]dsse.Envelope, error) {
	if env, err := loadEnvelopeFromFile(path); err == nil && len(env.Payload) > 0 {
		return []dsse.Envelope{env}, nil
	}
	f, err := os.Open(path) //nolint:gosec // G304: path is from --attestations / --bundle CLI flag
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r, err := bundle.Read(f)
	if err != nil {
		return nil, err
	}
	envs, err := r.Envelopes()
	if err != nil {
		return nil, err
	}
	return envs, nil
}

// extractSubjectDigests pulls the set of sha256 subject digests from
// an envelope's in-toto payload. Returns an empty map if the payload
// isn't a Statement (e.g. raw VSA, predicate-only envelope) — same
// best-effort contract as loadEnvelopesBestEffort.
func extractSubjectDigests(env dsse.Envelope) map[string]struct{} {
	out := map[string]struct{}{}
	if len(env.Payload) == 0 {
		return out
	}
	var stmt struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return out
	}
	for _, s := range stmt.Subject {
		if h, ok := s.Digest["sha256"]; ok && h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

// loadEnvelopeFromFile reads a DSSE envelope from path. Used by verify in
// preference to source.MemorySource.LoadFile when we also need the raw
// envelope (for --output-bundle accounting).
func loadEnvelopeFromFile(path string) (dsse.Envelope, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is from --attestations CLI flag
	if err != nil {
		return dsse.Envelope{}, err
	}
	var env dsse.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return dsse.Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	return env, nil
}

// loadEnvelopesFromBundle decompresses a cilock bundle from path, loads every
// envelope into memSource using a synthetic reference, and returns the slice
// for --output-bundle accounting.
func loadEnvelopesFromBundle(path string, memSource *source.MemorySource) ([]dsse.Envelope, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is from --bundle CLI flag
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	r, err := bundle.Read(f)
	if err != nil {
		return nil, err
	}
	envs, err := r.Envelopes()
	if err != nil {
		return nil, err
	}

	for i, env := range envs {
		ref := fmt.Sprintf("%s#%d", path, i)
		if err := memSource.LoadEnvelope(ref, env); err != nil {
			if _, dup := err.(source.ErrDuplicateReference); dup {
				continue
			}
			// A bundle may contain non-collection envelopes (raw VSA,
			// SLSA provenance, inclusion-proof) that envelopeToCollectionEnvelope
			// rejects. Skip — the policy engine picks them up via
			// SearchByPredicateType.
			log.Debugf("bundle %s: skipping envelope %d: %v", path, i, err)
			continue
		}
	}
	return envs, nil
}

// writeOutputBundle assembles the loaded explicit + Archivista-fetched
// envelopes into a single tar.gz bundle at path. Source/sourceURL are
// recorded in the manifest for downstream forensics.
func writeOutputBundle(path string, subjects []string, sourceKind, sourceURL string, loaded, archivistaFetched []dsse.Envelope) error {
	f, err := os.Create(path) //nolint:gosec // G304: path is from --output-bundle CLI flag
	if err != nil {
		return fmt.Errorf("create bundle file: %w", err)
	}

	w := bundle.NewWriter(f)
	w.SetSource(sourceKind, sourceURL)
	w.SetSubjects(subjects)

	for _, env := range loaded {
		if err := w.Add(env); err != nil {
			_ = f.Close()
			return fmt.Errorf("add loaded envelope: %w", err)
		}
	}
	for _, env := range archivistaFetched {
		if err := w.Add(env); err != nil {
			_ = f.Close()
			return fmt.Errorf("add archivista envelope: %w", err)
		}
	}

	if err := w.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("close bundle: %w", err)
	}
	return f.Close()
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
