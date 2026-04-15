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
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/spf13/cobra"
)

type VerifyOptions struct {
	ArchivistaOptions          ArchivistaOptions
	VerifierOptions            VerifierOptions
	KMSVerifierProviderOptions KMSVerifierProviderOptions
	SignerOptions              SignerOptions
	KMSSignerProviderOptions   KMSSignerProviderOptions
	KeyPath                    string
	AttestationFilePaths       []string
	PolicyFilePath             string
	ArtifactFilePath           string
	ArtifactDirectoryPath      string
	AdditionalSubjects         []string
	VSAOutFilePath             string
	VSATimestampServers        []string
	PolicyFulcioCertExtensions certificate.Extensions
	PolicyCARootPaths          []string
	PolicyCAIntermediatePaths  []string
	PolicyTimestampServers     []string
	PolicyCommonName           string
	PolicyDNSNames             []string
	PolicyEmails               []string
	PolicyOrganizations        []string
	PolicyURIs                 []string
}

func (vo *VerifyOptions) AddFlags(cmd *cobra.Command) {
	vo.VerifierOptions.AddFlags(cmd)
	vo.ArchivistaOptions.AddFlags(cmd)
	vo.KMSVerifierProviderOptions.AddFlags(cmd)
	// Register --publickey BEFORE signer flags so it claims the -k shorthand.
	// The signer registry adds --signer-file-key-path and, for backward compat
	// with `cilock sign`/`cilock run`, wants to bind -k — but here on verify,
	// -k has meant --publickey for the policy signer long before VSA signing
	// was added. addFlags() detects the collision and falls back to the long
	// form (--signer-file-key-path) when -k is already taken.
	cmd.Flags().StringVarP(&vo.KeyPath, "publickey", "k", "", "Path to the policy signer's public key")
	// Signer flags (mirroring cilock sign / cilock run) so the emitted VSA
	// can be signed via the same --signer-* providers (file, fulcio, kms, etc.)
	// when --vsa-outfile is set. Without a signer, the VSA is written as an
	// unsigned in-toto Statement JSON.
	vo.SignerOptions.AddFlags(cmd)
	vo.KMSSignerProviderOptions.AddFlags(cmd)
	cmd.Flags().StringVar(&vo.VSAOutFilePath, "vsa-outfile", "",
		"Write the Verification Summary Attestation (VSA) DSSE envelope to this path. Written on both pass and fail — downstream policies can still inspect a FAILED VSA. Requires signer flags for a signed DSSE; without a signer, emits the unsigned in-toto Statement JSON.")
	cmd.Flags().StringSliceVar(&vo.VSATimestampServers, "vsa-timestamp-servers", []string{},
		"Timestamp Authority Servers to use when signing the VSA envelope emitted via --vsa-outfile")
	cmd.Flags().StringSliceVarP(&vo.AttestationFilePaths, "attestations", "a", []string{}, "Attestation files to test against the policy")
	cmd.Flags().StringVarP(&vo.PolicyFilePath, "policy", "p", "", "Path to the policy to verify")
	cmd.Flags().StringVarP(&vo.ArtifactFilePath, "artifactfile", "f", "", "Path to the artifact subject to verify")
	cmd.Flags().StringVarP(&vo.ArtifactDirectoryPath, "directory-path", "", "", "Path to the directory subject to verify")
	cmd.Flags().StringSliceVarP(&vo.AdditionalSubjects, "subjects", "s", []string{}, "Additional subjects to lookup attestations")
	cmd.Flags().StringSliceVarP(&vo.PolicyCARootPaths, "policy-ca-roots", "", []string{}, "Paths to CA root certificates to use for verifying a policy signed with x.509")
	cmd.Flags().StringSliceVarP(&vo.PolicyCAIntermediatePaths, "policy-ca-intermediates", "", []string{}, "Paths to CA intermediate certificates to use for verifying a policy signed with x.509")
	cmd.Flags().StringSliceVarP(&vo.PolicyTimestampServers, "policy-timestamp-servers", "", []string{}, "Paths to the CA certificates for Timestamp Authority Servers to use when verifying policy signed with x.509")
	// Security: default to empty strings instead of wildcards so that x.509
	// certificate constraints are enforced by default. Wildcard defaults silently
	// accept any certificate matching the CA chain, bypassing intended identity
	// constraints. Users must explicitly opt into wildcards if desired.
	cmd.Flags().StringVar(&vo.PolicyCommonName, "policy-commonname", "", "The common name to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyDNSNames, "policy-dns-names", []string{}, "The DNS names to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyEmails, "policy-emails", []string{}, "The email addresses to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyOrganizations, "policy-organizations", []string{}, "The organizations to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyURIs, "policy-uris", []string{}, "The URIs to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVarP(&vo.PolicyCARootPaths, "policy-ca", "", []string{}, "Paths to CA certificates to use for verifying the policy (deprecated: use --policy-ca-roots instead)")

	// Fulcio cert extensions
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.Issuer, "policy-fulcio-oidc-issuer", "",
		"The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.")
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.BuildTrigger, "policy-fulcio-build-trigger", "",
		"Event or action that initiated the build.")
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.SourceRepositoryDigest, "policy-fulcio-source-repository-digest", "",
		"Immutable reference to a specific version of the source code that the build was based upon.")
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.RunInvocationURI, "policy-fulcio-run-invocation-uri", "",
		"Run Invocation URL to uniquely identify the build execution.")
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.SourceRepositoryIdentifier, "policy-fulcio-source-repository-identifier", "",
		"Immutable identifier for the source repository the workflow was based upon.")
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.SourceRepositoryRef, "policy-fulcio-source-repository-ref", "",
		"Source Repository Ref that the build run was based upon.")

	cmd.MarkFlagsRequiredTogether("policy")
	cmd.MarkFlagsOneRequired("publickey", "policy-ca", "policy-ca-roots", "policy-ca-intermediates", "verifier-kms-ref")
	cmd.MarkFlagsOneRequired("artifactfile", "subjects")
}
