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
	"time"

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
	BundlePaths                []string
	OutputBundlePath           string
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

	// ChainSidecarDir is a local directory containing chain-of-custody
	// sidecars (one per downstream step, named <step>.chain.json). When
	// set, the verifier installs a FilesystemChainSidecarSource and
	// prefers per-material RFC 6962 inclusion-proof verification over
	// the legacy path-by-path artifact comparison for any
	// ArtifactsFrom edge that has a matching sidecar. Empty disables.
	ChainSidecarDir string

	// ChainSidecarURL is an HTTP(S) URL template used to fetch chain
	// sidecars by upstream envelope digest. Placeholders:
	// {envelopeDigest}, {downstreamStep}, {upstreamStep}. When both
	// ChainSidecarDir and ChainSidecarURL are set, the filesystem
	// source is tried first; HTTP is the fallback.
	ChainSidecarURL string

	// RequireSidecar fails verification if a chain edge has an
	// upstream step but no matching chain sidecar is available. The
	// CLI flag defaults to TRUE for v0.4 — closing the vacuous-pass
	// attack surface where v0.3 attestations return empty
	// Materials() and the legacy compareArtifacts fallback trivially
	// passes. Users verifying legacy v0.1 chains can opt out via
	// `--require-sidecar=false`.
	//
	// Note: the Go struct's zero value is false; the flag default
	// in AddFlags is true. Callers constructing VerifyOptions
	// directly (without going through the CLI flag layer) must set
	// this explicitly if strict mode is desired.
	RequireSidecar bool

	// ChainSidecarHTTPTimeout overrides the per-request HTTP client
	// timeout used by the chain sidecar HTTP source. Defaults to
	// policy.DefaultHTTPChainSidecarTimeout (30s). Increase for very
	// large sidecars on cold caches; decrease in latency-sensitive
	// pipelines.
	ChainSidecarHTTPTimeout time.Duration

	// ChainSidecarHTTPMaxBytes caps the HTTP response body the
	// verifier will read from a chain sidecar server. Defaults to
	// policy.DefaultHTTPChainSidecarMaxBytes (64 MiB). Tune up for
	// builds with very large material sets; tune down to harden
	// against hostile servers.
	ChainSidecarHTTPMaxBytes int64
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
	cmd.Flags().StringSliceVar(&vo.BundlePaths, "bundle", []string{},
		"Attestation bundle file(s) to load envelopes from (tar.gz format produced by `cilock bundle create` or `--output-bundle`). Combines additively with --attestations and Archivista lookups.")
	cmd.Flags().StringVar(&vo.OutputBundlePath, "output-bundle", "",
		"After verify, write every envelope that was loaded (--attestations + --bundle + Archivista) to this path as a tar.gz bundle. Produces a portable evidence package for offline re-verify.")
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

	// v0.3 chain-of-custody verification.
	cmd.Flags().StringVar(&vo.ChainSidecarDir, "chain-sidecar-dir", "",
		"Directory containing chain-of-custody sidecars (one per downstream step, named <step>.chain.json). When set, the verifier validates ArtifactsFrom edges via per-material RFC 6962 inclusion proofs against the upstream step's signed Merkle root instead of the legacy path-by-path comparison.")
	cmd.Flags().StringVar(&vo.ChainSidecarURL, "chain-sidecar-url", "",
		"HTTP(S) URL template for fetching chain sidecars by upstream envelope digest. Placeholders: {envelopeDigest}, {downstreamStep}, {upstreamStep}. When both --chain-sidecar-dir and --chain-sidecar-url are set, the filesystem source is tried first.")
	cmd.Flags().BoolVar(&vo.RequireSidecar, "require-sidecar", true,
		"Strict-chain mode: fail verification if a chain edge has no matching chain sidecar (closes the v0.3 vacuous-pass attack surface). DEFAULT TRUE in v0.4. Pass --require-sidecar=false to verify legacy v0.1 chains without sidecars.")
	cmd.Flags().DurationVar(&vo.ChainSidecarHTTPTimeout, "chain-sidecar-http-timeout", 0,
		"Per-request HTTP client timeout for chain-sidecar fetches (Go duration format, e.g. 15s, 2m). "+
			"Zero (default) uses the compiled-in DefaultHTTPChainSidecarTimeout (30s). Increase for very large "+
			"sidecars on cold caches; decrease in latency-sensitive pipelines.")
	cmd.Flags().Int64Var(&vo.ChainSidecarHTTPMaxBytes, "chain-sidecar-http-max-bytes", 0,
		"Cap on the HTTP response body size when fetching a chain sidecar (raw bytes). "+
			"Zero (default) uses the compiled-in DefaultHTTPChainSidecarMaxBytes (64 MiB ≈ 67108864). "+
			"Tune up for builds with very large material sets; tune down to harden against hostile servers.")

	cmd.MarkFlagsRequiredTogether("policy")
	cmd.MarkFlagsOneRequired("publickey", "policy-ca", "policy-ca-roots", "policy-ca-intermediates", "verifier-kms-ref")
	cmd.MarkFlagsOneRequired("artifactfile", "subjects")
}
