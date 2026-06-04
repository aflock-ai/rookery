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
	"os"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/spf13/cobra"
)

type VerifyOptions struct {
	ArchivistaOptions          ArchivistaOptions
	VerifierOptions            VerifierOptions
	KMSVerifierProviderOptions KMSVerifierProviderOptions
	SignerOptions              SignerOptions
	KMSSignerProviderOptions   KMSSignerProviderOptions
	// PlatformURL derives archivista + TSA URLs the same way `cilock
	// run` does, so the verify-side of a cilock workflow uses the
	// same endpoint defaults the run-side wrote to. Pass `--platform-url ""`
	// to opt out (fully offline verification — no archivista lookup,
	// no platform-derived TSA verifier).
	PlatformURL                string
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
	// PolicyCARootsPEM holds CA root certificates discovered from the platform
	// (the inlined trust bundle in /.well-known/judge-configuration), as raw
	// PEM. It supplements PolicyCARootPaths so a logged-in `cilock verify` trusts
	// the platform's keyless signing CA without the user passing a CA file. The
	// cli layer parses it the same way it parses --policy-ca-roots files. Empty
	// when discovery is unavailable or --platform-url "" opted out.
	PolicyCARootsPEM       []byte
	PolicyTimestampServers []string
	PolicyCommonName       string
	PolicyDNSNames         []string
	PolicyEmails           []string
	PolicyOrganizations    []string
	PolicyURIs             []string

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

	// RequireSidecar enables strict-chain mode: a chain edge with an
	// upstream step must be backed by EITHER a matching chain sidecar
	// OR verified inline Merkle leaves (the v0.4 default — product and
	// material attestors embed their per-file leaves in the signed
	// predicate, so the engine rehydrates real Materials()/Products(),
	// confirms they reconstruct to the signed root, and compares).
	// Strict mode only fails closed when an edge has NEITHER — i.e. a
	// leaf-less v0.3 collection with no sidecar, the vacuous-pass attack
	// surface where empty Materials() made compareArtifacts pass
	// trivially. The CLI flag defaults to TRUE for v0.4. Users verifying
	// legacy v0.1 / leaf-less v0.3 chains without either proof can opt
	// out via `--require-sidecar=false`.
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

	// OutputFormat selects how the verify verdict is reported. "text"
	// (default) prints the human-readable evidence + binding line to
	// stderr. "json" additionally emits a single machine-readable verdict
	// object {passed, step, matchedSubject, slsaLevel?} to stdout so a CI
	// gate can branch without parsing logr prose. Set via --format / -o json.
	OutputFormat string

	// Offline is a clear alias for --platform-url "": fully offline verify
	// (no Archivista lookup, no discovery, no platform-derived TSA). Mirrors
	// RunOptions.Offline so the run and verify sides share one opt-out idiom.
	Offline bool
}

// OutputJSON reports whether the verify verdict should be emitted as a
// structured JSON object on stdout (set via --format json or -o json).
func (vo *VerifyOptions) OutputJSON() bool {
	return strings.EqualFold(vo.OutputFormat, "json")
}

// ResolvePlatformDefaults derives verification trust from the configured
// --platform-url so a logged-in `cilock verify` needs no CA files or issuer
// flags. It mirrors RunOptions's resolution for the verify subset and, beyond
// the Archivista URL, fetches the platform discovery document
// (/.well-known/judge-configuration) and — only where the operator did NOT set
// the corresponding flag — derives:
//   - the policy-signer CA roots, from the inlined trust bundle (PolicyCARootsPEM);
//   - the policy-signer Fulcio OIDC issuer (PolicyFulcioCertExtensions.Issuer);
//   - the expected signer email, from the stored login session (PolicyEmails).
//
// Every derived value is overridable: an explicit --policy-ca-roots /
// --policy-fulcio-oidc-issuer / --policy-emails always wins. Pass --platform-url ""
// to opt out entirely (fully offline verify; operator supplies the files).
// Discovery is best-effort: a fetch failure leaves the explicit-flag behavior
// untouched. Call after flag parsing, before any verify logic runs.
//
// Note: unlike `cilock run`, we do NOT auto-populate PolicyTimestampServers —
// verify's PolicyTimestampServers expects file paths to CA cert bundles, not
// URLs; embedded-trust / discovery TSA roots are applied in the cli layer.
func (vo *VerifyOptions) ResolvePlatformDefaults(cmd *cobra.Command) { //nolint:gocyclo,gocognit // login-gated discovery + archivista + trust-derivation branches; each is a distinct, intentional resolution path and sits just over the threshold.
	// --offline is a clear alias for --platform-url "": clear the platform URL
	// so the explicit-disable path takes over (no Archivista/discovery/TSA).
	if vo.Offline {
		vo.PlatformURL = ""
	}
	platformExplicitlyDisabled := (cmd.Flags().Changed("platform-url") || vo.Offline) && vo.PlatformURL == ""
	if platformExplicitlyDisabled {
		return
	}
	pc := platformconfig.Derive(vo.PlatformURL)
	// Attribute telemetry to this logged-in platform session (CILOCK_PLATFORM_URL)
	// so `cilock verify --platform-url X` is recorded against platform X, not the
	// compiled-in default. Mirrors RunOptions; only set when a credential exists.
	if cred, lookupErr := auth.Lookup(vo.PlatformURL); lookupErr == nil && cred != nil {
		_ = os.Setenv(platformconfig.PlatformURLEnv, auth.NormalizeURL(vo.PlatformURL))
	}
	// Archivista URL: use platform default if not explicitly overridden.
	if !cmd.Flags().Changed("archivista-server") && !cmd.Flags().Changed("archivist-server") {
		vo.ArchivistaOptions.Url = pc.Archivista
	}

	// Verification trust (CA roots, OIDC issuer, expected signer) is derived ONLY
	// for a platform the operator has actually logged in to. Without a session we
	// stop here — an unauthenticated verify must supply explicit --policy-ca-roots
	// / --policy-fulcio-oidc-issuer rather than trust whatever a (possibly
	// attacker-controlled) --platform-url advertises. The Archivista URL derived
	// above is not trust-sensitive: it only says WHERE to fetch evidence; the
	// signatures are still checked against explicit/embedded/discovered roots.
	cred, _ := auth.Lookup(vo.PlatformURL)
	if cred == nil {
		return
	}

	// Default the expected signer email to the session identity, so a user
	// verifying their own org's policy doesn't restate it.
	if len(vo.PolicyEmails) == 0 && cred.Email != "" {
		vo.PolicyEmails = []string{cred.Email}
	}
	// Enable Archivista by default when logged in (only defaulted, never
	// overriding an explicit choice), and attach the session bearer for
	// authenticated reads — origin-guarded so the platform token never travels to
	// a third-party --archivista-server. Opt out with --enable-archivista=false.
	if !cmd.Flags().Changed("enable-archivista") && !cmd.Flags().Changed("enable-archivist") {
		vo.ArchivistaOptions.Enable = true
	}
	if !hasAuthorizationHeader(vo.ArchivistaOptions.Headers) && sameOrigin(vo.ArchivistaOptions.Url, pc.Archivista) {
		vo.ArchivistaOptions.Headers = append(vo.ArchivistaOptions.Headers, "Authorization: Bearer "+cred.Token)
	}

	// Fetch discovery and derive the policy-signer trust material. Discover itself
	// refuses non-https (except loopback), so trust is never sourced over
	// plaintext. Best-effort: on any failure the explicit-flag / embedded-trust
	// paths in the cli layer still apply.
	disc, err := platformconfig.Discover(vo.PlatformURL)
	if err != nil || disc == nil || disc.Signing == nil {
		return
	}
	if len(vo.PolicyCARootPaths) == 0 && len(vo.PolicyCARootsPEM) == 0 && disc.Signing.TrustBundlePEM != "" {
		vo.PolicyCARootsPEM = []byte(disc.Signing.TrustBundlePEM)
	}
	if !cmd.Flags().Changed("policy-fulcio-oidc-issuer") && disc.Signing.FulcioOIDCIssuer != "" {
		vo.PolicyFulcioCertExtensions.Issuer = disc.Signing.FulcioOIDCIssuer
	}
}

//nolint:funlen // each verify flag carries its own multi-line help text; splitting the registration loses readability
func (vo *VerifyOptions) AddFlags(cmd *cobra.Command) {
	vo.VerifierOptions.AddFlags(cmd)
	vo.ArchivistaOptions.AddFlags(cmd)
	vo.KMSVerifierProviderOptions.AddFlags(cmd)
	cmd.Flags().StringVar(&vo.PlatformURL, "platform-url", platformconfig.DefaultPlatformURL,
		"TestifySec platform URL (derives archivista + TSA URLs the same way `cilock run` does). "+
			"Pass --platform-url \"\" to opt out (fully offline verify — no archivista lookup, "+
			"no platform-derived TSA verifier).")
	cmd.Flags().BoolVar(&vo.Offline, "offline", false,
		"Fully offline verify — a clear alias for --platform-url \"\". No Archivista lookup, no platform "+
			"discovery, no platform-derived TSA verifier; trust comes only from --policy-* flags or embedded trust.")
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
	// Deprecated alias retained for backward compatibility but hidden from
	// help to declutter the flag set — --policy-ca-roots is the supported flag.
	_ = cmd.Flags().MarkHidden("policy-ca")

	// Fulcio cert extensions.
	// Default the OIDC issuer to GitHub Actions: keyless policies in this
	// project are signed by the release workflow's GHA OIDC token, so this
	// is the overwhelmingly common case. It fails closed for other issuers
	// (a mismatching issuer is rejected) — override explicitly for non-GHA
	// keyless flows.
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.Issuer, "policy-fulcio-oidc-issuer", "https://token.actions.githubusercontent.com",
		"The OIDC issuer expected in a valid Fulcio certificate (default: GitHub Actions). Override for non-GHA keyless flows, e.g. https://oauth2.sigstore.dev/auth.")
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
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.SourceRepositoryURI, "policy-fulcio-source-repository-uri", "",
		"Source repository URI the policy signer's build was based upon (glob-matched). The stable way to pin a keyless policy signer to a repo, e.g. https://github.com/testifysec/judge — unlike the cert SAN URI, which embeds the per-run ref and changes every release.")
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.BuildConfigURI, "policy-fulcio-build-config-uri", "",
		"Build config (workflow) URI of the policy signer (glob-matched), e.g. https://github.com/testifysec/judge/.github/workflows/release.yml@* — pins WHICH workflow may sign a trusted policy without pinning the changing ref.")
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.RunnerEnvironment, "policy-fulcio-runner-environment", "",
		"Runner environment of the policy signer (glob-matched), e.g. github-hosted or self-hosted.")

	// v0.3 chain-of-custody verification.
	cmd.Flags().StringVar(&vo.ChainSidecarDir, "chain-sidecar-dir", "",
		"Directory containing chain-of-custody sidecars (one per downstream step, named <step>.chain.json). When set, the verifier validates ArtifactsFrom edges via per-material RFC 6962 inclusion proofs against the upstream step's signed Merkle root instead of the legacy path-by-path comparison.")
	cmd.Flags().StringVar(&vo.ChainSidecarURL, "chain-sidecar-url", "",
		"HTTP(S) URL template for fetching chain sidecars by upstream envelope digest. Placeholders: {envelopeDigest}, {downstreamStep}, {upstreamStep}. When both --chain-sidecar-dir and --chain-sidecar-url are set, the filesystem source is tried first.")
	cmd.Flags().BoolVar(&vo.RequireSidecar, "require-sidecar", true,
		"Strict-chain mode: every artifactsFrom edge must be backed by verified inline Merkle leaves (the v0.4 default) or a chain sidecar; fails closed only when an edge has neither (closes the v0.3 vacuous-pass attack surface). DEFAULT TRUE. Pass --require-sidecar=false to verify legacy chains lacking both.")
	cmd.Flags().DurationVar(&vo.ChainSidecarHTTPTimeout, "chain-sidecar-http-timeout", 0,
		"Per-request HTTP client timeout for chain-sidecar fetches (Go duration format, e.g. 15s, 2m). "+
			"Zero (default) uses the compiled-in DefaultHTTPChainSidecarTimeout (30s). Increase for very large "+
			"sidecars on cold caches; decrease in latency-sensitive pipelines.")
	cmd.Flags().Int64Var(&vo.ChainSidecarHTTPMaxBytes, "chain-sidecar-http-max-bytes", 0,
		"Cap on the HTTP response body size when fetching a chain sidecar (raw bytes). "+
			"Zero (default) uses the compiled-in DefaultHTTPChainSidecarMaxBytes (64 MiB ≈ 67108864). "+
			"Tune up for builds with very large material sets; tune down to harden against hostile servers.")

	cmd.Flags().StringVarP(&vo.OutputFormat, "format", "o", "text",
		"How to report the verdict. 'text' (default) prints human-readable evidence + the matched-subject "+
			"binding line to stderr. 'json' additionally emits a single machine-readable verdict object "+
			"{passed, step, matchedSubject, slsaLevel} to stdout so a CI gate can branch without parsing logs. "+
			"Branch on cilock's EXIT CODE, never on grepped output: `if cilock verify ...; then`. Piping to "+
			"tail/grep replaces the exit code with the pipe's and masks a verification failure.")

	cmd.MarkFlagsRequiredTogether("policy")
	// NOTE: policy-trust sources (publickey / policy-ca* / verifier-kms-ref) are
	// NOT enforced via MarkFlagsOneRequired here, because a cilock built with
	// embedded policy trust (see internal/embeddedtrust) needs none of them. The
	// requirement is enforced in runVerify, which is embedded-trust-aware and
	// emits a clearer error.
	// Note: we deliberately do NOT MarkFlagsOneRequired here. The
	// custom check in runVerify gives a much better error — it lists
	// candidate sha256 digests pulled from any supplied --attestations
	// / --bundle files so the operator can paste one into --subjects.
	// cobra's group-required error fires too early to see those.
}
