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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

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

	// NoEmbeddedTrust ignores the policy-signing trust compiled into this cilock
	// build (embeddedtrust). With it set, a released binary stops auto-trusting
	// its baked platform roots/signer and behaves like a stock build — verify
	// then requires explicit --policy-ca-roots / --policy-timestamp-servers /
	// --policy-* identity. Also settable via CILOCK_NO_EMBEDDED_TRUST (non-empty).
	NoEmbeddedTrust bool

	// TrustDiscovery opts in to (re-)trusting the platform's network-served
	// discovery trust_bundle_pem as the policy-signature CA roots. The discovered
	// bundle is trust-on-first-use pinned per platform; once pinned, a SILENTLY
	// CHANGED bundle is refused. Passing --trust-discovery accepts the current
	// bundle and re-pins it — the explicit operator acknowledgement required to
	// rotate a platform's policy-signer CA (GHSA #5988). Out-of-band
	// --policy-ca-roots always wins and makes this moot.
	TrustDiscovery bool
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
//
// Returns an error only for a hard security stop: a logged-in platform whose
// discovery trust_bundle_pem has CHANGED since it was first pinned (TOFU), unless
// the operator re-pins with --trust-discovery (GHSA #5988). All other resolution
// is best-effort and never errors.
func (vo *VerifyOptions) ResolvePlatformDefaults(cmd *cobra.Command) error { //nolint:gocyclo,gocognit // login-gated discovery + archivista + trust-derivation branches; each is a distinct, intentional resolution path and sits just over the threshold.
	// --offline is a clear alias for --platform-url "": clear the platform URL
	// so the explicit-disable path takes over (no Archivista/discovery/TSA).
	if vo.Offline {
		vo.PlatformURL = ""
	}
	platformExplicitlyDisabled := (cmd.Flags().Changed("platform-url") || vo.Offline) && vo.PlatformURL == ""
	if platformExplicitlyDisabled {
		return nil
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
		return nil
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
	// Best-effort by contract: any Discover failure returns a nil Discovery, so
	// the nil-checks below cover every error case. We deliberately discard the
	// error (rather than returning it) — on failure the explicit-flag /
	// embedded-trust paths in the cli layer still apply.
	disc, _ := platformconfig.Discover(vo.PlatformURL)
	if disc == nil || disc.Signing == nil {
		return nil
	}
	// Adopt the discovery trust bundle as the policy-signature CA roots only when
	// the operator supplied none out-of-band. Out-of-band --policy-ca-roots always
	// wins (and never reaches the TOFU gate below).
	if len(vo.PolicyCARootPaths) == 0 && len(vo.PolicyCARootsPEM) == 0 && disc.Signing.TrustBundlePEM != "" {
		// Trust-on-first-use pin (GHSA #5988): the network-served trust bundle
		// defines the CA roots that validate the very policies the platform serves.
		// Without pinning, a compromised/malicious platform could silently swap in
		// an attacker CA and make verify PASS against forged evidence. So we pin the
		// bundle's SHA-256 on first adoption and refuse a later CHANGE unless the
		// operator explicitly re-pins with --trust-discovery.
		sum := sha256.Sum256([]byte(disc.Signing.TrustBundlePEM))
		spki := hex.EncodeToString(sum[:])
		switch {
		case cred.TrustBundleSPKI == "" || vo.TrustDiscovery:
			// First use for this platform, or an explicit operator re-pin: adopt and
			// persist the pin so the next resolve can detect a silent change.
			vo.PolicyCARootsPEM = []byte(disc.Signing.TrustBundlePEM)
			if err := auth.SetTrustBundleSPKI(vo.PlatformURL, spki); err != nil {
				return fmt.Errorf("persist discovery trust-bundle pin for %s: %w", vo.PlatformURL, err)
			}
		case cred.TrustBundleSPKI == spki:
			// Unchanged since it was pinned — safe to keep trusting it.
			vo.PolicyCARootsPEM = []byte(disc.Signing.TrustBundlePEM)
		default:
			// Pinned bundle CHANGED with no operator opt-in. Refuse rather than
			// silently adopt the new (possibly attacker) CA. The bundle is NOT
			// adopted; the operator must re-pin with --trust-discovery (after
			// verifying the rotation is legitimate) or supply --policy-ca-roots.
			return fmt.Errorf(
				"platform %s now advertises a DIFFERENT policy-signer trust bundle than the one pinned on first use; "+
					"refusing to trust it silently. If this CA rotation is expected, re-run with --trust-discovery to re-pin, "+
					"or pass --policy-ca-roots to supply trust out-of-band (GHSA #5988)",
				vo.PlatformURL)
		}
	}
	if !cmd.Flags().Changed("policy-fulcio-oidc-issuer") && disc.Signing.FulcioOIDCIssuer != "" {
		vo.PolicyFulcioCertExtensions.Issuer = disc.Signing.FulcioOIDCIssuer
	}
	return nil
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

	cmd.Flags().BoolVar(&vo.NoEmbeddedTrust, "no-embedded-trust", false,
		"Ignore the policy-signing trust compiled into this cilock build (see `cilock version`). "+
			"The binary stops auto-trusting its baked platform roots/signer; verify then requires "+
			"explicit --policy-ca-roots / --policy-timestamp-servers / --policy-* identity. "+
			"Also settable via CILOCK_NO_EMBEDDED_TRUST.")

	cmd.Flags().BoolVar(&vo.TrustDiscovery, "trust-discovery", false,
		"Accept and (re-)pin the platform's network-served discovery trust bundle as the policy-signature "+
			"CA roots. The bundle is trust-on-first-use pinned per platform; once pinned, a CHANGED bundle is "+
			"refused unless you pass this flag to acknowledge the rotation. Out-of-band --policy-ca-roots always wins.")

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
