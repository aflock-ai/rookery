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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/aflock-ai/rookery/platformauth"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// bindingResolveFn / bindingMintLoginTokenFn are package vars so the run-entry
// product-binding gate can be unit-tested without a real platform or GitHub
// Actions OIDC endpoint.
var (
	bindingResolveFn        = platformauth.ResolveBinding
	bindingMintLoginTokenFn = fetchGitHubOIDCToken
)

var DefaultAttestors = []string{"environment", "git", "platform"}

// platformURLEnv tells the platform attestor which logged-in platform session
// to bind to. Kept as a literal (not an import of the attestor package) to
// avoid coupling options → attestor.
const platformURLEnv = platformconfig.PlatformURLEnv

// hasAuthorizationHeader reports whether an explicit Authorization header is
// already present, so a platform session doesn't clobber a user-supplied one.
func hasAuthorizationHeader(headers []string) bool {
	for _, h := range headers {
		if len(h) >= 14 && strings.EqualFold(h[:14], "authorization:") {
			return true
		}
	}
	return false
}

// sameOrigin reports whether two URLs share scheme+host (the security origin).
// The platform session token is a bearer credential scoped to the platform's
// own Archivista; it must never travel to a host the user redirected
// --archivista-server to. A parse failure or mismatch returns false so the
// token is withheld (fail closed).
func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil || ua.Host == "" {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// fulcioSignerNeedsToken reports whether the fulcio signer has no operator-chosen
// token source yet, so the login-driven keyless exchange may supply one. An
// explicit --signer-fulcio-token / -token-path / -oidc-issuer always wins. If the
// command never registered the fulcio signer (flag absent), there is nothing to
// fill, so it returns false.
func fulcioSignerNeedsToken(cmd *cobra.Command) bool {
	f := cmd.Flags().Lookup("signer-fulcio-token")
	if f == nil {
		return false
	}
	// An explicit non-fulcio signer (file / KMS / SPIFFE / vault) wins outright.
	// cilock accepts exactly one signer (cli/sign.go: "only one signer is
	// supported"), so attaching an ambient/session fulcio token here would select a
	// SECOND signer and fail the build — the regression Codex flagged on a CI job
	// that runs `cilock sign -k key.pem` with id-token: write present.
	if nonFulcioSignerSelected(cmd) {
		return false
	}
	for _, name := range []string{"signer-fulcio-token", "signer-fulcio-token-path", "signer-fulcio-oidc-issuer"} {
		if g := cmd.Flags().Lookup(name); g != nil && g.Changed {
			return false
		}
	}
	return true
}

// nonFulcioSignerSelected reports whether the operator explicitly selected a
// signer other than fulcio (e.g. --signer-file-key-path, --signer-kms-*,
// --signer-spiffe-*, --signer-vault-*). It mirrors cli.providersFromFlags, the
// canonical provider detector the signer loader itself uses: a provider is the
// second '-'-delimited segment of any CHANGED "signer-*" flag. We only treat a
// provider as chosen when its flag was actually set, so default-registered flags
// never count. Used to suppress the keyless fulcio-token wiring when the user has
// already committed to a different signer.
func nonFulcioSignerSelected(cmd *cobra.Command) bool {
	const fulcioSignerName = "fulcio" // the "fulcio" segment in e.g. --signer-fulcio-url
	selected := false
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if !strings.HasPrefix(f.Name, "signer-") {
			return
		}
		parts := strings.Split(f.Name, "-")
		if len(parts) < 2 {
			return
		}
		if parts[1] != fulcioSignerName {
			selected = true
		}
	})
	return selected
}

// fulcioFlagURL returns the fulcio signer's configured URL (set either by the
// user or by the platform-URL derivation earlier in ResolvePlatformDefaults). It
// is the origin the keyless OIDC token would be presented to, so the exchange is
// gated on it matching the platform's own Fulcio origin.
func fulcioFlagURL(cmd *cobra.Command) string {
	if f := cmd.Flags().Lookup("signer-fulcio-url"); f != nil {
		return f.Value.String()
	}
	return ""
}

// fulcioSignerSelected reports whether the fulcio signer is selected, mirroring
// cli.providersFromFlags: the signer is chosen when any *changed* flag carries the
// "signer-fulcio-" prefix (--signer-fulcio-token / -token-path / -oidc-issuer /
// -url). Used to decide when the platform should fill in a missing Fulcio URL.
func fulcioSignerSelected(cmd *cobra.Command) bool {
	selected := false
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if strings.HasPrefix(f.Name, "signer-fulcio-") {
			selected = true
		}
	})
	return selected
}

// ensureFulcioURL gives a SELECTED fulcio signer a URL when it has none, deriving
// it from the platform. The fulcio signer needs a host regardless of where its
// token comes from — an explicit --signer-fulcio-token (e.g. a CI OIDC token) or
// the keyless login exchange below — so without this,
// `cilock run|sign --platform-url X --signer-fulcio-token T` fails with
// "fulcio URL must include a host" unless the user also passes --signer-fulcio-url.
//
// CRITICAL: it only fills an EMPTY url and only when fulcio is ALREADY selected,
// so it never selects the signer itself. A non-keyless invocation with no
// signer-fulcio-* flag (local/KMS signing) is left completely untouched — that is
// the regression that broke local/KMS signing when the URL was derived
// unconditionally (the first bug Codex caught).
func ensureFulcioURL(cmd *cobra.Command, fulcioURL string) {
	if fulcioURL == "" || !fulcioSignerSelected(cmd) {
		return
	}
	if f := cmd.Flags().Lookup("signer-fulcio-url"); f != nil && f.Value.String() == "" {
		_ = cmd.Flags().Set("signer-fulcio-url", fulcioURL)
	}
}

// applyKeylessFulcioToken exchanges a stored platform login credential for a
// short-lived OIDC token the platform's Fulcio trusts and feeds it to the fulcio
// signer (--signer-fulcio-token). Shared by `cilock run` and `cilock sign` so
// both can sign keyless after `cilock login`. The caller pairs this with
// ensureFulcioURL, which supplies the URL the now-selected signer needs.
//
// It only fires when the user hasn't already chosen a Fulcio token source
// (--signer-fulcio-token / -token-path / -oidc-issuer) — an explicit choice
// always wins. If the user explicitly set --signer-fulcio-url to some origin,
// we only attach the token when it matches the platform's own Fulcio origin, so
// the session credential never travels to a third-party Fulcio. Fails OPEN: a
// failed exchange (offline, missing OIDC server) sets nothing and signing
// proceeds exactly as before — CI, offline, and local/KMS paths are unaffected.
//
// Returns the platform-reported assurance level (acr) when the exchange
// succeeded, so the caller can surface it in the run summary; nil otherwise.
// The refresher updates that same cell, so a caller that keeps the pointer
// always reads the level of the token that actually bought the certificate.
func applyKeylessFulcioToken(cmd *cobra.Command, platformURL, fulcioURL, sessionToken string) (*keylessAssurance, func() error) {
	if !fulcioSignerNeedsToken(cmd) {
		return nil, nil
	}
	if cur := fulcioFlagURL(cmd); cur != "" && !sameOrigin(cur, fulcioURL) {
		return nil, nil
	}
	res, err := auth.ExchangeSignTokenResult(platformURL, sessionToken)
	if err != nil {
		log.Debugf("keyless sign-token exchange skipped: %v", err)
		return nil, nil
	}
	// Setting the token selects the fulcio signer; ensureFulcioURL (called right
	// after this by the caller) gives it the platform URL.
	_ = cmd.Flags().Set("signer-fulcio-token", res.Token)
	assurance := &keylessAssurance{level: res.AssuranceLevel}

	// The same exchange, replayable at signing time. This pre-run call still has
	// to happen -- setting the token is what SELECTS the fulcio signer, so it
	// cannot simply be deferred -- but the value it installs is short lived, and
	// the certificate it feeds is now requested after the wrapped command. The
	// refresher replaces the token with a fresh one at that moment, and records
	// the assurance level THAT token was minted at: the summary must describe
	// the credential that bought the certificate, not the one that was thrown
	// away, or a downgraded re-exchange would be reported at the old, stronger
	// level.
	//
	// It fails CLOSED, unlike the pre-run path above. Before the command a failed
	// exchange means "this run is not keyless after all" and signing continues by
	// another route; at signing time the run is already committed to Fulcio, so a
	// stale token must surface as an error rather than a confusing HTTP 400 from
	// the certificate authority.
	refresh := func() error {
		fresh, err := auth.ExchangeSignTokenResult(platformURL, sessionToken)
		if err != nil {
			return fmt.Errorf("re-exchanging the platform signing token: %w", err)
		}
		if err := cmd.Flags().Set("signer-fulcio-token", fresh.Token); err != nil {
			return fmt.Errorf("installing the refreshed platform signing token: %w", err)
		}
		assurance.level = fresh.AssuranceLevel
		return nil
	}
	return assurance, refresh
}

// applyWorkflowKeylessFulcioToken wires the fulcio signer for ambient CI
// workflow identity (AuthModeWorkflowOIDC). It mints a fresh GitHub Actions OIDC
// token carrying the Fulcio signing audience and feeds it to --signer-fulcio-token,
// so `cilock run --platform-url <any>` signs keyless in CI with no manual
// --signer-fulcio-* flags after `cilock login --workflow-identity`. The session
// path (applyKeylessFulcioToken) cannot serve this case: a workflow-identity
// credential carries no stored token to exchange at /oauth/sign-token.
//
// Same guards as applyKeylessFulcioToken: an explicit --signer-fulcio-token /
// -token-path / -oidc-issuer always wins, and a user-set --signer-fulcio-url to a
// different origin suppresses the token so the workflow OIDC never travels to a
// third-party Fulcio. Fails OPEN — a missing OIDC server (not in GitHub Actions,
// or no id-token: write) sets nothing and signing proceeds as before.
//
// Returns true ONLY when it actually installed a workflow OIDC token (which
// selects the fulcio signer). Every fail-open path returns false: an explicit
// signer override, a foreign --signer-fulcio-url, no ambient OIDC server, or a
// flag-set error. Callers gate signerWorkflowIdentity on this result so the
// summary reports the workflow signing path only when it was actually used.
//
// The second return is the signing-time refresher, non-nil exactly when the
// first return is true. A minted GitHub Actions OIDC token is short lived just
// like an exchanged session token, and the Fulcio certificate is now requested
// AFTER the wrapped command, so the workflow-OIDC path needs the same deferred
// re-mint the session path gets (applyKeylessFulcioToken). Without it a build
// longer than the OIDC token lifetime presents an expired token to Fulcio.
// Callers that sign immediately -- no wrapped command between resolution and
// signature -- may discard it.
//
// Like the session refresher it fails CLOSED: before the command a failed mint
// means "this run is not keyless after all", but at signing time the run is
// already committed to Fulcio, so a stale token must surface as an error rather
// than a confusing HTTP 400 from the certificate authority.
func applyWorkflowKeylessFulcioToken(cmd *cobra.Command, fulcioURL, audience string) (bool, func() error) {
	if !fulcioSignerNeedsToken(cmd) {
		return false, nil
	}
	if cur := fulcioFlagURL(cmd); cur != "" && !sameOrigin(cur, fulcioURL) {
		return false, nil
	}
	oidcToken, err := fetchGitHubOIDCToken(audience)
	if err != nil {
		log.Debugf("workflow keyless OIDC mint skipped: %v", err)
		return false, nil
	}
	// Setting the token selects the fulcio signer; ensureFulcioURL (called by the
	// caller right after) gives it the platform's Fulcio URL.
	if err := cmd.Flags().Set("signer-fulcio-token", oidcToken); err != nil {
		log.Debugf("workflow keyless token set failed: %v", err)
		return false, nil
	}

	refresh := func() error {
		fresh, mintErr := fetchGitHubOIDCToken(audience)
		if mintErr != nil {
			return fmt.Errorf("re-minting the workflow OIDC signing token: %w", mintErr)
		}
		if setErr := cmd.Flags().Set("signer-fulcio-token", fresh); setErr != nil {
			return fmt.Errorf("installing the refreshed workflow OIDC signing token: %w", setErr)
		}
		return nil
	}
	return true, refresh
}

type RunOptions struct {
	SignerOptions            SignerOptions
	KMSSignerProviderOptions KMSSignerProviderOptions
	ArchivistaOptions        ArchivistaOptions
	PlatformURL              string // TestifySec platform URL — derives archivista, fulcio, tsa URLs
	WorkingDir               string
	Attestations             []string
	DirHashGlobs             []string
	Hashes                   []string
	OutFilePath              string
	StepName                 string
	Tracing                  bool
	// ScriptCapture selects how much of an executed script or makefile is
	// recorded: "identity" (default — path + digest), "content" (also embeds
	// the body), or "off". Empty means identity.
	ScriptCapture string
	// CaptureMode controls where the material + product attestors get
	// their digests. "auto" (default) picks the fastest available source
	// — trace events when --trace is on, otherwise directory walk.
	// "walk" forces the legacy walk path. "trace" requires --trace and
	// errors if no trace data is available. "ima" requires CONFIG_IMA.
	// Empty string is equivalent to "auto".
	CaptureMode string

	// Cache classification controls. The framework ships defaults that
	// cover common build caches across languages (Go, Rust, Python,
	// Node, etc.) — see attestation.DefaultCachePatterns. These flags
	// let the operator tune that list per build.
	CacheAddPatterns     []string // additive glob patterns
	CacheAllowPatterns   []string // patterns to remove from the effective set
	CacheDisableDefaults bool     // drop DefaultCachePatterns entirely
	CacheDisableEnvProbe bool     // skip SystemCachePathsFromEnv discovery
	// IgnoreCommandExitCode tells cilock to record the wrapped command's
	// exit code in `command-run/v0.1.exitcode` but NOT abort the cilock run
	// when the command exits non-zero. Without this flag, every postproduct
	// attestor (sarif/sbom/vex/etc.) is skipped on non-zero exit, which
	// breaks integration with tools that exit non-zero on findings
	// (semgrep, gosec, hadolint, checkov, trivy `--exit-code`, prowler v3,
	// govulncheck) unless each tool's own soft-fail flag is known and used.
	// Policy Rego still has access to the recorded exit code via
	// `input.attestation.exitcode` if a deny rule wants to gate on it.
	IgnoreCommandExitCode bool

	// Diagnose enables verbose internal logging across cilock subsystems:
	// eBPF program loading, fanotify event traces, ringbuf drop reporting,
	// fs-verity probe results, etc. Off by default — the normal run is
	// already loud enough for typical operators. Turn on when filing a
	// bug or debugging a CI flake.
	//
	// Internally sets CILOCK_DIAGNOSE=1 for downstream subprocess /
	// subpackage consumers. Replaces (and consolidates) the per-feature
	// env vars: CILOCK_EBPF_DEBUG, CILOCK_BPF_DIAGNOSE.
	Diagnose bool

	// Hardening bundles the per-feature integrity toggles (fanotify,
	// fs-verity, require-zero-drops) into a named profile. Recognised:
	//
	//   - "off"      — minimum overhead; no fanotify, no fs-verity,
	//                  no zero-drops gate. Use when iterating on a
	//                  CI policy locally.
	//   - "standard" (default) — fanotify on, fs-verity opportunistic
	//                  (sealed where supported, skipped silently
	//                  elsewhere), drops surfaced as warnings.
	//   - "strict"   — fanotify required, fs-verity required, drops
	//                  fail the run. For release-grade attestations.
	//
	// Explicit env vars (CILOCK_FANOTIFY, CILOCK_FSVERITY) still win;
	// the profile only sets defaults. Phase 3 of #234.
	Hardening string

	// RequireZeroDrops forces the run to fail if the eBPF ringbuf
	// dropped any event during the trace. Hard gate against silent
	// loss. Defaults from --hardening (strict ⇒ true).
	RequireZeroDrops bool

	// Workload selects how attestors are picked. "auto" (default)
	// inspects the workspace at startup and adds detected attestors
	// to whatever the operator listed via --attestations; "manual"
	// uses --attestations as the exact set. Phase 4 of #234.
	Workload string

	// ValidateOnly runs the pre-flight workload + tool-availability
	// checks, prints the planned attestor set + any warnings, and
	// exits without running the user command. Lets operators dry-run
	// their cilock config in CI.
	ValidateOnly     bool
	TimestampServers []string
	// Subjects holds raw --subjects flag values. Each entry is either a bare
	// subject name (e.g. "product:<uuid>") — in which case a sha256 digest of
	// the name is synthesised — or a "name=<alg>:<hex>" form that supplies an
	// explicit digest. Values are injected into the in-toto statement of the
	// attestation collection in addition to whatever attestors discover.
	Subjects                []string
	AttestorOptSetters      map[string][]func(attestation.Attestor) (attestation.Attestor, error)
	EnvFilterSensitiveVars  bool
	EnvDisableSensitiveVars bool
	EnvAddSensitiveKeys     []string
	EnvAllowSensitiveKeys   []string
	// EnvCaptureAllowlist switches the environment attestor into positive-
	// allowlist mode: only env keys matching one of the supplied patterns
	// (exact key or glob) are captured. Use when committing captured
	// envelopes to a public repo — the default denylist still records
	// host-identifying state (PATH-with-homebrew-prefix, USER, SHELL,
	// validator-installed CLIs) that's fine in production but noisy in
	// committed validation artifacts. See rookery#142.
	EnvCaptureAllowlist []string

	// PrewalkSkipDirs is the user-supplied addition to the built-in
	// pre-trace walk skip list (commandrun.DefaultPrewalkSkipDirs).
	// Each entry is a single directory basename. Additive only —
	// does NOT remove anything from the default set; use
	// --prewalk-include-dir for that.
	PrewalkSkipDirs []string

	// PrewalkIncludeDirs forces directory basenames to be descended
	// into during the pre-trace walk even when they are in the
	// built-in default skip set or the user's PrewalkSkipDirs.
	// Most-specific wins: include beats skip.
	PrewalkIncludeDirs []string

	// NoDefaultAttestors lists names of always-on attestors to drop
	// from the alwaysRunAttestors set (product, material). Repeated
	// flag values are merged. Disabling BOTH is a hard error — the
	// attestation collection would have no body to attest.
	NoDefaultAttestors []string

	// OutputFormat selects how the run result is reported. "text"
	// (default) prints a human-readable self-explaining summary to
	// stderr. "json" emits a single machine-readable RunSummary object
	// to stdout (logr + the human summary stay on stderr). --json is a
	// shorthand for --output-format json. Designed so an agent driving
	// cilock gets a clean tool-result instead of grepping logr text.
	OutputFormat string

	// NoProductBinding opts a platform-authenticated run out of the fail-closed
	// product-binding gate, so a legitimate authenticated-but-no-product run (an
	// org-level attestation not tied to a product) can proceed. Fail-closed by
	// DEFAULT: without this flag, an authenticated run whose repo maps to zero or
	// multiple products is a hard error. It does NOT disable the platform
	// attestor — it only stops the gate from failing the run.
	NoProductBinding bool

	// RequireProducts refuses to persist or upload a collection whose product
	// attestor recorded nothing. A step wrapped to prove WHICH artifact it
	// produced — a build, an image promote — has no meaning without that
	// subject: the envelope still names the commit and the pipeline, so it
	// reads as a successful, well-formed record of a deploy while answering
	// none of the questions it was minted to answer. Callers that intend a
	// specific artifact (they passed --attestor-product-include-glob) should
	// set this so a glob that stops matching, a working directory that moves,
	// or a build whose output never lands fails LOUDLY at mint time instead of
	// filling the evidence store with subjectless collections.
	//
	// Off by default: plenty of legitimate runs produce no files.
	RequireProducts bool

	// Offline is a clear alias for --platform-url "": it runs cilock with
	// no platform integration (no hosted Fulcio / TSA / Archivista, no
	// session lookup). It exists so an operator signing with a local -k key
	// doesn't have to know the empty-string idiom, and so "offline" is an
	// explicit, greppable intent rather than an inference. ResolvePlatformDefaults
	// honours it by clearing PlatformURL before any derivation.
	Offline bool

	// resolved* fields are populated by ResolvePlatformDefaults from the
	// logged-in credential and platform derivation so the post-run summary
	// can report the tenant / identity / destinations cilock actually bound
	// to without re-deriving or re-reading the credential store. They are
	// not flags.
	resolvedTenantName  string
	resolvedSignerEmail string
	resolvedFulcioURL   string

	// keylessAssurance is the assurance level of the platform-minted signing
	// token as of its MOST RECENT mint -- see the type for why it is a pointer.
	// nil for workflow-identity, offline, local-key and explicit-token runs.
	keylessAssurance *keylessAssurance

	// agentPrincipal is the enrolled agent principal that signed, as of the
	// signing token's MOST RECENT exchange -- see the type for why it is a
	// pointer. nil for every non-agent run.
	agentPrincipal *agentPrincipal

	// platformPrincipal is the stored credential this run signs as — the input
	// to the fail-closed evidence gate (EnforceEvidenceStorage). Set by the
	// agent and session credential paths; nil when no stored credential
	// resolved. See the type for why it is its own field.
	platformPrincipal *platformPrincipal

	// agentIdentityErr is a FAIL-CLOSED failure on the enrolled-agent path: an
	// unreadable agent store, a refused credential exchange, or a Fulcio origin
	// the agent token is not valid at. Callers of ResolvePlatformDefaults must
	// check AgentIdentityError and abort.
	//
	// Even an unchecked caller cannot sign as the human by accident: a failure
	// here returns BEFORE the session lookup, so no session token is installed
	// and the run has no keyless identity at all.
	agentIdentityErr error

	// signerWorkflowIdentity records that cilock minted the signing identity from
	// the platform's workflow-identity path — the ambient-CI OIDC exchange or a
	// stored workflow-identity marker. It records the signing path only; it does
	// not establish build-platform isolation or a SLSA/ALPS level. It is not set
	// for browser/token sessions, explicit --signer-fulcio-token overrides, or
	// offline/local-key runs.
	signerWorkflowIdentity bool

	// refreshFulcioToken re-runs the /oauth/sign-token exchange and reinstalls
	// the result on --signer-fulcio-token. It is set ONLY when the pre-run
	// exchange succeeded, so CI, offline, local-key and explicit-token runs
	// carry a nil refresher and are completely unaffected.
	//
	// It exists because the pre-run exchange alone is not enough. The token is
	// minted during option resolution, BEFORE the wrapped command; the Fulcio
	// certificate is now minted lazily at first signature, AFTER it. A command
	// that runs longer than the token's lifetime therefore presents an expired
	// token to Fulcio and gets HTTP 400 "There was an error processing the
	// identity token" -- measured on a 295.7s run. Deferring the certificate
	// without also refreshing the token just moves the expiry one layer down.
	refreshFulcioToken func() error
}

// FulcioTokenRefresher returns the signing-time token refresher, or nil when
// this run has no platform session to re-exchange. Callers must treat nil as
// "nothing to refresh", never as an error.
func (ro *RunOptions) FulcioTokenRefresher() func() error { return ro.refreshFulcioToken }

// OutputJSON reports whether the run result should be emitted as a structured
// JSON object on stdout (set via --json or --output-format json).
func (ro *RunOptions) OutputJSON() bool {
	return strings.EqualFold(ro.OutputFormat, "json")
}

// ResolvedTenantName returns the tenant the logged-in credential is scoped to,
// as captured during ResolvePlatformDefaults. Empty when not logged in.
func (ro *RunOptions) ResolvedTenantName() string { return ro.resolvedTenantName }

// ResolvedSignerEmail returns the signing identity's email from the logged-in
// credential, as captured during ResolvePlatformDefaults. Empty when unknown.
func (ro *RunOptions) ResolvedSignerEmail() string { return ro.resolvedSignerEmail }

// ResolvedFulcioURL returns the platform-derived Fulcio URL, as captured
// during ResolvePlatformDefaults. Empty when the platform was disabled.
func (ro *RunOptions) ResolvedFulcioURL() string { return ro.resolvedFulcioURL }

// ResolvedAssuranceLevel returns the assurance level (acr) the platform minted
// the keyless signing identity at, as reported by the sign-token exchange that
// bought the certificate -- the signing-time re-exchange when one ran, not the
// pre-command one. Empty for offline / local-key runs or when the platform
// supplied none.
func (ro *RunOptions) ResolvedAssuranceLevel() string {
	if ro.keylessAssurance == nil {
		return ""
	}
	return ro.keylessAssurance.level
}

// keylessAssurance is the assurance level (acr) of the platform-minted keyless
// signing token, as of its most recent mint.
//
// It is a heap cell shared by pointer rather than a string field on RunOptions
// because cli/run.go hands RunOptions to runRun BY VALUE, while the signing-time
// refresher installed by applyKeylessFulcioToken re-mints the token AFTER the
// wrapped command and may be handed a different level than the pre-command
// exchange was. A value field would leave the summary -- built from the copy,
// after signing -- reporting the level of the initial, unused token.
type keylessAssurance struct {
	level string
}

// ResolvedAgentPrincipal returns the SPIFFE ID of the enrolled agent principal
// that signed, as reported by the credential exchange that bought the
// certificate. Empty for every run that did not sign as an agent.
func (ro *RunOptions) ResolvedAgentPrincipal() string {
	if ro.agentPrincipal == nil {
		return ""
	}
	return ro.agentPrincipal.spiffeID
}

// AgentIdentityError returns the fail-closed error from the enrolled-agent
// signing path, or nil. Every caller of ResolvePlatformDefaults must check it
// and abort the command: continuing means running without the principal the
// operator configured.
func (ro *RunOptions) AgentIdentityError() error { return ro.agentIdentityErr }

// SignerIsWorkflowIdentity reports whether the run signed with a platform
// workflow identity (ambient CI OIDC or a stored workflow-identity marker), as
// captured during ResolvePlatformDefaults. It is a signing-path observation,
// not a build-platform or standards assessment.
func (ro *RunOptions) SignerIsWorkflowIdentity() bool { return ro.signerWorkflowIdentity }

var RequiredRunFlags = []string{
	"step",
}

// ResolvePlatformDefaults applies platform-derived defaults to any options
// that weren't explicitly set. Call this after flag parsing but before use,
// then check AgentIdentityError and abort on a non-nil result — the
// enrolled-agent signing path fails closed and reports through that accessor.
//
// To run cilock fully offline (no platform integration), users pass
// `--platform-url ""`. That sets ro.PlatformURL to the empty string AND
// marks the flag as user-changed, so we know NOT to fall back to the
// compiled-in DefaultPlatformURL. In that mode no TSA is added (signing
// continues with the configured signer only — no third-party
// timestamp) and the archivista URL stays whatever the user set.
// applyActivePlatformDefault points --platform-url at the platform you logged
// into (the active stored platform) when the flag was not given and we're not
// offline — so `cilock login <staging>` then a bare `cilock run` targets staging
// rather than the compiled-in prod default.
func (ro *RunOptions) applyActivePlatformDefault(cmd *cobra.Command) {
	if cmd.Flags().Changed("platform-url") || ro.Offline {
		return
	}
	if active := auth.ActivePlatformURL(); active != "" {
		ro.PlatformURL = active
	}
}

func (ro *RunOptions) ResolvePlatformDefaults(cmd *cobra.Command) {
	// --offline is a clear alias for --platform-url "". Clear the platform URL
	// up front so the explicit-disable path below takes over; cmd.Flags() is
	// also patched so the Changed("platform-url") check sees the opt-out even
	// when the operator used --offline instead of --platform-url "".
	if ro.Offline {
		ro.PlatformURL = ""
		log.Info("--offline: running with no platform (no hosted Fulcio/TSA/Archivista, no session lookup)")
	}

	ro.applyActivePlatformDefault(cmd)

	// Detect the explicit-disable case. If the user did NOT change
	// --platform-url, ro.PlatformURL holds the compiled-in default.
	// If the user passed --platform-url "" (or any empty value), we
	// treat that as "no platform" and skip all derivation.
	platformExplicitlyDisabled := (cmd.Flags().Changed("platform-url") || ro.Offline) && ro.PlatformURL == ""
	if platformExplicitlyDisabled {
		// User opted out of the platform. Don't derive anything — and drop the
		// auto-added platform attestor, since there is no platform to bind to.
		ro.dropDefaultPlatformAttestor(cmd)
		return
	}

	pc := platformconfig.Derive(ro.PlatformURL)

	// Record the platform-derived Fulcio URL for the post-run summary so an
	// agent can see the signing destination even on a local/KMS run where the
	// fulcio signer flag is never set.
	ro.resolvedFulcioURL = pc.Fulcio

	// Archivista URL: use platform default if not explicitly overridden
	if !cmd.Flags().Changed("archivista-server") && !cmd.Flags().Changed("archivist-server") {
		ro.ArchivistaOptions.Url = pc.Archivista
	}

	// OIDC audience: derive from platform if not set
	if ro.ArchivistaOptions.Audience == "" {
		ro.ArchivistaOptions.Audience = pc.OIDCAudience
	}

	// Timestamp servers: add platform TSA if none explicitly configured
	if len(ro.TimestampServers) == 0 {
		ro.TimestampServers = []string{pc.TSA}
	}

	// NOTE: We deliberately do NOT derive --signer-fulcio-url unconditionally.
	// Setting it marks the flag "changed", which SELECTS the fulcio signer (signer
	// selection keys off changed signer-* flags). Deriving it for every run would
	// force fulcio onto local/KMS signing and fail with "no token provided" when
	// not logged in. Instead ensureFulcioURL (below) fills the URL only once the
	// fulcio signer is already selected — by an explicit --signer-fulcio-* flag or
	// by the keyless exchange.

	// Platform session: if the user has logged in (`cilock login`) to this
	// platform, authenticate Archivista uploads with the session token and
	// expose the platform URL to the platform attestor (via CILOCK_PLATFORM_URL)
	// so it can bind the attestation to the tenant/product. Best-effort — a
	// missing/expired session just means no platform auth (offline/CI paths
	// keep working).
	// LookupAny (not Lookup) so a workflow-identity marker — which carries no
	// stored token — is returned too; its keyless signing comes from a freshly
	// minted ambient OIDC token, not a stored bearer.
	// platformActive tracks whether this run has a real platform identity — a
	// stored session or an ambient CI workflow identity. The platform attestor
	// exists to bind a run to that identity; when it's absent we trim the
	// attestor from the auto defaults below.
	platformActive := ro.resolvePlatformIdentity(cmd, pc)

	// The platform attestor binds a run to a logged-in platform tenant; with no
	// session and no CI identity it has nothing to record, so trim it from the
	// auto defaults. This keeps an offline/local-key run — or a preset binary
	// that never registered the platform attestor — from dead-ending on a
	// platform attestor it never opted into. An explicit -a is left untouched.
	if !platformActive {
		ro.dropDefaultPlatformAttestor(cmd)
	}

	// Give a selected fulcio signer a URL if it lacks one — whether it was
	// selected by the keyless exchange above or by an explicit --signer-fulcio-token
	// (a CI OIDC token). Runs outside the login block so the explicit-token path
	// works without `cilock login`. No-op for local/KMS signing (fulcio unselected).
	ensureFulcioURL(cmd, pc.Fulcio)
}

// resolvePlatformIdentity resolves the run's platform identity — an enrolled
// agent principal, a stored login session, or an ambient CI workflow identity —
// and wires it into the run (Archivista bearer, keyless Fulcio token,
// platform-attestor binding). Returns true when such an identity exists; false
// means the run has no platform identity to bind (offline / logged out / local
// key).
//
// PRECEDENCE: an enrolled agent credential for this platform WINS over the
// human session, and the human session is not reachable behind it. Both an
// agent failure and an unreadable agent store return before the session lookup,
// so no failure on the agent path can end in a signature attributed to the
// human. The chosen principal is named in the run summary.
func (ro *RunOptions) resolvePlatformIdentity(cmd *cobra.Command, pc platformconfig.PlatformConfig) bool {
	agentCred, agentErr := auth.ResolveAgentCredential(ro.PlatformURL)
	if agentErr != nil {
		ro.agentIdentityErr = fmt.Errorf("read the enrolled agent credential for %s: %w", ro.PlatformURL, agentErr)
		return false
	}
	if agentCred != nil {
		if err := ro.applyAgentCredential(cmd, *agentCred, pc); err != nil {
			ro.agentIdentityErr = err
			return false
		}
		return true
	}
	if cred, lookupErr := auth.LookupAny(ro.PlatformURL); lookupErr == nil && cred != nil {
		ro.applyPlatformCredential(cmd, cred, pc)
		return true
	}
	if auth.WorkflowOIDCAvailable() {
		// Not logged in, but running in CI with an ambient OIDC identity
		// (ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN present ⇒ `permissions: id-token:
		// write`). Sign keyless with the workflow identity directly, so a bare
		// `cilock run --platform-url X` works in CI with no `cilock login` step.
		// The minted OIDC token carries the Fulcio signing audience (sigstore) and
		// is presented to the platform's own Fulcio (derived from --platform-url).
		// Only claim workflow identity when the token was ACTUALLY installed —
		// the helper fails open (no CI OIDC, explicit override, foreign Fulcio),
		// and an over-claimed identity would misstate the signing path.
		ro.signerWorkflowIdentity, ro.refreshFulcioToken = applyWorkflowKeylessFulcioToken(cmd, pc.Fulcio, pc.OIDCClientID)

		// Expose the platform URL to the platform attestor so it binds the run to
		// the tenant even with no prior `cilock login`: in CI the ambient GitHub
		// Actions OIDC token authenticates the Archivista upload directly
		// (ArchivistaOptions.OIDC, auto-enabled when ACTIONS_ID_TOKEN_REQUEST_URL is
		// set), and the platform resolves the tenant/product server-side from that
		// credential. Same-origin guard: never advertise the platform binding for an
		// upload aimed at a third-party --archivista-server (the OIDC token, and the
		// binding it implies, only make sense against the platform's own Archivista).
		if ro.ArchivistaOptions.OIDC && sameOrigin(ro.ArchivistaOptions.Url, pc.Archivista) {
			normalized := auth.NormalizeURL(ro.PlatformURL)
			_ = os.Setenv(platformURLEnv, normalized)
			// In-process trust handshake: authorize the platform attestor to emit a
			// workflow-identity binding for THIS url. CILOCK_PLATFORM_URL alone is
			// user-controllable (inheritable env), so the attestor additionally
			// requires this marker — set only here, after the same-origin check — to
			// match before binding. Closes the confused-deputy gap where a hostile CI
			// step exports CILOCK_PLATFORM_URL to forge a platform binding.
			platformconfig.MarkTrustedPlatformBinding(normalized)
		}
		return true
	}
	if !cmd.Flags().Changed("platform-url") {
		// No platform session, no ambient CI identity, and the operator never
		// changed --platform-url — so cilock is silently using the compiled-in
		// HOSTED platform defaults (TSA, Archivista) while signing with whatever
		// local --signer-* key was supplied. That is fine, but make it VISIBLE:
		// the operator is effectively running offline against the local key, and
		// the only platform interaction left is the default TSA timestamp. Pass
		// --offline (or --platform-url "") to drop the hosted defaults entirely.
		log.Info("no platform session — running offline (signing with the local key; pass --offline to drop hosted platform defaults)")
	}
	return false
}

// dropDefaultPlatformAttestor removes the "platform" attestor from the AUTO
// attestor defaults when there is no platform identity to bind to (offline, not
// logged in, or platform disabled). The platform attestor records a run's
// binding to a logged-in platform tenant; with no session it has nothing to
// emit, and demanding it would break a build that never opted into the platform
// — e.g. an offline local-key run, or a preset binary (cilock-all) that does not
// register the platform attestor at all.
//
// Only the auto defaults are trimmed. If the operator explicitly passed
// -a/--attestations, that is their exact set and is honored verbatim — an
// explicit `-a platform` still asks for the platform attestor.
func (ro *RunOptions) dropDefaultPlatformAttestor(cmd *cobra.Command) {
	if cmd.Flags().Changed("attestations") {
		return
	}
	// Build a fresh slice: ro.Attestations may share DefaultAttestors' backing
	// array (cobra's default), so an in-place filter would corrupt the package
	// default for later invocations.
	out := make([]string, 0, len(ro.Attestations))
	for _, a := range ro.Attestations {
		if a == "platform" { // matches the "platform" entry in DefaultAttestors
			continue
		}
		out = append(out, a)
	}
	ro.Attestations = out
}

// explicitFulcioTokenSource reports whether the operator already supplied a
// Fulcio token source on the command line (--signer-fulcio-token / -token-path /
// -oidc-issuer). When true, the keyless platform identity is irrelevant — the
// operator is bringing their own token — so the pre-flight identity gate must
// stand down and let signer construction proceed.
func explicitFulcioTokenSource(cmd *cobra.Command) bool {
	for _, name := range []string{"signer-fulcio-token", "signer-fulcio-token-path", "signer-fulcio-oidc-issuer"} {
		if g := cmd.Flags().Lookup(name); g != nil && g.Changed {
			return true
		}
	}
	return false
}

// PreflightIdentity is the first-run identity gate. A brand-new operator who
// runs `cilock run --platform-url <url> -- <cmd>` with no `cilock login`, no
// local --signer-* key, and no ambient CI OIDC identity has no way to obtain a
// signing certificate: the bare path dead-ends in signer construction with
// "failed to load any signers", and an explicit --signer-fulcio-url dead-ends in
// "no token provided" — neither mentions "account" or "login", and the wrapped
// build never runs. This returns a friendly, actionable error BEFORE signer
// construction so the operator is steered to `cilock login` (or a local key)
// instead of decoding a Fulcio internal.
//
// It must run AFTER ResolvePlatformDefaults, which is what installs the keyless
// token/URL when a session or CI identity IS present — so by the time we get
// here, the absence of any of those is conclusive.
//
// The gate stands down (returns nil) in every case where signing has a real
// path, so it never blocks a working invocation:
//   - platform disabled (--offline / --platform-url ""): no platform signing at all.
//   - a non-fulcio signer is selected (-k / --signer-file-* / KMS / SPIFFE / vault):
//     local signing needs no platform identity.
//   - an explicit --signer-fulcio-token / -token-path / -oidc-issuer is set: the
//     operator brought their own Fulcio token (CI OIDC, interactive issuer).
//   - ambient CI workflow OIDC is available (GitHub Actions id-token: write): the
//     keyless identity is minted per-call, so no `cilock login` is needed.
//   - a stored platform session exists (LookupAny != nil): the operator is logged
//     in (browser/token session OR a workflow-identity marker).
func (ro *RunOptions) PreflightIdentity(cmd *cobra.Command) error {
	// Platform disabled — no hosted Fulcio in play, so there is nothing to gate.
	if (cmd.Flags().Changed("platform-url") || ro.Offline) && ro.PlatformURL == "" {
		return nil
	}
	// A non-fulcio local/KMS/SPIFFE/vault signer was explicitly chosen, or the
	// operator brought their own Fulcio token — signing has a path either way.
	if nonFulcioSignerSelected(cmd) || explicitFulcioTokenSource(cmd) {
		return nil
	}
	// Ambient CI workflow OIDC identity (GitHub Actions id-token: write) signs
	// keyless with no `cilock login` step — never block the CI path.
	if auth.WorkflowOIDCAvailable() {
		return nil
	}
	// A stored session (browser/token) or workflow-identity marker means the
	// operator is logged in to this platform — let the run proceed.
	if cred, lookupErr := auth.LookupAny(ro.PlatformURL); lookupErr == nil && cred != nil {
		return nil
	}
	// No local key, no token, no CI identity, no session — the run would otherwise
	// dead-end inside Fulcio signer construction with an opaque error and never run
	// the wrapped command. Steer the operator to the fix.
	platformURL := auth.NormalizeURL(ro.PlatformURL)
	if platformURL == "" {
		platformURL = platformconfig.DefaultPlatformURL
	}
	return fmt.Errorf("not signed in to %s — run 'cilock login' first, "+
		"or pass -k/--signer-file-key-path for a local key (or --offline to skip platform signing)", platformURL)
}

// EnforcePlatformBinding is the client-side fail-closed product-binding gate. It
// runs at run START (before the wrapped command executes) so a misconfigured
// pipeline wastes no build time and the error is unambiguous.
//
// Rule (matching the design):
//   - Not platform-authenticated (no session, no ambient OIDC targeting the
//     platform) → proceed unchanged (the platform attestor soft-skips).
//   - --no-product-binding → proceed (explicit opt-out).
//   - Authenticated + repo resolves to exactly ONE product → proceed; the
//     resolved binding is threaded to the platform attestor.
//   - Authenticated + repo maps to ZERO (repository_not_mapped) or is AMBIGUOUS
//     (repo→multiple, no valid selector) from a REACHABLE endpoint → HARD FAIL
//     with a machine-actionable message.
//   - Endpoint unreachable / not deployed yet / 5xx / auth rejected → loud
//     SOFT-skip (WARN), so a client that ships before the server is deployed
//     never breaks the build (evidence just won't auto-link).
//
// Must run AFTER ResolvePlatformDefaults (which sets CILOCK_PLATFORM_URL for the
// ambient path after its same-origin check).
func (ro *RunOptions) EnforcePlatformBinding(cmd *cobra.Command) error {
	platformDisabled := (cmd.Flags().Changed("platform-url") || ro.Offline) && ro.PlatformURL == ""
	return ro.enforcePlatformBinding(platformDisabled)
}

// enforcePlatformBinding is EnforcePlatformBinding with the cobra-derived
// "platform disabled" decision passed in, so the gate logic is unit-testable
// without a live command.
func (ro *RunOptions) enforcePlatformBinding(platformDisabled bool) error {
	if ro.NoProductBinding || platformDisabled {
		return nil
	}
	platformURL := ro.PlatformURL
	if platformURL == "" {
		platformURL = platformconfig.DefaultPlatformURL
	}
	pc := platformconfig.Derive(platformURL)

	bearer, selector, ok := ro.bindingCredentials(platformURL, pc)
	if !ok {
		// Not platform-authenticated → nothing to bind; the attestor soft-skips.
		return nil
	}

	binding, err := bindingResolveFn(platformURL, bearer, selector)
	if err != nil {
		return classifyBindingGateError(platformURL, err)
	}

	// Success: thread the resolved binding to the platform attestor (ambient
	// path) and capture it for the run summary. Never persisted.
	platformconfig.MarkResolvedBinding(platformconfig.ResolvedProductBinding{
		PlatformURL: auth.NormalizeURL(platformURL),
		TenantID:    binding.TenantID,
		TenantName:  binding.TenantName,
		ProductID:   binding.ProductID,
		ProductName: binding.ProductName,
	})
	ro.resolvedTenantName = binding.TenantName
	return nil
}

// bindingCredentials returns the bearer token and product selector the binding
// exchange should use, and whether the run is platform-authenticated at all.
//
//   - A stored `cilock login` session (bearer-carrying) → the session bearer,
//     with the login-bound product as the disambiguation selector.
//   - Otherwise an ambient CI workflow OIDC identity that TARGETS the platform
//     (CILOCK_PLATFORM_URL set by ResolvePlatformDefaults after its same-origin
//     check) → a freshly-minted login-audience OIDC token, with any workflow
//     marker's bound product as selector.
//   - Neither → (”, ”, false): not authenticated.
func (ro *RunOptions) bindingCredentials(platformURL string, pc platformconfig.PlatformConfig) (bearer, selector string, ok bool) {
	if cred, err := auth.Lookup(platformURL); err == nil && cred != nil && cred.Token != "" {
		return cred.Token, cred.ProductID, true
	}
	// Ambient path: only when the run actually targets the platform's own
	// Archivista (ResolvePlatformDefaults set CILOCK_PLATFORM_URL after its
	// same-origin + ambient-OIDC check). A raw CILOCK_PLATFORM_URL is not enough
	// on its own, but here it only selects the login audience for a token we mint
	// ourselves — the platform still authenticates the OIDC token server-side.
	if auth.WorkflowOIDCAvailable() && os.Getenv(platformURLEnv) != "" {
		token, err := bindingMintLoginTokenFn(pc.OIDCLoginAudience)
		if err != nil {
			// Can't mint a login token → treat as not-authenticated for binding
			// (the run still proceeds; ambient upload auth is separate).
			log.Warnf("product binding skipped: could not mint a login-audience OIDC token: %v", err)
			return "", "", false
		}
		sel := ""
		if cred, _ := auth.LookupAny(platformURL); cred != nil {
			sel = cred.ProductID
		}
		return token, sel, true
	}
	return "", "", false
}

// classifyBindingGateError decides whether a binding-exchange error hard-fails
// the run or degrades to a loud soft-skip. Only a genuine config error from a
// REACHABLE endpoint (repository_not_mapped / ambiguous_product) hard-fails;
// every transport/availability failure (endpoint not deployed yet, 5xx, auth
// rejected) is a WARN + proceed, so a client that ships ahead of the server's
// deploy never breaks the build.
func classifyBindingGateError(platformURL string, err error) error {
	var notMapped *platformauth.RepositoryNotMappedError
	if errors.As(err, &notMapped) {
		return errors.New(repoNotMappedMessage(platformURL, notMapped))
	}
	var ambiguous *platformauth.AmbiguousProductError
	if errors.As(err, &ambiguous) {
		return errors.New(ambiguousProductMessage(ambiguous))
	}
	// Soft-skip ONLY a genuinely-unavailable endpoint (server not deployed yet,
	// transport failure, 5xx, non-JSON 200) so a client shipped ahead of the
	// server's deploy never breaks the build. EVERY other error — invalid/absent
	// product, 401, 403, malformed response — is a deterministic config/auth
	// failure and MUST fail closed.
	var unavailable *platformauth.BindingUnavailableError
	if errors.As(err, &unavailable) {
		log.Warnf("platform binding endpoint unavailable (the server may not be deployed yet) — "+
			"proceeding without product binding; evidence will not auto-link to a product: %v", err)
		return nil
	}
	return fmt.Errorf("platform binding failed (authenticated, but could not resolve a product binding): %w. "+
		"Fix the configuration, or pass --no-product-binding to attest without a product binding", err)
}

// repoNotMappedMessage builds the machine-actionable failure for the zero-product
// case. It names the repository (+ github_repository_id), the tenant, and the
// exact remediation, so an automated agent reading the log can self-correct.
func repoNotMappedMessage(platformURL string, e *platformauth.RepositoryNotMappedError) string {
	repo, repoID := repoIdentifiers(e.Repository, e.RepositoryID)
	return fmt.Sprintf("platform binding failed: repository %s (github_repository_id=%s) is authenticated to "+
		"tenant %q (%s) but is not connected to any product. Fix: connect the repo to a product at %s/settings, "+
		"or pass an explicit product (`cilock login --product <uuid>`). To intentionally attest without a product "+
		"binding, pass --no-product-binding.",
		repo, repoID, e.TenantName, e.TenantID, strings.TrimRight(auth.NormalizeURL(platformURL), "/"))
}

// ambiguousProductMessage builds the machine-actionable failure for the
// multiple-product case, listing every candidate UUID + name so an agent can
// choose exactly one.
func ambiguousProductMessage(e *platformauth.AmbiguousProductError) string {
	repo, _ := repoIdentifiers(e.Repository, e.RepositoryID)
	parts := make([]string, 0, len(e.Candidates))
	for _, c := range e.Candidates {
		parts = append(parts, fmt.Sprintf("%s %q", c.ProductID, c.ProductName))
	}
	return fmt.Sprintf("platform binding is ambiguous: repository %s maps to %d products in tenant %q: [%s]. "+
		"Pass exactly one: `cilock login --product <uuid>`.",
		repo, len(e.Candidates), e.TenantName, strings.Join(parts, ", "))
}

// repoIdentifiers prefers the endpoint-supplied repository + id, falling back to
// the ambient GitHub Actions env (GITHUB_REPOSITORY / GITHUB_REPOSITORY_ID) so
// the message names the repo even when the typed error omits it.
func repoIdentifiers(repo, repoID string) (string, string) {
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if repoID == "" {
		repoID = os.Getenv("GITHUB_REPOSITORY_ID")
	}
	if repo == "" {
		repo = "(unknown repository)"
	}
	if repoID == "" {
		repoID = "(unknown)"
	}
	return repo, repoID
}

// applyPlatformCredential wires a stored login credential into the run: the
// Archivista bearer (session credentials only), the keyless Fulcio signer, and
// the logged-in Archivista-on default. Split out of ResolvePlatformDefaults to
// keep that method's nesting flat.
func (ro *RunOptions) applyPlatformCredential(cmd *cobra.Command, cred *auth.Credential, pc platformconfig.PlatformConfig) {
	_ = os.Setenv(platformURLEnv, auth.NormalizeURL(ro.PlatformURL))

	// Capture the tenant + identity for the post-run summary so the agent can
	// confirm WHICH tenant/identity the attestation was bound to without
	// re-reading the credential store.
	ro.resolvedTenantName = cred.TenantName
	ro.resolvedSignerEmail = cred.Email
	ro.platformPrincipal = &platformPrincipal{Kind: "session", Name: sessionPrincipalName(cred, ro.PlatformURL)}

	// Only attach the platform bearer when uploading to the platform's own
	// Archivista origin (never leak the JWT to a third-party --archivista-server),
	// and only for a session credential — a workflow-identity marker carries no
	// stored token (its Archivista auth comes from --archivista-oidc, auto-enabled
	// in GitHub Actions).
	if cred.Token != "" && !hasAuthorizationHeader(ro.ArchivistaOptions.Headers) && sameOrigin(ro.ArchivistaOptions.Url, pc.Archivista) {
		ro.ArchivistaOptions.Headers = append(ro.ArchivistaOptions.Headers, "Authorization: Bearer "+cred.Token)
	}

	// Keyless signing — feed the fulcio signer an OIDC token the platform's Fulcio
	// trusts so a minimal-flag `cilock run` signs keyless after `cilock login`:
	//   - workflow identity (CI ambient OIDC, no stored token): mint a fresh GitHub
	//     Actions OIDC token carrying the Fulcio signing audience.
	//   - session login (browser/token): exchange the stored session at
	//     /oauth/sign-token for a short-lived signing token.
	if cred.AuthMode == auth.AuthModeWorkflowOIDC {
		// Only claim workflow identity when the token was ACTUALLY installed —
		// the helper fails open (no CI OIDC, explicit override, foreign Fulcio),
		// and an over-claimed identity would misstate the signing path.
		ro.signerWorkflowIdentity, ro.refreshFulcioToken = applyWorkflowKeylessFulcioToken(cmd, pc.Fulcio, pc.OIDCClientID)
	} else {
		ro.keylessAssurance, ro.refreshFulcioToken = applyKeylessFulcioToken(cmd, ro.PlatformURL, pc.Fulcio, cred.Token)
	}

	// Archivista on by default whenever we have a platform identity — a SESSION
	// credential (carries a tenant) OR a CI workflow identity (whose ambient OIDC
	// `cilock trust` maps to a tenant; its upload auth comes from --archivista-oidc,
	// auto-enabled in GitHub Actions). The user clearly wants their evidence on the
	// platform, so requiring --enable-archivista is needless friction — and silently
	// NOT uploading is its own footgun. An UNTRUSTED CI identity gets a clear
	// "run cilock trust" error on upload (see uploadError in cli/run.go), not a
	// silent sign-only. Never override an explicit choice; offline/no-platform
	// (no credential resolved here) keeps Enable false.
	if !cmd.Flags().Changed("enable-archivista") && !cmd.Flags().Changed("enable-archivist") {
		ro.ArchivistaOptions.Enable = true
	}
}

//nolint:funlen // each flag carries its own multi-line help text; splitting the registration loses readability
func (ro *RunOptions) AddFlags(cmd *cobra.Command) {
	ro.SignerOptions.AddFlags(cmd)
	ro.ArchivistaOptions.AddFlags(cmd)
	cmd.Flags().StringVar(&ro.PlatformURL, "platform-url", platformconfig.DefaultPlatformURL,
		"TestifySec platform URL — derives the Archivista, Fulcio, and TSA URLs "+
			"(default "+platformconfig.DefaultPlatformURL+"). Run 'cilock login' to authenticate to the "+
			"hosted platform, or bring your own infrastructure by overriding --signer-* (key provider), "+
			"--timestamp-servers (timestamper), and --archivista-server (attestation storage). Pass "+
			"--platform-url \"\" to run fully offline. Additional key/signer providers can be compiled in — "+
			"see https://github.com/aflock-ai/rookery/blob/main/docs/signers.md")
	cmd.Flags().BoolVar(&ro.Offline, "offline", false,
		"Run with no platform integration — a clear alias for --platform-url \"\". Drops the hosted "+
			"Fulcio/TSA/Archivista defaults and skips the session lookup; signing continues with the "+
			"configured local --signer-* key only (no third-party timestamp).")
	cmd.Flags().BoolVar(&ro.NoProductBinding, "no-product-binding", false,
		"Opt a platform-authenticated run out of the fail-closed product-binding gate. By default, "+
			"when cilock is authenticated to the platform it resolves the repository's product and FAILS "+
			"the run if the repo maps to zero or multiple products (so no unlinkable evidence is produced). "+
			"Set this for a legitimate authenticated run not tied to a product (e.g. an org-level attestation).")
	cmd.Flags().StringVarP(&ro.WorkingDir, "workingdir", "d", "", "Directory from which commands will run")
	cmd.Flags().StringSliceVarP(&ro.Attestations, "attestations", "a", DefaultAttestors, "Attestations to record ('product' and 'material' are always recorded)")
	cmd.Flags().StringSliceVar(&ro.DirHashGlobs, "dirhash-glob", []string{}, "Dirhash glob can be used to collapse material and product hashes on matching directory matches.")
	cmd.Flags().StringSliceVar(&ro.Hashes, "hashes", []string{"sha256"}, "Hashes selected for digest calculation. Defaults to SHA256")
	cmd.Flags().StringVarP(&ro.OutFilePath, "outfile", "o", "", "File to write signed data to")
	cmd.Flags().StringVarP(&ro.StepName, "step", "s", "", "Name of the step being run")
	cmd.Flags().BoolVarP(&ro.Tracing, "trace", "r", false, "Enable tracing for the command")
	cmd.Flags().StringVar(&ro.ScriptCapture, "script-capture", "identity",
		"How much of an executed script or makefile to record: 'identity' (default — "+
			"resolved path, size and sha256, no bytes), 'content' (additionally embeds "+
			"the script body), or 'off'. Content is opt-in because build scripts routinely "+
			"inline credentials and an attestation is signed, immutable and broadly "+
			"readable — a secret captured there cannot be withdrawn.")
	cmd.Flags().StringVar(&ro.CaptureMode, "capture-mode", "auto",
		"Where material + product attestors get their digests, plus optional tracer-backend "+
			"selector for trace modes. Base modes: 'auto' (default — picks the fastest available), "+
			"'walk' (directory walk; race-prone with concurrent writers), 'trace' (requires "+
			"tracing data; fails if unavailable), 'ima' (kernel IMA — not yet wired). "+
			"Trace modes accept an optional ':<backend>' suffix: "+
			"'trace:ebpf' = require eBPF, fail loudly if unavailable; "+
			"'trace:ptrace' = use ptrace+seccomp, skip eBPF probe; "+
			"'trace:auto' = probe eBPF then fall back to ptrace silently (recommended default).")
	cmd.Flags().StringSliceVar(&ro.CacheAddPatterns, "cache-add-pattern", nil,
		"Add a glob pattern to the cache/temp classifier. Files written by the tracee "+
			"matching any cache pattern are surfaced as cache artifacts, not products. "+
			"Repeatable. Globs use gobwas/glob syntax (* matches non-/; ** matches any).")
	cmd.Flags().StringSliceVar(&ro.CacheAllowPatterns, "cache-allow-pattern", nil,
		"Remove a pattern from the cache/temp classifier. Matches against the configured "+
			"pattern strings (defaults + user adds), not against file paths. Use to keep a "+
			"specific path as a product when a default classifies it as cache (e.g., "+
			"--cache-allow-pattern='**/target/release/**' to treat Rust release binaries as products).")
	cmd.Flags().BoolVar(&ro.CacheDisableDefaults, "cache-disable-defaults", false,
		"Drop the built-in DefaultCachePatterns set entirely. Operator must explicitly add "+
			"any cache patterns via --cache-add-pattern. Useful for sealed-environment compliance builds.")
	cmd.Flags().BoolVar(&ro.CacheDisableEnvProbe, "cache-disable-env-probe", false,
		"Skip env-var discovery of cache paths (XDG_CACHE_HOME, GOCACHE, CARGO_HOME, etc.). "+
			"Use in containerized builds where host env vars should not influence classification.")
	cmd.Flags().BoolVar(&ro.IgnoreCommandExitCode, "ignore-command-exit-code", false,
		"Record the wrapped command's exit code in command-run/v0.1 but do NOT abort the cilock run "+
			"on non-zero exit. Use with tools that exit non-zero on findings (semgrep, gosec, hadolint, "+
			"checkov, trivy --exit-code, prowler v3, govulncheck) so postproduct attestors still fire and "+
			"the SARIF/JSON output is captured. Policy Rego retains access to the real exit code via "+
			"input.attestation.exitcode for gating.")
	cmd.Flags().BoolVar(&ro.Diagnose, "diagnose", false,
		"Enable verbose internal logging across cilock subsystems (eBPF program loading, "+
			"fanotify event traces, ringbuf drop reporting, fs-verity probe results). "+
			"Off by default. Replaces the per-feature CILOCK_EBPF_DEBUG / CILOCK_BPF_DIAGNOSE env vars.")
	cmd.Flags().StringVar(&ro.Hardening, "hardening", "standard",
		"Bundle integrity toggles (fanotify, fs-verity, require-zero-drops) into a named profile. "+
			"'off' = minimum overhead, no fanotify or fs-verity. "+
			"'standard' (default) = fanotify on, fs-verity opportunistic, drops surfaced as warnings. "+
			"'strict' = fanotify required, fs-verity required, drops fail the run. "+
			"Explicit CILOCK_FANOTIFY / CILOCK_FSVERITY env vars still win.")
	cmd.Flags().BoolVar(&ro.RequireZeroDrops, "require-zero-drops", false,
		"Fail the run if the eBPF ringbuf dropped any event during the trace. "+
			"Default derives from --hardening (strict ⇒ true).")
	cmd.Flags().StringVar(&ro.Workload, "workload", "auto",
		"How attestors are picked. By default cilock auto-detects ONLY when you "+
			"don't pass -a: it inspects the workspace (go-build for go.mod, git "+
			"for .git/, etc.) and attaches detected attestors. Pass -a and that "+
			"becomes your exact set with no detection. Set --workload explicitly "+
			"to override: 'auto' forces detection even alongside -a; 'manual' "+
			"disables detection entirely.")
	cmd.Flags().BoolVar(&ro.ValidateOnly, "validate-only", false,
		"Run the pre-flight workload + tool-availability checks, print the planned "+
			"attestor set + warnings, then exit without running the user command. "+
			"Use to dry-run a cilock config in CI before committing it.")
	cmd.Flags().StringSliceVarP(&ro.TimestampServers, "timestamp-servers", "t", []string{}, "Timestamp Authority Servers to use when signing envelope")

	cmd.Flags().StringVar(&ro.OutputFormat, "output-format", "text",
		"How to report the run result. 'text' (default) prints a human-readable, "+
			"self-explaining summary (working dir, subjects/anchor, tenant, signer, "+
			"Fulcio/TSA/Archivista destinations) to stderr. 'json' emits a single "+
			"machine-readable result object {gitoid, archivista_url, tenant, signer, "+
			"subjects, attestors:[{name,status}], wrapped_command:{exit_code}, ...} to "+
			"stdout — logr and the human summary stay on stderr, and the wrapped command's "+
			"own output is redirected to stderr so stdout carries ONLY the JSON object.")
	var jsonShorthand bool
	cmd.Flags().BoolVar(&jsonShorthand, "json", false, "Shorthand for --output-format json (structured run result on stdout).")
	// Resolve --json into OutputFormat at parse time. PreRunE composes with
	// any existing hook so this stays self-contained to the flag registration.
	prev := cmd.PreRunE
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		if jsonShorthand && !c.Flags().Changed("output-format") {
			ro.OutputFormat = "json"
		}
		if prev != nil {
			return prev(c, args)
		}
		return nil
	}

	cmd.Flags().StringArrayVar(&ro.Subjects, "subjects", []string{},
		"Additional in-toto subject to inject into the attestation collection. Repeat the flag to add multiple. "+
			"Each value is either a bare name (e.g. 'product:<uuid>') in which case a sha256 digest of the name is synthesised, "+
			"or 'name=<alg>:<hex>' to supply an explicit digest (e.g. 'binary=sha256:abc...'). "+
			"User subjects are additive; on key collision the explicit entry wins.")

	cmd.Flags().BoolVarP(&ro.EnvFilterSensitiveVars, "env-filter-sensitive-vars", "", false, "Switch from obfuscate to filtering variables which removes them from the output completely.")
	cmd.Flags().BoolVarP(&ro.EnvDisableSensitiveVars, "env-disable-default-sensitive-vars", "", false, "Disable the default list of sensitive vars and only use the items mentioned by --add-sensitive-key.")
	cmd.Flags().StringSliceVar(&ro.EnvAddSensitiveKeys, "env-add-sensitive-key", []string{}, "Add keys or globs (e.g. '*TEXT') to the list of sensitive environment keys.")
	cmd.Flags().StringSliceVar(&ro.EnvAllowSensitiveKeys, "env-allow-sensitive-key", []string{}, "Allow specific keys from the list of sensitive environment keys. Note: This does not support globs.")
	cmd.Flags().StringSliceVar(&ro.PrewalkSkipDirs, "prewalk-skip-dir", nil,
		"Add a directory basename to the pre-trace walk skip list. The walk snapshots "+
			"workspace state to distinguish overwrites from clean creations; by default it skips "+
			".git, node_modules, vendor, .cache. Repeatable. Additive on top of defaults. "+
			"Use --prewalk-include-dir to remove names from the skip set.")
	cmd.Flags().StringSliceVar(&ro.PrewalkIncludeDirs, "prewalk-include-dir", nil,
		"Force the pre-trace walk to descend into the given directory basename even if it "+
			"is in the built-in skip set or --prewalk-skip-dir list. Repeatable. Most-specific "+
			"wins: include beats skip. Use when a build legitimately writes into one of the "+
			"default-skipped trees (e.g. a vendoring step producing files under vendor/).")
	cmd.Flags().StringSliceVar(&ro.NoDefaultAttestors, "no-default-attestor", nil,
		"Drop the named always-on attestor (product, material) from the run. Repeatable. "+
			"Disabling BOTH product and material is a fatal error: the attestation collection "+
			"would have no body to attest. Use sparingly — these defaults exist for a reason.")
	cmd.Flags().BoolVar(&ro.RequireProducts, "require-products", false,
		"Refuse to write or upload the attestation when the product attestor recorded nothing. "+
			"Use on steps that exist to prove which artifact they produced: without a product "+
			"subject the envelope still names the commit and the pipeline, so a silently empty "+
			"product set reads as a complete record of a build that in fact proves no artifact.")
	cmd.Flags().StringSliceVar(&ro.EnvCaptureAllowlist, "env-capture-allowlist", []string{},
		"Positive allowlist for environment capture. When set, only env keys matching one of the patterns "+
			"(exact key like PATH, or glob like GITHUB_*) are captured. Everything else is dropped — not obfuscated, not recorded. "+
			"Use when committing captured envelopes to a public repo to avoid leaking validator-workstation state. "+
			"Defense-in-depth: the sensitive-keys obfuscate/filter pipeline still runs on top of the allowlist.")

	cmd.MarkFlagsRequiredTogether(RequiredRunFlags...)

	attestationRegistrations := attestation.RegistrationEntries()
	ro.AttestorOptSetters = addFlagsFromRegistry("attestor", attestationRegistrations, cmd)

	ro.KMSSignerProviderOptions.AddFlags(cmd)
}

type ArchivistaOptions struct {
	Enable   bool
	Url      string
	Headers  []string
	OIDC     bool   // Enable OIDC auth — fetch GitHub Actions OIDC token as Bearer
	Audience string // OIDC audience (defaults to archivista server URL)

	// UploadRetries is how many EXTRA attempts a retryable upload failure gets
	// beyond the first. 0 restores the historical single-attempt behaviour.
	UploadRetries int
	// UploadRetryBudget caps the TOTAL wall-clock time the upload may take —
	// the requests as well as the sleeps between them — so neither a server
	// handing back long Retry-After values nor one that simply stops answering
	// can park a CI job. An attempt still in flight when it expires is cut off.
	UploadRetryBudget time.Duration
}

func (o *ArchivistaOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.Enable, "enable-archivista", false,
		"Use Archivista to store or retrieve attestations (automatic for authenticated platform runs)")
	cmd.Flags().BoolVar(&o.Enable, "enable-archivist", false, "Use Archivista to store or retrieve attestations (deprecated)")
	if err := cmd.Flags().MarkHidden("enable-archivist"); err != nil {
		log.Errorf("failed to hide enable-archivist flag: %v", err)
	}

	defaultArchivista := platformconfig.Derive("").Archivista
	cmd.Flags().StringVar(&o.Url, "archivista-server", defaultArchivista, "URL of the Archivista server (derived from --platform-url if not set)")
	cmd.Flags().StringVar(&o.Url, "archivist-server", defaultArchivista, "URL of the Archivista server (deprecated)")
	if err := cmd.Flags().MarkHidden("archivist-server"); err != nil {
		log.Debugf("failed to hide archivist-server flag: %v", err)
	}

	cmd.Flags().StringArrayVar(&o.Headers, "archivista-headers", []string{}, "Headers to provide to the Archivista client when making requests")

	defaultRetry := archivista.DefaultRetryPolicy()
	cmd.Flags().IntVar(&o.UploadRetries, "archivista-upload-retries", defaultRetry.MaxAttempts-1,
		"Extra attempts for a retryable attestation upload failure (5xx, timeout, connection reset, 429). "+
			"0 disables retry. Terminal failures (400/401/403/422) never retry.")
	cmd.Flags().DurationVar(&o.UploadRetryBudget, "archivista-upload-retry-budget", defaultRetry.Budget,
		"Total wall-clock time the attestation upload may take across all attempts, including the "+
			"requests themselves, before giving up")
	cmd.Flags().BoolVar(&o.OIDC, "archivista-oidc", os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "", "Use GitHub Actions OIDC token for Archivista auth (auto-enabled in GitHub Actions)")
	cmd.Flags().StringVar(&o.Audience, "archivista-audience", "", "OIDC audience for Archivista token (defaults to archivista server URL)")
}

// Client creates an Archivista client from the current options.
// Returns (nil, nil) if archivista is not enabled.
func (o *ArchivistaOptions) Client() (*archivista.Client, error) {
	if !o.Enable {
		return nil, nil
	}

	headers := http.Header{}

	opts := make([]archivista.Option, 0)

	// OIDC auth: mint GitHub Actions OIDC tokens for Archivista requests.
	// Same pattern as Fulcio signing — requests a token from the GitHub Actions
	// OIDC endpoint with a custom audience scoped to Archivista.
	//
	// The token is installed as a PER-REQUEST source, NOT a frozen header:
	// GitHub OIDC tokens expire ~5 minutes after issue, and a token pinned at
	// client construction outlives its validity on long operations. The v4.1.2
	// release verify hit exactly this — one policyverify ran >5 minutes and
	// every archivista graphql call after the 5-minute mark 401'd
	// ("Invalid API credential"). The source re-mints before expiry, so the
	// credential is live however long the client is used. The eager mint here
	// keeps the fail-fast behavior (a misconfigured runner errors at client
	// construction, not mid-operation) and the log line.
	if o.OIDC {
		audience := o.Audience
		if audience == "" {
			audience = o.Url
		}
		source := newGitHubOIDCTokenSource(audience, fetchGitHubOIDCToken)
		if _, err := source(); err != nil {
			return nil, fmt.Errorf("archivista OIDC auth: %w", err)
		}
		opts = append(opts, archivista.WithAuthTokenSource(source))
		log.Infof("Using GitHub Actions OIDC token for Archivista (audience: %s)", audience)
	}

	// Static headers (can override OIDC if both set — explicit headers win: an
	// explicit Authorization header suppresses the token source per the
	// archivista client's WithAuthTokenSource contract)
	for _, hString := range o.Headers {
		hParts := strings.SplitN(hString, ":", 2)
		if len(hParts) != 2 {
			return nil, fmt.Errorf("could not parse value %v as http header", hString)
		}
		headers.Set(strings.TrimSpace(hParts[0]), strings.TrimSpace(hParts[1]))
	}

	if len(headers) > 0 {
		opts = append(opts, archivista.WithHeaders(headers))
	}

	// Bounded upload retry. A transient Archivista 5xx used to abort the whole
	// `cilock run` with the signed envelope already produced but never stored,
	// which destroys the value of the entire gate execution — the only recovery
	// was to re-run the wrapped command and re-attest (~6 minutes in the case
	// that motivated this). Retrying HERE, inside the live run, is the correct
	// and only place to absorb it: the execution context is still open, so the
	// evidence stays attached to the act that produced it.
	//
	// The retry is deliberately NOT enabled inside archivista.New — this client
	// is shared with judge-api and the policy-publish path, which should keep
	// their existing single-attempt semantics.
	if o.UploadRetries > 0 {
		policy := archivista.DefaultRetryPolicy()
		policy.MaxAttempts = o.UploadRetries + 1
		if o.UploadRetryBudget > 0 {
			policy.Budget = o.UploadRetryBudget
		}
		opts = append(opts, archivista.WithRetry(policy))
	}

	return archivista.New(o.Url, opts...), nil
}

// githubOIDCRefreshAfter is how long a minted GitHub Actions OIDC token is
// served from cache before the source re-mints. GitHub issues these tokens
// with a ~5-minute exp; refreshing at 4 minutes keeps a >=1-minute liveness
// margin on every request while staying far from per-request mint chatter.
const githubOIDCRefreshAfter = 4 * time.Minute

// newGitHubOIDCTokenSource returns a concurrency-safe token source that mints
// a GitHub Actions OIDC token for audience via fetch and re-mints once the
// cached token is older than githubOIDCRefreshAfter.
//
// A refresh failure is returned as an error, NOT papered over with the stale
// token: the stale token is at/near expiry, and sending it would reproduce
// the confusing mid-operation 401 this source exists to prevent. fetch is a
// parameter for testability.
func newGitHubOIDCTokenSource(audience string, fetch func(string) (string, error)) func() (string, error) {
	var mu sync.Mutex
	var token string
	var mintedAt time.Time
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if token != "" && time.Since(mintedAt) < githubOIDCRefreshAfter {
			return token, nil
		}
		t, err := fetch(audience)
		if err != nil {
			return "", fmt.Errorf("mint github actions oidc token: %w", err)
		}
		token, mintedAt = t, time.Now()
		return token, nil
	}
}

// fetchGitHubOIDCToken requests an OIDC token from GitHub Actions with the
// given audience. Reuses the same ACTIONS_ID_TOKEN_REQUEST_URL mechanism
// that Fulcio uses for signing certs.
func fetchGitHubOIDCToken(audience string) (string, error) {
	tokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if tokenURL == "" {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL not set (not in GitHub Actions, or missing id-token: write permission)")
	}
	bearerToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if bearerToken == "" {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")
	}

	u, err := url.Parse(tokenURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse token URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+bearerToken)

	// Bound the request. This is the FIRST network op on the ambient-OIDC path
	// (it mints the token for both keyless Fulcio signing and the Archivista
	// upload), and http.DefaultClient has no Timeout. A GitHub OIDC endpoint that
	// TCP-accepts then stalls would otherwise park `cilock run` until the CI job
	// timeout (observed: a 20-min hang with no error). A client Timeout bounds the
	// whole request even though this helper carries no context.
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("OIDC token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode OIDC token response: %w", err)
	}
	if tokenResp.Value == "" {
		return "", fmt.Errorf("empty OIDC token in response")
	}

	return tokenResp.Value, nil
}
