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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

var DefaultAttestors = []string{"environment", "git", "platform"}

// platformURLEnv tells the platform attestor which logged-in platform session
// to bind to. Kept as a literal (not an import of the attestor package) to
// avoid coupling options → attestor.
const platformURLEnv = "CILOCK_PLATFORM_URL"

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
}

var RequiredRunFlags = []string{
	"step",
}

// ResolvePlatformDefaults applies platform-derived defaults to any options
// that weren't explicitly set. Call this after flag parsing but before use.
//
// To run cilock fully offline (no platform integration), users pass
// `--platform-url ""`. That sets ro.PlatformURL to the empty string AND
// marks the flag as user-changed, so we know NOT to fall back to the
// compiled-in DefaultPlatformURL. In that mode no TSA is added (signing
// continues with the configured signer only — no third-party
// timestamp) and the archivista URL stays whatever the user set.
func (ro *RunOptions) ResolvePlatformDefaults(cmd *cobra.Command) {
	// Detect the explicit-disable case. If the user did NOT change
	// --platform-url, ro.PlatformURL holds the compiled-in default.
	// If the user passed --platform-url "" (or any empty value), we
	// treat that as "no platform" and skip all derivation.
	platformExplicitlyDisabled := cmd.Flags().Changed("platform-url") && ro.PlatformURL == ""
	if platformExplicitlyDisabled {
		// User opted out of the platform. Don't derive anything.
		return
	}

	pc := platformconfig.Derive(ro.PlatformURL)

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

	// Platform session: if the user has logged in (`cilock login`) to this
	// platform, authenticate Archivista uploads with the session token and
	// expose the platform URL to the platform attestor (via CILOCK_PLATFORM_URL)
	// so it can bind the attestation to the tenant/product. Best-effort — a
	// missing/expired session just means no platform auth (offline/CI paths
	// keep working).
	if cred, lookupErr := auth.Lookup(ro.PlatformURL); lookupErr == nil && cred != nil {
		_ = os.Setenv(platformURLEnv, auth.NormalizeURL(ro.PlatformURL))
		// Only attach the platform bearer token when the upload target is the
		// platform's own Archivista origin. Without this guard a user who
		// points --archivista-server at a third-party host while logged in
		// would leak their platform JWT to that host. Fail closed: an origin
		// mismatch (e.g. a custom --archivista-server) gets no auth header,
		// and the upload proceeds unauthenticated as it would offline.
		if !hasAuthorizationHeader(ro.ArchivistaOptions.Headers) && sameOrigin(ro.ArchivistaOptions.Url, pc.Archivista) {
			ro.ArchivistaOptions.Headers = append(ro.ArchivistaOptions.Headers, "Authorization: Bearer "+cred.Token)
		}
	}

	// NOTE: We intentionally do NOT force enable-archivista here.
	// The flag defaults to false and users/configs may rely on that.
	// Archivista is enabled explicitly via --enable-archivista or config.
}

//nolint:funlen // each flag carries its own multi-line help text; splitting the registration loses readability
func (ro *RunOptions) AddFlags(cmd *cobra.Command) {
	ro.SignerOptions.AddFlags(cmd)
	ro.ArchivistaOptions.AddFlags(cmd)
	cmd.Flags().StringVar(&ro.PlatformURL, "platform-url", platformconfig.DefaultPlatformURL, "TestifySec platform URL (derives archivista, fulcio, and TSA URLs)")
	cmd.Flags().StringVarP(&ro.WorkingDir, "workingdir", "d", "", "Directory from which commands will run")
	cmd.Flags().StringSliceVarP(&ro.Attestations, "attestations", "a", DefaultAttestors, "Attestations to record ('product' and 'material' are always recorded)")
	cmd.Flags().StringSliceVar(&ro.DirHashGlobs, "dirhash-glob", []string{}, "Dirhash glob can be used to collapse material and product hashes on matching directory matches.")
	cmd.Flags().StringSliceVar(&ro.Hashes, "hashes", []string{"sha256"}, "Hashes selected for digest calculation. Defaults to SHA256")
	cmd.Flags().StringVarP(&ro.OutFilePath, "outfile", "o", "", "File to write signed data to")
	cmd.Flags().StringVarP(&ro.StepName, "step", "s", "", "Name of the step being run")
	cmd.Flags().BoolVarP(&ro.Tracing, "trace", "r", false, "Enable tracing for the command")
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
		"How attestors are picked. 'auto' (default) inspects the workspace at "+
			"startup and adds detected attestors (go-build for go.mod, sbom for "+
			"package.json, git for .git/, etc.) to whatever --attestations lists. "+
			"'manual' uses --attestations as the exact set with no detection.")
	cmd.Flags().BoolVar(&ro.ValidateOnly, "validate-only", false,
		"Run the pre-flight workload + tool-availability checks, print the planned "+
			"attestor set + warnings, then exit without running the user command. "+
			"Use to dry-run a cilock config in CI before committing it.")
	cmd.Flags().StringSliceVarP(&ro.TimestampServers, "timestamp-servers", "t", []string{}, "Timestamp Authority Servers to use when signing envelope")

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
}

func (o *ArchivistaOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.Enable, "enable-archivista", false, "Use Archivista to store or retrieve attestations")
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

	// OIDC auth: fetch a GitHub Actions OIDC token for Archivista uploads.
	// Same pattern as Fulcio signing — requests a token from the GitHub Actions
	// OIDC endpoint with a custom audience scoped to Archivista.
	if o.OIDC {
		audience := o.Audience
		if audience == "" {
			audience = o.Url
		}
		token, err := fetchGitHubOIDCToken(audience)
		if err != nil {
			return nil, fmt.Errorf("archivista OIDC auth: %w", err)
		}
		headers.Set("Authorization", "Bearer "+token)
		log.Infof("Using GitHub Actions OIDC token for Archivista (audience: %s)", audience)
	}

	// Static headers (can override OIDC if both set — explicit headers win)
	for _, hString := range o.Headers {
		hParts := strings.SplitN(hString, ":", 2)
		if len(hParts) != 2 {
			return nil, fmt.Errorf("could not parse value %v as http header", hString)
		}
		headers.Set(strings.TrimSpace(hParts[0]), strings.TrimSpace(hParts[1]))
	}

	opts := make([]archivista.Option, 0)
	if len(headers) > 0 {
		opts = append(opts, archivista.WithHeaders(headers))
	}

	return archivista.New(o.Url, opts...), nil
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

	resp, err := http.DefaultClient.Do(req)
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
