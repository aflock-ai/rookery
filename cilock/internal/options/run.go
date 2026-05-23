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
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

var DefaultAttestors = []string{"environment", "git"}

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
	TimestampServers         []string
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

	// NOTE: We intentionally do NOT force enable-archivista here.
	// The flag defaults to false and users/configs may rely on that.
	// Archivista is enabled explicitly via --enable-archivista or config.
}

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
