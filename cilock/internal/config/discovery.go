// Package config — platform discovery.
//
// The platform serves a single discovery document at
// /.well-known/judge-configuration that collates everything a client needs to
// sign AND verify against it: service URLs, the Fulcio signing endpoint, the
// public OIDC issuer baked into keyless certs, the CA trust bundle (inlined),
// and the assurance level signatures are minted at. Fetching this one document
// is what lets `cilock verify` derive trust with no CA files or issuer flags.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// discoveryPath is the well-known discovery endpoint, served unauthenticated.
const discoveryPath = "/.well-known/judge-configuration"

// SigningDiscovery is the signing/trust half of the discovery document.
type SigningDiscovery struct {
	FulcioURL        string `json:"fulcio_url"`
	FulcioOIDCIssuer string `json:"fulcio_oidc_issuer"`
	OIDCAudience     string `json:"oidc_audience"`
	TrustBundleURL   string `json:"trust_bundle_url"`
	TrustBundlePEM   string `json:"trust_bundle_pem"`
	TSACertChainURL  string `json:"tsa_cert_chain_url"`
	AssuranceLevel   string `json:"assurance_level"`
}

// Discovery is the parsed /.well-known/judge-configuration document.
type Discovery struct {
	ArchivistaURL string            `json:"archivista_url"`
	TSAURL        string            `json:"tsa_url"`
	GraphQLURL    string            `json:"graphql_url"`
	Signing       *SigningDiscovery `json:"signing"`
}

// Discover fetches and parses the platform discovery document. platformURL is
// the platform origin; the well-known path is appended. Returns an error on any
// transport/parse failure — callers treat discovery as best-effort and fall
// back to explicit flags, so a failure here is non-fatal at the call site.
func Discover(platformURL string) (*Discovery, error) {
	base := strings.TrimRight(NormalizeURL(platformURL), "/")
	if base == "" {
		return nil, fmt.Errorf("empty platform url")
	}
	// Discovery establishes VERIFICATION TRUST (the policy-signer CA roots and the
	// Fulcio OIDC issuer). Sourcing that over plaintext lets any on-path attacker
	// substitute trust material, so a verify would PASS against attacker-signed
	// evidence. Require HTTPS — the one exception is loopback, where standalone/dev
	// legitimately serves the platform over http://localhost.
	if err := RequireSecurePlatformURL(base); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, base+discoveryPath, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %d", resp.StatusCode)
	}
	var d Discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode discovery: %w", err)
	}
	return &d, nil
}

// FetchTSACertChain downloads the platform TSA certificate chain (PEM) that
// discovery advertises at Signing.TSACertChainURL. It is the timestamp-trust
// analogue of the inlined Signing.TrustBundlePEM: the chain that lets verify
// validate RFC3161 tokens minted by the platform TSA without the user passing
// --policy-timestamp-servers.
//
// Two guards, mirroring how the trust bundle travels:
//   - same-origin: the chain is fetched only from the PLATFORM's own origin. A
//     (possibly attacker-influenced) discovery document must not be able to
//     point trust-material retrieval at a third-party host (#5987).
//   - secure transport: https, or http for loopback only, exactly like the
//     discovery fetch itself — timestamp roots sourced over cleartext could be
//     substituted by an on-path attacker (see issue #5997).
//
// Callers must additionally gate ADOPTION of the returned chain on the same
// trust decision that governs the discovery CA bundle (the GHSA #5988 TOFU
// pin) — fetching is transport-safe here, but trusting is the caller's call.
func FetchTSACertChain(platformURL string, disc *Discovery) ([]byte, error) {
	if disc == nil || disc.Signing == nil || disc.Signing.TSACertChainURL == "" {
		return nil, nil
	}
	chainURL := disc.Signing.TSACertChainURL
	if !SameOrigin(chainURL, platformURL) {
		return nil, fmt.Errorf("discovery tsa_cert_chain_url %q is not on the platform origin %q; refusing cross-origin trust material", chainURL, platformURL)
	}
	if err := RequireSecurePlatformURL(chainURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, chainURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build tsa cert chain request: %w", err)
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: SameOriginRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch tsa cert chain: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa cert chain endpoint returned %d", resp.StatusCode)
	}
	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read tsa cert chain: %w", err)
	}
	if !strings.Contains(string(pemBytes), "BEGIN CERTIFICATE") {
		return nil, fmt.Errorf("tsa cert chain endpoint %q returned no PEM certificates", chainURL)
	}
	return pemBytes, nil
}

// NormalizeURL trims surrounding space and a trailing slash so platform URLs
// compare and concatenate consistently. Mirrors auth.NormalizeURL (kept here to
// avoid an import cycle: auth already depends on config).
func NormalizeURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

// RequireSecurePlatformURL refuses a platform URL that would carry trust
// material or a bearer token over cleartext. It permits https:// for any host,
// and http:// only for loopback (local standalone/dev). Any other scheme — most
// importantly a non-loopback http:// — is rejected with an error that names the
// https requirement.
//
// This is the single guard shared by discovery (which sources trust material)
// and every token-bearing call site (which attaches a session bearer): both
// must refuse cleartext to a non-loopback host before any request is sent, so
// a typo, copy-paste, or MITM downgrade cannot leak a replayable bearer to an
// on-path observer. See issue #5997.
func RequireSecurePlatformURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("parse platform url: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing to use platform url over %q: must be https for a non-loopback host (got %q)", u.Scheme, rawURL)
}

// isLoopbackHost reports whether host is a loopback target for which plaintext
// http discovery is acceptable (local standalone/dev): "localhost", the reserved
// .localhost TLD, or a loopback IP (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
