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
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse platform url: %w", err)
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("refusing to source trust from discovery over %q: platform url must be https (got %q)", u.Scheme, base)
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

// NormalizeURL trims surrounding space and a trailing slash so platform URLs
// compare and concatenate consistently. Mirrors auth.NormalizeURL (kept here to
// avoid an import cycle: auth already depends on config).
func NormalizeURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

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
