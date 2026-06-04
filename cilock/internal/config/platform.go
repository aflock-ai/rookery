// Package config provides platform configuration for the TestifySec platform.
// It derives all service URLs from a single platform URL.
package config

import (
	"strings"
	"sync"
)

// DefaultPlatformURL is the hosted TestifySec platform.
// This is compiled into the binary and used when no platform-url is specified.
// Enterprise/self-hosted builds override this via ldflags.
var DefaultPlatformURL = "https://platform.testifysec.com"

// PlatformURLEnv carries the platform URL the current cilock command bound to
// (the logged-in platform session resolved from --platform-url). run/verify set
// it when a credential exists for that platform; telemetry reads it so usage is
// attributed to the platform actually used (staging / self-hosted / a custom
// --platform-url), not just the compiled-in default. Single source of truth for
// the env-var name shared by the options and telemetry packages.
const PlatformURLEnv = "CILOCK_PLATFORM_URL"

// trustedPlatformBinding records the platform URL that the trusted run-option
// resolver (RunOptions.ResolvePlatformDefaults) authorized for a workflow-identity
// platform binding, after it confirmed the upload targets the platform's OWN
// Archivista origin (same-origin) under an ambient OIDC identity.
//
// It is the in-process trust handshake between the resolver and the platform
// attestor. CILOCK_PLATFORM_URL alone is NOT sufficient to bind: that env var is
// inherited/user-controllable, so a hostile CI step could export it directly and
// make the attestor stamp a forged platform_url into a signed predicate without
// the resolver's same-origin check ever running. This flag, set only by trusted
// in-process code paths, closes that confused-deputy gap — an external env var
// cannot flip it. Stored normalized (NormalizeURL-equivalent: trimmed, no trailing
// slash) so the attestor can compare it to the value it is about to bind.
var (
	trustedPlatformBinding   string
	trustedPlatformBindingMu sync.RWMutex
)

// MarkTrustedPlatformBinding records that the trusted resolver authorized a
// workflow-identity platform binding for platformURL. Called by
// RunOptions.ResolvePlatformDefaults after its same-origin + ambient-OIDC checks
// pass. The platform attestor's ambient branch requires this marker to match the
// URL it is about to bind, so an externally-injected CILOCK_PLATFORM_URL cannot
// forge a binding on its own.
func MarkTrustedPlatformBinding(platformURL string) {
	trustedPlatformBindingMu.Lock()
	defer trustedPlatformBindingMu.Unlock()
	trustedPlatformBinding = strings.TrimRight(strings.TrimSpace(platformURL), "/")
}

// TrustedPlatformBinding reports the platform URL the trusted resolver authorized
// for a workflow-identity binding, and whether one was set this process. Empty +
// false when no trusted in-process path marked a binding.
func TrustedPlatformBinding() (string, bool) {
	trustedPlatformBindingMu.RLock()
	defer trustedPlatformBindingMu.RUnlock()
	return trustedPlatformBinding, trustedPlatformBinding != ""
}

// PlatformConfig holds derived service URLs from a single platform URL.
type PlatformConfig struct {
	PlatformURL  string
	Archivista   string
	Fulcio       string
	TSA          string
	OIDCAudience string
	// OIDCLoginAudience is the audience a workflow-identity OIDC token must carry
	// to authenticate `cilock login` against the platform. It is intentionally
	// DISTINCT from OIDCAudience (Archivista upload) and from the Fulcio signing
	// audience ("sigstore") — reusing either would be a confused-deputy hazard
	// (a token minted for one purpose replayed to obtain a login session).
	OIDCLoginAudience string
	OIDCIssuer        string
	OIDCClientID      string
}

// Derive computes all service URLs from the platform URL.
// If platformURL is empty, uses DefaultPlatformURL.
func Derive(platformURL string) PlatformConfig {
	if platformURL == "" {
		platformURL = DefaultPlatformURL
	}
	// Normalize: strip trailing slash
	platformURL = strings.TrimRight(platformURL, "/")

	return PlatformConfig{
		PlatformURL: platformURL,
		Archivista:  platformURL + "/archivista",
		// Fulcio's gRPC-gateway REST API is mounted at the platform root
		// (/api/v2/signingCert); the fulcio signer appends the /api/v2 path
		// itself, so the base URL is the platform root, NOT a /fulcio subpath.
		Fulcio:            platformURL,
		TSA:               platformURL + "/api/v1/timestamp",
		OIDCAudience:      platformURL + "/archivista",
		OIDCLoginAudience: platformURL + "/login",
		OIDCIssuer:        "https://token.actions.githubusercontent.com",
		OIDCClientID:      "sigstore",
	}
}
