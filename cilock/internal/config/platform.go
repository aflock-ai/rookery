// Package config provides platform configuration for the TestifySec platform.
// It derives all service URLs from a single platform URL.
package config

import "strings"

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
