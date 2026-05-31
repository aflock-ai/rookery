// Package config provides platform configuration for the TestifySec platform.
// It derives all service URLs from a single platform URL.
package config

import "strings"

// DefaultPlatformURL is the hosted TestifySec platform.
// This is compiled into the binary and used when no platform-url is specified.
// Enterprise/self-hosted builds override this via ldflags.
var DefaultPlatformURL = "https://platform.testifysec.com"

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
		PlatformURL:       platformURL,
		Archivista:        platformURL + "/archivista",
		Fulcio:            platformURL + "/fulcio",
		TSA:               platformURL + "/api/v1/timestamp",
		OIDCAudience:      platformURL + "/archivista",
		OIDCLoginAudience: platformURL + "/login",
		OIDCIssuer:        "https://token.actions.githubusercontent.com",
		OIDCClientID:      "sigstore",
	}
}
