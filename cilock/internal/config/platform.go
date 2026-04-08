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
	OIDCIssuer   string
	OIDCClientID string
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
		PlatformURL:  platformURL,
		Archivista:   platformURL + "/archivista",
		Fulcio:       platformURL + "/fulcio",
		TSA:          platformURL + "/api/v1/timestamp",
		OIDCAudience: platformURL + "/archivista",
		OIDCIssuer:   "https://token.actions.githubusercontent.com",
		OIDCClientID: "sigstore",
	}
}
