package manifest

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Manifest represents a build configuration file
type Manifest struct {
	Name               string       `yaml:"name"`
	Output             string       `yaml:"output"`
	Preset             string       `yaml:"preset,omitempty"`
	AttestationVersion string       `yaml:"attestation_version,omitempty"`
	Plugins            []PluginSpec `yaml:"plugins,omitempty"`
	BuildOptions       BuildOptions `yaml:"build_options,omitempty"`
}

// PluginSpec represents a plugin specification in the manifest
type PluginSpec struct {
	ImportPath string `yaml:"import_path"`
	Version    string `yaml:"version,omitempty"`
	LocalPath  string `yaml:"local_path,omitempty"`
}

// BuildOptions represents build configuration options
type BuildOptions struct {
	LdFlags    string `yaml:"ldflags,omitempty"`
	Trimpath   *bool  `yaml:"trimpath,omitempty"`
	FipsMode   string `yaml:"fips_mode,omitempty"`   // "on", "only", or "" for off
	CustomerID string `yaml:"customer_id,omitempty"` // Optional customer identifier
	TenantID   string `yaml:"tenant_id,omitempty"`   // Optional tenant identifier
}

// LoadManifest loads a manifest from a YAML file
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Set defaults
	if m.Output == "" {
		if m.Name != "" {
			m.Output = m.Name
		} else {
			m.Output = "aflock-custom"
		}
	}

	// Make output path absolute if relative
	if !filepath.IsAbs(m.Output) {
		absPath, err := filepath.Abs(m.Output)
		if err == nil {
			m.Output = absPath
		}
	}

	return &m, nil
}
