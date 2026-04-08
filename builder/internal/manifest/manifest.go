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

// PluginSpec represents a plugin in the manifest.
// Exactly one of Module, Git, or Path should be set.
type PluginSpec struct {
	// Module is a Go module import path (fetched via go get)
	Module string `yaml:"module,omitempty"`
	// Version pins the module version (only with Module)
	Version string `yaml:"version,omitempty"`

	// Git is a git repository URL (cloned and used locally)
	Git string `yaml:"git,omitempty"`
	// Ref is a branch, tag, or commit (only with Git, defaults to HEAD)
	Ref string `yaml:"ref,omitempty"`
	// Subdir is a subdirectory within the git repo containing the plugin (only with Git)
	Subdir string `yaml:"subdir,omitempty"`

	// Path is a local filesystem path to a plugin module
	Path string `yaml:"path,omitempty"`
}

// BuildOptions represents build configuration options
type BuildOptions struct {
	LdFlags     string `yaml:"ldflags,omitempty"`
	Trimpath    *bool  `yaml:"trimpath,omitempty"`
	FipsMode    string `yaml:"fips_mode,omitempty"`    // "on", "only", or "" for off
	CustomerID  string `yaml:"customer_id,omitempty"`  // Optional customer identifier
	TenantID    string `yaml:"tenant_id,omitempty"`    // Optional tenant identifier
	PlatformURL string `yaml:"platform_url,omitempty"` // TestifySec platform URL (baked into binary)
}

// LoadManifest loads a manifest from a YAML file
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is caller-provided manifest path
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

	// Validate plugin specs
	for i, p := range m.Plugins {
		sources := 0
		if p.Module != "" {
			sources++
		}
		if p.Git != "" {
			sources++
		}
		if p.Path != "" {
			sources++
		}
		if sources == 0 {
			return nil, fmt.Errorf("plugin %d: must specify one of module, git, or path", i)
		}
		if sources > 1 {
			return nil, fmt.Errorf("plugin %d: specify only one of module, git, or path", i)
		}
	}

	return &m, nil
}
