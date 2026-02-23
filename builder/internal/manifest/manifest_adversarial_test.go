//go:build audit

package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestManifest_PluginModuleInjection tests that plugin module paths containing
// Go source code injection payloads are rejected. Module paths are interpolated
// directly into generated Go import statements via fmt.Sprintf("\t_ %q\n", ...).
// While Go's %q will quote the string, a malicious module path could still be a
// valid Go string that causes unintended behavior when used as an import path.
func TestManifest_PluginModuleInjection(t *testing.T) {
	payloads := []struct {
		name   string
		module string
	}{
		{
			name:   "go code in module path",
			module: `"; os.Exit(1); //`,
		},
		{
			name:   "newline injection in module path",
			module: "github.com/evil\nimport \"os\"\nfunc init() { os.Exit(1) } //",
		},
		{
			name:   "backtick injection in module path",
			module: "github.com/evil`; rm -rf /; `",
		},
		{
			name:   "null byte in module path",
			module: "github.com/evil\x00malicious",
		},
		{
			name:   "tab injection in module path",
			module: "github.com/evil\t\"os\"\n",
		},
		{
			name:   "double quote escape in module path",
			module: `github.com/evil" + "os" + "`,
		},
		{
			name:   "carriage return injection",
			module: "github.com/evil\r\nimport \"os\"",
		},
		{
			name:   "unicode null in module path",
			module: "github.com/evil\u0000hack",
		},
		{
			name:   "path traversal in module",
			module: "../../../etc/passwd",
		},
		{
			name:   "absolute path as module",
			module: "/etc/passwd",
		},
		{
			name:   "empty module",
			module: "",
		},
		{
			name:   "space-only module",
			module: "   ",
		},
		{
			name:   "go pragma injection",
			module: "//go:generate rm -rf /",
		},
		{
			name:   "build constraint injection",
			module: "//go:build ignore",
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			// The manifest loader does NOT validate module path content.
			// It only checks that exactly one source field is set.
			// This means injection payloads pass right through.
			yaml := `
name: test
plugins:
  - module: ` + tt.module + `
`
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				// YAML parse error is acceptable — it's a form of rejection.
				// But it's not intentional validation.
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			// If we got here, the manifest loaded successfully with the malicious module path.
			// This is a VULNERABILITY — there is no validation of module path content.
			if len(m.Plugins) > 0 && m.Plugins[0].Module != "" {
				t.Logf("FINDING: Malicious module path accepted without validation: %q", m.Plugins[0].Module)
			}
		})
	}
}

// TestManifest_GitURLInjection tests that malicious git URLs are not validated.
// Git URLs are passed directly to `git clone` via exec.Command, which means
// certain URL schemes can trigger local file access or command execution.
func TestManifest_GitURLInjection(t *testing.T) {
	payloads := []struct {
		name string
		git  string
		ref  string
	}{
		{
			name: "file protocol read local files",
			git:  "file:///etc/passwd",
		},
		{
			name: "ssh command injection via URL",
			git:  "ssh://-oProxyCommand=touch${IFS}/tmp/pwned/evil.git",
		},
		{
			name: "ext protocol command execution",
			git:  "ext::sh -c touch% /tmp/pwned",
		},
		{
			name: "git protocol with null byte",
			git:  "git://evil.com/repo\x00--upload-pack=evil",
		},
		{
			name: "local path via git field",
			git:  "/tmp/evil-repo",
		},
		{
			name: "relative path via git field",
			git:  "../../../etc",
		},
		{
			name: "command substitution in ref",
			git:  "https://github.com/legit/repo.git",
			ref:  "$(touch /tmp/pwned)",
		},
		{
			name: "semicolon in ref",
			git:  "https://github.com/legit/repo.git",
			ref:  "main; touch /tmp/pwned",
		},
		{
			name: "pipe in ref",
			git:  "https://github.com/legit/repo.git",
			ref:  "main | touch /tmp/pwned",
		},
		{
			name: "newline in git URL",
			git:  "https://evil.com/repo\n--upload-pack=evil",
		},
		{
			name: "dash-prefixed URL (flag injection)",
			git:  "--upload-pack=evil",
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
name: test
plugins:
  - git: ` + tt.git + `
`
			if tt.ref != "" {
				yaml += `    ref: ` + tt.ref + `
`
			}

			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			// If we got here, the malicious git URL was accepted.
			if len(m.Plugins) > 0 && m.Plugins[0].Git != "" {
				t.Logf("FINDING: Malicious git URL accepted without validation: git=%q ref=%q",
					m.Plugins[0].Git, m.Plugins[0].Ref)
			}
		})
	}
}

// TestManifest_SubdirTraversal tests path traversal via the subdir field.
// The subdir is joined to the clone directory via filepath.Join, which does
// NOT prevent traversal via "../" sequences.
func TestManifest_SubdirTraversal(t *testing.T) {
	payloads := []struct {
		name   string
		subdir string
	}{
		{name: "parent traversal", subdir: "../../../etc"},
		{name: "absolute path", subdir: "/etc/passwd"},
		{name: "double dot", subdir: ".."},
		{name: "embedded traversal", subdir: "legit/../../etc"},
		{name: "null byte", subdir: "legit\x00/../etc"},
		{name: "tilde home", subdir: "~/malicious"},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
name: test
plugins:
  - git: https://github.com/legit/repo.git
    subdir: ` + tt.subdir + `
`
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			if len(m.Plugins) > 0 && m.Plugins[0].Subdir != "" {
				t.Logf("FINDING: Path traversal subdir accepted without validation: %q", m.Plugins[0].Subdir)
			}
		})
	}
}

// TestManifest_LdFlagsInjection tests that ldflags from the manifest are not
// validated before being passed to the Go compiler. The ldflags value is
// concatenated into the build command and could be used to inject arbitrary
// linker flags or even compiler flags.
func TestManifest_LdFlagsInjection(t *testing.T) {
	payloads := []struct {
		name    string
		ldflags string
	}{
		{
			name:    "shell command substitution",
			ldflags: "$(touch /tmp/pwned)",
		},
		{
			name:    "backtick command substitution",
			ldflags: "`touch /tmp/pwned`",
		},
		{
			name:    "flag injection via ldflags",
			ldflags: "-extldflags '-Wl,-rpath,/evil/lib'",
		},
		{
			name:    "null byte in ldflags",
			ldflags: "-X 'main.Version=1.0\x00' -extldflags '-evil'",
		},
		{
			name:    "newline injection in ldflags",
			ldflags: "-X 'main.Version=1.0'\n-toolexec 'touch /tmp/pwned'",
		},
		{
			name:    "toolexec injection via ldflags value",
			ldflags: "' -toolexec 'touch /tmp/pwned",
		},
		{
			name:    "extremely long ldflags (buffer overflow attempt)",
			ldflags: strings.Repeat("A", 100000),
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
name: test
build_options:
  ldflags: "` + strings.ReplaceAll(tt.ldflags, `"`, `\"`) + `"
plugins:
  - module: github.com/aflock-ai/rookery/plugins/attestors/git
`
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			if m.BuildOptions.LdFlags != "" {
				t.Logf("FINDING: Malicious ldflags accepted without validation: %q", m.BuildOptions.LdFlags)
			}
		})
	}
}

// TestManifest_FipsModeInjection tests that fips_mode values are not validated
// in the manifest. The fips mode is interpolated directly into a //go:debug directive
// via fmt.Sprintf("//go:debug fips140=%s\n", fipsMode), which means arbitrary
// Go pragmas or comment directives could be injected.
//
// Note: the CLI main() validates fips mode, but the manifest loader does NOT.
func TestManifest_FipsModeInjection(t *testing.T) {
	payloads := []struct {
		name     string
		fipsMode string
	}{
		{
			name:     "newline pragma injection",
			fipsMode: "on\n//go:generate touch /tmp/pwned",
		},
		{
			name:     "newline + code injection",
			fipsMode: "on\npackage exploit\n",
		},
		{
			name:     "arbitrary go:debug value",
			fipsMode: "on\n//go:debug default=all",
		},
		{
			name:     "invalid value (not on/only/off)",
			fipsMode: "evil-value",
		},
		{
			name:     "empty string",
			fipsMode: "",
		},
		{
			name:     "null byte",
			fipsMode: "on\x00//go:generate evil",
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
name: test
build_options:
  fips_mode: "` + strings.ReplaceAll(tt.fipsMode, `"`, `\"`) + `"
plugins:
  - module: github.com/aflock-ai/rookery/plugins/attestors/git
`
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			if m.BuildOptions.FipsMode != "" {
				// The manifest loader does not validate fips mode values.
				// Only the main() function validates against "on", "only", "off".
				// This means a crafted manifest with fips_mode containing newlines
				// could inject arbitrary Go pragmas into the generated source.
				t.Logf("FINDING: Unvalidated fips_mode accepted from manifest: %q", m.BuildOptions.FipsMode)
			}
		})
	}
}

// TestManifest_OutputPathTraversal tests that the output path from the manifest
// can contain path traversal sequences. The output is used directly as the
// destination for os.WriteFile of the compiled binary.
func TestManifest_OutputPathTraversal(t *testing.T) {
	payloads := []struct {
		name   string
		output string
	}{
		{
			name:   "absolute path to /tmp",
			output: "/tmp/evil-binary",
		},
		{
			name:   "parent directory traversal",
			output: "../../../tmp/evil-binary",
		},
		{
			name:   "overwrite system binary",
			output: "/usr/local/bin/go",
		},
		{
			name:   "dot dot slash to home",
			output: "~/evil-binary",
		},
		{
			name:   "hidden file",
			output: ".evil-binary",
		},
		{
			name:   "null byte in output path",
			output: "/tmp/legit\x00evil",
		},
		{
			name:   "newline in output path",
			output: "/tmp/legit\nevil",
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
name: test
output: "` + strings.ReplaceAll(tt.output, `"`, `\"`) + `"
plugins:
  - module: github.com/aflock-ai/rookery/plugins/attestors/git
`
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			// Check if the output path escapes the expected working directory
			if filepath.IsAbs(m.Output) {
				t.Logf("FINDING: Absolute output path accepted without restriction: %q", m.Output)
			}
			if strings.Contains(m.Output, "..") {
				t.Logf("FINDING: Path traversal in output accepted: %q", m.Output)
			}
		})
	}
}

// TestManifest_CustomerIDInjection tests that customer_id and tenant_id values
// are passed unsanitized to ldflags. These values are embedded via:
//   -X 'rookery-build/buildinfo.CustomerID=%s'
// If they contain single quotes, they can break out of the -X argument.
func TestManifest_CustomerTenantIDInjection(t *testing.T) {
	payloads := []struct {
		name       string
		customerID string
		tenantID   string
	}{
		{
			name:       "single quote breakout in customer ID",
			customerID: "legit' -X 'rookery-build/buildinfo.Plugins=pwned",
			tenantID:   "",
		},
		{
			name:       "single quote breakout in tenant ID",
			customerID: "",
			tenantID:   "legit' -extldflags '-Wl,-evil",
		},
		{
			name:       "command substitution in customer ID",
			customerID: "$(touch /tmp/pwned)",
			tenantID:   "",
		},
		{
			name:       "newline in customer ID",
			customerID: "legit\nevil-flag",
			tenantID:   "",
		},
		{
			name:       "backtick in tenant ID",
			tenantID:   "`touch /tmp/pwned`",
			customerID: "",
		},
		{
			name:       "very long customer ID",
			customerID: strings.Repeat("A", 100000),
			tenantID:   "",
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			custYaml := ""
			if tt.customerID != "" {
				custYaml = `  customer_id: "` + strings.ReplaceAll(tt.customerID, `"`, `\"`) + `"`
			}
			tenantYaml := ""
			if tt.tenantID != "" {
				tenantYaml = `  tenant_id: "` + strings.ReplaceAll(tt.tenantID, `"`, `\"`) + `"`
			}

			yaml := `
name: test
build_options:
` + custYaml + `
` + tenantYaml + `
plugins:
  - module: github.com/aflock-ai/rookery/plugins/attestors/git
`
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			if m.BuildOptions.CustomerID != "" {
				t.Logf("FINDING: Unvalidated customer_id accepted: %q", m.BuildOptions.CustomerID)
			}
			if m.BuildOptions.TenantID != "" {
				t.Logf("FINDING: Unvalidated tenant_id accepted: %q", m.BuildOptions.TenantID)
			}
		})
	}
}

// TestManifest_PathFieldTraversal tests that the path field for local plugins
// is not validated for traversal or suspicious content.
func TestManifest_PathFieldTraversal(t *testing.T) {
	payloads := []struct {
		name string
		path string
	}{
		{name: "absolute /etc", path: "/etc/passwd"},
		{name: "absolute /tmp", path: "/tmp/evil-plugin"},
		{name: "deep parent traversal", path: "../../../../etc"},
		{name: "home directory", path: "~/evil-plugin"},
		{name: "symlink traversal", path: "/proc/self/root/etc"},
		{name: "null byte", path: "/tmp/legit\x00/evil"},
		{name: "space padding", path: "  /etc/passwd  "},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
name: test
plugins:
  - path: "` + strings.ReplaceAll(tt.path, `"`, `\"`) + `"
`
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.yaml")
			if err := os.WriteFile(manifestPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			m, err := LoadManifest(manifestPath)
			if err != nil {
				t.Logf("YAML parse error (incidental rejection): %v", err)
				return
			}

			if len(m.Plugins) > 0 && m.Plugins[0].Path != "" {
				t.Logf("FINDING: Unvalidated path accepted: %q", m.Plugins[0].Path)
			}
		})
	}
}
