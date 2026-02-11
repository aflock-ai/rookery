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

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/builder/internal/manifest"
	"github.com/aflock-ai/rookery/builder/internal/version"
)

// Preset plugin sets. Each entry is a full import path.
var presets = map[string][]string{
	"minimal": {
		"github.com/aflock-ai/rookery/plugins/attestors/commandrun",
		"github.com/aflock-ai/rookery/plugins/attestors/environment",
		"github.com/aflock-ai/rookery/plugins/attestors/git",
		"github.com/aflock-ai/rookery/plugins/attestors/material",
		"github.com/aflock-ai/rookery/plugins/attestors/product",
		"github.com/aflock-ai/rookery/plugins/signers/file",
	},
	"cicd": {
		"github.com/aflock-ai/rookery/plugins/attestors/commandrun",
		"github.com/aflock-ai/rookery/plugins/attestors/environment",
		"github.com/aflock-ai/rookery/plugins/attestors/git",
		"github.com/aflock-ai/rookery/plugins/attestors/github",
		"github.com/aflock-ai/rookery/plugins/attestors/gitlab",
		"github.com/aflock-ai/rookery/plugins/attestors/material",
		"github.com/aflock-ai/rookery/plugins/attestors/product",
		"github.com/aflock-ai/rookery/plugins/attestors/slsa",
		"github.com/aflock-ai/rookery/plugins/signers/file",
	},
	"all": {
		"github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild",
		"github.com/aflock-ai/rookery/plugins/attestors/aws-iid",
		"github.com/aflock-ai/rookery/plugins/attestors/commandrun",
		"github.com/aflock-ai/rookery/plugins/attestors/docker",
		"github.com/aflock-ai/rookery/plugins/attestors/environment",
		"github.com/aflock-ai/rookery/plugins/attestors/gcp-iit",
		"github.com/aflock-ai/rookery/plugins/attestors/git",
		"github.com/aflock-ai/rookery/plugins/attestors/github",
		"github.com/aflock-ai/rookery/plugins/attestors/gitlab",
		"github.com/aflock-ai/rookery/plugins/attestors/jenkins",
		"github.com/aflock-ai/rookery/plugins/attestors/jwt",
		"github.com/aflock-ai/rookery/plugins/attestors/k8smanifest",
		"github.com/aflock-ai/rookery/plugins/attestors/link",
		"github.com/aflock-ai/rookery/plugins/attestors/lockfiles",
		"github.com/aflock-ai/rookery/plugins/attestors/material",
		"github.com/aflock-ai/rookery/plugins/attestors/maven",
		"github.com/aflock-ai/rookery/plugins/attestors/oci",
		"github.com/aflock-ai/rookery/plugins/attestors/omnitrail",
		"github.com/aflock-ai/rookery/plugins/attestors/product",
		"github.com/aflock-ai/rookery/plugins/attestors/sarif",
		"github.com/aflock-ai/rookery/plugins/attestors/sbom",
		"github.com/aflock-ai/rookery/plugins/attestors/secretscan",
		"github.com/aflock-ai/rookery/plugins/attestors/slsa",
		"github.com/aflock-ai/rookery/plugins/attestors/system-packages",
		"github.com/aflock-ai/rookery/plugins/attestors/vex",
		"github.com/aflock-ai/rookery/plugins/signers/debug-signer",
		"github.com/aflock-ai/rookery/plugins/signers/file",
		"github.com/aflock-ai/rookery/plugins/signers/fulcio",
		"github.com/aflock-ai/rookery/plugins/signers/kms/aws",
		"github.com/aflock-ai/rookery/plugins/signers/kms/azure",
		"github.com/aflock-ai/rookery/plugins/signers/kms/gcp",
		"github.com/aflock-ai/rookery/plugins/signers/spiffe",
		"github.com/aflock-ai/rookery/plugins/signers/vault",
		"github.com/aflock-ai/rookery/plugins/signers/vault-transit",
	},
}

type pluginSpec struct {
	ImportPath string
	Version    string
	LocalPath  string
}

func parseSpecs(args []string) ([]pluginSpec, error) {
	var specs []pluginSpec
	for i := 0; i < len(args); i++ {
		if args[i] == "--with" && i+1 < len(args) {
			raw := args[i+1]
			i++
			// "=<path>" form
			if strings.Contains(raw, "=") && !strings.HasPrefix(raw, "=") {
				parts := strings.SplitN(raw, "=", 2)
				specs = append(specs, pluginSpec{ImportPath: parts[0], LocalPath: parts[1]})
				continue
			}
			// "@<version>" form
			if at := strings.LastIndex(raw, "@"); at > 0 {
				specs = append(specs, pluginSpec{ImportPath: raw[:at], Version: raw[at+1:]})
				continue
			}
			// local module path form
			if strings.HasPrefix(raw, ".") || strings.HasPrefix(raw, "/") {
				abs, _ := filepath.Abs(raw)
				importPath := getModulePath(abs)
				if importPath == "" {
					importPath = "local-plugin"
				}
				specs = append(specs, pluginSpec{ImportPath: importPath, LocalPath: abs})
			} else {
				specs = append(specs, pluginSpec{ImportPath: raw})
			}
		}
	}
	return specs, nil
}

func showUsage() {
	fmt.Printf(`rookery-builder - Build custom attestation binaries with selected plugins

Usage:
  rookery-builder [flags] [--with <plugin>...]
  rookery-builder --manifest <file>
  rookery-builder --preset <name>

Flags:
  --output <file>       Output binary name (default: aflock-custom)
  --preset <name>       Use a preset plugin set: minimal, cicd, all
  --manifest <file>     Build from manifest file (YAML)
  --fips <mode>         Enable FIPS 140-3 mode: "on" or "only"
  --customer <id>       Customer identifier (optional)
  --tenant <id>         Tenant identifier (optional)
  --version, -v         Show version information
  --help, -h            Show this help

Plugin forms:
  --with github.com/aflock-ai/rookery/plugins/attestors/git
  --with github.com/org/custom-plugin@v1.0.0
  --with github.com/org/plugin=../path    # local replace
  --with ./path/to/plugin                 # local plugin path

Presets:
  minimal    commandrun, environment, git, material, product + file signer
  cicd       minimal + github, gitlab, slsa
  all        all 25 attestors + all 9 signers

Examples:
  rookery-builder --preset minimal --output ./my-attestor
  rookery-builder --with github.com/aflock-ai/rookery/plugins/attestors/aws-iid \
                  --with github.com/aflock-ai/rookery/plugins/signers/kms/aws
  rookery-builder --manifest build.yaml
  rookery-builder --fips on --preset cicd

Only plugins you select are compiled into the binary.
No unused dependencies are included.
`)
}

func main() {
	out := "aflock-custom"
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	var manifestPath string
	var ldflags string
	var trimpath = true
	var fipsMode string
	var customerID string
	var tenantID string
	var presetName string
	var attestationVer string

	// Parse flags
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			showUsage()
			return
		case "--version", "-v":
			fmt.Println(version.Info())
			return
		case "--output":
			if i+1 < len(args) {
				out = args[i+1]
				i++
			}
		case "--preset":
			if i+1 < len(args) {
				presetName = args[i+1]
				i++
			}
		case "--attestation-version":
			if i+1 < len(args) {
				attestationVer = args[i+1]
				i++
			}
		case "--manifest":
			if i+1 < len(args) {
				manifestPath = args[i+1]
				i++
			}
		case "--fips":
			if i+1 < len(args) {
				fipsMode = args[i+1]
				i++
			}
		case "--customer":
			if i+1 < len(args) {
				customerID = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
		}
	}

	var specs []pluginSpec
	var err error

	if manifestPath != "" {
		// Load from manifest
		m, err := manifest.LoadManifest(manifestPath)
		must(err)

		if m.Output != "" {
			out = m.Output
		}
		if m.AttestationVersion != "" {
			attestationVer = m.AttestationVersion
		}
		if m.BuildOptions.LdFlags != "" {
			ldflags = m.BuildOptions.LdFlags
		}
		if m.BuildOptions.Trimpath != nil {
			trimpath = *m.BuildOptions.Trimpath
		}
		if m.BuildOptions.FipsMode != "" {
			fipsMode = m.BuildOptions.FipsMode
		}
		if m.BuildOptions.CustomerID != "" {
			customerID = m.BuildOptions.CustomerID
		}
		if m.BuildOptions.TenantID != "" {
			tenantID = m.BuildOptions.TenantID
		}

		// Manifest can specify a preset
		if m.Preset != "" {
			presetName = m.Preset
		}

		specs = convertManifestPlugins(m.Plugins)
		fmt.Printf("Building from manifest: %s\n", manifestPath)
	} else {
		// Parse command line plugins
		specs, err = parseSpecs(args)
		must(err)
	}

	// Resolve preset if specified
	if presetName != "" {
		presetPlugins, ok := presets[presetName]
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: unknown preset %q (available: minimal, cicd, all)\n", presetName)
			os.Exit(1)
		}
		for _, p := range presetPlugins {
			specs = append(specs, pluginSpec{ImportPath: p})
		}
	}

	// Deduplicate specs by import path
	seen := make(map[string]bool)
	deduped := make([]pluginSpec, 0, len(specs))
	for _, s := range specs {
		if !seen[s.ImportPath] {
			seen[s.ImportPath] = true
			deduped = append(deduped, s)
		}
	}
	specs = deduped

	if len(specs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no plugins specified. Use --preset, --with, or --manifest.")
		fmt.Fprintln(os.Stderr, "Run rookery-builder --help for usage.")
		os.Exit(1)
	}

	// Validate FIPS mode
	if fipsMode != "" && fipsMode != "on" && fipsMode != "only" {
		fmt.Fprintf(os.Stderr, "Error: --fips must be 'on' or 'only' (got %q)\n", fipsMode)
		os.Exit(1)
	}

	// Collect build metadata
	buildTime := time.Now().UTC().Format(time.RFC3339)
	builderVer := version.Version
	if version.GitCommit != "" {
		if len(version.GitCommit) > 7 {
			builderVer += "-" + version.GitCommit[:7]
		}
	}

	pluginList := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.Version != "" {
			pluginList = append(pluginList, s.ImportPath+"@"+s.Version)
		} else {
			pluginList = append(pluginList, s.ImportPath)
		}
	}
	pluginsStr := strings.Join(pluginList, ",")

	fipsModeStr := "off"
	if fipsMode != "" {
		fipsModeStr = fipsMode
	}

	fmt.Printf("Building custom binary with %d plugin(s)...\n", len(specs))

	tmp, err := os.MkdirTemp("", "rookery-build-*")
	must(err)
	defer os.RemoveAll(tmp)

	// Create minimal module
	run(tmp, "go", "mod", "init", "rookery-build")

	// Get the attestation core (needed for attestor/signer registry listing)
	if attestationVer != "" {
		run(tmp, "go", "get", "github.com/aflock-ai/rookery/attestation@"+attestationVer)
	} else {
		run(tmp, "go", "get", "github.com/aflock-ai/rookery/attestation")
	}

	// Get the signer registry package
	if attestationVer != "" {
		run(tmp, "go", "get", "github.com/aflock-ai/rookery/attestation/signer@"+attestationVer)
	} else {
		run(tmp, "go", "get", "github.com/aflock-ai/rookery/attestation/signer")
	}

	// Handle plugin requires / replaces
	var imports bytes.Buffer
	for _, s := range specs {
		switch {
		case s.LocalPath != "" && s.ImportPath != "":
			run(tmp, "go", "mod", "edit", "-replace", s.ImportPath+"="+s.LocalPath)
			run(tmp, "go", "get", s.ImportPath)
			imports.WriteString(fmt.Sprintf("\t_ %q\n", s.ImportPath))
		case s.Version != "":
			run(tmp, "go", "get", s.ImportPath+"@"+s.Version)
			imports.WriteString(fmt.Sprintf("\t_ %q\n", s.ImportPath))
		default:
			run(tmp, "go", "get", s.ImportPath)
			imports.WriteString(fmt.Sprintf("\t_ %q\n", s.ImportPath))
		}
	}

	// Create buildinfo package
	buildinfoDir := filepath.Join(tmp, "buildinfo")
	must(os.MkdirAll(buildinfoDir, 0o755))

	buildInfoGo := `package buildinfo

import (
	"fmt"
	"runtime"
)

// Build metadata injected via ldflags
var (
	BuilderVersion = "unknown"
	BuildTime      = "unknown"
	Plugins        = "none"
	FipsMode       = "off"
	CustomerID     = ""
	TenantID       = ""
)

// Info returns formatted build information
func Info() string {
	result := fmt.Sprintf("Built with rookery-builder: %s\n", BuilderVersion)
	result += fmt.Sprintf("Build time: %s\n", BuildTime)
	result += fmt.Sprintf("Plugins: %s\n", Plugins)
	result += fmt.Sprintf("FIPS mode: %s\n", FipsMode)
	if CustomerID != "" {
		result += fmt.Sprintf("Customer ID: %s\n", CustomerID)
	}
	if TenantID != "" {
		result += fmt.Sprintf("Tenant ID: %s\n", TenantID)
	}
	result += fmt.Sprintf("Go version: %s", runtime.Version())
	return result
}
`
	must(os.WriteFile(filepath.Join(buildinfoDir, "buildinfo.go"), []byte(buildInfoGo), 0o644))

	// Compose main.go — standalone binary with attestor/signer listing
	var mainGoPrefix string
	if fipsMode != "" {
		mainGoPrefix = fmt.Sprintf("//go:debug fips140=%s\n", fipsMode)
	}

	mainGo := fmt.Sprintf(`%spackage main

import (
	"fmt"
	"os"
	"sort"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/signer"

	"rookery-build/buildinfo"

	// plugins
%s)

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "attestors":
		listAttestors()
	case "signers":
		listSigners()
	case "buildinfo", "version":
		fmt.Println(buildinfo.Info())
	case "license":
		showLicense()
	case "help", "--help", "-h":
		showHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %%s\n", os.Args[1])
		showHelp()
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Println("Usage: <binary> <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  attestors   List registered attestors")
	fmt.Println("  signers     List registered signers")
	fmt.Println("  buildinfo   Show build information")
	fmt.Println("  version     Show version information")
	fmt.Println("  license     Show license information")
	fmt.Println("  help        Show this help")
}

func listAttestors() {
	entries := attestation.RegistrationEntries()
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	fmt.Printf("Registered attestors (%%d):\n", len(names))
	for _, name := range names {
		fmt.Printf("  - %%s\n", name)
	}
}

func listSigners() {
	entries := signer.RegistryEntries()
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	fmt.Printf("Registered signers (%%d):\n", len(names))
	for _, name := range names {
		fmt.Printf("  - %%s\n", name)
	}
}

func showLicense() {
	fmt.Println("PROPRIETARY SOFTWARE LICENSE")
	fmt.Println("========================================")
	fmt.Println("")
	if buildinfo.CustomerID != "" {
		fmt.Printf("This software is owned by Aflock, Inc. and\nbuilt exclusively for %%s\n", buildinfo.CustomerID)
	} else {
		fmt.Println("This software is owned by Aflock, Inc.")
	}
	fmt.Println("")
	fmt.Println("Copyright (c) 2025 Aflock, Inc.")
	fmt.Println("All rights reserved.")
	fmt.Println("")
	fmt.Println("LICENSE RESTRICTIONS:")
	fmt.Println("  - This software is licensed for internal use only")
	fmt.Println("  - Redistribution is strictly prohibited")
	fmt.Println("  - Reverse engineering is strictly prohibited")
	fmt.Println("  - Modification is strictly prohibited")
	fmt.Println("  - Sublicensing is strictly prohibited")
	fmt.Println("")
	fmt.Println("Unauthorized copying, distribution, modification, reverse")
	fmt.Println("engineering, or use of this software is a violation of this")
	fmt.Println("license agreement and may result in severe civil and criminal")
	fmt.Println("penalties, including but not limited to injunctive relief,")
	fmt.Println("damages, and criminal prosecution.")
	fmt.Println("")
	if buildinfo.TenantID != "" {
		fmt.Printf("Tenant: %%s\n", buildinfo.TenantID)
		fmt.Println("")
	}
	fmt.Println("For licensing inquiries: license@aflock.ai")
}
`, mainGoPrefix, imports.String())

	must(os.WriteFile(filepath.Join(tmp, "main.go"), []byte(mainGo), 0o644))

	// Build
	run(tmp, "go", "mod", "tidy")
	tmpBin := filepath.Join(tmp, "rookery-build-output")

	// Inject build metadata via ldflags
	metadataFlags := fmt.Sprintf("-X 'rookery-build/buildinfo.BuilderVersion=%s' "+
		"-X 'rookery-build/buildinfo.BuildTime=%s' "+
		"-X 'rookery-build/buildinfo.Plugins=%s' "+
		"-X 'rookery-build/buildinfo.FipsMode=%s' "+
		"-X 'rookery-build/buildinfo.CustomerID=%s' "+
		"-X 'rookery-build/buildinfo.TenantID=%s'",
		builderVer, buildTime, pluginsStr, fipsModeStr, customerID, tenantID)

	// Combine with user ldflags
	combinedLdflags := ldflags
	if combinedLdflags != "" {
		combinedLdflags += " " + metadataFlags
	} else {
		combinedLdflags = "-s -w " + metadataFlags
	}

	buildArgs := []string{"build"}
	if trimpath {
		buildArgs = append(buildArgs, "-trimpath")
	}
	buildArgs = append(buildArgs, "-ldflags", combinedLdflags, "-o", tmpBin, ".")

	run(tmp, "go", buildArgs...)

	// Copy to final location
	outData, err := os.ReadFile(tmpBin)
	must(err)
	must(os.WriteFile(out, outData, 0o755))

	fmt.Printf("Built %s\n", out)
	fmt.Printf("\nTry: ./%s attestors\n", out)
}

func run(dir string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must(cmd.Run())
}

func getModulePath(dir string) string {
	goModPath := filepath.Join(dir, "go.mod")
	f, err := os.Open(goModPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

func convertManifestPlugins(manifestPlugins []manifest.PluginSpec) []pluginSpec {
	var specs []pluginSpec
	for _, p := range manifestPlugins {
		spec := pluginSpec{
			ImportPath: p.ImportPath,
			Version:    p.Version,
			LocalPath:  p.LocalPath,
		}

		// Handle local path forms
		if strings.HasPrefix(p.ImportPath, ".") || strings.HasPrefix(p.ImportPath, "/") {
			abs, _ := filepath.Abs(p.ImportPath)
			spec.LocalPath = abs
			spec.ImportPath = getModulePath(abs)
			if spec.ImportPath == "" {
				spec.ImportPath = "local-plugin"
			}
		}

		specs = append(specs, spec)
	}
	return specs
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
