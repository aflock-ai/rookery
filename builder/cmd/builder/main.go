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

const fipsModeOff = "off"

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
		"github.com/aflock-ai/rookery/plugins/attestors/githubwebhook",
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
		"github.com/aflock-ai/rookery/plugins/attestors/policyverify",
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

// resolvedPlugin is a plugin ready for the build stage.
type resolvedPlugin struct {
	importPath string
	version    string // empty = latest
	localPath  string // non-empty = use replace directive
}

func showUsage() {
	fmt.Printf(`rookery-builder - Build custom attestation binaries with selected plugins

Usage:
  rookery-builder --manifest <file>
  rookery-builder --preset <name> [--local [<root>]]
  rookery-builder [flags] [--with <plugin>...]

Flags:
  --output <file>       Output binary name (default: aflock-custom)
  --preset <name>       Use a preset plugin set: minimal, cicd, all
  --manifest <file>     Build from manifest file (YAML)
  --local [<root>]      Use local monorepo paths (auto-detects root if omitted)
  --fips <mode>         FIPS 140-3 mode: "on" (default), "only", or "off"
  --customer <id>       Customer identifier (optional)
  --tenant <id>         Tenant identifier (optional)
  --version, -v         Show version information
  --help, -h            Show this help

Manifest format:
  name: my-attestor
  output: ./my-attestor
  preset: minimal              # optional base preset
  plugins:
    - module: github.com/org/plugin           # Go module path
      version: v1.0.0                         # optional version
    - git: git@github.com:org/private-plugin  # Git repository
      ref: main                               # branch/tag/commit
      subdir: plugins/foo                     # subdirectory (optional)
    - path: ../local-plugin                   # local filesystem path

CLI plugin forms:
  --with github.com/aflock-ai/rookery/plugins/attestors/git
  --with github.com/org/custom-plugin@v1.0.0
  --with github.com/org/plugin=../path    # local replace
  --with ./path/to/plugin                 # local plugin path

Presets:
  minimal    commandrun, environment, git, material, product + file signer
  cicd       minimal + github, gitlab, slsa
  all        all attestors + all signers

Examples:
  rookery-builder --manifest build.yaml
  rookery-builder --local --preset minimal
  rookery-builder --preset cicd --with github.com/org/custom-plugin@v1.0.0

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
	var fipsMode = "on"
	var customerID string
	var tenantID string
	var platformURL string
	var presetName string
	var attestationVer string
	var localRoot string

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
		case "--local":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				localRoot = args[i+1]
				i++
			} else {
				localRoot = findMonorepoRoot()
				if localRoot == "" {
					fmt.Fprintln(os.Stderr, "Error: --local: could not find rookery monorepo root (no go.work found)")
					os.Exit(1)
				}
			}
		}
	}

	// Create temp dir for build + git clones
	tmp, err := os.MkdirTemp("", "rookery-build-*")
	must(err)
	defer func() { _ = os.RemoveAll(tmp) }()

	var plugins []resolvedPlugin

	if manifestPath != "" { //nolint:nestif
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
		if m.BuildOptions.PlatformURL != "" {
			platformURL = m.BuildOptions.PlatformURL
		}
		if m.Preset != "" {
			presetName = m.Preset
		}

		plugins = resolveManifestPlugins(m.Plugins, tmp)
		fmt.Printf("Building from manifest: %s\n", manifestPath)
	} else {
		// Parse --with flags from CLI
		plugins = parseCLIPlugins(args)
	}

	// Resolve preset if specified
	if presetName != "" {
		presetPlugins, ok := presets[presetName]
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: unknown preset %q (available: minimal, cicd, all)\n", presetName) //nolint:gosec // G705: presetName is from CLI flags, not user-controlled web input
			os.Exit(1)
		}
		for _, p := range presetPlugins {
			plugins = append(plugins, resolvedPlugin{importPath: p})
		}
	}

	// Deduplicate by import path (first wins — manifest/CLI overrides preset)
	seen := make(map[string]bool)
	deduped := make([]resolvedPlugin, 0, len(plugins))
	for _, p := range plugins {
		if !seen[p.importPath] {
			seen[p.importPath] = true
			deduped = append(deduped, p)
		}
	}
	plugins = deduped

	if len(plugins) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no plugins specified. Use --manifest, --preset, or --with.")
		fmt.Fprintln(os.Stderr, "Run rookery-builder --help for usage.")
		os.Exit(1)
	}

	// Validate FIPS mode
	if fipsMode != "" && fipsMode != "on" && fipsMode != "only" && fipsMode != fipsModeOff {
		fmt.Fprintf(os.Stderr, "Error: --fips must be 'on', 'only', or 'off' (got %q)\n", fipsMode) //nolint:gosec // G705: fipsMode is from CLI flags
		os.Exit(1)
	}
	if fipsMode == fipsModeOff {
		fipsMode = ""
	}

	// Collect build metadata
	buildTime := time.Now().UTC().Format(time.RFC3339)
	builderVer := version.Version
	if version.GitCommit != "" && len(version.GitCommit) > 7 {
		builderVer += "-" + version.GitCommit[:7]
	}

	pluginList := make([]string, 0, len(plugins))
	for _, p := range plugins {
		if p.version != "" {
			pluginList = append(pluginList, p.importPath+"@"+p.version)
		} else {
			pluginList = append(pluginList, p.importPath)
		}
	}
	pluginsStr := strings.Join(pluginList, ",")

	fipsModeStr := fipsModeOff
	if fipsMode != "" {
		fipsModeStr = fipsMode
	}

	fmt.Printf("Building custom binary with %d plugin(s)...\n", len(plugins))

	// Set up build module
	buildDir := filepath.Join(tmp, "build")
	must(os.MkdirAll(buildDir, 0o755)) //nolint:gosec // G301: build dir in temp, needs to be readable by go toolchain
	run(buildDir, "go", "mod", "init", "rookery-build")

	// When --local is set, add replace directives for all monorepo modules
	if localRoot != "" {
		absRoot, err := filepath.Abs(localRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not resolve --local path %q: %v\n", localRoot, err) //nolint:gosec // G705: localRoot is from CLI flags
			os.Exit(1)
		}
		localRoot = absRoot
		fmt.Printf("Using local monorepo: %s\n", localRoot)

		modules := parseGoWorkModules(localRoot)
		for _, mod := range modules {
			run(buildDir, "go", "mod", "edit", "-replace", mod.importPath+"="+mod.localPath)
		}
		fmt.Printf("Added %d local replace directives\n", len(modules))
	}

	// Get attestation core
	if attestationVer != "" {
		run(buildDir, "go", "get", "github.com/aflock-ai/rookery/attestation@"+attestationVer)
	} else {
		run(buildDir, "go", "get", "github.com/aflock-ai/rookery/attestation")
	}

	// Get signer registry
	if attestationVer != "" {
		run(buildDir, "go", "get", "github.com/aflock-ai/rookery/attestation/signer@"+attestationVer)
	} else {
		run(buildDir, "go", "get", "github.com/aflock-ai/rookery/attestation/signer")
	}

	// Resolve each plugin
	var imports bytes.Buffer
	for _, p := range plugins {
		if p.localPath != "" {
			run(buildDir, "go", "mod", "edit", "-replace", p.importPath+"="+p.localPath)
			run(buildDir, "go", "get", p.importPath)
		} else if p.version != "" {
			run(buildDir, "go", "get", p.importPath+"@"+p.version)
		} else {
			run(buildDir, "go", "get", p.importPath)
		}
		fmt.Fprintf(&imports, "\t_ %q\n", p.importPath) //nolint:gosec // G705: importPath is from manifest/CLI, not web input
	}

	// Create buildinfo package
	buildinfoDir := filepath.Join(buildDir, "buildinfo")
	must(os.MkdirAll(buildinfoDir, 0o755))                                                          //nolint:gosec // G301: build dir in temp
	must(os.WriteFile(filepath.Join(buildinfoDir, "buildinfo.go"), []byte(buildInfoSource), 0o644)) //nolint:gosec // G306: generated source file needs to be readable

	// Compose main.go
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

	must(os.WriteFile(filepath.Join(buildDir, "main.go"), []byte(mainGo), 0o644)) //nolint:gosec // G306: generated source file needs to be readable

	// Build
	run(buildDir, "go", "mod", "tidy")
	tmpBin := filepath.Join(buildDir, "rookery-build-output")

	metadataFlags := fmt.Sprintf("-X 'rookery-build/buildinfo.BuilderVersion=%s' "+
		"-X 'rookery-build/buildinfo.BuildTime=%s' "+
		"-X 'rookery-build/buildinfo.Plugins=%s' "+
		"-X 'rookery-build/buildinfo.FipsMode=%s' "+
		"-X 'rookery-build/buildinfo.CustomerID=%s' "+
		"-X 'rookery-build/buildinfo.TenantID=%s' "+
		"-X 'rookery-build/buildinfo.PlatformURL=%s'",
		builderVer, buildTime, pluginsStr, fipsModeStr, customerID, tenantID, platformURL)
	// Also bake PlatformURL into the cilock config package default
	if platformURL != "" {
		metadataFlags += fmt.Sprintf(" -X 'github.com/aflock-ai/rookery/cilock/internal/config.DefaultPlatformURL=%s'", platformURL)
	}

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

	run(buildDir, "go", buildArgs...)

	// Copy to final location
	outData, err := os.ReadFile(tmpBin) //nolint:gosec // G304: tmpBin is a path we just built into
	must(err)
	must(os.WriteFile(out, outData, 0o755)) //nolint:gosec // G306: output binary needs to be executable

	fmt.Printf("Built %s\n", out)
	fmt.Printf("\nTry: ./%s attestors\n", out)
}

// resolveManifestPlugins converts manifest plugin specs into resolved plugins,
// cloning git repos as needed.
func resolveManifestPlugins(specs []manifest.PluginSpec, tmpDir string) []resolvedPlugin {
	var plugins []resolvedPlugin
	cloneIdx := 0

	for _, spec := range specs {
		switch {
		case spec.Module != "":
			plugins = append(plugins, resolvedPlugin{
				importPath: spec.Module,
				version:    spec.Version,
			})

		case spec.Git != "":
			// Clone the git repo
			cloneDir := filepath.Join(tmpDir, fmt.Sprintf("git-clone-%d", cloneIdx))
			cloneIdx++

			cloneArgs := []string{"clone", "--depth=1"}
			if spec.Ref != "" {
				cloneArgs = append(cloneArgs, "--branch", spec.Ref)
			}
			cloneArgs = append(cloneArgs, spec.Git, cloneDir)

			fmt.Printf("Cloning %s", spec.Git)
			if spec.Ref != "" {
				fmt.Printf(" (ref: %s)", spec.Ref)
			}
			fmt.Println()
			run(".", "git", cloneArgs...)

			// Determine plugin directory within the clone
			pluginDir := cloneDir
			if spec.Subdir != "" {
				pluginDir = filepath.Join(cloneDir, spec.Subdir)
			}

			importPath := getModulePath(pluginDir)
			if importPath == "" {
				fmt.Fprintf(os.Stderr, "Error: no go.mod found in cloned repo at %s\n", pluginDir) //nolint:gosec // G705: pluginDir is from manifest
				os.Exit(1)
			}

			plugins = append(plugins, resolvedPlugin{
				importPath: importPath,
				localPath:  pluginDir,
			})

		case spec.Path != "":
			absPath, err := filepath.Abs(spec.Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: could not resolve path %q: %v\n", spec.Path, err) //nolint:gosec // G705: spec.Path is from manifest
				os.Exit(1)
			}

			importPath := getModulePath(absPath)
			if importPath == "" {
				fmt.Fprintf(os.Stderr, "Error: no go.mod found at %s\n", absPath) //nolint:gosec // G705: absPath is from manifest
				os.Exit(1)
			}

			plugins = append(plugins, resolvedPlugin{
				importPath: importPath,
				localPath:  absPath,
			})
		}
	}

	return plugins
}

// parseCLIPlugins parses --with flags from command line args.
func parseCLIPlugins(args []string) []resolvedPlugin {
	var plugins []resolvedPlugin
	for i := 0; i < len(args); i++ {
		if args[i] != "--with" || i+1 >= len(args) {
			continue
		}
		raw := args[i+1]
		i++

		// "importpath=localpath" form
		if strings.Contains(raw, "=") && !strings.HasPrefix(raw, "=") {
			parts := strings.SplitN(raw, "=", 2)
			abs, _ := filepath.Abs(parts[1])
			plugins = append(plugins, resolvedPlugin{importPath: parts[0], localPath: abs})
			continue
		}
		// "@version" form
		if at := strings.LastIndex(raw, "@"); at > 0 {
			plugins = append(plugins, resolvedPlugin{importPath: raw[:at], version: raw[at+1:]})
			continue
		}
		// local path form
		if strings.HasPrefix(raw, ".") || strings.HasPrefix(raw, "/") {
			abs, _ := filepath.Abs(raw)
			importPath := getModulePath(abs)
			if importPath == "" {
				fmt.Fprintf(os.Stderr, "Error: no go.mod found at %s\n", abs) //nolint:gosec // G705: abs is from CLI --with flag
				os.Exit(1)
			}
			plugins = append(plugins, resolvedPlugin{importPath: importPath, localPath: abs})
		} else {
			plugins = append(plugins, resolvedPlugin{importPath: raw})
		}
	}
	return plugins
}

func run(dir string, name string, args ...string) {
	cmd := exec.Command(name, args...) //nolint:gosec // G204: name is always a known tool (go, git)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must(cmd.Run())
}

func getModulePath(dir string) string {
	goModPath := filepath.Join(dir, "go.mod")
	f, err := os.Open(goModPath) //nolint:gosec // G304: goModPath is constructed from known directory
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

type localModule struct {
	importPath string
	localPath  string
}

func parseGoWorkModules(root string) []localModule {
	goWorkPath := filepath.Join(root, "go.work")
	data, err := os.ReadFile(goWorkPath) //nolint:gosec // G304: goWorkPath constructed from known root
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", goWorkPath, err) //nolint:gosec // G705: goWorkPath is from known root
		return nil
	}

	var modules []localModule
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inUse := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "use (" {
			inUse = true
			continue
		}
		if line == ")" {
			inUse = false
			continue
		}
		if !inUse || line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		relPath := strings.TrimPrefix(line, "./")
		absPath := filepath.Join(root, relPath)
		modPath := getModulePath(absPath)
		if modPath == "" {
			continue
		}
		modules = append(modules, localModule{importPath: modPath, localPath: absPath})
	}
	return modules
}

func findMonorepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

const buildInfoSource = `package buildinfo

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
	PlatformURL    = ""
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
	if PlatformURL != "" {
		result += fmt.Sprintf("Platform URL: %s\n", PlatformURL)
	}
	result += fmt.Sprintf("Go version: %s", runtime.Version())
	return result
}
`
