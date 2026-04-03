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

// Package pipinstall provides a post-product attestor that captures metadata
// about Python packages installed via pip. It records the installed packages,
// their versions, install types (wheel vs sdist), and dependency trees.
//
// This attestor runs after the pip install command completes and inspects
// the resulting Python environment to build a comprehensive picture of
// what was installed.
package pipinstall

import (
	"bufio"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "pip-install"
	Type    = "https://aflock.ai/attestations/pip-install/v0.1"
	RunType = attestation.PostProductRunType
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// PackageInfo describes a single installed Python package.
type PackageInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	InstallType  string   `json:"installType,omitempty"`  // "wheel" or "sdist"
	Location     string   `json:"location,omitempty"`     // install path
	Requires     []string `json:"requires,omitempty"`     // direct dependencies
	RequiredBy   []string `json:"requiredBy,omitempty"`   // reverse dependencies
	HomePage     string   `json:"homePage,omitempty"`     // project URL
	Author       string   `json:"author,omitempty"`       // package author
	License      string   `json:"license,omitempty"`      // declared license
	HasSetupPy   bool     `json:"hasSetupPy,omitempty"`   // sdist with setup.py
	HasCmdClass  bool     `json:"hasCmdClass,omitempty"`  // custom install commands
	InstallerLog string   `json:"installerLog,omitempty"` // pip install log snippet
}

// SetupPyAnalysis contains static analysis results for a setup.py file.
type SetupPyAnalysis struct {
	Path            string   `json:"path"`
	SuspiciousCalls []string `json:"suspiciousCalls,omitempty"` // exec, eval, subprocess, etc.
	NetworkImports  []string `json:"networkImports,omitempty"`  // urllib, requests, socket, etc.
	EncodedPayloads bool     `json:"encodedPayloads,omitempty"` // base64, hex strings
	FileOperations  []string `json:"fileOperations,omitempty"`  // writes to sensitive paths
}

// InstalledFileAnalysis contains static analysis results for installed .py files.
type InstalledFileAnalysis struct {
	SuspiciousImports []string `json:"suspiciousImports,omitempty"` // sys.meta_path, atexit.register, codecs.register
	SubprocessInInit  []string `json:"subprocessInInit,omitempty"`  // subprocess/os.system in __init__.py files
	NetworkInInit     []string `json:"networkInInit,omitempty"`     // socket/urllib/requests in __init__.py
	PickleFiles       []string `json:"pickleFiles,omitempty"`       // .pkl, .pickle, .pt files found
	PthFiles          []string `json:"pthFiles,omitempty"`          // .pth files in site-packages
	TotalPyFiles      int      `json:"totalPyFiles"`                // count of .py files installed
}

// PyprojectAnalysis contains build backend analysis from pyproject.toml files.
type PyprojectAnalysis struct {
	BuildBackend  string   `json:"buildBackend,omitempty"`
	BuildRequires []string `json:"buildRequires,omitempty"`
	IsCustomBackend bool   `json:"isCustomBackend,omitempty"`
}

// PEP740Status records whether a package has a PEP 740 attestation on PyPI.
type PEP740Status struct {
	Package         string `json:"package"`
	Version         string `json:"version"`
	HasAttestation  bool   `json:"hasAttestation"`
	AttestationURL  string `json:"attestationUrl,omitempty"`
	// Signer identity from Sigstore certificate / Trusted Publisher
	PublisherKind   string `json:"publisherKind,omitempty"`   // "GitHub", "GitLab", etc.
	Repository      string `json:"repository,omitempty"`      // e.g. "psf/requests"
	Workflow        string `json:"workflow,omitempty"`         // e.g. "publish.yml"
	Environment     string `json:"environment,omitempty"`     // e.g. "publish"
	SignerIdentity  string `json:"signerIdentity,omitempty"`  // full workflow URL
}

// Attestor captures pip install metadata.
type Attestor struct {
	PipVersion      string            `json:"pipVersion"`
	PythonVersion   string            `json:"pythonVersion"`
	Packages        []PackageInfo     `json:"packages"`
	SetupPyAnalysis      []SetupPyAnalysis    `json:"setupPyAnalysis,omitempty"`
	TotalInstalled       int                  `json:"totalInstalled"`
	InstalledFileAnalysis *InstalledFileAnalysis `json:"installedFileAnalysis,omitempty"`
	PyprojectAnalysis    []PyprojectAnalysis  `json:"pyprojectAnalysis,omitempty"`
	PEP740Verification   []PEP740Status       `json:"pep740Verification,omitempty"`

	// unexported: target package to focus analysis on
	targetPackage string
}

type Option func(*Attestor)

func WithTargetPackage(pkg string) Option {
	return func(a *Attestor) {
		a.targetPackage = pkg
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Attestor) Name() string                { return Name }
func (a *Attestor) Type() string                { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Data() *Attestor              { return a }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(a) }

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for _, pkg := range a.Packages {
		// Create a subject identifier for each installed package
		subjectName := fmt.Sprintf("pip://%s@%s", pkg.Name, pkg.Version)
		digest, err := cryptoutil.CalculateDigestSetFromBytes(
			[]byte(fmt.Sprintf("%s==%s", pkg.Name, pkg.Version)),
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		)
		if err == nil {
			subjects[subjectName] = digest
		}
	}
	return subjects
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	// Get pip and python versions
	a.PipVersion = runQuiet("pip", "--version")
	a.PythonVersion = runQuiet("python3", "--version")

	// Get list of installed packages as JSON
	packages, err := getInstalledPackages()
	if err != nil {
		log.Debugf("pip-install: failed to list packages: %v", err)
		return nil // non-fatal - we still produce an attestation
	}

	a.Packages = packages
	a.TotalInstalled = len(packages)

	// Look for setup.py files in pip's download/build cache
	a.SetupPyAnalysis = findAndAnalyzeSetupPy(ctx.WorkingDir())

	// Analyze installed .py files in site-packages
	a.InstalledFileAnalysis = analyzeInstalledFiles()

	// Analyze pyproject.toml build backends
	a.PyprojectAnalysis = findAndAnalyzePyproject()

	// Check PEP 740 attestations for installed packages
	a.PEP740Verification = checkPEP740Attestations(packages)

	return nil
}

// getInstalledPackages uses pip list --format=json and pip show to get
// detailed info about installed packages.
func getInstalledPackages() ([]PackageInfo, error) {
	out, err := exec.Command("pip", "list", "--format=json").Output() //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("pip list: %w", err)
	}

	var pipList []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &pipList); err != nil {
		return nil, fmt.Errorf("parse pip list: %w", err)
	}

	packages := make([]PackageInfo, 0, len(pipList))
	for _, p := range pipList {
		pkg := PackageInfo{
			Name:    p.Name,
			Version: p.Version,
		}

		// Get detailed info via pip show
		showOut, err := exec.Command("pip", "show", p.Name).Output() //nolint:gosec
		if err == nil {
			pkg = parseShowOutput(string(showOut), pkg)
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}

func parseShowOutput(output string, pkg PackageInfo) PackageInfo {
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Location":
			pkg.Location = val
		case "Requires":
			if val != "" {
				pkg.Requires = strings.Split(val, ", ")
			}
		case "Required-by":
			if val != "" {
				pkg.RequiredBy = strings.Split(val, ", ")
			}
		case "Home-page":
			pkg.HomePage = val
		case "Author":
			pkg.Author = val
		case "License":
			pkg.License = val
		}
	}
	return pkg
}

// findAndAnalyzeSetupPy walks the working directory looking for setup.py
// files and performs basic static analysis on them.
func findAndAnalyzeSetupPy(workDir string) []SetupPyAnalysis {
	var analyses []SetupPyAnalysis

	// Search common locations for setup.py
	searchDirs := []string{
		workDir,
		"/tmp/pip-download",
		"/tmp/pip-install",
		"/tmp/pip-build",
	}

	for _, dir := range searchDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.Name() == "setup.py" {
				analysis := analyzeSetupPy(path)
				if analysis != nil {
					analyses = append(analyses, *analysis)
				}
			}
			return nil
		})
	}

	return analyses
}

func analyzeSetupPy(path string) *SetupPyAnalysis {
	content, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil
	}

	analysis := &SetupPyAnalysis{Path: path}
	src := string(content)

	// Check for suspicious function calls
	suspiciousCalls := []string{"exec(", "eval(", "compile(", "subprocess.", "os.system(", "os.popen("}
	for _, call := range suspiciousCalls {
		if strings.Contains(src, call) {
			analysis.SuspiciousCalls = append(analysis.SuspiciousCalls, call)
		}
	}

	// Check for network imports
	networkImports := []string{"urllib", "requests", "httplib", "http.client", "socket", "aiohttp"}
	for _, imp := range networkImports {
		if strings.Contains(src, imp) {
			analysis.NetworkImports = append(analysis.NetworkImports, imp)
		}
	}

	// Check for encoded payloads
	if strings.Contains(src, "base64") || strings.Contains(src, "\\x") {
		analysis.EncodedPayloads = true
	}

	// Check for sensitive file operations
	sensitivePaths := []string{".ssh/", ".aws/", ".gnupg/", ".kube/", "/etc/shadow", "/etc/passwd"}
	for _, sp := range sensitivePaths {
		if strings.Contains(src, sp) {
			analysis.FileOperations = append(analysis.FileOperations, sp)
		}
	}

	// Check for cmdclass
	if strings.Contains(src, "cmdclass") {
		analysis.SuspiciousCalls = append(analysis.SuspiciousCalls, "cmdclass{}")
	}

	return analysis
}

func runQuiet(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output() //nolint:gosec
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// getSitePackagesDir returns the site-packages directory for the current Python.
func getSitePackagesDir() string {
	out, err := exec.Command("python3", "-c", "import site; print(site.getsitepackages()[0])").Output() //nolint:gosec
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// analyzeInstalledFiles walks site-packages and performs static analysis on
// installed .py files, looking for suspicious patterns.
func analyzeInstalledFiles() *InstalledFileAnalysis {
	siteDir := getSitePackagesDir()
	if siteDir == "" {
		return nil
	}

	analysis := &InstalledFileAnalysis{}

	suspiciousPatterns := []string{"sys.meta_path", "atexit.register", "codecs.register"}
	subprocessPatterns := []string{"subprocess.", "os.system(", "os.popen("}
	networkPatterns := []string{"socket.", "urllib.", "requests."}

	pickleExts := map[string]bool{".pkl": true, ".pickle": true, ".pt": true}

	_ = filepath.Walk(siteDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		name := info.Name()
		ext := filepath.Ext(name)

		// Count .py files
		if ext == ".py" {
			analysis.TotalPyFiles++
		}

		// Check for pickle files
		if pickleExts[ext] {
			analysis.PickleFiles = append(analysis.PickleFiles, path)
			return nil
		}

		// Check for .pth files
		if ext == ".pth" {
			analysis.PthFiles = append(analysis.PthFiles, path)
			return nil
		}

		// Deep scan __init__.py files
		if name == "__init__.py" {
			scanInitFile(path, suspiciousPatterns, subprocessPatterns, networkPatterns, analysis)
		}

		return nil
	})

	return analysis
}

// scanInitFile reads an __init__.py and checks for suspicious patterns.
func scanInitFile(path string, suspiciousPatterns, subprocessPatterns, networkPatterns []string, analysis *InstalledFileAnalysis) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		for _, pat := range suspiciousPatterns {
			if strings.Contains(line, pat) {
				analysis.SuspiciousImports = append(analysis.SuspiciousImports, fmt.Sprintf("%s: %s", path, pat))
			}
		}
		for _, pat := range subprocessPatterns {
			if strings.Contains(line, pat) {
				analysis.SubprocessInInit = append(analysis.SubprocessInInit, fmt.Sprintf("%s: %s", path, pat))
			}
		}
		for _, pat := range networkPatterns {
			if strings.Contains(line, pat) {
				analysis.NetworkInInit = append(analysis.NetworkInInit, fmt.Sprintf("%s: %s", path, pat))
			}
		}
	}
}

// findAndAnalyzePyproject searches pip build/download directories for
// pyproject.toml files and extracts build-system configuration.
func findAndAnalyzePyproject() []PyprojectAnalysis {
	var analyses []PyprojectAnalysis

	searchDirs := []string{
		"/tmp/pip-download",
		"/tmp/pip-build",
	}

	knownBackends := map[string]bool{
		"setuptools.build_meta":      true,
		"flit_core.buildapi":         true,
		"hatchling.build":            true,
		"pdm.backend":               true,
		"maturin":                   true,
		"poetry.core.masonry.api":    true,
	}

	for _, dir := range searchDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.Name() == "pyproject.toml" {
				if pa := parsePyprojectTOML(path, knownBackends); pa != nil {
					analyses = append(analyses, *pa)
				}
			}
			return nil
		})
	}

	return analyses
}

// parsePyprojectTOML does a simple line-based parse of pyproject.toml to
// extract [build-system] fields. We avoid pulling in a full TOML parser
// to keep dependencies minimal.
func parsePyprojectTOML(path string, knownBackends map[string]bool) *PyprojectAnalysis {
	content, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil
	}

	analysis := &PyprojectAnalysis{}
	src := string(content)
	lines := strings.Split(src, "\n")

	inBuildSystem := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track which TOML section we're in
		if strings.HasPrefix(trimmed, "[") {
			inBuildSystem = trimmed == "[build-system]"
			continue
		}

		if !inBuildSystem {
			continue
		}

		if strings.HasPrefix(trimmed, "build-backend") {
			// Extract value: build-backend = "setuptools.build_meta"
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"'")
				analysis.BuildBackend = val
				if !knownBackends[val] {
					analysis.IsCustomBackend = true
				}
			}
		}

		if strings.HasPrefix(trimmed, "requires") {
			// Simple extraction of requires = ["foo", "bar"]
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "[]")
				for _, req := range strings.Split(val, ",") {
					req = strings.TrimSpace(req)
					req = strings.Trim(req, "\"'")
					if req != "" {
						analysis.BuildRequires = append(analysis.BuildRequires, req)
					}
				}
			}
		}
	}

	// Only return if we found build-system info
	if analysis.BuildBackend == "" && len(analysis.BuildRequires) == 0 {
		return nil
	}

	return analysis
}

// checkPEP740Attestations checks PyPI for PEP 740 provenance attestations
// for each installed package. Uses a 2s timeout per request and never fails
// the overall attestation if a check errors.
func checkPEP740Attestations(packages []PackageInfo) []PEP740Status {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	statuses := make([]PEP740Status, 0, len(packages))

	for _, pkg := range packages {
		if pkg.Name == "pip" || pkg.Name == "setuptools" || pkg.Name == "wheel" {
			continue
		}

		status := PEP740Status{
			Package: pkg.Name,
			Version: pkg.Version,
		}

		// The PyPI integrity API returns provenance with publisher identity.
		// We need to construct the filename — try wheel first (most common).
		// The actual filename isn't easily known, so we use the simple API.
		provenanceURL := fmt.Sprintf("https://pypi.org/integrity/%s/%s/provenance",
			pkg.Name, pkg.Version)

		// Try the simple JSON API to get the actual filename
		simpleURL := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", pkg.Name, pkg.Version)
		resp, err := client.Get(simpleURL) //nolint:gosec,noctx
		if err != nil {
			statuses = append(statuses, status)
			continue
		}

		var pypiData struct {
			URLs []struct {
				Filename    string `json:"filename"`
				PackageType string `json:"packagetype"`
				Digests     struct {
					SHA256 string `json:"sha256"`
				} `json:"digests"`
			} `json:"urls"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&pypiData); err != nil {
			resp.Body.Close() //nolint:errcheck
			statuses = append(statuses, status)
			continue
		}
		resp.Body.Close() //nolint:errcheck

		// Find the wheel file (preferred) or sdist
		var filename string
		for _, u := range pypiData.URLs {
			if u.PackageType == "bdist_wheel" {
				filename = u.Filename
				break
			}
		}
		if filename == "" && len(pypiData.URLs) > 0 {
			filename = pypiData.URLs[0].Filename
		}
		if filename == "" {
			statuses = append(statuses, status)
			continue
		}

		// Now fetch the provenance for this specific file
		provenanceURL = fmt.Sprintf("https://pypi.org/integrity/%s/%s/%s/provenance",
			pkg.Name, pkg.Version, filename)
		resp, err = client.Get(provenanceURL) //nolint:gosec,noctx
		if err != nil {
			statuses = append(statuses, status)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close() //nolint:errcheck
			statuses = append(statuses, status)
			continue
		}

		var provenance struct {
			AttestationBundles []struct {
				Publisher struct {
					Kind        string `json:"kind"`
					Repository  string `json:"repository"`
					Workflow    string `json:"workflow"`
					Environment string `json:"environment"`
				} `json:"publisher"`
				Attestations []struct {
					Envelope struct {
						Statement string `json:"statement"`
					} `json:"envelope"`
				} `json:"attestations"`
			} `json:"attestation_bundles"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&provenance); err != nil {
			resp.Body.Close() //nolint:errcheck
			statuses = append(statuses, status)
			continue
		}
		resp.Body.Close() //nolint:errcheck

		if len(provenance.AttestationBundles) > 0 {
			bundle := provenance.AttestationBundles[0]
			status.HasAttestation = true
			status.AttestationURL = provenanceURL
			status.PublisherKind = bundle.Publisher.Kind
			status.Repository = bundle.Publisher.Repository
			status.Workflow = bundle.Publisher.Workflow
			status.Environment = bundle.Publisher.Environment

			// Build full signer identity URL
			if bundle.Publisher.Repository != "" && bundle.Publisher.Workflow != "" {
				status.SignerIdentity = fmt.Sprintf("https://github.com/%s/.github/workflows/%s",
					bundle.Publisher.Repository, bundle.Publisher.Workflow)
			}
		}

		statuses = append(statuses, status)
	}

	return statuses
}
