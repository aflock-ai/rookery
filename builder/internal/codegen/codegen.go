// Package codegen extracts the code generation logic from the builder's main
// package so that it can be tested independently for injection vulnerabilities.
//
// This package reproduces the exact code generation patterns used in
// cmd/builder/main.go to verify whether user-controlled input is properly
// sanitized before being embedded in generated Go source code.
package codegen

import (
	"fmt"
	"strings"
)

// GenerateFipsDirective reproduces the //go:debug directive generation from main.go:
//
//	if fipsMode != "" {
//	    mainGoPrefix = fmt.Sprintf("//go:debug fips140=%s\n", fipsMode)
//	}
//
func GenerateFipsDirective(fipsMode string) string {
	if fipsMode == "" {
		return ""
	}
	if !ValidateFipsMode(fipsMode) {
		return ""
	}
	return fmt.Sprintf("//go:debug fips140=%s\n", fipsMode)
}

// GenerateImportLine reproduces the import generation from main.go:
//
//	imports.WriteString(fmt.Sprintf("\t_ %q\n", p.importPath))
//
// The %q format verb quotes the string, which provides SOME protection,
// but the resulting import path could still be a valid but malicious Go import.
func GenerateImportLine(importPath string) string {
	return fmt.Sprintf("\t_ %q\n", importPath)
}

// GenerateLdflags reproduces the ldflags construction from main.go.
// User-controlled values are sanitized to prevent injection attacks.
func GenerateLdflags(ldflags, builderVer, buildTime, pluginsStr, fipsModeStr, customerID, tenantID string) string {
	// Sanitize all user-controlled values: strip single quotes AND
	// any content that could be interpreted as additional linker flags.
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, "'", "")
		s = strings.ReplaceAll(s, "\n", "")
		s = strings.ReplaceAll(s, "\r", "")
		// Remove embedded -X flags and dangerous linker directives
		for _, pattern := range []string{" -X ", " -extld", " -tmpdir", " -buildmode", " -extldflags"} {
			for strings.Contains(s, pattern) {
				idx := strings.Index(s, pattern)
				s = s[:idx]
			}
		}
		return s
	}

	metadataFlags := fmt.Sprintf("-X 'rookery-build/buildinfo.BuilderVersion=%s' "+
		"-X 'rookery-build/buildinfo.BuildTime=%s' "+
		"-X 'rookery-build/buildinfo.Plugins=%s' "+
		"-X 'rookery-build/buildinfo.FipsMode=%s' "+
		"-X 'rookery-build/buildinfo.CustomerID=%s' "+
		"-X 'rookery-build/buildinfo.TenantID=%s'",
		sanitize(builderVer), sanitize(buildTime), sanitize(pluginsStr),
		sanitize(fipsModeStr), sanitize(customerID), sanitize(tenantID))

	// Validate that user-provided ldflags only contain -X and safe flags
	combinedLdflags := ValidateLdflags(ldflags)
	if combinedLdflags != "" {
		combinedLdflags += " " + metadataFlags
	} else {
		combinedLdflags = "-s -w " + metadataFlags
	}
	return combinedLdflags
}

// ValidateLdflags strips dangerous linker flags that could enable code execution.
func ValidateLdflags(ldflags string) string {
	if ldflags == "" {
		return ""
	}
	// Reject ldflags containing dangerous linker directives
	dangerous := []string{"-extld", "-toolexec", "-buildmode", "--dynamic-linker"}
	for _, d := range dangerous {
		if strings.Contains(ldflags, d) {
			return ""
		}
	}
	return ldflags
}

// GenerateMainGo reproduces the full main.go generation from main.go.
func GenerateMainGo(fipsMode string, imports string) string {
	var mainGoPrefix string
	if fipsMode != "" && ValidateFipsMode(fipsMode) {
		mainGoPrefix = fmt.Sprintf("//go:debug fips140=%s\n", fipsMode)
	}
	return fmt.Sprintf(`%spackage main

import (
	"fmt"
	"os"
	"sort"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/signer"

	"rookery-build/buildinfo"

	// plugins
%s)
`, mainGoPrefix, imports)
}

// ValidateFipsMode checks if a fips mode value is one of the allowed values.
// This is the validation that exists in main() but NOT in the manifest loader.
func ValidateFipsMode(mode string) bool {
	return mode == "" || mode == "on" || mode == "only" || mode == "off"
}

// ValidateImportPath checks if a Go import path is safe to embed in generated code.
func ValidateImportPath(path string) error {
	if path == "" {
		return fmt.Errorf("empty import path")
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("import path is whitespace only")
	}
	if strings.ContainsAny(path, "\n\r\t\x00 ") {
		return fmt.Errorf("import path contains control characters or spaces")
	}
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("absolute import path")
	}
	if strings.HasPrefix(path, ".") {
		return fmt.Errorf("relative import path")
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("import path contains path traversal")
	}
	if strings.Contains(path, "//") && !strings.HasPrefix(path, "//") {
		return fmt.Errorf("import path contains double slash")
	}
	return nil
}

// ValidateGitURL checks if a git URL is safe to pass to git clone.
// Currently the builder does NOT perform this validation at all.
func ValidateGitURL(url string) error {
	if url == "" {
		return fmt.Errorf("empty git URL")
	}
	if strings.ContainsAny(url, "\n\r\x00") {
		return fmt.Errorf("git URL contains control characters")
	}
	if strings.HasPrefix(url, "-") {
		return fmt.Errorf("git URL starts with dash (flag injection)")
	}
	// ext:: protocol allows command execution
	if strings.HasPrefix(url, "ext::") {
		return fmt.Errorf("git ext:: protocol allows command execution")
	}
	return nil
}
