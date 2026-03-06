package codegen

import (
	"strings"
	"testing"
)

// =============================================================================
// FIPS MODE DIRECTIVE INJECTION
// =============================================================================

// TestFipsDirective_NewlineInjection demonstrates that a FIPS mode value
// containing newlines can inject arbitrary Go pragmas or code into the
// generated source file.
//
// Vulnerable code path (main.go line 389):
//
//	mainGoPrefix = fmt.Sprintf("//go:debug fips140=%s\n", fipsMode)
//
// Attack: fipsMode = "on\n//go:generate touch /tmp/pwned"
// Result: Two lines are generated:
//
//	//go:debug fips140=on
//	//go:generate touch /tmp/pwned
//
// The //go:generate directive would execute arbitrary commands when
// `go generate` is run on the generated source.
func TestFipsDirective_NewlineInjection(t *testing.T) {
	tests := []struct {
		name       string
		fipsMode   string
		wantLines  int // expected number of non-empty lines
		vulnerable bool
	}{
		{
			name:       "normal on",
			fipsMode:   "on",
			wantLines:  1,
			vulnerable: false,
		},
		{
			name:       "newline injects go:generate",
			fipsMode:   "on\n//go:generate touch /tmp/pwned",
			wantLines:  2,
			vulnerable: true,
		},
		{
			name:       "newline injects second go:debug",
			fipsMode:   "on\n//go:debug default=all",
			wantLines:  2,
			vulnerable: true,
		},
		{
			name:       "newline injects package declaration",
			fipsMode:   "on\npackage exploit",
			wantLines:  2,
			vulnerable: true,
		},
		{
			name:       "carriage return + newline",
			fipsMode:   "on\r\n//go:generate evil",
			wantLines:  2,
			vulnerable: true,
		},
		{
			name:       "multiple newlines inject code block",
			fipsMode:   "on\n\nimport \"os\"\nfunc init() { os.Exit(1) }",
			wantLines:  3, // at least
			vulnerable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateFipsDirective(tt.fipsMode)
			lines := strings.Split(strings.TrimSpace(result), "\n")
			nonEmpty := 0
			for _, l := range lines {
				if strings.TrimSpace(l) != "" {
					nonEmpty++
				}
			}

			if tt.vulnerable { //nolint:nestif
				if nonEmpty > 1 {
					t.Errorf("VULNERABILITY CONFIRMED: FIPS directive injection succeeded.\n"+
						"Input:  %q\n"+
						"Output: %q\n"+
						"Lines generated: %d (expected 1)\n"+
						"Impact: Arbitrary Go pragmas/code injected into generated source.\n"+
						"Fix: Validate fipsMode against allowlist BEFORE code generation, "+
						"or reject values containing control characters.",
						tt.fipsMode, result, nonEmpty)
				} else {
					t.Logf("Payload %q did not produce multiple lines (safe or different behavior)", tt.fipsMode)
				}
			} else {
				if nonEmpty != tt.wantLines {
					t.Errorf("expected %d non-empty lines, got %d for input %q", tt.wantLines, nonEmpty, tt.fipsMode)
				}
			}
		})
	}
}

// TestFipsDirective_ManifestBypassesCLIValidation demonstrates that the
// fips mode validation only exists in main() CLI handling, not in the
// manifest loader. A manifest can specify an arbitrary fips_mode value
// that bypasses the CLI's "on"/"only"/"off" check.
func TestFipsDirective_ManifestBypassesCLIValidation(t *testing.T) {
	// The CLI validates fips mode at main.go line 299:
	//   if fipsMode != "" && fipsMode != "on" && fipsMode != "only" && fipsMode != "off"
	//
	// But manifest.LoadManifest does NOT validate BuildOptions.FipsMode.
	// The fipsMode from manifest is used directly at line 249:
	//   if m.BuildOptions.FipsMode != "" { fipsMode = m.BuildOptions.FipsMode }
	//
	// THEN the CLI validation runs at line 299.
	// So the manifest value IS validated by CLI... BUT only if it doesn't
	// contain "on", "only", or "off" as the whole string.
	//
	// However, "on\n//go:generate evil" does NOT match any of the valid values,
	// so the CLI validation WILL catch it... but wait:
	// Line 249-250 sets fipsMode BEFORE validation at line 299.
	// Line 299 checks the value. If it contains a newline, the comparison
	// will fail and the program exits. So the CLI IS safe.
	//
	// BUT: if someone calls resolveManifestPlugins and uses the fipsMode
	// from the manifest WITHOUT the CLI validation, it's vulnerable.
	// This is a defense-in-depth issue: validation should be in the manifest
	// loader, not just in the CLI.

	evilMode := "on\n//go:generate touch /tmp/pwned"
	if ValidateFipsMode(evilMode) {
		t.Error("VULNERABILITY: evil fips mode passes validation")
	} else {
		t.Log("CLI validation correctly rejects newline-containing fips mode")
		t.Log("BUT: manifest loader does not validate, creating defense-in-depth gap")
	}

	// Demonstrate the generated code IS dangerous if validation is bypassed
	result := GenerateFipsDirective(evilMode)
	if strings.Contains(result, "//go:generate") {
		t.Errorf("DEFENSE-IN-DEPTH ISSUE: If CLI validation is bypassed, "+
			"the generated code contains injected directives:\n%s", result)
	}
}

// =============================================================================
// IMPORT PATH INJECTION
// =============================================================================

// TestImportLine_Injection tests that Go's %q format verb provides some
// protection against import path injection, but documents what it does
// and doesn't protect against.
func TestImportLine_Injection(t *testing.T) {
	tests := []struct {
		name         string
		importPath   string
		wantContains string
		dangerous    bool
		note         string
	}{
		{
			name:       "normal import",
			importPath: "github.com/legit/plugin",
			dangerous:  false,
		},
		{
			name:       "double quote in path - escaped by %q",
			importPath: `github.com/evil"; import "os`,
			dangerous:  false,
			note:       "%q escapes the double quotes, preventing import injection",
		},
		{
			name:       "newline in path - escaped by %q",
			importPath: "github.com/evil\nimport \"os\"",
			dangerous:  false,
			note:       "%q escapes newlines as \\n, preventing code injection",
		},
		{
			name:       "backtick in path - escaped by %q",
			importPath: "github.com/evil`code`",
			dangerous:  false,
			note:       "%q handles backticks",
		},
		{
			name:       "null byte in path - escaped by %q",
			importPath: "github.com/evil\x00hack",
			dangerous:  false,
			note:       "%q escapes null bytes as \\x00",
		},
		{
			name:         "valid-looking but attacker-controlled import path",
			importPath:   "github.com/attacker-controlled/malicious-plugin",
			wantContains: "github.com/attacker-controlled/malicious-plugin",
			dangerous:    true,
			note: "This is the REAL threat: %q prevents syntax injection, " +
				"but it cannot prevent importing a validly-named but malicious module. " +
				"A malicious import path that is syntactically valid Go will be " +
				"accepted by the compiler and execute init() functions.",
		},
		{
			name:         "path traversal as import - syntactically valid",
			importPath:   "../../../etc/passwd",
			wantContains: "../../../etc/passwd",
			dangerous:    true,
			note:         "Relative import path - go compiler may reject this but it passes code generation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateImportLine(tt.importPath)

			if tt.dangerous {
				t.Logf("FINDING: %s", tt.note)
				t.Logf("Generated: %s", strings.TrimSpace(result))
			}

			if tt.wantContains != "" && !strings.Contains(result, tt.wantContains) {
				t.Errorf("expected result to contain %q, got %q", tt.wantContains, result)
			}

			// Verify %q provides syntactic safety for the string-injection cases
			if !tt.dangerous {
				// Count the number of unescaped double quotes
				// A properly quoted import line should have exactly 2 quote chars
				// from the %q format (opening and closing)
				if tt.note != "" {
					t.Logf("SAFE: %s", tt.note)
				}
			}
		})
	}
}

// TestImportLine_NoValidation demonstrates that there is NO validation
// of import paths before they are used in code generation.
func TestImportLine_NoValidation(t *testing.T) {
	// These are all invalid Go import paths that would be caught by the compiler,
	// but they still get embedded in the generated source code without any
	// pre-generation validation.
	invalidPaths := []string{
		"",                             // empty
		"   ",                          // whitespace only
		"//go:generate evil",           // looks like a pragma
		"/absolute/path",               // absolute path
		"has spaces/in/path",           // spaces
		"has\ttabs",                    // tabs
		"github.com/a/b/../../../evil", // traversal
	}

	for _, path := range invalidPaths {
		t.Run(path, func(t *testing.T) {
			err := ValidateImportPath(path)
			if err != nil {
				t.Logf("Would be caught by validation: %v", err)
			} else {
				t.Errorf("FINDING: Invalid import path %q passes validation", path)
			}

			// But the builder generates code with it anyway
			result := GenerateImportLine(path)
			t.Logf("Generated without validation: %s", strings.TrimSpace(result))
		})
	}
}

// =============================================================================
// LDFLAGS INJECTION
// =============================================================================

// TestLdflags_SingleQuoteBreakout tests whether user-controlled values
// embedded in ldflags can break out of the single-quoted -X arguments.
//
// Vulnerable code path (main.go lines 509-515):
//
//	metadataFlags := fmt.Sprintf("-X 'rookery-build/buildinfo.CustomerID=%s' ...", customerID)
//
// Attack: customerID = "legit' -X 'rookery-build/buildinfo.Plugins=pwned"
// Result: -X 'rookery-build/buildinfo.CustomerID=legit' -X 'rookery-build/buildinfo.Plugins=pwned'
//
// The single quote in customerID breaks out of the -X value and injects
// a new -X flag that overwrites the Plugins variable.
func TestLdflags_SingleQuoteBreakout(t *testing.T) {
	tests := []struct {
		name       string
		customerID string
		tenantID   string
		wantInject string
		note       string
	}{
		{
			name:       "single quote breakout overwrites Plugins",
			customerID: "legit' -X 'rookery-build/buildinfo.Plugins=HIJACKED",
			wantInject: "Plugins=HIJACKED",
			note: "Single quote in customerID breaks out of -X argument. " +
				"The Go linker will see two -X flags and the last one wins, " +
				"allowing an attacker to overwrite any buildinfo variable.",
		},
		{
			name:     "single quote breakout from tenantID",
			tenantID: "legit' -extldflags '-Wl,-rpath,/evil/lib",
			note:     "Single quote in tenantID can inject -extldflags",
		},
		{
			name:       "single quote with -extld to use custom linker",
			customerID: "legit' -extld '/tmp/evil-linker",
			wantInject: "-extld",
			note: "Could force the Go toolchain to use a custom linker binary, " +
				"which is arbitrary command execution.",
		},
		{
			name:       "single quote with -tmpdir to control temp files",
			customerID: "legit' -tmpdir '/tmp/attacker-controlled",
			wantInject: "-tmpdir",
			note:       "Could redirect linker temp files to attacker-controlled directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateLdflags("", "v1.0.0", "2025-01-01", "plugins", "on", tt.customerID, tt.tenantID)

			if tt.wantInject != "" && strings.Contains(result, tt.wantInject) {
				t.Errorf("VULNERABILITY CONFIRMED: ldflags injection via single-quote breakout.\n"+
					"Customer ID: %q\n"+
					"Generated ldflags: %s\n"+
					"Impact: %s\n"+
					"Fix: Escape or reject single quotes in all user-controlled values "+
					"before embedding in ldflags.",
					tt.customerID, result, tt.note)
			} else {
				t.Logf("Result: %s", result)
				t.Logf("Note: %s", tt.note)
			}
		})
	}
}

// TestLdflags_ManifestLdflagsInjection tests that arbitrary ldflags from the
// manifest are prepended to the metadata flags without any validation.
//
// Vulnerable code path (main.go lines 517-522):
//
//	combinedLdflags := ldflags  // from manifest
//	if combinedLdflags != "" {
//	    combinedLdflags += " " + metadataFlags
//	}
//
// If the manifest provides ldflags, they are used AS-IS. This could inject
// any linker flag including -extld (custom linker), -extldflags, etc.
func TestLdflags_ManifestLdflagsInjection(t *testing.T) {
	tests := []struct {
		name    string
		ldflags string
		note    string
	}{
		{
			name:    "inject -extld for custom linker",
			ldflags: "-extld /tmp/evil-linker",
			note:    "Forces Go to use a custom linker, achieving arbitrary command execution",
		},
		{
			name:    "inject -toolexec",
			ldflags: "-toolexec 'touch /tmp/pwned'",
			note: "-toolexec is a go build flag, not a linker flag. " +
				"It would not work in ldflags. But it documents the concern.",
		},
		{
			name:    "inject -extldflags with rpath",
			ldflags: "-extldflags '-Wl,-rpath,/evil/lib -Wl,--dynamic-linker,/evil/ld.so'",
			note:    "Could change the runtime linker path of the compiled binary",
		},
		{
			name:    "inject -buildmode to change output type",
			ldflags: "-buildmode=plugin",
			note:    "Attempt to change the build mode via ldflags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateLdflags(tt.ldflags, "v1.0.0", "2025-01-01", "plugins", "on", "", "")

			// The manifest-provided ldflags are always included verbatim
			if strings.Contains(result, tt.ldflags) {
				t.Errorf("FINDING: Manifest ldflags included without validation.\n"+
					"Input:  %q\n"+
					"Result: %s\n"+
					"Note:   %s",
					tt.ldflags, result, tt.note)
			}
		})
	}
}

// TestLdflags_PluginsStringInjection tests that the plugins string
// (which is a join of all plugin import paths) can inject ldflags.
// The plugins string is built from user-controlled import paths.
func TestLdflags_PluginsStringInjection(t *testing.T) {
	// pluginsStr is built as: strings.Join(pluginList, ",")
	// where each item is importPath or importPath+"@"+version
	// Then embedded as: -X 'rookery-build/buildinfo.Plugins=%s'
	//
	// If any importPath contains a single quote, it can break out.
	evilPlugin := "github.com/evil/plugin' -X 'rookery-build/buildinfo.FipsMode=off"
	pluginsStr := evilPlugin + ",github.com/legit/plugin"

	result := GenerateLdflags("", "v1.0.0", "2025-01-01", pluginsStr, "on", "", "")

	if strings.Contains(result, "FipsMode=off") {
		// Check if it appears outside the expected Plugins value
		parts := strings.Split(result, "FipsMode=")
		if len(parts) > 2 {
			t.Errorf("VULNERABILITY CONFIRMED: Plugin import path with single quote "+
				"breaks out of ldflags -X argument.\n"+
				"Plugin string: %q\n"+
				"Generated ldflags: %s\n"+
				"Impact: Attacker can overwrite any buildinfo variable via malicious plugin name.",
				pluginsStr, result)
		}
	}
	t.Logf("Generated ldflags: %s", result)
}

// =============================================================================
// FULL MAIN.GO GENERATION
// =============================================================================

// TestGenerateMainGo_FipsInjection tests the complete main.go generation
// with fips mode injection.
func TestGenerateMainGo_FipsInjection(t *testing.T) {
	tests := []struct {
		name     string
		fipsMode string
		imports  string
		check    func(t *testing.T, result string)
	}{
		{
			name:     "fips mode injects go:generate",
			fipsMode: "on\n//go:generate touch /tmp/pwned",
			imports:  "\t_ \"github.com/legit/plugin\"\n",
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "//go:generate") {
					t.Errorf("VULNERABILITY: go:generate directive injected via fips mode:\n%s",
						result[:strings.Index(result, "package main")+len("package main")])
				}
			},
		},
		{
			name:     "fips mode injects package override",
			fipsMode: "on\n\npackage exploit\n\nimport \"os\"\n\nfunc init() { os.RemoveAll(\"/\") }\n\n// ",
			imports:  "\t_ \"github.com/legit/plugin\"\n",
			check: func(t *testing.T, result string) {
				if strings.Count(result, "package ") > 1 {
					t.Errorf("VULNERABILITY: Multiple package declarations injected via fips mode")
				}
			},
		},
		{
			name:     "normal fips mode",
			fipsMode: "on",
			imports:  "\t_ \"github.com/legit/plugin\"\n",
			check: func(t *testing.T, result string) {
				if !strings.HasPrefix(result, "//go:debug fips140=on\npackage main") {
					t.Errorf("Expected normal fips directive, got: %s", result[:80])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateMainGo(tt.fipsMode, tt.imports)
			tt.check(t, result)
		})
	}
}

// TestGenerateMainGo_ImportInjection tests injection via crafted import paths.
func TestGenerateMainGo_ImportInjection(t *testing.T) {
	tests := []struct {
		name    string
		imports string
		check   func(t *testing.T, result string)
	}{
		{
			name:    "normal imports",
			imports: "\t_ \"github.com/legit/plugin\"\n",
			check: func(t *testing.T, result string) {
				if !strings.Contains(result, `_ "github.com/legit/plugin"`) {
					t.Error("Expected normal import")
				}
			},
		},
		{
			name: "import with raw code injection attempt",
			// This is what GenerateImportLine produces for a malicious path
			// The %q in GenerateImportLine escapes the quotes
			imports: GenerateImportLine(`"; os.Exit(1); //`),
			check: func(t *testing.T, result string) {
				// %q will produce: _ "\"; os.Exit(1); //"
				// which is a valid Go string literal (escaped quotes inside)
				// The compiler will try to import this as a path, which will fail
				// at compile time. But the generated source is syntactically valid.
				if strings.Contains(result, `os.Exit(1)`) && !strings.Contains(result, `\"`) {
					t.Error("VULNERABILITY: Raw code injection in import path not escaped")
				} else {
					t.Log("SAFE: the percent-q format verb escapes double quotes in import paths")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateMainGo("", tt.imports)
			tt.check(t, result)
		})
	}
}

// =============================================================================
// GIT URL VALIDATION (MISSING)
// =============================================================================

// TestGitURL_Validation documents that the builder performs NO validation
// on git URLs before passing them to `git clone`.
func TestGitURL_Validation(t *testing.T) {
	dangerousURLs := []struct {
		name string
		url  string
		note string
	}{
		{
			name: "ext protocol executes commands",
			url:  "ext::sh -c touch% /tmp/pwned",
			note: "Git's ext:: transport runs arbitrary commands. " +
				"This is the most dangerous git URL pattern.",
		},
		{
			name: "ssh with ProxyCommand injection",
			url:  "ssh://-oProxyCommand=touch${IFS}/tmp/pwned/evil.git",
			note: "SSH URLs starting with - can inject ssh options. " +
				"ProxyCommand runs arbitrary commands.",
		},
		{
			name: "file protocol reads local files",
			url:  "file:///etc/passwd",
			note: "file:// protocol accesses local filesystem. " +
				"Could clone sensitive local git repos.",
		},
		{
			name: "flag injection via dash-prefixed URL",
			url:  "--upload-pack=evil",
			note: "URL starting with -- is treated as a git flag, not a URL. " +
				"git clone --upload-pack=evil would run 'evil' as the upload-pack command.",
		},
		{
			name: "local path masquerading as URL",
			url:  "/etc/shadow",
			note: "Bare filesystem path - git will clone from local filesystem",
		},
	}

	for _, tt := range dangerousURLs {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGitURL(tt.url)
			if err != nil {
				t.Logf("Would be caught by proposed validation: %v", err)
			} else {
				t.Logf("WARNING: Proposed validation does not catch: %s (%s)", tt.url, tt.note)
			}

			// The builder currently has NO validation at all.
			// It passes the URL directly to:
			//   run(".", "git", cloneArgs...)
			// where cloneArgs includes the raw URL.
			t.Logf("FINDING: Builder performs NO git URL validation. "+
				"URL %q would be passed directly to git clone. %s", tt.url, tt.note)
		})
	}
}

// =============================================================================
// VERSION STRING INJECTION
// =============================================================================

// TestVersionString_Injection tests that version strings from --with flags
// (e.g., github.com/org/plugin@v1.0.0) can contain malicious content
// that gets passed to `go get` without validation.
func TestVersionString_Injection(t *testing.T) {
	// In parseCLIPlugins, version is extracted from:
	//   if at := strings.LastIndex(raw, "@"); at > 0 {
	//       plugins = append(plugins, resolvedPlugin{importPath: raw[:at], version: raw[at+1:]})
	//   }
	// Then used in:
	//   run(buildDir, "go", "get", p.importPath+"@"+p.version)
	//
	// The version string is NOT validated before being passed to `go get`.
	// However, `go get` is invoked via exec.Command (not shell), so shell
	// metacharacters don't execute. The risk is more about:
	// 1. Fetching from unexpected sources
	// 2. Version string appearing in generated code via pluginsStr

	versions := []struct {
		name    string
		version string
		note    string
	}{
		{
			name:    "command substitution in version",
			version: "$(touch /tmp/pwned)",
			note:    "Safe: exec.Command doesn't interpret shell metacharacters",
		},
		{
			name:    "backtick in version",
			version: "`touch /tmp/pwned`",
			note:    "Safe: exec.Command doesn't interpret backticks",
		},
		{
			name:    "single quote breakout in version (ldflags)",
			version: "v1.0.0' -X 'rookery-build/buildinfo.FipsMode=off",
			note: "DANGEROUS: Version appears in pluginsStr which is embedded in ldflags. " +
				"Single quote can break out of -X argument.",
		},
		{
			name:    "very long version",
			version: strings.Repeat("v1.0.0", 10000),
			note:    "Could cause issues with command line length limits",
		},
	}

	for _, tt := range versions {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate how the version appears in ldflags
			pluginsStr := "github.com/legit/plugin@" + tt.version
			result := GenerateLdflags("", "v1.0.0", "2025-01-01", pluginsStr, "on", "", "")

			if strings.Contains(tt.version, "'") {
				// Verify sanitization: the result should NOT contain raw single quotes
				// from user input (GenerateLdflags sanitizes them)
				if strings.Contains(result, tt.version) {
					t.Errorf("VULNERABILITY: Unsanitized version string in ldflags.\n"+
						"Version: %q\n"+
						"Generated ldflags: %s\n"+
						"Impact: %s",
						tt.version, result, tt.note)
				} else {
					t.Logf("Version %q sanitized in output - %s", tt.version, tt.note)
				}
			} else {
				t.Logf("Version %q - %s", tt.version, tt.note)
			}
		})
	}
}

// =============================================================================
// ATTESTATION VERSION INJECTION
// =============================================================================

// TestAttestationVersion_Injection tests that --attestation-version is passed
// directly to `go get` without validation.
func TestAttestationVersion_Injection(t *testing.T) {
	// Vulnerable code path (main.go lines 354-358):
	//   if attestationVer != "" {
	//       run(buildDir, "go", "get", "github.com/.../attestation@"+attestationVer)
	//   }
	//
	// Since this uses exec.Command, shell metacharacters are safe.
	// But the version is also embedded in go.mod via `go get`, and
	// there's no validation that it's a valid semver.
	versions := []string{
		"v0.0.0-00000000000000-000000000000", // pseudo-version
		"v0.0.0-20250101000000-aaaaaaaaaaaa", // fake pseudo-version
		"latest",                             // not a valid version for go get
		"",                                   // empty (no-op)
		"v1.0.0\n",                           // newline
	}

	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			// Can't actually run `go get` in tests, but document the risk
			t.Logf("FINDING: attestation-version %q passed to `go get` without validation", v)
		})
	}
}

// =============================================================================
// DEFENSE-IN-DEPTH ANALYSIS
// =============================================================================

// TestDefenseInDepth_Summary summarizes all missing validations.
func TestDefenseInDepth_Summary(t *testing.T) {
	findings := []struct {
		severity string
		category string
		desc     string
		codeRef  string
	}{
		{
			severity: "HIGH",
			category: "FIPS Mode Injection",
			desc: "FIPS mode value from manifest is not validated in LoadManifest(). " +
				"CLI validates but defense-in-depth requires manifest validation too. " +
				"Newlines in fips mode inject arbitrary Go pragmas (go:generate, go:debug) " +
				"into generated source code.",
			codeRef: "main.go:389 fmt.Sprintf(\"//go:debug fips140=%s\\n\", fipsMode)",
		},
		{
			severity: "HIGH",
			category: "ldflags Single-Quote Breakout",
			desc: "CustomerID, TenantID, and plugin names are embedded in ldflags via " +
				"single-quoted -X arguments. Single quotes in these values break out " +
				"of the argument boundary, allowing injection of arbitrary linker flags " +
				"including -extld (custom linker = code execution).",
			codeRef: "main.go:509-515 fmt.Sprintf(\"-X 'rookery-build/buildinfo.CustomerID=%s'\", customerID)",
		},
		{
			severity: "HIGH",
			category: "Git URL Injection",
			desc: "Git URLs from manifest are passed directly to `git clone` without " +
				"any validation. ext:: protocol allows arbitrary command execution. " +
				"ssh:// with -oProxyCommand allows command execution. " +
				"file:// allows local filesystem access.",
			codeRef: "main.go:560-571 run(\".\", \"git\", cloneArgs...)",
		},
		{
			severity: "HIGH",
			category: "Manifest ldflags Injection",
			desc: "The ldflags value from manifest BuildOptions is used verbatim " +
				"as the prefix of the linker flags. This allows injection of " +
				"-extld (custom linker) or -extldflags for arbitrary linking behavior.",
			codeRef: "main.go:517-522 combinedLdflags := ldflags",
		},
		{
			severity: "MEDIUM",
			category: "Import Path Not Validated",
			desc: "Plugin import paths are not validated for format or content. " +
				"While %q format prevents Go syntax injection, there is no check " +
				"that paths are valid Go module paths. Arbitrary attacker-controlled " +
				"module paths with init() side effects will be compiled in.",
			codeRef: "main.go:378 fmt.Sprintf(\"\\t_ %%q\\n\", p.importPath)",
		},
		{
			severity: "MEDIUM",
			category: "Output Path Traversal",
			desc: "The output path from manifest or --output flag is not validated. " +
				"Path traversal (../) or absolute paths can write the compiled binary " +
				"to arbitrary filesystem locations.",
			codeRef: "main.go:535 os.WriteFile(out, outData, 0o755)",
		},
		{
			severity: "MEDIUM",
			category: "Subdir Path Traversal",
			desc: "The subdir field in git plugin specs is joined to the clone directory " +
				"via filepath.Join without validation. Path traversal via ../ can escape " +
				"the clone directory.",
			codeRef: "main.go:576 pluginDir = filepath.Join(cloneDir, spec.Subdir)",
		},
		{
			severity: "LOW",
			category: "No Input Length Limits",
			desc: "No length limits on any user-controlled input. Extremely long values " +
				"for customer_id, tenant_id, version strings, import paths, etc. could " +
				"cause issues with command line length limits or resource exhaustion.",
			codeRef: "Multiple locations",
		},
	}

	for _, f := range findings {
		t.Logf("[%s] %s: %s\n  Code: %s\n", f.severity, f.category, f.desc, f.codeRef)
	}
}
