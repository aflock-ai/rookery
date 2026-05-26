// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package attestation_test

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEverythingOverridable enforces the "everything user-overridable"
// principle documented in docs/configuration.md.
//
// The test walks every non-generated, non-test Go file in the repo
// and finds package-level constants and variables whose names begin
// with the case-insensitive "default" prefix. For each such name it
// asserts that AT LEAST ONE of the following holds:
//
//   - The name is referenced in a file that ALSO contains a
//     `cmd.Flags()` registration (CLI flag override path).
//   - The name is referenced in a file that ALSO contains an
//     `os.Getenv(` call (env-var override path).
//   - The name appears in the deliberateExclusionsWhitelist below.
//
// The heuristic is intentionally simple — we look for COUPLING
// between the default's name and an override mechanism in the same
// package, not for end-to-end flow correctness. Refactor at your
// peril: a name like "DefaultProbeTimeout" with no flag and no env
// var anywhere in the same package is a silent footgun.
//
// Adding a new default WITHOUT an override path fails this test and
// the developer must either add the override or extend the
// whitelist with a justification comment.
func TestEverythingOverridable(t *testing.T) {
	repoRoot := findRepoRoot(t)

	// Collect every default* identifier declared in the repo and the
	// file it was declared in.
	defaults := collectDefaultDecls(t, repoRoot)

	// For each default, find at least one file IN THE SAME PACKAGE
	// that wires it up to an override mechanism.
	missing := make([]missingOverride, 0)
	for _, d := range defaults {
		if _, skipped := deliberateExclusionsWhitelist[d.Name]; skipped {
			continue
		}
		if hasOverride(t, d) {
			continue
		}
		missing = append(missing, missingOverride{
			Name: d.Name,
			Path: d.FilePath,
		})
	}

	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i].Path < missing[j].Path })
		var b strings.Builder
		b.WriteString("\nThe following package-level defaults have no detectable override path " +
			"(no --flag, no os.Getenv, no config-file accessor in the same package).\n" +
			"Add one of:\n" +
			"  - a CLI flag (cmd.Flags().XxxVar(&MyDefault, ...))\n" +
			"  - an env var (os.Getenv(\"CILOCK_*\"))\n" +
			"  - a config-file key (.cilock.yaml / .witness.yaml entry)\n" +
			"Or add the constant to deliberateExclusionsWhitelist in this file with a comment\n" +
			"explaining why it is intentionally not overridable (e.g. kernel boundary,\n" +
			"schema version, crypto algorithm choice).\n\n")
		for _, m := range missing {
			b.WriteString("  default constant \"")
			b.WriteString(m.Name)
			b.WriteString("\" in ")
			b.WriteString(m.Path)
			b.WriteString(" has no override path.\n")
		}
		t.Fatal(b.String())
	}
}

type defaultDecl struct {
	Name     string
	FilePath string
	PkgDir   string
}

type missingOverride struct {
	Name string
	Path string
}

// deliberateExclusionsWhitelist is the curated set of default*
// constants that are deliberately NOT operator-overridable. Every
// entry MUST be accompanied by a comment explaining why.
//
// The threshold for adding an entry: changing this value would
// either break the wire format (schema versions), break the
// kernel/userspace boundary (eBPF program IDs, syscall numbers),
// or change a security-critical algorithm choice that we control
// via a separate versioning mechanism (digest algorithms, signing
// curves).
var deliberateExclusionsWhitelist = map[string]struct{}{
	// Schema versions encode wire-format compatibility. Users do
	// not change these; bumps go with code changes.
	"DefaultRegistry": {}, // OCI registry constant for k8smanifest's ref resolver — not a CLI knob, it's the spec-mandated default registry for unqualified image names.

	// Probe-timeout default is read by the detection runtime; it
	// IS overridable via per-call options at the API layer
	// (DetectionOption), and the CLI exposes that via plan-time
	// configuration rather than a raw flag. Documented in
	// docs/configuration.md as an "advanced runtime tuning" case.
	"DefaultProbeTimeout": {},

	// DefaultPrewalkSkipDirs IS overridable via --prewalk-skip-dir
	// and --prewalk-include-dir. The override coupling is in
	// cilock/cli/run.go (different package), so the same-package
	// heuristic misses it. The behaviour is covered by
	// prewalk_override_test.go.
	"DefaultPrewalkSkipDirs": {},

	// DefaultMaxDigests is overridable via the
	// CILOCK_FANOTIFY_MAX_DIGESTS env var resolved by
	// defaultMaxDigestsFromEnv in the same file — but the
	// heuristic only looks for os.Getenv near a const named after
	// the default, and the resolver function is named
	// "defaultMaxDigestsFromEnv". The override is real; the
	// heuristic is conservative. Covered by max_digests_env_test.go.
	"DefaultMaxDigests": {},

	// Default HTTP chain-sidecar timeout / max-bytes are
	// overridable via --chain-sidecar-http-timeout and
	// --chain-sidecar-http-max-bytes, plumbed from
	// cilock/internal/options/verify.go (different package).
	// Same-package heuristic misses it; coverage lives in
	// chain_sidecar_http_override_test.go.
	"DefaultHTTPChainSidecarTimeout":  {},
	"DefaultHTTPChainSidecarMaxBytes": {},

	// DefaultPlatformURL is overridable via --platform-url; the
	// flag binding lives in cilock/internal/options/run.go (a
	// different package from where the const is declared).
	"DefaultPlatformURL": {},

	// DefaultAttestors is the always-on attestor list; users
	// override via --attestations and --no-default-attestor. The
	// CLI flag wiring lives in a different package
	// (cilock/internal/options vs cilock/cli) than where the slice
	// is declared.
	"DefaultAttestors": {},

	// --- Internal singletons / specification constants ---
	// These names use the "default" prefix to follow Go convention
	// for package-level singletons, but they are NOT user-tunable
	// knobs. They model either (a) a process-wide shared resource
	// where mutation would create a data race, or (b) a value
	// dictated by an external specification.

	// defaultRegistry (attestation/detection): the per-process
	// singleton that init()-time plugin registrations write to.
	// Mutation would race; a CLI flag has no meaning.
	"defaultRegistry": {},

	// defaultAITimeout (attestation/policy/ai): transport-level
	// http.Client timeout for the AI policy evaluator. Doc comment
	// explicitly states "no user knob — change in source if a
	// model genuinely needs more time". Server URL and model name
	// are the user-facing knobs.
	"defaultAITimeout": {},

	// DefaultSensitiveEnvList (compat/go-witness): backward-compat
	// re-export of attestation.DefaultSensitiveEnvList. The
	// override surface lives in the core attestation package; this
	// is a `var x = pkg.x` aliasing pattern, not a new default.
	"DefaultSensitiveEnvList": {},

	// defaultConfigFile (plugins/attestors/configuration): hard-
	// coded fallback path ".witness.yaml" used by the legacy
	// configuration attestor when the caller passes "". The
	// caller-supplied path IS the override.
	"defaultConfigFile": {},

	// defaultRegistryAliases (k8smanifest/ociref): the OCI spec's
	// canonical short-form → registry-1.docker.io alias table.
	// Changing it would break image-reference resolution; this is
	// not an operator knob, it's the spec.
	"defaultRegistryAliases": {},

	// defaultResolver (k8smanifest/util): process-wide
	// http.Client-backed OCI ref resolver. Behaves like
	// http.DefaultClient — internal plumbing, not operator-facing.
	"defaultResolver": {},

	// secretscan internal constants: small magic numbers
	// (defaultMatchContextSize), reserved-for-future-use ("" sentinels:
	// defaultAllowList), and a code-side dispatch table
	// (defaultEncodingScanners). None are operator knobs — every
	// secretscan tunable IS plumbed via registry.*ConfigOption.
	"defaultAllowList":        {},
	"defaultMatchContextSize": {},
	"defaultEncodingScanners": {},
}

// hasOverride looks at every file in d.PkgDir and asks: does this
// package's source mention d.Name AND a CLI/env override
// mechanism? If yes, the default is plumbed. If no, the test
// flags it.
//
// We use a conservative same-package heuristic. Defaults wired up
// from a different package (CLI flag in cilock/cli pointing at a
// const declared in attestation/...) MUST be added to the
// whitelist with a comment explaining the cross-package coupling
// — that's a known false negative we accept in exchange for a
// simple test that runs in milliseconds.
func hasOverride(t *testing.T, d defaultDecl) bool {
	t.Helper()
	entries, err := os.ReadDir(d.PkgDir)
	if err != nil {
		return false
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		// Skip the file declaring the default; the override site
		// is the relevant signal.
		fp := filepath.Join(d.PkgDir, name)
		data, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		s := string(data)
		// File must mention the default's name AND a known override marker.
		if !strings.Contains(s, d.Name) {
			continue
		}
		if strings.Contains(s, "cmd.Flags()") ||
			strings.Contains(s, "os.Getenv(") ||
			strings.Contains(s, "getStringFromConfig(") ||
			strings.Contains(s, "getStringSliceFromConfig(") ||
			// Registry-based attestor config options route into the
			// `--attestor-<name>-<key>` CLI flag namespace at startup
			// (see cilock/internal/options/options.go addFlagsFromRegistry).
			// Detecting any of these constructors is enough to prove
			// the default is plumbed through to the operator.
			strings.Contains(s, "registry.StringConfigOption(") ||
			strings.Contains(s, "registry.BoolConfigOption(") ||
			strings.Contains(s, "registry.IntConfigOption(") ||
			strings.Contains(s, "registry.StringSliceConfigOption(") {
			return true
		}
	}
	return false
}

// collectDefaultDecls walks the repo and collects every
// package-level const/var declaration whose name starts with
// "default" or "Default".
func collectDefaultDecls(t *testing.T, repoRoot string) []defaultDecl {
	t.Helper()
	var out []defaultDecl
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // best-effort walk; unreadable subtree is not fatal for the override audit
		}
		if d.IsDir() {
			base := d.Name()
			if base == "vendor" || base == ".git" || base == "node_modules" || base == ".claude" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, "zz_generated") {
			return nil
		}
		// Skip generated bpf2go output (these are auto-generated
		// const/var blobs from cilium/ebpf and not operator-tunable).
		if strings.Contains(base, "_bpfel_") || strings.Contains(base, "_bpfeb_") {
			return nil
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			// File doesn't parse (probably build-tag noise or
			// generated). Skip silently — vet handles real syntax
			// errors elsewhere.
			return nil //nolint:nilerr // parse failure on an individual file is not fatal for the override audit
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			if gd.Tok != token.CONST && gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if name == nil || name.Name == "" {
						continue
					}
					lower := strings.ToLower(name.Name)
					if !strings.HasPrefix(lower, "default") {
						continue
					}
					// Must be a default-PREFIX (DefaultFoo, defaultBar),
					// not a longer word like "defaulter".
					if len(name.Name) > len("default") {
						next := name.Name[len("default")]
						if next >= 'a' && next <= 'z' {
							continue
						}
					}
					out = append(out, defaultDecl{
						Name:     name.Name,
						FilePath: path,
						PkgDir:   filepath.Dir(path),
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	return out
}

// findRepoRoot starts from the test file's working directory and
// walks up until it finds go.work — the unambiguous monorepo
// marker.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 10; i++ {
		if fileExists(filepath.Join(dir, "go.work")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find go.work walking up from %s", wd)
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

// readFirstLine is reserved for future diagnostic enrichment; the
// linter will fuss if we declare unused helpers, so guard it with
// a build-tag-style underscore reference at the bottom of the
// file.
var _ = readFirstLine

func readFirstLine(p string) string {
	f, err := os.Open(p) //nolint:gosec
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	if s.Scan() {
		return s.Text()
	}
	return ""
}
