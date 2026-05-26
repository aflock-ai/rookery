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

package cli

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/gobwas/glob"
	"github.com/spf13/cobra"
)

var alwaysRunAttestors = []attestation.Attestor{product.New(), material.New()}

// defaultAttestorNames lists the always-on attestor names that
// --no-default-attestor can disable. Kept in sync with
// alwaysRunAttestors; if a name appears here it MUST be present in
// the slice above and vice versa.
var defaultAttestorNames = []string{product.Name, material.Name}

// applyNoDefaultAttestors filters out always-on attestors named in
// the operator's --no-default-attestor flags. Hard-fails when the
// detectWorkloadAttestors probes the working directory for indicators
// of common build systems and returns the names of attestors that
// should run on top of whatever the operator already configured.
// Cheap stat-based detection — no recursive walks, no file content
// reading. The probe runs once at startup, before any attestor fires.
//
// Detection rules:
//
//   - go.mod                          → go-build, govulncheck
//   - package.json or package-lock    → sbom, lockfiles
//   - Cargo.toml                      → lockfiles
//   - Dockerfile / Containerfile      → oci
//   - .git/                           → git
//
// Names returned are merged with --attestations by the caller via
// dedupe; an operator's explicit choice is never silently dropped.
// Phase 4 of #234.
func detectWorkloadAttestors(workdir string) []string {
	if workdir == "" {
		var err error
		workdir, err = os.Getwd()
		if err != nil {
			return nil
		}
	}
	var detected []string
	add := func(name string) {
		for _, d := range detected {
			if d == name {
				return
			}
		}
		detected = append(detected, name)
	}
	exists := func(name string) bool {
		_, err := os.Stat(workdir + "/" + name)
		return err == nil
	}
	if exists("go.mod") {
		add("go-build")
		add("govulncheck")
	}
	if exists("package.json") || exists("package-lock.json") {
		add("sbom")
		add("lockfiles")
	}
	if exists("Cargo.toml") {
		add("lockfiles")
	}
	if exists("Dockerfile") || exists("Containerfile") {
		add("oci")
	}
	if exists(".git") {
		add("git")
	}
	return detected
}

// attestorExternalGenerators returns the external tool binaries whose
// output the named attestor records. cilock NEVER invokes these — the
// user's build command must run them; we only check PATH to warn the
// operator when an attestor will come out empty.
//
// The list is sourced entirely from the detection registry (the
// attestor's own detector.yaml plus the embedded catalog), so adding a
// tool is a YAML edit, not a code change. Two contributions are unioned:
//
//  1. Format attestors. The "sbom" attestor signs whatever syft / cdxgen /
//     bom produce; those catalog entries declare emits_formats: [sbom].
//     We collect the argv head of every registry entry that emits this
//     attestor's name as a format.
//  2. Tool-wrapper attestors. "trivy" wraps trivy, "go-build" wraps go,
//     "oci" recognizes docker save / skopeo copy / crane. We collect the
//     argv head from the attestor's own pre/post predicates.
//
// Empty result = self-contained attestor (git reads .git/, environment
// reads env vars — no external generator, so no PATH warning).
//
// Pre-flight intentionally trusts the registry over a hand-curated list:
// a generator cilock can't recognize at runtime is one whose absence is
// not worth warning about, since its output wouldn't be detected anyway.
func attestorExternalGenerators(name string) []string {
	reg := detection.Default()
	seen := make(map[string]struct{})
	var out []string
	add := func(bin string) {
		if bin == "" {
			return
		}
		if _, dup := seen[bin]; dup {
			return
		}
		seen[bin] = struct{}{}
		out = append(out, bin)
	}

	// (1) Every registry entry that emits this attestor's name as a format.
	all, _ := reg.LookupAll()
	for _, d := range all {
		for _, f := range d.EmitsFormats {
			if f == name {
				collectArgvHeads(d, add)
				break
			}
		}
	}
	// (2) The attestor's own detector predicates.
	if d, ok, err := reg.Lookup(name); err == nil && ok && d != nil {
		collectArgvHeads(d, add)
	}

	sort.Strings(out) // deterministic ordering for output + tests
	return out
}

// collectArgvHeads walks a detector's pre/post predicate trees and feeds
// the first token of every argv_prefix to add. The head token is the
// invoked binary (e.g. ["docker", "save"] -> "docker"); that is what
// pre-flight looks up on PATH.
func collectArgvHeads(d *detection.DetectorYAML, add func(string)) {
	var visit func(p *detection.Predicate)
	visit = func(p *detection.Predicate) {
		if p == nil {
			return
		}
		if len(p.ArgvPrefix) > 0 {
			add(p.ArgvPrefix[0])
		}
		for i := range p.AnyOf {
			visit(&p.AnyOf[i])
		}
		for i := range p.AllOf {
			visit(&p.AllOf[i])
		}
		visit(p.Not)
		visit(p.ExecObserved)
	}
	for _, g := range []*detection.GateBlock{d.Pre, d.Post} {
		if g != nil {
			visit(g.Match)
		}
	}
}

// attestorWorkspacePrereq reports the workspace file/dir path an
// attestor needs present in the workdir to produce any output. Empty
// = no workspace prerequisite. Pre-flight surfaces missing prereqs
// as warnings so operators don't wait for the build to complete
// before learning their attestor will fail.
func attestorWorkspacePrereq(name string) string {
	switch name {
	case "git":
		return ".git"
	}
	return ""
}

// preflightAttestorTooling inspects every attestor in the active set
// and emits one-line warnings for prerequisites the operator hasn't
// satisfied. Returns true if any warning was emitted — callers may
// surface the count in --validate-only output.
//
// Two checks per attestor:
//
//  1. External generator on PATH (sbom needs syft/cdxgen/bom,
//     govulncheck needs govulncheck, ...). The candidate list comes from
//     the detection registry; cilock never invokes the generator, the
//     user's build command must produce its output.
//  2. Workspace prereq present (git needs .git/, etc.).
//
// Warnings are non-fatal — the attestor itself decides whether the
// missing prereq is a soft-error (sbom) or a hard-error (git) at
// run time. Pre-flight just gives operators a heads-up so they can
// fix the gap before the build runs.
func preflightAttestorTooling(workdir string, attestors []string) (warned bool) {
	if workdir == "" {
		if cwd, err := os.Getwd(); err == nil {
			workdir = cwd
		}
	}
	for _, name := range attestors {
		// Workspace prereq check.
		if prereq := attestorWorkspacePrereq(name); prereq != "" {
			path := workdir + "/" + prereq
			if _, err := os.Stat(path); err != nil {
				log.Warnf("attestor %q will fail: workspace is missing %q (the attestor reads from it)", name, prereq)
				warned = true
			}
		}
		// External-generator check: if any candidate generator is on
		// PATH, the attestor has a chance of seeing its output.
		gens := attestorExternalGenerators(name)
		if len(gens) == 0 {
			continue
		}
		found := false
		var available []string
		for _, g := range gens {
			if _, err := execLookPath(g); err == nil {
				found = true
				available = append(available, g)
				break
			}
		}
		if !found {
			// Render the generator list once, comma-joined, to avoid the
			// double-bracketed `[[a b c]]` cosmetic bug the round-4 UX
			// test caught when %v stringified an already-formatted slice.
			gensList := strings.Join(gens, ", ")
			log.Warnf("attestor %q will produce no output: no generator found on PATH (looked for [%s]) — "+
				"this attestor RECORDS the output of an external tool; cilock does NOT invoke the generator. "+
				"Install one of those or drop the attestor from --attestations.",
				name, gensList)
			warned = true
			continue
		}
		_ = available
	}
	return warned
}

// mergeAttestorNames adds detected names into the operator's list,
// dropping duplicates while preserving the operator-supplied order
// first. Returns the merged list and a slice of names actually added
// (for the --validate-only report).
func mergeAttestorNames(operatorList, detected []string) (merged, added []string) {
	seen := make(map[string]struct{}, len(operatorList)+len(detected))
	for _, name := range operatorList {
		merged = append(merged, name)
		seen[name] = struct{}{}
	}
	for _, name := range detected {
		if _, ok := seen[name]; ok {
			continue
		}
		merged = append(merged, name)
		added = append(added, name)
		seen[name] = struct{}{}
	}
	return merged, added
}

// validateUserCommand checks that args[0] resolves on PATH (or as an
// absolute path). Returns a non-nil error if the resolution fails;
// the run.go caller decides whether to treat that as fatal or just
// a warning depending on --validate-only.
func validateUserCommand(args []string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := args[0]
	// LookPath handles both bare names (resolves on PATH) and paths
	// (verifies existence + executable bit). No special-case needed.
	if _, err := execLookPath(cmd); err != nil {
		return fmt.Errorf("user command %q: %w", cmd, err)
	}
	return nil
}

// execLookPath is a tiny wrapper so the lookup can be mocked in tests.
// Kept as a var so tests can swap it.
var execLookPath = exec.LookPath

// applyHardeningProfile sets per-feature env defaults based on the
// named --hardening profile, leaving explicit operator env vars
// untouched. Recognised profiles:
//
//   - "off"      — fanotify off, fs-verity off, no require-zero-drops
//   - "standard" — fanotify on,  fs-verity opportunistic, drops surfaced
//   - "strict"   — fanotify required, fs-verity required, drops fail
//
// requireZeroDrops is updated only when the operator didn't explicitly
// pass --require-zero-drops on the command line (changed=false).
// Operators can still pin individual env vars; the profile only seeds
// defaults via setEnvIfUnset.
//
// Phase 3 of #234.
func applyHardeningProfile(profile string, requireZeroDrops *bool, requireZeroDropsExplicit bool) error {
	switch profile {
	case "", "standard":
		setEnvIfUnset("CILOCK_FANOTIFY", "1")
		setEnvIfUnset("CILOCK_FSVERITY", "auto")
		// standard: drops surfaced but not fatal (no override).
	case "off":
		setEnvIfUnset("CILOCK_FANOTIFY", "off")
		setEnvIfUnset("CILOCK_FSVERITY", "off")
		// off: drops are non-fatal (no override).
	case "strict":
		setEnvIfUnset("CILOCK_FANOTIFY", "1")
		setEnvIfUnset("CILOCK_FSVERITY", "1")
		if !requireZeroDropsExplicit {
			*requireZeroDrops = true
		}
	default:
		return fmt.Errorf("--hardening: unknown profile %q (valid: off, standard, strict)", profile)
	}
	return nil
}

// setEnvIfUnset sets an env var only when no value is already present.
// Used by applyHardeningProfile so explicit operator env vars take
// precedence over profile defaults.
func setEnvIfUnset(key, value string) {
	if _, present := os.LookupEnv(key); !present {
		_ = os.Setenv(key, value)
	}
}

// splitCaptureModeSuffix parses an optional `:backend` suffix from the
// --capture-mode value. Recognised: `trace:ebpf`, `trace:ptrace`,
// `trace:auto`, or `auto:ebpf|ptrace|auto` (auto mode can also pin the
// tracer backend explicitly). Empty backend means "no suffix supplied;
// commandrun chooses based on CILOCK_TRACE_MODE / its own default".
//
// Phase 2 of #234 — replaces CILOCK_TRACE_MODE as the canonical knob
// for the tracer backend; the env var still works but is now derived
// from --capture-mode.
func splitCaptureModeSuffix(s string) (mode, backend string) {
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// warnLegacyDiagnosticEnv prints a one-line migration message for each
// legacy diagnostic env var the operator still has set in their CI YAML.
// The new world is a single --diagnose flag (or CILOCK_DIAGNOSE=1 for
// equivalent effect from env). The renamed CILOCK_DEV_BPF_* vars keep
// the same behavior as their unprefixed predecessors; they're flagged
// as "dev-only" so operators understand they're not part of the supported
// surface.
func warnLegacyDiagnosticEnv() {
	// Logging vars folded into --diagnose / CILOCK_DIAGNOSE.
	for _, v := range []string{"CILOCK_EBPF_DEBUG", "CILOCK_BPF_DIAGNOSE"} {
		if os.Getenv(v) != "" {
			log.Warnf("%s is no longer recognized; use --diagnose (or CILOCK_DIAGNOSE=1) instead", v)
		}
	}
	// Dev-only tuning vars renamed with CILOCK_DEV_ prefix to signal
	// "not for production use". Auto-translate if both old + new are
	// unset — preserves operator workflows that haven't migrated yet,
	// surfaces the warning so the migration happens.
	for _, m := range []struct{ old, new string }{
		{"CILOCK_BPF_OBJECT_PATH", "CILOCK_DEV_BPF_OBJECT_PATH"},
		{"CILOCK_BPF_REBUILD", "CILOCK_DEV_BPF_REBUILD"},
		{"CILOCK_BPF_SKIP_PROGRAMS", "CILOCK_DEV_BPF_SKIP_PROGRAMS"},
	} {
		if v := os.Getenv(m.old); v != "" {
			log.Warnf("%s is deprecated; rename to %s (dev-only knob; not part of the supported surface)", m.old, m.new)
			if os.Getenv(m.new) == "" {
				_ = os.Setenv(m.new, v)
			}
		}
	}
}

// user disables every default attestor — the attestation collection
// would have no body to attest.
func applyNoDefaultAttestors(base []attestation.Attestor, disabled []string) ([]attestation.Attestor, error) {
	if len(disabled) == 0 {
		return base, nil
	}
	disabledSet := make(map[string]struct{}, len(disabled))
	for _, name := range disabled {
		if name == "" {
			continue
		}
		known := false
		for _, k := range defaultAttestorNames {
			if k == name {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("--no-default-attestor=%q: not a recognised default attestor (valid: %s)",
				name, strings.Join(defaultAttestorNames, ", "))
		}
		disabledSet[name] = struct{}{}
	}
	if len(disabledSet) >= len(defaultAttestorNames) {
		return nil, fmt.Errorf(
			"SECURITY: --no-default-attestor disables every always-on attestor (%s). "+
				"The resulting attestation collection would have no product or material evidence — "+
				"refusing to proceed. Drop one of the --no-default-attestor flags",
			strings.Join(defaultAttestorNames, ", "))
	}
	out := make([]attestation.Attestor, 0, len(base))
	for _, a := range base {
		if _, drop := disabledSet[a.Name()]; drop {
			log.Warnf("--no-default-attestor: dropping always-on attestor %q (operator override)", a.Name())
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

//nolint:funlen,gocognit // RunCmd composes flag registration + pre-flight gates inline; refactoring would split closely-related code
func RunCmd() *cobra.Command {
	o := options.RunOptions{
		AttestorOptSetters:       make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}

	cmd := &cobra.Command{
		Use:   "run [cmd]",
		Short: "Runs the provided command and records attestations about the execution",
		Long: `Runs the provided command and records attestations about the execution.

Exit-code policy (finding #221):
  Attestor errors are split into two classes:

  Fatal (exit 1, logged under "Errors:")
    - signer failure
    - command exited non-zero
    - --trace requested on a platform that doesn't support tracing
    - output path inaccessible / key parse failed
    - any other attestor contract violation

  Soft  (exit 0, logged under "Warnings:")
    - sbom: no products to attest / no SBOM file found
    - go-build: no Go binaries among products
    - any attestor that ran successfully but had nothing to do

  CI should gate on cilock's exit code — only a fatal class produces
  a non-zero exit.`,
		Example: `  # Wrap a build, sign with a local key, capture Go build provenance
  cilock run --step build -k cosign.key --workload manual -a environment,git,go-build -o build.att.json -- go build ./...

  # Wrap any command, signing it with just the environment attestor
  cilock run --step unit-test -k cosign.key --workload manual -a environment -o test.att.json -- go test ./...

  # On Linux, add -r/--trace to capture file + network materials via eBPF
  # (falls back to ptrace). --enable-archivista stores the result remotely.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply platform-derived defaults (archivista, TSA URLs) for any
			// flags not explicitly set by the user or config file.
			o.ResolvePlatformDefaults(cmd)

			// Warn loudly if operators are still using legacy diagnostic env
			// vars; tell them how to migrate. Then translate --diagnose into
			// the single CILOCK_DIAGNOSE env var that downstream subpackages
			// read.
			warnLegacyDiagnosticEnv()
			if o.Diagnose {
				_ = os.Setenv("CILOCK_DIAGNOSE", "1")
			}

			// Apply --hardening profile defaults BEFORE any attestor runs.
			// Per-feature env vars still win — applyHardeningProfile only
			// sets defaults via setEnvIfUnset. Profile also seeds the
			// --require-zero-drops gate when --hardening=strict.
			if err := applyHardeningProfile(o.Hardening, &o.RequireZeroDrops, cmd.Flags().Changed("require-zero-drops")); err != nil {
				return err
			}

			// Workload auto-detection: probe the workspace for build-system
			// indicators (go.mod, package.json, .git, etc.) and merge the
			// matched attestors into the operator's --attestations list.
			// Phase 4 of #234. Skip when --workload=manual.
			var detectedNames []string
			if o.Workload != "manual" {
				probed := detectWorkloadAttestors(o.WorkingDir)
				var merged []string
				merged, detectedNames = mergeAttestorNames(o.Attestations, probed)
				o.Attestations = merged
			}

			// Infer --step from the wrapped command when the operator didn't
			// set one: the detection engine matches the argv to a tool, and
			// the tool's lexicon category becomes the step name. Unknown or
			// ambiguous commands get an actionable diagnostic and a hard
			// error — cilock will not silently guess the routing key the
			// policy verifier binds evidence by.
			if o.StepName == "" {
				if err := inferStepName(&o, args); err != nil {
					return err
				}
			}

			// Validate the user command resolves before doing the real run.
			// Soft warning when --validate-only is off; hard exit when on.
			cmdErr := validateUserCommand(args)

			// Pre-flight: warn the operator about attestors whose
			// prerequisites aren't satisfied (no .git/ for git; no SBOM
			// generator on PATH for sbom; no govulncheck binary on PATH;
			// etc.). cilock never invokes these tools — the warnings let
			// operators install them OR drop the attestor before the
			// build runs and produces an empty attestation.
			preflightWarned := preflightAttestorTooling(o.WorkingDir, o.Attestations)

			if o.ValidateOnly {
				fmt.Fprintln(os.Stderr, "cilock pre-flight:")
				fmt.Fprintf(os.Stderr, "  attestations (operator + detected): %v\n", o.Attestations)
				if len(detectedNames) > 0 {
					fmt.Fprintf(os.Stderr, "  workload auto-added: %v\n", detectedNames)
				}
				fmt.Fprintf(os.Stderr, "  hardening: %s\n", o.Hardening)
				fmt.Fprintf(os.Stderr, "  capture-mode: %s\n", o.CaptureMode)
				if cmdErr != nil {
					fmt.Fprintf(os.Stderr, "  WARN: %v\n", cmdErr)
				}
				if preflightWarned {
					fmt.Fprintln(os.Stderr, "  (see WARN lines above — at least one attestor's prerequisite is missing)")
				}
				fmt.Fprintln(os.Stderr, "  (--validate-only — exiting without running the command)")
				return nil
			}
			if cmdErr != nil {
				// Non-fatal in normal mode — the user command may be a
				// shell builtin, a wrapper, or come from a PATH the
				// subprocess will set up. Print and continue.
				log.Warnf("%v", cmdErr)
			}

			signers, err := loadSigners(cmd.Context(), o.SignerOptions, o.KMSSignerProviderOptions, providersFromFlags("signer", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signers: %w", err)
			}

			// Capture which registry-derived flags the operator
			// explicitly set on the command line. The product
			// attestor's precedence table treats a user-set
			// --attestor-product-include-glob as a rescue signal
			// that overrides default cache classification; without
			// the Changed() bit we can't distinguish "user typed *"
			// from "default *". cobra is the only layer that has
			// this signal.
			userSetFlags := map[string]bool{
				"attestor-product-include-glob": cmd.Flags().Changed("attestor-product-include-glob"),
			}

			return runRun(cmd.Context(), o, args, userSetFlags, signers...)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

func runRun(ctx context.Context, ro options.RunOptions, args []string, userSetFlags map[string]bool, signers ...cryptoutil.Signer) error { //nolint:gocognit,gocyclo,funlen
	if len(signers) > 1 {
		return fmt.Errorf("only one signer is supported")
	}

	if len(signers) == 0 {
		return fmt.Errorf("no signers found")
	}

	timestampers := []timestamp.Timestamper{}
	for _, url := range ro.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	// Create fresh attestor instances each time to avoid leaking state
	// from prior invocations (alwaysRunAttestors holds shared singletons).
	defaults := []attestation.Attestor{product.New(), material.New()}
	attestors, err := applyNoDefaultAttestors(defaults, ro.NoDefaultAttestors)
	if err != nil {
		return err
	}
	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(
			commandrun.WithCommand(args),
			commandrun.WithTracing(ro.Tracing),
			commandrun.WithIgnoreExitCode(ro.IgnoreCommandExitCode),
			commandrun.WithPrewalkSkipDirs(ro.PrewalkSkipDirs),
			commandrun.WithPrewalkIncludeDirs(ro.PrewalkIncludeDirs),
			commandrun.WithRequireZeroDrops(ro.RequireZeroDrops),
		))
	}

	for _, a := range ro.Attestations {
		if a == "command-run" {
			log.Warnf("'command-run' is a builtin attestor and cannot be called with --attestations flag")
			continue
		}

		duplicate := false
		for _, att := range attestors {
			if a != att.Name() {
			} else {
				log.Warnf("Attestor %s already declared, skipping", a)
				duplicate = true
				break
			}
		}

		if !duplicate {
			attestor, err := attestation.GetAttestor(a)
			if err != nil {
				return fmt.Errorf("failed to create attestor: %w", err)
			}
			attestors = append(attestors, attestor)
		}
	}

	for i, attestor := range attestors {
		setters, ok := ro.AttestorOptSetters[attestor.Name()]
		if !ok {
			continue
		}

		updated, err := registry.SetOptions(attestor, setters...)
		if err != nil {
			return fmt.Errorf("failed to set attestor option for %v: %w", attestor.Type(), err)
		}
		attestors[i] = updated
	}

	// Stamp user-intent flags on the product attestor AFTER the
	// registry option setters have run. The registry layer only sees
	// flag values, not whether the value came from the operator or
	// the default. The precedence table in product.Attest needs the
	// Changed() bit to decide whether to treat the include-glob as a
	// rescue signal (operator intent) or just a filter (default).
	if userSetFlags["attestor-product-include-glob"] {
		for i, attestor := range attestors {
			prod, ok := attestor.(*product.Attestor)
			if !ok {
				continue
			}
			product.WithIncludeGlobUserIntent(true)(prod)
			attestors[i] = prod
		}
	}

	var roHashes []cryptoutil.DigestValue
	for _, hashStr := range ro.Hashes {
		hash, err := cryptoutil.HashFromString(hashStr)
		if err != nil {
			return fmt.Errorf("failed to parse hash: %w", err)
		}
		roHashes = append(roHashes, cryptoutil.DigestValue{Hash: hash, GitOID: false})
	}

	for _, dirHashGlobItem := range ro.DirHashGlobs {
		_, err := glob.Compile(dirHashGlobItem)
		if err != nil {
			return fmt.Errorf("failed to compile glob: %v", err)
		}
	}

	// Build attestation context options.
	//
	// Phase 2: --capture-mode accepts an optional tracer-backend suffix
	// `:ebpf|:ptrace|:auto` (e.g. `trace:ebpf`). The suffix selects the
	// commandrun tracer backend by setting CILOCK_TRACE_MODE before any
	// attestor runs. Without a suffix, behavior is the same as before
	// (commandrun's own auto-fallback applies).
	baseCaptureMode, traceBackend := splitCaptureModeSuffix(ro.CaptureMode)
	captureMode := attestation.CaptureMode(baseCaptureMode)
	if err := captureMode.Validate(); err != nil {
		return fmt.Errorf("--capture-mode: %w", err)
	}
	if traceBackend != "" {
		if captureMode != attestation.CaptureTrace && captureMode != attestation.CaptureAuto {
			return fmt.Errorf("--capture-mode: backend suffix %q is only meaningful with capture-mode=trace or =auto, not %q", traceBackend, baseCaptureMode)
		}
		_ = os.Setenv("CILOCK_TRACE_MODE", traceBackend)
	}
	attestationOpts := []attestation.AttestationContextOption{
		attestation.WithWorkingDir(ro.WorkingDir),
		attestation.WithHashes(roHashes),
		attestation.WithDirHashGlob(ro.DirHashGlobs),
		attestation.WithCaptureMode(captureMode),
		attestation.WithCachePatternOptions(attestation.CachePatternOptions{
			Add:                ro.CacheAddPatterns,
			Allow:              ro.CacheAllowPatterns,
			DisableDefaults:    ro.CacheDisableDefaults,
			DisableSystemQuery: ro.CacheDisableEnvProbe,
		}),
	}

	if ro.EnvFilterSensitiveVars {
		attestationOpts = append(attestationOpts, attestation.WithEnvFilterVarsEnabled())
	}
	if ro.EnvDisableSensitiveVars {
		attestationOpts = append(attestationOpts, attestation.WithEnvDisableDefaultSensitiveList())
	}
	if len(ro.EnvAddSensitiveKeys) > 0 {
		attestationOpts = append(attestationOpts, attestation.WithEnvAdditionalKeys(ro.EnvAddSensitiveKeys))
	}
	if len(ro.EnvAllowSensitiveKeys) > 0 {
		attestationOpts = append(attestationOpts, attestation.WithEnvExcludeKeys(ro.EnvAllowSensitiveKeys))
	}
	if len(ro.EnvCaptureAllowlist) > 0 {
		attestationOpts = append(attestationOpts, attestation.WithEnvCaptureAllowlist(ro.EnvCaptureAllowlist))
	}

	additionalSubjects, err := parseSubjectFlags(ro.Subjects)
	if err != nil {
		return fmt.Errorf("failed to parse --subjects: %w", err)
	}

	runOpts := []workflow.RunOption{
		workflow.RunWithSigners(signers...),
		workflow.RunWithAttestors(attestors),
		workflow.RunWithAttestationOpts(attestationOpts...),
		workflow.RunWithTimestampers(timestampers...),
	}
	if len(additionalSubjects) > 0 {
		runOpts = append(runOpts, workflow.RunWithAdditionalSubjects(additionalSubjects))
	}

	results, runErr := workflow.RunWithExports(ro.StepName, runOpts...)
	// Don't return immediately on error — write whatever results were
	// produced first (e.g. secretscan findings), then return the error.
	// This ensures attestation files are always written for forensic
	// analysis even when an attestor fails (e.g. --attestor-secretscan-fail-on-detection).
	if runErr != nil && len(results) == 0 {
		return runErr
	}

	// Empty-bundle warning. After the run completes, if the operator
	// wrapped a successful command but every traced write was filtered
	// out by cache classification or product globs, the signed
	// envelope will contain no binary subject. That's almost always a
	// misconfiguration — typical case: build output landed under
	// /tmp/** (a default cache pattern) and the operator didn't pass
	// --cache-allow-pattern or --attestor-product-include-glob to
	// rescue it. Surfacing this before sign-and-write turns a silent
	// failure into a loud one. (Fixes blind Linux UX test Bug 1.)
	warnEmptyProductBundle(attestors)

	// When multiple results are produced (e.g. MultiExporter attestors), an output
	// file path is required — otherwise exported attestors would create files named
	// "-<name>.json" in the current directory instead of writing to stdout.
	hasExported := false
	for _, result := range results {
		if result.AttestorName != "" {
			hasExported = true
			break
		}
	}
	if hasExported && ro.OutFilePath == "" {
		return fmt.Errorf("--outfile is required when attestors export multiple attestations")
	}

	for _, result := range results {
		signedBytes, err := json.Marshal(&result.SignedEnvelope)
		if err != nil {
			return fmt.Errorf("failed to marshal envelope: %w", err)
		}

		outfile := ro.OutFilePath
		if result.AttestorName != "" {
			// Sanitize attestor name: MultiExporter uses "parent/child" format
			// which would create unintended subdirectories in the output path.
			safeName := strings.ReplaceAll(result.AttestorName, "/", "-")
			outfile += "-" + safeName + ".json"
		}

		out, err := loadOutfile(outfile)
		if err != nil {
			return fmt.Errorf("failed to open out file: %w", err)
		}

		_, writeErr := out.Write(signedBytes)
		closeOutfile(out)
		if writeErr != nil {
			return fmt.Errorf("failed to write envelope to out file: %w", writeErr)
		}

		if ro.ArchivistaOptions.Enable {
			archivistaClient, err := ro.ArchivistaOptions.Client()
			if err != nil {
				return fmt.Errorf("failed to create archivista client: %w", err)
			}

			gitoid, err := archivistaClient.Store(ctx, result.SignedEnvelope)
			if err != nil {
				return fmt.Errorf("failed to store artifact in archivista: %w", err)
			}
			log.Infof("Stored in archivista as %v\n", gitoid)
		}
	}

	// Emit v0.3 product/material tree sidecars adjacent to the signed
	// attestation file. These sidecars carry the full leaf set the
	// Merkle root commits to and are consumed by `cilock prove` to
	// generate per-leaf inclusion proofs. They are NOT signed —
	// integrity comes from the fact that the reconstructed Merkle
	// root must match the root in the signed collection attestation.
	//
	// If --outfile was empty (stdout), no sidecars are written: there
	// is no on-disk anchor to derive the sidecar path from.
	if ro.OutFilePath != "" {
		if err := emitRunSidecars(ro.OutFilePath, attestors); err != nil {
			// Don't fail the whole run on a sidecar write error: the
			// signed attestation is already on disk and is the real
			// artifact. But the sidecar IS required for `cilock prove`,
			// so emit an unambiguous error-tagged line to stderr too so
			// CI log scrapers don't miss it — a missing sidecar surfaces
			// later as a confusing "no such file" from `prove`, which is
			// a known operator footgun.
			log.Errorf("tree sidecar write failed; `cilock prove` will not work against this attestation until the sidecar is regenerated: %v", err)
			fmt.Fprintf(os.Stderr, "error: tree sidecar write failed: %v\n", err)
		}
		// Shadow-mode detection: emit <outfile>.detection.json with the
		// pre-gate plan. This is informational only — it does NOT change
		// which attestors fired in this run. Verifiers may inspect the
		// sidecar to see what cilock *would* have auto-selected. Errors
		// are non-fatal for the same reason as above: the signed
		// attestation is the real artifact.
		if err := emitDetectionSidecar(ro.OutFilePath, args); err != nil {
			log.Debugf("detection sidecar emit failed (non-fatal): %v", err)
		}
	}

	// Return the deferred attestor error (e.g. secretscan fail-on-detection)
	// after writing all output files. Soft attestor errors (sbom found no
	// SBOM file, etc.) are demoted to warnings and the process exits 0;
	// only contract violations (signer failure, tracing unsupported,
	// command exit, etc.) propagate to exit 1. See finding #221.
	if runErr != nil {
		return classifyAttestorRunError(runErr)
	}
	return nil
}

// classifyAttestorRunError splits a workflow.Run error into the two classes
// finding #221 calls for: soft (attestor had nothing to do — exit 0,
// warn-level log under a "Warnings:" header) and fatal (contract violation —
// exit 1, error-level log under an "Errors:" header).
//
// When the deferred error is NOT a *workflow.AttestorRunErrors (e.g. a
// signer or sidecar error returned earlier in the run pipeline), the error
// is treated as fatal and returned unchanged.
func classifyAttestorRunError(runErr error) error {
	var aggregate *workflow.AttestorRunErrors
	if !errors.As(runErr, &aggregate) || aggregate == nil {
		// Not an aggregate — propagate as fatal. Pre-workflow errors
		// (signer load, key parse) and any other error type land here.
		return runErr
	}

	softLegs := aggregate.SoftLegs()
	fatalLegs := aggregate.FatalLegs()

	// Surface soft legs as warnings BEFORE the (possibly) fatal exit so
	// CI logs always show the full picture, even when something also
	// went wrong.
	if len(softLegs) > 0 {
		log.Warn("Warnings:")
		for _, leg := range softLegs {
			log.Warnf("  - %s", leg.Err)
		}
	}

	if len(fatalLegs) > 0 {
		// Build a new aggregate containing only the fatal legs so the
		// returned error message reflects what actually drove the exit
		// code. log.Errorf separately so the "Errors:" header is
		// visible whether or not the caller has a top-level error log.
		log.Error("Errors:")
		for _, leg := range fatalLegs {
			log.Errorf("  - %s", leg.Err)
		}
		return &workflow.AttestorRunErrors{Legs: fatalLegs}
	}

	// Only soft legs — exit 0.
	return nil
}

// emitDetectionSidecar computes the pre-gate detection plan against
// the wrapped command's argv + current process env + working dir, and
// writes it as <outfile>.detection.json. The sidecar is informational
// only — it documents what cilock's auto-detection *would* have fired
// for this invocation, independent of which attestors actually ran in
// this run.
//
// Shadow-mode by design: the sidecar adds zero behavioral change to
// the existing run. Verifiers and LLM consumers can read it; ignore-
// it-completely is also fine. Once cilock run --auto lands, the
// same plan will drive which attestors actually fire.
func emitDetectionSidecar(outfile string, args []string) error {
	if len(args) == 0 {
		// Plan-without-command is meaningless; nothing to evaluate.
		return nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get cwd: %w", err)
	}
	env := make(map[string]string, 64)
	for _, kv := range os.Environ() {
		eq := indexByte(kv, '=')
		if eq < 0 {
			continue
		}
		env[kv[:eq]] = kv[eq+1:]
	}
	plan := detection.RunPrePlan(detection.PrePlan{
		Argv: args,
		Env:  env,
		Cwd:  cwd,
	})
	rec := detection.RecommendTrace(detection.Default(), plan)
	envelope := map[string]any{
		"schema_version":       "cilock.detection/v0.1-shadow",
		"plan":                 plan,
		"trace_recommendation": rec,
	}
	bytes, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	path := outfile + ".detection.json"
	return os.WriteFile(path, bytes, 0o600)
}

// indexByte is a tiny stdlib-free helper so we don't pull strings.IndexByte
// in just for this. Kept inline because it's clearer than fanning out.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// warnEmptyProductBundle logs a triple-line warning when:
//
//   - cilock wrapped a command (commandrun attestor present)
//   - the command exited 0 (or ignore-exit-code is in play, but even
//     then the build "succeeded" enough to reach product attestation)
//   - the product set is empty
//   - the trace observed >0 writes — i.e., something WAS dropped
//     during classification rather than the build genuinely emitting
//     nothing
//
// Conditions chosen so the warning fires on the silent-failure case
// (cache pattern ate everything) but stays quiet when the user
// genuinely ran a no-op or non-build command. The warning prints
// before the bundle is written, on stderr; the run still completes
// (the attestation is the real artifact, even if empty).
func warnEmptyProductBundle(attestors []attestation.Attestor) {
	var prod *product.Attestor
	var cmd *commandrun.CommandRun
	for _, a := range attestors {
		if p, ok := a.(*product.Attestor); ok {
			prod = p
		}
		if c, ok := a.(*commandrun.CommandRun); ok {
			cmd = c
		}
	}
	// Required state: a command ran, it exited 0, and we have a
	// product attestor we can interrogate.
	if prod == nil || cmd == nil {
		return
	}
	if cmd.ExitCode != 0 {
		return
	}
	if len(prod.Products()) > 0 {
		return
	}
	dropped := prod.DroppedByClassification()
	if dropped == 0 {
		// Trace observed no writes — this isn't the silent-drop
		// failure; the operator simply ran a command that didn't
		// produce files. Stay quiet.
		return
	}
	log.Warnf("command exited 0 and traced %d file write(s), but all were classified as cache or filtered out.", dropped)
	log.Warnf("products set is empty — the signed envelope will NOT include any binary subject.")
	log.Warnf("Check: build output path vs --workingdir, --attestor-product-include-glob, --cache-allow-pattern <pattern>")
}

// emitRunSidecars walks the attestor list looking for product and
// material attestors, extracts their (path -> sha256-hex) maps, and
// hands them to writeSidecarsForRun. Decoupled into its own function
// so the sidecar logic doesn't dominate runRun.
func emitRunSidecars(outfile string, attestors []attestation.Attestor) error {
	products := map[string]string{}
	materials := map[string]string{}
	sha256DV := cryptoutil.DigestValue{Hash: crypto.SHA256}

	for _, att := range attestors {
		if p, ok := att.(attestation.Producer); ok {
			for path, prod := range p.Products() {
				digest, hasSHA := prod.Digest[sha256DV]
				if !hasSHA {
					// A product without a sha256 digest cannot
					// participate in the v0.3 tree. Skip silently —
					// the v0.3 attestor will emit the same skip.
					continue
				}
				products[inclusionproof.NormalizePath(path)] = digest
			}
		}
		if m, ok := att.(attestation.Materialer); ok {
			for path, ds := range m.Materials() {
				digest, hasSHA := ds[sha256DV]
				if !hasSHA {
					continue
				}
				materials[inclusionproof.NormalizePath(path)] = digest
			}
		}
	}

	return writeSidecarsForRun(outfile, products, materials)
}
