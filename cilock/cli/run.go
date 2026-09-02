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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/keyguard"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
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
// shouldAutoDetect decides whether workload auto-detection runs for a run.
//
// Default behavior: auto-detect ONLY when the operator didn't specify
// attestors (`-a`). If they passed -a, that's their exact set and we don't
// add to it. An explicit `--workload` overrides the default — "auto" forces
// detection even alongside -a, "manual" disables it.
func shouldAutoDetect(attestationsSet, workloadSet bool, workload string) bool {
	if workloadSet {
		return workload != "manual"
	}
	return !attestationsSet
}

// detectCatalogAttestors runs the catalog detection engine against the
// wrapped command (argv + env + working dir) and returns the attestor names
// to attach on top of whatever the operator configured. This is the single,
// data-driven detection path: every rule lives in a detector.yaml
// (argv_prefix / file_exists / env_set), not hardcoded in Go. It replaces
// the old marker-file probe — `.git/HEAD` still attaches git (the spine
// subject), `go build` / `go.mod` attaches go-build, and a tool only
// attaches its scanner when that tool actually runs (govulncheck fires on
// `argv_prefix: [govulncheck]`, never on a plain build).
//
// Each fired detector resolves to attestor(s):
//   - a plugin-backed detector (git, go-build, govulncheck, trivy, …) IS an
//     attestor — attach it by name.
//   - a detection-only catalog entry (syft, semgrep, …) is not itself an
//     attestor; attach the format attestor(s) it feeds via emits_formats
//     (syft → sbom, semgrep → sarif).
//
// Names returned are merged with --attestations by the caller via dedupe;
// an operator's explicit choice is never silently dropped.
func detectCatalogAttestors(argv []string, workdir string) []string {
	if len(argv) == 0 {
		return nil
	}
	if workdir == "" {
		if wd, err := os.Getwd(); err == nil {
			workdir = wd
		}
	}
	plan := detection.RunPrePlan(detection.PrePlan{
		Argv: argv,
		Env:  envSliceToMap(os.Environ()),
		Cwd:  workdir,
	})
	return resolveDetectedAttestors(plan.Fire, registeredAttestorNames(), detection.Default())
}

// resolveDetectedAttestors maps fired detectors to the attestor names to
// attach. Pure (registry + registered-set injected) so it's unit-testable
// without a fully-linked plugin set. A fired detector that is itself a
// registered attestor attaches by name; a detection-only catalog entry
// attaches the format attestor(s) it declares via emits_formats.
func resolveDetectedAttestors(fire []detection.FireDecision, registered map[string]bool, reg *detection.Registry) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, f := range fire {
		if registered[f.Attestor] {
			add(f.Attestor)
			continue
		}
		if d, _, err := reg.Lookup(f.Attestor); err == nil && d != nil {
			for _, fmtName := range d.EmitsFormats {
				add(fmtName)
			}
		}
	}
	return out
}

// registeredAttestorNames is the set of attestor names linked into this
// binary. Used to distinguish a plugin-backed detector (whose name is an
// attestor) from a detection-only catalog entry (whose evidence is captured
// by a format attestor named in emits_formats).
func registeredAttestorNames() map[string]bool {
	entries := attestation.RegistrationEntries()
	m := make(map[string]bool, len(entries))
	for _, e := range entries {
		m[e.Name] = true
	}
	return m
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

// parseDisabledDefaultAttestors validates the --no-default-attestor values and
// returns them as a set. Empty entries are ignored (a bare flag is not a
// request to drop anything); an unrecognised name is an error rather than a
// silent no-op, so a typo can never quietly leave an attestor enabled.
//
// It also holds the refusal that gives applyNoDefaultAttestors its reason to
// exist: if the operator disables EVERY default attestor, the resulting
// collection would have no body to attest, so we refuse rather than mint an
// evidence-free bundle.
func parseDisabledDefaultAttestors(disabled []string) (map[string]struct{}, error) {
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
	return disabledSet, nil
}

// warnDroppedDefaultAttestor emits the operator-facing warnings for one
// always-on attestor being dropped. It warns; it never refuses — the refusal
// for dropping ALL of them lives in parseDisabledDefaultAttestors.
func warnDroppedDefaultAttestor(name string) {
	log.Warnf("--no-default-attestor: dropping always-on attestor %q (operator override)", name)
	// Dropping material (or product) leaves the collection unable to
	// serve as a build step downstream: `cilock policy from-bundles`
	// build steps require BOTH material/v0.3 (inputs) and product/v0.3
	// (outputs) to wire + verify the chain. Spell out the consequence so
	// the operator isn't surprised when a from-bundles policy built on
	// this bundle won't verify.
	if name == material.Name || name == product.Name {
		log.Warnf("--no-default-attestor: build-step policies require material/v0.3 + product/v0.3; "+
			"a `cilock policy from-bundles` build step built from this bundle (missing %s/v0.3) won't verify end-to-end.", name)
	}
	// Dropping product specifically is usually a size decision, and it
	// is the wrong lever for that job. Material records what went IN;
	// product is the only record of what the run PRODUCED, so a bundle
	// without it cannot answer "what did this build emit?" at all — the
	// question attestation exists to answer. Trading that away to avoid
	// walking a node_modules tree spends evidence to buy seconds.
	//
	// So the warning names the cheaper lever rather than only
	// disapproving: narrowing the capture keeps the record and skips the
	// bytes. A message that says "this is discouraged" and stops sends
	// the reader straight back to the flag.
	//
	// SINGULAR "a single ... glob" is load-bearing, not style. The flag
	// is a registry.StringConfigOption, bound by cmd.Flags().String
	// (cilock/internal/options/options.go) — pflag semantics are
	// last-one-wins, so repeating it applies only the final occurrence
	// while parsing cleanly and reporting nothing. Advising a repeat
	// would hand the operator a silent no-op. Several trees go in one
	// pattern via brace alternation, and the `{**/,}` prefix is required
	// to match a top-level directory: `**/node_modules/**` alone matches
	// nothing at the root of the working directory (measured).
	//
	// The example names DEPENDENCY trees only. It deliberately does not
	// say `dist` or `target`, the way the material-oriented advice in
	// attestation/archivista/size_advice.go does: build output is
	// exactly what the product attestor exists to record, so an example
	// that excluded it would teach the reader to drop their own
	// deliverable — the failure this warning is here to prevent.
	if name == product.Name {
		log.Warnf("--no-default-attestor product: the bundle will carry no record of what the build produced — " +
			"material attests the inputs, product is the only attestation of the outputs, and nothing downstream " +
			"can recover it. If the goal is a smaller envelope, measure first: product records only what the run " +
			"actually emitted and is usually a tiny share of the bytes. To shrink it, keep the attestor and narrow " +
			"what it captures with a single --attestor-product-exclude-glob (the flag takes ONE pattern; repeating " +
			"it silently keeps only the last). Brace alternation covers several dependency trees at once, e.g. " +
			"--attestor-product-exclude-glob '{**/,}{node_modules,.venv}/**' — exclude dependencies, not build output.")
	}
}

// applyNoDefaultAttestors removes the operator-disabled always-on attestors
// from base, warning on each drop. It refuses (via
// parseDisabledDefaultAttestors) when the user disables every default attestor
// — the attestation collection would have no body to attest.
func applyNoDefaultAttestors(base []attestation.Attestor, disabled []string) ([]attestation.Attestor, error) {
	if len(disabled) == 0 {
		return base, nil
	}
	disabledSet, err := parseDisabledDefaultAttestors(disabled)
	if err != nil {
		return nil, err
	}
	out := make([]attestation.Attestor, 0, len(base))
	for _, a := range base {
		if _, drop := disabledSet[a.Name()]; drop {
			warnDroppedDefaultAttestor(a.Name())
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

Platform & trust:
  By default cilock targets the hosted TestifySec platform
  (https://platform.testifysec.com) for keyless Fulcio signing, RFC 3161
  timestamps, and Archivista attestation storage — the Fulcio, TSA, and
  Archivista URLs are all derived from --platform-url. Run 'cilock login' to
  authenticate to the hosted platform. To bring your own infrastructure instead,
  override the providers individually: --signer-* selects a key provider,
  --timestamp-servers a timestamper, and --archivista-server attestation
  storage. Pass --platform-url "" to run fully offline (no platform, no TSA).
  Additional key/signer providers can be compiled in; see
  https://github.com/aflock-ai/rookery/blob/main/docs/signers.md.

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
			// flags not explicitly set by the user.
			o.ResolvePlatformDefaults(cmd)
			// The enrolled-agent signing path fails closed: a refused credential
			// exchange must end the command, never continue on the human session.
			if err := o.AgentIdentityError(); err != nil {
				return err
			}

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

			// Attestor auto-detection: run the catalog detection engine
			// against the wrapped command and merge the attestors it matches
			// into the --attestations list. All detection rules live in
			// detector.yaml (argv_prefix / file_exists / env_set) — there is
			// no hardcoded marker probe anymore.
			//
			// Default: auto-detect ONLY when the operator didn't specify
			// attestors. If they passed -a, that's their exact set — we
			// don't second-guess it. An explicit --workload always wins
			// over this default (--workload=auto forces detection even
			// alongside -a; --workload=manual disables it).
			autoDetect := shouldAutoDetect(
				cmd.Flags().Changed(flagAttestations),
				cmd.Flags().Changed("workload"),
				o.Workload,
			)
			var detectedNames []string
			if autoDetect {
				probed := detectCatalogAttestors(args, o.WorkingDir)
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

			if err := preRunGates(cmd, &o); err != nil {
				return err
			}

			signerProviders := providersFromFlags("signer", cmd.Flags())
			// The refresher is what keeps a long wrapped command from outliving
			// its signing identity: the certificate is already deferred to first
			// signature, and this re-mints the token that buys it at the same
			// moment. Nil for CI, offline, local-key and explicit-token runs.
			signers, err := loadSigners(cmd.Context(), o.SignerOptions, o.KMSSignerProviderOptions, signerProviders,
				withFulcioTokenRefresh(o.FulcioTokenRefresher()))
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
				flagAttestorProductIncludeGlob: cmd.Flags().Changed(flagAttestorProductIncludeGlob),
			}

			return runRun(cmd.Context(), o, args, userSetFlags, signerProviders, signers...)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

// preRunGates runs the fail-closed checks that must refuse BEFORE the wrapped
// command executes, in order. Each needs only what ResolvePlatformDefaults
// already established, so a misconfigured pipeline wastes no build time and
// the refusal is unambiguous.
func preRunGates(cmd *cobra.Command, o *options.RunOptions) error {
	// First-run identity gate: a brand-new operator with no `cilock login`,
	// no local --signer-* key, and no ambient CI OIDC identity would
	// otherwise dead-end inside Fulcio signer construction with an opaque
	// error ("failed to load any signers" / "no token provided") and never
	// run the wrapped command. Catch it here with an actionable message that
	// names 'cilock login'. Stands down for every path that CAN sign (local
	// key, explicit token, CI ambient OIDC, logged-in session, --offline).
	if err := o.PreflightIdentity(cmd); err != nil {
		return err
	}
	// Fail-closed evidence gate: a run that signs as a stored platform
	// principal but would store nothing must not exit 0 — the exit code is
	// what the next push is gated on (incident 2026-09-02). Refuse here,
	// before the build, unless the operator explicitly passed
	// --enable-archivista=false.
	if err := o.EnforceEvidenceStorage(cmd); err != nil {
		return err
	}
	// Fail-closed product-binding gate: when platform-authenticated, resolve
	// the repository's product and HARD FAIL before the build runs if it maps
	// to zero or multiple products (so no unlinkable evidence is produced).
	// Not-authenticated / opt-out / endpoint-unavailable proceed.
	return o.EnforcePlatformBinding(cmd)
}

func runRun(ctx context.Context, ro options.RunOptions, args []string, userSetFlags map[string]bool, signerProviders map[string]struct{}, signers ...cryptoutil.Signer) error { //nolint:gocognit,gocyclo,funlen
	if len(signers) > 1 {
		return onlyOneSignerError()
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
	// Under --json the wrapped command's stdout must NOT leak onto the
	// parent's stdout — stdout is reserved for the single structured result
	// object. WithSilent(true) drops commandrun's default os.Stdout/os.Stderr
	// writers; the WithOutputWriters([]io.Writer{os.Stderr}) attestation opt
	// below then re-attaches os.Stderr so the command's output is still
	// visible (on stderr) and still captured into the attestation. Nothing is
	// lost — only the destination of the passthrough changes.
	jsonOutput := ro.OutputJSON()
	scriptCapture, err := commandrun.ParseScriptCaptureMode(ro.ScriptCapture)
	if err != nil {
		return fmt.Errorf("--script-capture: %w", err)
	}
	if len(args) > 0 {
		cmdOpts := []commandrun.Option{
			commandrun.WithCommand(args),
			commandrun.WithTracing(ro.Tracing),
			commandrun.WithIgnoreExitCode(ro.IgnoreCommandExitCode),
			commandrun.WithPrewalkSkipDirs(ro.PrewalkSkipDirs),
			commandrun.WithPrewalkIncludeDirs(ro.PrewalkIncludeDirs),
			commandrun.WithRequireZeroDrops(ro.RequireZeroDrops),
			commandrun.WithScriptCapture(scriptCapture),
		}
		if jsonOutput {
			cmdOpts = append(cmdOpts, commandrun.WithSilent(true))
		}
		attestors = append(attestors, commandrun.New(cmdOpts...))
	}

	for _, a := range ro.Attestations {
		if a == attestorCommandRun {
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
	if userSetFlags[flagAttestorProductIncludeGlob] {
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
	// In JSON mode, re-route the wrapped command's stdout+stderr to the
	// parent's stderr (paired with commandrun.WithSilent above) so the
	// command's output stays visible but stdout is reserved for the JSON
	// result object.
	if jsonOutput {
		attestationOpts = append(attestationOpts, attestation.WithOutputWriters([]io.Writer{os.Stderr}))
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

	// The enforcing form of the warning above, for callers that told us this
	// step exists to prove which artifact it produced. It runs BEFORE the
	// envelope is written or uploaded, so a collection with no product subject
	// never reaches a file or Archivista. It deliberately does NOT stand down
	// when the wrapped command failed: a failed command is exactly the case
	// that leaves the product set empty, and cilock stores evidence for failed
	// runs too — which is how a subjectless collection ends up in the evidence
	// store looking like a completed build.
	if ro.RequireProducts {
		if err := requireProductSubject(attestors); err != nil {
			if runErr != nil {
				return fmt.Errorf("%w; the wrapped run also failed: %w", err, runErr)
			}
			return err
		}
	}

	// Capture-completeness warning. Each attestor's detector.yaml contract can
	// declare that a subject SHOULD be captured (always, or when a documented
	// precondition holds). Compare that against what the attestors actually
	// emitted and TELL the user about the delta — with the remedy — instead of
	// exiting 0 and letting them discover months later that their evidence is
	// unfindable by the identifier they'd actually search with. Advisory only:
	// this never changes the exit code.
	captureReport := collectCaptureGaps(attestors, runErr, additionalSubjects)
	warnCaptureGaps(captureReport)

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

	// uploadedGitoid records the gitoid of the collection envelope once it is
	// stored in Archivista, for the structured/human run summary below.
	var uploadedGitoid string

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

		// Under --json, stdout is reserved for the machine-readable run summary.
		// When no --outfile is given the envelope would otherwise default to
		// stdout (loadOutfile("") == os.Stdout) and corrupt that JSON object, so
		// route it to stderr instead. Pass --outfile to persist it to a file.
		var out *os.File
		if jsonOutput && outfile == "" {
			out = os.Stderr
		} else {
			out, err = loadOutfile(outfile)
			if err != nil {
				return fmt.Errorf("failed to open out file: %w", err)
			}
		}

		_, writeErr := out.Write(signedBytes)
		if out != os.Stderr {
			closeOutfile(out)
		}
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
				return uploadError(ro.PlatformURL, err)
			}
			log.Infof("Stored in archivista as %q\n", gitoid)
			// The collection envelope (AttestorName == "") carries the
			// collection subjects — it is the correlation anchor we report
			// in the run summary. Per-attestor sidecar gitoids are not the
			// anchor, so only the collection gitoid is surfaced.
			if result.AttestorName == "" {
				uploadedGitoid = gitoid
			}
		}
	}

	// v0.3 forces inline leaves into the signed predicate, so the full
	// leaf set the Merkle root commits to travels inside the signed
	// envelope itself — there is no separate off-envelope tree sidecar to
	// write (the `cilock prove` off-envelope subsystem was removed).
	//
	// If --outfile was empty (stdout), no detection sidecar is written:
	// there is no on-disk anchor to derive the path from.
	if ro.OutFilePath != "" {
		// Shadow-mode detection: emit <outfile>.detection.json with the
		// pre-gate plan. This is informational only — it does NOT change
		// which attestors fired in this run. Verifiers may inspect the
		// sidecar to see what cilock *would* have auto-selected. Errors
		// are non-fatal: the signed attestation is the real artifact.
		if err := emitDetectionSidecar(ro.OutFilePath, args); err != nil {
			log.Debugf("detection sidecar emit failed (non-fatal): %v", err)
		}
	}

	// Report the run result. The human-readable self-explaining summary
	// always goes to stderr (alongside logr); --json additionally emits the
	// single structured result object to stdout. Built from data already in
	// scope — no extra server round-trips. Emitted before the deferred error
	// return so the summary is present even when an attestor fails.
	summary := buildRunSummary(ro, args, attestors, results, signerProviders, uploadedGitoid, runErr)
	// Report standards without self-certification. SLSA Build levels require an
	// assessment of the producer and build platform; ALPS levels require an
	// independent verifier of identity and boundary evidence. This local producer
	// summary records observations and leaves both levels unassigned.
	runFailed := classifyAttestorRunError(runErr) != nil ||
		(summary.WrappedCommand != nil && summary.WrappedCommand.ExitCode != 0)
	summary.ComputeStandardsAssessment(runFailed)
	summary.AssuranceLevel = ro.ResolvedAssuranceLevel()
	// Carry the capture delta (already warned about above) into the structured
	// summary so a CI job can consume it. nil when nothing declared an
	// expectation — an empty report would falsely read as "capture verified".
	summary.Capture = captureReport
	summary.WriteHuman(os.Stderr)
	// Non-upload warning: when a platform is configured (--platform-url set)
	// and signing succeeded but Archivista upload was never enabled, the signed
	// attestation lives only on the operator's disk — it was NOT stored on the
	// platform, so nothing on the platform can verify against it later. That is
	// a silent surprise for a first-run operator who passed --platform-url
	// expecting end-to-end platform integration. Call it out with the one flag
	// that fixes it.
	if shouldWarnNotUploaded(ro.PlatformURL, ro.ArchivistaOptions.Enable, runFailed, ro.OutputJSON()) {
		// Upload is auto-enabled whenever a platform identity is present, so this
		// fires only when there is no usable identity (e.g. a local-key run with no
		// `cilock login`) or upload was explicitly disabled — don't prescribe a flag
		// that may not be the fix.
		fmt.Fprintln(os.Stderr, "warning: signed locally; not uploaded to the platform (run `cilock login` to store attestations there)")
	}
	if ro.OutputJSON() {
		if err := summary.WriteJSON(os.Stdout); err != nil {
			// Don't mask a successful run on a summary-marshal error, but make
			// it loud — an agent relying on the JSON contract needs to know.
			fmt.Fprintf(os.Stderr, "error: failed to emit JSON run summary: %v\n", err)
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

// shouldWarnNotUploaded reports whether the run should emit the "signed locally;
// not uploaded" stderr warning. The condition: a platform was configured
// (platformURL non-empty) but Archivista upload was never enabled, the run did
// not fatally fail (so there IS a completed signed attestation that could have
// been uploaded), and the operator is not consuming machine-readable JSON (where
// the Uploaded:false field already carries this fact). Pure so the policy is
// unit-testable without driving a full run.
func shouldWarnNotUploaded(platformURL string, archivistaEnabled, runFailed, jsonOutput bool) bool {
	return platformURL != "" && !archivistaEnabled && !runFailed && !jsonOutput
}

// uploadError wraps an Archivista store failure.
//
// Two distinct failure classes reach here, and they need different advice.
//
// A 401/403 means signing succeeded but the repo/identity is not trusted for
// upload yet, so surface the one-time fix (`cilock trust`) instead of a raw
// "Invalid API credential". This is decided on the TYPED status code, not by
// running strings.Contains over the message: the error carries up to 500 bytes
// of server response body, so a 503 whose body happened to mention 401 used to
// be mis-advised as an auth problem.
//
// Anything else has already been through the bounded retry in the Archivista
// client (see archivista.WithRetry), so by the time it lands here a transient
// 5xx has been retried and is still failing. The signed envelope cannot be
// stored out of band — an attestation is evidence of an execution, and
// uploading a held bundle later would detach the evidence from the act that
// produced it — so the recovery genuinely is to re-run `cilock run`. Say that
// plainly rather than leaving the operator hunting for an upload command that
// does not, and should not, exist.
func uploadError(platformURL string, err error) error {
	var statusErr *archivista.StatusError
	isAuth := errors.As(err, &statusErr) &&
		(statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden)
	if platformURL != "" && isAuth {
		return fmt.Errorf("upload to %s rejected (%w)\n"+
			"  this repo/identity is not trusted for upload yet — run `cilock trust` once,\n"+
			"  or sign without uploading via --enable-archivista=false",
			platformURL, err)
	}
	// Deliberately does not claim "after retrying": a terminal status (400, 404,
	// 422) never entered the retry loop, and retry can be switched off. The
	// wrapped error already reports "gave up after N attempts" when retries
	// actually ran, so asserting it here would be wrong in exactly the cases
	// where an operator most needs the message to be accurate.
	return fmt.Errorf("failed to store attestation on the platform: %w\n"+
		"  the attestation was signed but not stored, so this run produced no platform evidence — re-run `cilock run` to regenerate it\n"+
		"  tune the retry with --archivista-upload-retries / --archivista-upload-retry-budget, or run with --log-level debug for per-attempt detail",
		err)
}

// buildRunSummary assembles the structured RunSummary from data the run
// already produced: the signed collection's subjects (the correlation
// anchors), the attestor set with each one's ran/skipped/failed status, the
// signer kind, the wrapped command's exit code, and the platform/credential
// facts captured during ResolvePlatformDefaults. Pure given its inputs so the
// assembly logic is unit-testable without a live run.
func buildRunSummary(
	ro options.RunOptions,
	args []string,
	attestors []attestation.Attestor,
	results []workflow.RunResult,
	signerProviders map[string]struct{},
	uploadedGitoid string,
	runErr error,
) *options.RunSummary {
	s := &options.RunSummary{
		Step:               ro.StepName,
		WorkingDir:         ro.WorkingDir,
		PlatformURL:        ro.PlatformURL,
		Tenant:             ro.ResolvedTenantName(),
		Signer:             signerKind(signerProviders),
		SignerEmail:        ro.ResolvedSignerEmail(),
		TimestampAuthority: ro.TimestampServers,
		FulcioURL:          ro.ResolvedFulcioURL(),
		ArchivistaURL:      ro.ArchivistaOptions.Url,
		Uploaded:           uploadedGitoid != "",
		Gitoid:             uploadedGitoid,
		OutFile:            ro.OutFilePath,
		Subjects:           collectionSubjects(results),
		Attestors:          attestorOutcomes(attestors, runErr),
	}
	// An agent run names the SPIFFE principal the platform issued and drops the
	// human email outright. The drop is belt-and-braces — the agent path never
	// populates the email — and it is what makes "the summary cannot name a
	// human for an agent signature" a property of this function rather than of
	// every future edit to the resolution path.
	if principal := ro.ResolvedAgentPrincipal(); principal != "" {
		s.AgentPrincipal = principal
		s.PrincipalKind = "agent"
		s.SignerEmail = ""
	}
	// Only report a platform-derived Fulcio/TSA/Archivista when the platform
	// is actually in play. Offline runs (--platform-url "" / --offline) leave
	// them blank — otherwise the summary contradicts itself by naming the
	// hosted Archivista the run deliberately opted out of.
	if ro.PlatformURL == "" {
		s.FulcioURL = ""
		s.TimestampAuthority = nil
		// Keep an Archivista URL only when an upload actually happened (the
		// operator pointed --archivista-server at their own store and enabled
		// it); otherwise drop the misleading hosted default.
		if !ro.ArchivistaOptions.Enable {
			s.ArchivistaURL = ""
		}
	}
	if cmd := wrappedCommandOutcome(args, attestors); cmd != nil {
		s.WrappedCommand = cmd
	}
	// Record the in-process anti-tamper state that was in effect while the
	// signing key was live (read back from the kernel by keyguard.Protect in
	// preRoot, never asserted). This is a scoped runtime observation, not by
	// itself proof of SLSA or ALPS conformance.
	if kp := keyguard.Current(); kp.Applied {
		s.KeyProtection = &kp
	}
	// Signing-path and network observations are carried independently. Neither
	// is promoted into a SLSA Build or ALPS level by this producer-side summary.
	//
	// Require BOTH that cilock installed a workflow OIDC token AND that the
	// fulcio signer was the one actually used: the workflow flag alone could be
	// stale if an explicit signer override won at sign time, so we confirm the
	// signer kind before reporting the workflow-identity path.
	s.WorkflowIdentity = ro.SignerIsWorkflowIdentity() && s.Signer == "fulcio"
	stampNetworkObservation(s, attestors)
	return s
}

// stampNetworkObservation records the wrapped command's observed network
// behavior. It is meaningful ONLY when tracing actually captured. It never
// labels the build hermetic: network is only one part of that assessment.
//
// This observation conservatively counts channels that can fetch external
// inputs. Ordinary local IPC and bind/listen operations are excluded.
func stampNetworkObservation(s *options.RunSummary, attestors []attestation.Attestor) {
	for _, a := range attestors {
		cr, ok := a.(*commandrun.CommandRun)
		if !ok || !cr.TracingEnabled() {
			continue
		}
		mode := traceModeLabel(cr)
		if mode == "" {
			// Tracing was requested but captured nothing (unsupported platform or a
			// failed backend) — no evidence, so make no network claim.
			return
		}
		s.Tracing = mode
		s.NetworkEgress = externalEgress(cr.Processes)
		// AN EMPTY EGRESS LIST MEANS NOTHING UNLESS THE CHANNEL THAT WOULD
		// HAVE REPORTED EGRESS IS KNOWN TO WORK. The check above already
		// refuses a trace that captured NOTHING; the macOS backend adds a
		// case it does not reach — the trace succeeds, has a capture mode,
		// records execs and files, and its NETWORK reports specifically were
		// never proven to arrive. Without this, a backend that accepted the
		// sandbox profile and then emitted no network reports at all handed
		// back an empty list for a build that could have fetched anything,
		// and it was stamped as an observation of no egress.
		//
		// Any egress that DID arrive stays in the list either way: a report
		// that came back is evidence regardless of whether the channel was
		// proven complete. It is only the NEGATIVE claim that needs the
		// capability, because only the negative claim rests on absence.
		// An empty egress list means nothing unless the channel that would have
		// reported egress is known to work. The check above already refuses a
		// trace that captured NOTHING; the darwin backend adds a case it does
		// not reach — the trace succeeds, has a capture mode, records execs and
		// files, and only its NETWORK reports were never proven to arrive.
		s.NoExternalNetworkEgressObserved = len(s.NetworkEgress) == 0 && networkChannelProven(cr)
		// Surfaced, not refused. These execs were observed but could not be
		// tied to the tree, and they carry no image identity in the
		// attestation by design — so an image policy cannot match them and a
		// forbidden fast child would otherwise read as a bare pid gap that
		// nothing an operator looks at mentions.
		if d := cr.Summary.Diagnostics.Darwin; d != nil {
			s.UnattributedExecs = len(d.UnprovenExecs)
			// Rejected records, so nothing of the build's is missing — but
			// something was writing kernel-shaped messages into the log while
			// it ran, and a counter nobody reads does not tell an operator.
			s.ForgedReportRecords = d.ForgedRecords
		}
		return
	}
}

// networkChannelProven reports whether the backend established that its
// network reports actually arrive, rather than assuming it from the capture
// request it made.
//
// Only the darwin sandbox-report backend can answer: its report channel is a
// separate capability from the exec one, so it proves the channel with a live
// probe and records the result. Every other backend derives network events
// from the same instrumentation as everything else it captured — there is no
// separate channel to lose — so a nil block means "not applicable", never
// "unproven", and must not cost those platforms their verdict.
func networkChannelProven(cr *commandrun.CommandRun) bool {
	if cr.Summary == nil || cr.Summary.Diagnostics.Darwin == nil {
		return true
	}
	return cr.Summary.Diagnostics.Darwin.NetworkObserved
}

// traceModeLabel returns the commandrun capture mode that actually observed the
// build ("ebpf", "ptrace", or the raw mode string), or "" when the attestor
// recorded NO capture. The empty return prevents an unsupported or failed trace
// from being rendered as an observation of no egress.
func traceModeLabel(cr *commandrun.CommandRun) string {
	if cr.Summary == nil {
		return ""
	}
	switch {
	case strings.Contains(cr.Summary.CaptureMode, "ebpf"):
		return "ebpf"
	case strings.Contains(cr.Summary.CaptureMode, "ptrace"):
		return "ptrace"
	default:
		return cr.Summary.CaptureMode // raw mode, or "" when none was recorded
	}
}

// externalEgress returns the sorted, de-duplicated set of network destinations
// the traced processes connected to. See egressEndpoint for classification.
func externalEgress(procs []commandrun.ProcessInfo) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range procs {
		if p.Network == nil {
			continue
		}
		for _, c := range p.Network.Connections {
			ep, ok := egressEndpoint(c)
			if !ok {
				continue
			}
			if _, dup := seen[ep]; dup {
				continue
			}
			seen[ep] = struct{}{}
			out = append(out, ep)
		}
	}
	sort.Strings(out)
	return out
}

// egressEndpoint classifies one observed connect() as a channel through which
// a command can pull an external input, returning a named endpoint and true:
//
//   - External IP egress — an IP-family connect() to a non-loopback host.
//   - Loopback IP — a connect() to 127.0.0.0/8 or ::1 reaches a localhost
//     service or proxy, which can itself fetch external inputs. We cannot prove
//     it didn't, so it is counted (labelled "loopback:<host>:<port>").
//   - Container-runtime UNIX sockets — an AF_UNIX connect() to docker.sock /
//     containerd / podman / crio can pull images or run commands that fetch
//     undeclared inputs (labelled "unix:<path>").
//   - Remote-capable non-IP families — AF_VSOCK reaches the hypervisor host
//     from a guest, so a build can pull an undeclared input over one exactly as
//     it can over TCP (labelled "<family>:<host>:<port>").
//   - Any family the vocabulary does NOT classify — see THE DEFAULT IS TO
//     COUNT below (labelled "unclassified-family:<family>:<host>:<port>").
//   - An operation the observer SAW and could not describe, which the
//     vocabulary names FamilyNotObservable (labelled
//     "unclassified-family:(family-not-observable):<host>:<port>"). An
//     unwatched channel is one a build could have fetched through, and no
//     amount of not looking turns that into proof it did not.
//
// Ordinary AF_UNIX IPC (D-Bus, NSS, journald, …) and bind()/listen() are NOT
// counted: they are pervasive in any build and are not input-fetch vectors.
//
// WHICH FAMILIES REACH WHAT IS NOT DECIDED HERE. commandrun owns that
// vocabulary and classifies it in one table (commandrun.ClassifySocketFamily),
// because this filter is the place where an unrecognised family turns into a
// false observation: a family this function fails to count drops out of
// externalEgress and publishes "no external egress observed" for a command that
// used an unclassified channel. Asking the vocabulary
// means a family the attestor learns to emit — an IP socket whose version a
// backend could not read, say — is counted here without this file being edited.
//
// THE DEFAULT IS TO COUNT, NOT TO SKIP, and that is the difference between a
// classifier that is total over its COMPILE-TIME constants and one that is
// total over its RUNTIME input. commandrun's constants are all classified and a
// gate proves it — but the Linux tracer writes "AF_<n>" for any domain it has
// no name for, and no constant declares "AF_42". Such a string reached this
// switch, matched nothing, and was dropped. AF_VSOCK is the case that makes it
// a hole rather than a nuisance: it is remote-capable, so a command could talk
// to its host over one while the summary reported an empty egress list.
//
// So an unclassified family COUNTS as egress, labelled
// "unclassified-family:<family>:…" so the reason is legible in the signed
// summary rather than silent. Counting (rather than erroring) is deliberate:
// this is an attestation, and the honest report of "a channel I cannot vouch
// for was used" is an observation a verifier can read and a policy can waive —
// not a failed build on a kernel we have never seen. The cost is
// bounded because the tracer names every domain the vocabulary knows
// (AF_NETLINK, on every Linux build, included), so ordinary builds never reach
// this default.
// isInboundSyscall reports whether an operation ACCEPTED an inbound
// connection, under any of the names a backend might use for it.
//
// The kernel has more than one accept entry point and backends differ: Linux
// commonly reports accept4 where the darwin sandbox channel reports a plain
// inbound accept. Matching one spelling would let the other fall through as
// "not connect" and be dropped — an inbound input channel silently producing a
// no-egress summary — which is a spelling bug with the consequence of a
// security hole.
func isInboundSyscall(name string) bool {
	switch name {
	case "accept", "accept4":
		return true
	}
	return false
}

// isServingSyscall reports the operations that are the build OFFERING a
// service rather than reaching for input. These are the only operations
// dropped by name; everything unrecognised is counted instead.
func isServingSyscall(name string) bool {
	switch name {
	case "bind", "listen":
		return true
	}
	return false
}

func egressEndpoint(c commandrun.NetworkConnection) (string, bool) {
	// An ACCEPTED inbound connection is an undeclared input channel. The peer
	// was already running — its own outbound report is a stranger's and is
	// dropped — so if the build's inbound is ignored too, a helper outside
	// the tree can feed the build and the run still reads hermetic. The peer
	// is not observable from this channel, so the operation itself is the
	// evidence; it is labelled "inbound:" rather than a destination, the way
	// the resolver channel is labelled, so a policy that accepts a build
	// serving its own tests can waive precisely this and nothing else.
	if isInboundSyscall(c.Syscall) {
		// The PORT is part of the channel's identity. macOS often cannot
		// observe the peer host but does report the port, and collapsing
		// every accept onto "inbound:(host-not-observable)" meant a waiver
		// written for one intended test listener waived every inbound
		// channel on the machine.
		// THE FAMILY IS PART OF THE IDENTITY. Without it an AF_UNIX accept on
		// a socket someone created at the path "127.0.0.1:8080" is
		// indistinguishable from an AF_INET accept on 127.0.0.1:8080, and
		// these labels are waivers.
		// The family AS REPORTED, not its class: the class collapses AF_INET
		// and AF_INET6 together, and the whole point here is that two channels
		// must not share a label. An unobservable family gets a name that
		// cannot be mistaken for one.
		fam := c.Family
		if fam == "" {
			fam = commandrun.FamilyNotObservable
		}
		if c.Port != 0 {
			return "inbound:" + fam + ":" + joinHostPort(c.Address, c.Port), true
		}
		return "inbound:" + fam + ":" + c.Address, true
	}
	// EVERY OPERATION IS ACCOUNTED FOR, and an unrecognised one is COUNTED.
	//
	// bind and listen really are serving rather than fetching, so they are
	// dropped by name. But dropping everything that is merely not "connect"
	// was a fail-open of the same shape this file already rejects for socket
	// FAMILIES: an op the decoder did not have a case for vanished, and a
	// vanished operation reads downstream as "there was nothing there". The
	// linux backend's opName already returns "unknown" for an op it cannot
	// name, and a future backend will add operations before this consumer
	// learns about them.
	//
	// So: known-serving is dropped, known-fetching is classified, and anything
	// else is counted under a label that says plainly it was not understood.
	if isServingSyscall(c.Syscall) {
		return "", false
	}
	if c.Syscall != "connect" {
		return labelledEndpoint("unclassified-syscall:"+c.Syscall, c), true
	}

	switch commandrun.ClassifySocketFamily(c.Family) {
	case commandrun.FamilyClassUnix:
		// AF_UNIX: container-runtime control sockets and the system resolver
		// are fetch vectors; ordinary local IPC is not.
		if isContainerRuntimeSocket(c.Address) {
			return "unix:" + c.Address, true
		}
		// NO PATH-BASED LABEL, and that includes the resolver. Labelling
		// mDNSResponder "resolver:" made the label a WAIVER a policy could
		// accept, resting on the pathname alone — and this channel cannot
		// authenticate a peer, so a privileged build or a prearranged helper
		// replacing that path inherits the waiver. Resolution really is
		// remote I/O by proxy and really should count; it counts as ordinary
		// unix egress, named by its path, and a policy that wants to accept
		// DNS waives that exact path knowing it is trusting a name.

		// A UNIX socket is a channel like any other. The OS's own IPC
		// endpoints (/var/run, systemd's, the system D-Bus, /dev/log) are
		// how a process talks to the system and do not count — counting them
		// would put hermeticity out of reach on every machine. Anything ELSE
		// — a socket under /tmp, under $HOME, in the workspace — is a peer
		// somebody set up, and a build can fetch undeclared inputs through a
		// local proxy at such a path exactly as it could over TCP. Those
		// count, labelled unix:<path>. A socket the tree itself bound counts
		// TOO: the report channel carries no unlink and no socket identity,
		// so "the tree bound this path earlier" cannot prove the listener
		// the connect reached was still the tree's — a stranger can rebind
		// an unlinked path between the two. A build that talks to its own
		// local server over a UNIX socket is therefore not hermetic under
		// this rule, and the endpoint says exactly which socket.
		// NO PATH IS EXEMPT. This channel reports a pathname and nothing
		// about the peer — no pid, no uid, no socket identity — so "this
		// path is the OS's own logging socket" is a claim about a NAME, not
		// about who answered. A privileged build, or a helper arranged
		// before the build ran, can replace /dev/log or /var/run/syslog and
		// the connection is then a bidirectional channel wearing a trusted
		// label. Three rounds of narrowing this allowlist (dropping the bind
		// exemption, then directory prefixes, then nscd) each ended with
		// another way to abuse a name; the honest end of that sequence is
		// that a name cannot carry the exemption at all. Every AF_UNIX
		// connect counts, and the endpoint says which socket, so a policy
		// that accepts a build talking to syslog waives exactly that path
		// and nothing else.
		return "unix:" + c.Address, true

	case commandrun.FamilyClassNonRemote:
		// Classified, DESCRIBED, and unable to name a remote host — AF_NETLINK
		// reaches the local kernel, AF_UNSPEC on connect() dissolves a UDP
		// socket's association and reaches nothing at all. The ONLY class that
		// is skipped on the strength of the family alone, and it is skipped
		// because the observer SAW what the operation was.
		return "", false

	case commandrun.FamilyClassUnobservable:
		// The observer saw an outbound operation and could not describe it.
		// That is not the same fact as the case above and it does not get the
		// same answer: an unwatched channel is one a build could have fetched
		// through, so it counts, labelled with WHY rather than with a family.
		return labelledEndpoint(unclassifiedFamilyLabel(c.Family), c), true

	case commandrun.FamilyClassIP:
		return ipEgressEndpoint(c)

	case commandrun.FamilyClassRemoteNonIP:
		return labelledEndpoint(c.Family, c), true

	default:
		// FamilyClassUndefined, and any class added to the vocabulary that this
		// switch has not learned yet. Both mean "this consumer cannot say what
		// the channel reaches", and the conservative reading of that is egress.
		return labelledEndpoint(unclassifiedFamilyLabel(c.Family), c), true
	}
}

// unclassifiedFamilyLabel names the channel in an egress entry for a family
// this consumer cannot vouch for, so a reader of the signed summary sees why
// it was counted instead of an unexplained endpoint. The entry has to say
// "something was reached and nothing about it could be named", which is a
// different statement from "nothing was reached".
//
// Two inputs mean the family was never read: the empty string an observer
// leaves when it records no family, and commandrun.FamilyNotObservable, the
// name a backend reports the same fact under. Both get the one label, because
// they are one fact.
func unclassifiedFamilyLabel(family string) string {
	if family == "" || family == commandrun.FamilyNotObservable {
		return "unclassified-family:(family-not-observable)"
	}
	return "unclassified-family:" + family
}

// labelledEndpoint joins a channel label to the destination as far as the
// observer could see it, so one egress entry names both WHAT channel the build
// used and WHERE it went. An unnameable destination becomes
// commandrun.HostNotObservable rather than disappearing.
// joinHostPort renders a host and port so the two cannot run together.
//
// An endpoint label is a POLICY WAIVER, so two different channels must never
// produce the same string. The ambiguity is specifically a field FOLLOWED BY
// another field: an IPv6 address contains ':', so "fd00::1" with port 443 and
// the bare address "fd00::1:443" both render as "fd00::1:443" when joined
// naively, and a waiver for one covers the other. net.JoinHostPort brackets a
// host containing ':' — the same rule URLs use — which keeps a legitimate
// IPv6 address readable instead of escaping it into noise.
//
// A field that ENDS the label (a unix path, an address with no port) needs
// nothing: it is the remainder, so there is nothing for it to run into.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func labelledEndpoint(label string, c commandrun.NetworkConnection) string {
	where := c.Address
	if c.Hostname != "" {
		where = c.Hostname
	}
	if where == "" {
		where = commandrun.HostNotObservable
	}
	if c.Port != 0 {
		return label + ":" + joinHostPort(where, c.Port)
	}
	return label + ":" + where
}

// ipEgressEndpoint names an IP-family connect(). Loopback is called out
// because it reaches a localhost service or proxy that can itself fetch
// external inputs, which is a different fact for an operator than a direct
// external fetch — but both are external-input channels for this observation.
func ipEgressEndpoint(c commandrun.NetworkConnection) (string, bool) {
	host := c.Address
	if c.Hostname != "" {
		host = c.Hostname // prefer the TLS SNI hostname when known
	}
	if host == "" {
		// An IP connect() the observer could not name a destination for. It is
		// still an OBSERVED IP connect(), so it counts: "we could not look" must
		// never be published as "there was nothing there". HostNotObservable
		// exists precisely so this has a name that cannot be misread as a host.
		host = commandrun.HostNotObservable
	}
	// Escaped for the same reason as every other label field: a hostname or an
	// IPv6 address contains ':' and would otherwise run into the port, letting
	// two different destinations render as one waiver.
	endpoint := host
	if c.Port != 0 {
		endpoint = joinHostPort(host, c.Port)
	}
	// Loopback reaches a localhost service/proxy that can fetch external inputs;
	// label it so the observation identifies the indirect external-input path.
	if isLoopbackAddr(c.Address) {
		return "loopback:" + endpoint, true
	}
	return endpoint, true
}

// isLoopbackAddr reports whether an address is an IP loopback address.
func isLoopbackAddr(addr string) bool {
	if ip := net.ParseIP(addr); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isContainerRuntimeSocket reports whether a UNIX socket path is a container
// runtime control socket (docker / containerd / podman / cri-o). Connecting to
// one during a build can pull images or exec commands that fetch undeclared
// inputs, so it is counted. Matched by basename to tolerate the varied
// host paths these sockets live at (/var/run, /run, rootless dirs, …).
func isContainerRuntimeSocket(path string) bool {
	if path == "" {
		return false
	}
	base := path
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "docker.sock", "containerd.sock", "podman.sock", "crio.sock", "cri-dockerd.sock":
		return true
	}
	return false
}

// signerKind names the selected signer provider (file, fulcio, kms, spiffe…)
// from the changed --signer-<kind>-* flags. Empty when no provider matched.
func signerKind(signerProviders map[string]struct{}) string {
	kinds := make([]string, 0, len(signerProviders))
	for k := range signerProviders {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ",")
}

// collectionSubjects extracts the in-toto subject set from the signed
// collection result (the RunResult with an empty AttestorName), which is the
// anchor set an uploaded attestation is correlated by. Per-attestor sidecar
// results are skipped — their subjects are the union the collection already
// carries.
func collectionSubjects(results []workflow.RunResult) []options.RunSubject {
	for _, r := range results {
		if r.AttestorName != "" {
			continue
		}
		out := make([]options.RunSubject, 0, len(r.CollectionSubjects))
		for name, ds := range r.CollectionSubjects {
			// ds (the per-iteration range variable, Go 1.22+) is addressable,
			// so the pointer-receiver ToNameMap can be called on it directly.
			digests, err := ds.ToNameMap()
			if err != nil {
				digests = nil
			}
			out = append(out, options.RunSubject{Name: name, Digests: digests})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}
	return nil
}

// attestorOutcomes maps the final attestor set onto ran/skipped/failed
// statuses. The default is "ran"; soft error legs (attestor had nothing to do)
// become "skipped" and fatal legs become "failed", with the leg's error as the
// actionable detail. The commandrun attestor is excluded — its result is
// reported separately under wrapped_command.
func attestorOutcomes(attestors []attestation.Attestor, runErr error) []options.AttestorOutcome {
	type legInfo struct {
		soft   bool
		detail string
	}
	legs := map[string]legInfo{}
	var aggregate *workflow.AttestorRunErrors
	if errors.As(runErr, &aggregate) && aggregate != nil {
		for _, leg := range aggregate.SoftLegs() {
			legs[leg.Attestor] = legInfo{soft: true, detail: legDetail(leg.Err)}
		}
		for _, leg := range aggregate.FatalLegs() {
			legs[leg.Attestor] = legInfo{soft: false, detail: legDetail(leg.Err)}
		}
	}

	var out []options.AttestorOutcome
	for _, a := range attestors {
		name := a.Name()
		if name == attestorCommandRun {
			continue
		}
		oc := options.AttestorOutcome{Name: name, Status: options.AttestorStatusRan}
		if li, ok := legs[name]; ok {
			if li.soft {
				oc.Status = options.AttestorStatusSkipped
				oc.Detail = enrichSkippedDetail(name, li.detail)
			} else {
				oc.Status = options.AttestorStatusFailed
				oc.Detail = li.detail
			}
		}
		out = append(out, oc)
	}
	return out
}

// enrichSkippedDetail makes a skipped attestor's detail actionable. A skipped
// (soft) attestor "ran but had nothing to do" — usually because the external
// tool whose output it records never ran. When the attestor's own soft-error
// message doesn't already name a generator (some emit a generic "no products
// to attest"), append the list of generators that WOULD feed it, sourced from
// the detection registry (attestorExternalGenerators). This turns
// "sbom: skipped (no products to attest)" into
// "sbom: skipped (no products to attest; record an SBOM tool's output —
// cilock does NOT run it — e.g. one of: apko, bom, cdxgen, melange, syft)".
func enrichSkippedDetail(name, detail string) string {
	gens := attestorExternalGenerators(name)
	if len(gens) == 0 {
		// Self-contained attestor (git, environment) — no external generator,
		// so there's nothing actionable to add beyond its own message.
		return detail
	}
	// Don't double up if the attestor's own message already named a generator.
	for _, g := range gens {
		if strings.Contains(detail, g) {
			return detail
		}
	}
	hint := fmt.Sprintf("record an external tool's output — cilock does NOT run it — e.g. one of: %s", strings.Join(gens, ", "))
	if detail == "" {
		return hint
	}
	return detail + "; " + hint
}

// legDetail strips the "attestor <name> failed: " wrapper the workflow layer
// adds and the "soft: " log-reader prefix a SoftError carries, so the summary
// detail reads as the underlying actionable message. The ran/skipped/failed
// status field already conveys the soft-vs-fatal classification.
func legDetail(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.Index(msg, "failed: "); i >= 0 {
		msg = msg[i+len("failed: "):]
	}
	msg = strings.TrimPrefix(msg, "soft: ")
	return msg
}

// wrappedCommandOutcome reports the wrapped command's exit code from the
// commandrun attestor, if one was present. Returns nil when cilock wrapped no
// command (sign-only / attest-only style invocation).
func wrappedCommandOutcome(args []string, attestors []attestation.Attestor) *options.WrappedCommand {
	for _, a := range attestors {
		if cr, ok := a.(*commandrun.CommandRun); ok {
			return &options.WrappedCommand{Args: args, ExitCode: cr.ExitCode}
		}
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
			log.Warnf("  - %q", leg.Err)
		}
	}

	if len(fatalLegs) > 0 {
		// Build a new aggregate containing only the fatal legs so the
		// returned error message reflects what actually drove the exit
		// code. log.Errorf separately so the "Errors:" header is
		// visible whether or not the caller has a top-level error log.
		log.Error("Errors:")
		for _, leg := range fatalLegs {
			log.Errorf("  - %q", leg.Err)
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
// collectCaptureGaps compares what each attestor ACTUALLY emitted against the
// capture expectations its detector.yaml contract declares, returning the
// run-level delta (nil when no attestor in the run declared any expectation).
//
// Attestors that failed or were skipped are excluded: when an attestor errored
// the error is the signal, and stacking "you didn't capture X" on top of "the
// attestor blew up" is noise that buries both. The subject keys read here are
// the attestor's own un-namespaced keys — the same form the contract prefixes
// are written against, NOT the "<predicate-type>/<key>" form Collection.Subjects
// produces.
//
// additionalSubjects are the operator's own --subjects entries (the
// pre-existing escape hatch — never the recommended remedy; guidance text
// points at workflow changes, not flags). They are passed through with their
// PROVENANCE intact rather than merged into each attestor's keys: a
// when-available expectation is about whether the RUN's evidence is findable
// by that identifier, so a supplied subject closes it (warning past a closed
// gap trains people to ignore the signal) — but an always expectation is a
// claim about what THE ATTESTOR emits on every run, and a pasted value must
// not mask an attestor that failed to emit it (a false Complete() report).
func collectCaptureGaps(attestors []attestation.Attestor, runErr error, additionalSubjects map[string]cryptoutil.DigestSet) *detection.CaptureReport {
	supplied := make([]string, 0, len(additionalSubjects))
	for k := range additionalSubjects {
		supplied = append(supplied, k)
	}

	unhealthy := map[string]bool{}
	var aggregate *workflow.AttestorRunErrors
	if errors.As(runErr, &aggregate) && aggregate != nil {
		for _, leg := range aggregate.SoftLegs() {
			unhealthy[leg.Attestor] = true
		}
		for _, leg := range aggregate.FatalLegs() {
			unhealthy[leg.Attestor] = true
		}
	}

	emitted := map[string][]string{}
	for _, a := range attestors {
		name := a.Name()
		if unhealthy[name] {
			continue
		}
		subjecter, ok := a.(attestation.Subjecter)
		if !ok {
			continue
		}
		subjects := subjecter.Subjects()
		keys := make([]string, 0, len(subjects))
		for k := range subjects {
			keys = append(keys, k)
		}
		emitted[name] = keys
	}

	report := detection.BuildCaptureReportSupplemented(emitted, supplied)
	if len(report.Attestors) == 0 {
		// Nothing declared an expectation, so there is nothing to report. Return
		// nil rather than an empty report: an empty report in the JSON summary
		// would read as "capture verified, no gaps", which is a stronger claim
		// than "nobody checked".
		return nil
	}
	return report
}

// warnCaptureGaps prints one actionable warning per gap at NORMAL verbosity —
// a capture gap the user never sees is the failure this whole mechanism exists
// to fix, so it must not sit behind -v. It never returns an error and never
// influences the exit code.
func warnCaptureGaps(report *detection.CaptureReport) {
	if report == nil || len(report.Gaps) == 0 {
		return
	}
	for _, gap := range report.Gaps {
		// One log call per line: the structured logger collapses an embedded
		// newline into a literal "\n" inside a single logfmt field, which buries
		// the remedy. Same shape as warnEmptyProductBundle below.
		for _, line := range gap.WarningLines() {
			log.Warnf("%s", line)
		}
	}
}

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

// requireProductSubject reports whether the run produced a product subject,
// for --require-products.
//
// The test is the attestor's Merkle LEAVES, not its product map: the leaves are
// exactly what the tree root commits to, and the tree root is what becomes the
// product subject of the collection. A product the tree could not carry (an
// entry with no content digest) is not a subject, so counting the map instead
// would pass a run whose subject digest is still the hash of nothing.
func requireProductSubject(attestors []attestation.Attestor) error {
	for _, a := range attestors {
		p, ok := a.(*product.Attestor)
		if !ok {
			continue
		}
		if len(p.Leaves()) > 0 {
			return nil
		}
		return fmt.Errorf("--require-products: the product attestor recorded no artifact, "+
			"so this attestation would carry no product subject and could not identify what the step produced "+
			"(%d file(s) were dropped by cache/glob classification). "+
			"Refusing to write or upload it. Check the command's output path against --workingdir, "+
			"--attestor-product-include-glob and --cache-allow-pattern", p.DroppedByClassification())
	}
	return fmt.Errorf("--require-products: no product attestor ran, so nothing could record a product subject " +
		"(was it dropped with --no-default-attestor product?)")
}
