// Copyright 2026 TestifySec, Inc.
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

package alpsevidence

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// CodexProvider identifies OpenAI's Codex CLI.
//
// Two install shapes were measured on macOS and both defeat a plain
// basename-equals-"codex" test:
//
//   - Homebrew cask: /opt/homebrew/bin/codex is a symlink to
//     /opt/homebrew/Caskroom/codex/<version>/codex-aarch64-apple-darwin, so the
//     real image basename is the release triple, and the version sits in the
//     path.
//   - npm: .../bin/codex is a `#!/usr/bin/env node` script that spawns the
//     native binary from @openai/codex-<platform>. The spawned process IS
//     named codex, so the plain rule does fire for the process cilock actually
//     descends from; the node shim is matched separately for the case where
//     only the shim is in the ancestry.
//
// Every rule is exact equality on a basename or a whole path element.
// /tmp/not-codex matches nothing.
type CodexProvider struct{}

// productCodex is the executable name Codex installs on PATH. Compared for
// exact equality, never as a substring.
const productCodex = "codex"

// codexNpmNamespace is the npm scope Codex publishes under. Every use compares
// a whole path element to it for exact equality, so "not-@openai" and
// "@openai-mirror" are different directories, not near-misses.
const codexNpmNamespace = "@openai"

// Every fingerprint names the BASIS that fired, and the basis half is built
// from the shared constants rather than spelled out here, so a fingerprint
// cannot drift from the vocabulary the rest of the package publishes.
// TestBasisNamesAreNeverSpelledOutByHand pins that.
const (
	fpCodexExecutable    = basisExecutableBase + ":" + productCodex
	fpCodexReleaseBinary = basisExecutableBase + ":codex-<target-triple>"
	fpCodexResolvedLink  = "resolved-symlink:codex-<target-triple>"

	// The image itself is node — kernel-recorded — while the element naming
	// Codex comes out of the one argv slot node was told to RUN, which the
	// process controls. The name says both halves: which slot, and that it is
	// argv.
	fpCodexNpmShim = basisNodeScriptArg + ":" + codexNpmNamespace + "/" + productCodex

	fpCodexComm         = basisKernelComm + ":" + productCodex
	fpCodexProcessTitle = basisArgv0Title + ":" + productCodex
)

// codexReleaseBinaries are the exact artifact names OpenAI publishes per target
// triple. Listed explicitly rather than pattern-matched on a "codex-" prefix,
// because a prefix rule would happily claim /tmp/codex-evil.
var codexReleaseBinaries = map[string]struct{}{
	"codex-aarch64-apple-darwin":        {},
	"codex-x86_64-apple-darwin":         {},
	"codex-aarch64-unknown-linux-musl":  {},
	"codex-x86_64-unknown-linux-musl":   {},
	"codex-aarch64-unknown-linux-gnu":   {},
	"codex-x86_64-unknown-linux-gnu":    {},
	"codex-aarch64-pc-windows-msvc.exe": {},
	"codex-x86_64-pc-windows-msvc.exe":  {},
}

func (CodexProvider) Vendor() string  { return "openai" }
func (CodexProvider) Product() string { return productCodex }

// EnvAllowlist deliberately omits anything that could carry an API key.
// CODEX_HOME is a directory location needed to find the config file; it is
// requested from the agent process only.
func (CodexProvider) EnvAllowlist() []EnvKey {
	return []EnvKey{
		{Name: "CODEX_HOME", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent, EnvScopeSelf}},
		{Name: "CODEX_SANDBOX", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent}},
		{Name: "CODEX_SANDBOX_NETWORK_DISABLED", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent}},
	}
}

func (CodexProvider) Match(p ProcessInfo) MatchResult {
	base := executableBase(p)
	if base == productCodex || base == productCodex+".exe" {
		return matched(fpCodexExecutable)
	}
	if _, ok := codexReleaseBinaries[base]; ok {
		return matched(fpCodexReleaseBinary)
	}
	// A MATCH-TIME resolution, and its type says so: matchTimeResolve returns
	// a fingerprintPath, which answers identity questions and nothing else. It
	// cannot be turned back into a path, so this resolution can never reach the
	// predicate or resolveVersion — only the executable snapshot's resolution
	// does that.
	if resolved := matchTimeResolve(p.Executable); resolved.differsFrom(p.Executable) && resolved.isCodexReleaseBinary() {
		return matchedViaResolution(fpCodexResolvedLink)
	}
	if isCodexNpmShim(p) {
		return matched(fpCodexNpmShim)
	}
	if commBase(p) == productCodex {
		return matched(fpCodexComm)
	}
	if prog := argvProgram(p); prog == productCodex || prog == productCodex+".exe" {
		return matched(fpCodexProcessTitle)
	}
	return MatchResult{}
}

func (c CodexProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}

	agentEnvObs, agentEnv := collectEnv(r, EnvScopeAgent, c.EnvAllowlist())
	selfEnvObs, selfEnv := collectEnv(r, EnvScopeSelf, c.EnvAllowlist())
	out.Environment = mergeEnv(agentEnvObs, selfEnvObs)

	out.Version = c.resolveVersion(r)
	if out.Version == nil {
		out.Warnings = append(out.Warnings, codexVersionUnobservable(r.Executable))
	}

	// $CODEX_HOME decides WHICH FILE is read at all, so only the AGENT's own
	// environment may answer it. cilock's inherited copy is not consulted for
	// the location: when the agent's environment was read and carried no
	// $CODEX_HOME, the agent used the default — a $CODEX_HOME sitting only in
	// cilock's environment describes cilock's launch, not the agent's, and
	// following it would read (and sign) a config file the agent never
	// resolved. A blocked read leaves an override unruled-out, and the file
	// found at the default location is then evidence of existence only.
	codexHome, homeBlocked := resolveEnvValue("CODEX_HOME", agentEnv)
	codexHomeKnown := !homeBlocked
	if codexHome == "" {
		if selfHome, _ := resolveEnvValue("CODEX_HOME", selfEnv); selfHome != "" && !homeBlocked {
			out.Warnings = append(out.Warnings,
				"codex: CODEX_HOME is set in cilock's own inherited environment but not in the agent process's; it is recorded as a cilock-process environment observation only and does not decide which config file is read.")
		}
		if home := userHomeDir(); home != "" {
			codexHome = filepath.Join(home, ".codex")
		}
	}

	configs, model, settings, configWarnings := c.resolveConfig(r, codexHome, codexHomeKnown)
	out.Configuration = configs
	out.Model = model
	out.Settings = settings
	out.Warnings = append(out.Warnings, configWarnings...)
	switch {
	case out.Model == nil:
		out.Warnings = append(out.Warnings,
			"codex: effective model not observable. It was not passed on the command line and no model key was found in the Codex config that was read.")
	case out.Model.Assurance == AssuranceConfigObserved:
		out.Warnings = append(out.Warnings, configuredDefaultWarning("codex", out.Model.Source))
	}

	c.collectArgvFields(r.Process, out.ArgvFields)
	return out
}

// resolveVersion reads the version out of the install layout, which is the only
// place it appears without executing the agent binary.
//
// Running `codex --version` would be a stronger read and is deliberately not
// done: this attestor must never execute a process it is inspecting.
//
// The two layouts answer with different evidence, and the split between them is
// the point:
//
//   - A Caskroom version is parsed out of a PATH STRING and reads no file at
//     all. The kernel's exec record is a fact about this process that no later
//     package replacement can alter, so parsing it is safe; the snapshot's own
//     resolution is consulted after it, for the symlink shape.
//   - An npm version lives in a package manifest, a DIFFERENT FILE sitting
//     beside the image. Reading it asks the filesystem a fresh question at
//     inspection time, so it is asked only of the path the snapshot BOUND to
//     the digested handle — snapshot.npmPackageVersion takes no path precisely
//     so no other one can be supplied. When the snapshot bound no path, the
//     read does not happen and no version is claimed: a manifest replaced after
//     this process started would otherwise pair a new version with the old
//     image, which is what round 5 found.
//
// Both are graded AssuranceInferred, and for the same reason: each is located
// by a layout convention — a Caskroom directory name, a package directory whose
// parent is literally @openai — rather than read out of the image itself. The
// npm read was previously graded configuration-observed on the grounds that the
// value came from a file's content; that reasoning graded the READ instead of
// the CLAIM, and let a policy demanding observed evidence accept a layout guess.
func (CodexProvider) resolveVersion(r InspectRequest) *Observation {
	if v := codexVersionFromCaskPath(r.Process.Executable); v != "" {
		return &Observation{Value: v, Source: "process.executable", Assurance: AssuranceInferred}
	}
	if resolved := r.Executable.resolved(); resolved != "" && resolved != r.Process.Executable {
		if v := codexVersionFromCaskPath(resolved); v != "" {
			return &Observation{Value: v, Source: "process.executable(resolved symlink)", Assurance: AssuranceInferred}
		}
	}
	if v := r.Executable.npmPackageVersion(codexNpmNamespace); v != "" {
		return &Observation{
			Value:     v,
			Source:    "process.executable(snapshot) -> " + codexNpmNamespace + " package.json",
			Assurance: AssuranceInferred,
		}
	}
	return nil
}

// codexVersionUnobservable explains an absent version, and says WHICH of the
// two reasons applies.
//
// The distinction is not cosmetic. "The layout carried no version" and "there
// may well be a version next to the binary, but nothing tied that file to the
// image this predicate digested, so it was not read" are different facts about
// the run, and a reader deciding how much to trust an absent version needs the
// second one stated rather than inferred from silence.
func codexVersionUnobservable(snap executableSnapshot) string {
	const updateCheckFile = " $CODEX_HOME/version.json is deliberately not consulted — it records the latest version available upstream, not the version that ran."

	if snap.resolved() == "" {
		return "codex: version not observable. The executable path could not be bound to the image this predicate digested, so the " +
			codexNpmNamespace + " package.json that carries an npm-installed version was not read: a package replaced after this " +
			"process started would pair its version with the earlier image." + updateCheckFile
	}
	return "codex: version not observable from the install layout." + updateCheckFile
}

// resolveConfig resolves model and posture settings within the local sources
// this observer can read. A returned configuration-observed value is not a
// claim about the effective runtime stack: Codex also supports system, cloud,
// and managed layers that this process observer cannot authoritatively query.
//
// Precedence implemented here is the current Codex CLI contract measured from
// `codex --help`: command-line flags beat configuration; the base file is
// $CODEX_HOME/config.toml; and --profile <name> layers
// $CODEX_HOME/<name>.config.toml over that base. This applies to EVERY setting,
// not just the model — a base config saying sandbox_mode = "read-only" under
// a profile or CLI override granting full access describes a different run,
// and reporting it would sign a safer posture than the agent actually had.
//
// Earlier Codex releases used [profiles.<name>] tables in config.toml. Reading
// that legacy table for a current `-p unsafe` run is actively unsafe: a stale
// table can say read-only while the selected unsafe.config.toml grants full
// access. The observer therefore follows only the current overlay-file shape.
// A missing, unreadable, oversize, or malformed selected overlay blocks base
// resolution rather than falling through.
//
// Project configuration is recorded but is NOT resolved into model or posture.
// Codex loads the .codex/config.toml files between the working directory and
// its project root, above user/profile configuration; a bare config.toml is
// not a Codex layer at any level (measured against codex-cli 0.147.0 — see
// codexProjectConfigPaths and testdata/codex-cli-0.147.0-config-contract.txt).
// This observer conservatively checks every ancestor (it need not infer Codex's
// private trust/root decision): if any project tier is present or the bounded
// scan cannot complete, user/profile values degrade to observed rather than
// claiming the safer value from a lower tier. Only CLI-derived values, whose
// precedence over every file is confirmed, survive that gap.
//
// Every file is read as one immutable snapshot: every value and its recorded
// digest come from the same bytes (see configSnapshot).
//
// codexHomeKnown reports whether the codexHome location is actually known to
// be the one this run used: false when an unreadable environment left a
// $CODEX_HOME override unruled-out, in which case the file found at the
// fallback location is evidence of existence only, never of effect.
func (CodexProvider) resolveConfig(r InspectRequest, codexHome string, codexHomeKnown bool) ([]ConfigSource, *Observation, []SettingObservation, []string) {
	var (
		sources  []ConfigSource
		warnings []string
	)

	model := codexModelFromArgv(r.Process.Argv)
	profile, profileSelected := codexProfileSelection(r.Process.Argv)
	profileValid := !profileSelected || validCodexProfileName(profile)
	fromCLI := codexSettingsFromArgv(r.Process.Argv)
	fromConfig := map[string]SettingObservation{}

	// A valueless posture flag replaces sandbox_mode and approval_policy
	// wholesale. No value is invented for it — the composite each flag
	// expands to is version-dependent — but the file's posture demonstrably
	// did not survive it, so the file must not be consulted for those keys:
	// absence plus the warning below never claims a safer posture, while the
	// file's read-only would.
	overrideFlag := codexPostureOverrideFlag(r.Process.Argv)
	if overrideFlag != "" {
		warnings = append(warnings,
			"codex: "+overrideFlag+" replaces the sandbox and approval posture; config.toml's sandbox_mode and approval_policy do not describe this run and are not reported. The flag itself is recorded in argv_fields.")
	}

	// Project configuration is loaded FIRST: whether any tier exists must be
	// known before deciding what the lower user/profile stack may claim. Cilock
	// receives a working directory, not a repository root; Codex walks from
	// that directory through parent .codex directories. Looking only at
	// WorkingDir/.codex misses the ordinary `repo/subdir` invocation and can
	// publish a lower, safer posture.
	project := loadCodexProjectTier(r.RepoRoot)
	sources = append(sources, project.sources...)
	if project.unreadable {
		warnings = append(warnings,
			"codex: at least one project configuration tier exists but could not be read safely; nothing was resolved from the lower user/profile stack because that tier may override it.")
	}

	home := loadCodexHomeTier(codexHome, profile, profileSelected && profileValid)

	// Resolve only when every tier that could affect these fields was observed
	// coherently. CLI values remain valid even when file resolution blocks.
	blocker := codexFileResolutionBlocker(codexHomeKnown, project, home, profile, profileSelected, profileValid)
	if blocker != "" {
		warnings = append(warnings, blocker)
		sources = append(sources, home.describeObservedOnly()...)
		return sources, model, codexMergeSettings(fromCLI, fromConfig), warnings
	}

	var resolvedSources []ConfigSource
	resolvedSources, model, fromConfig = codexResolveConfigLayers(home.layers(), model, fromCLI, overrideFlag)
	sources = append(sources, resolvedSources...)
	if home.userSnap != nil || home.profileSnap != nil {
		warnings = append(warnings,
			"codex: values resolved from the observed user/profile files are configured values, not proof of effective runtime posture; system, cloud, and managed configuration layers are outside this process observer.")
	}

	return sources, model, codexMergeSettings(fromCLI, fromConfig), warnings
}

// codexProjectTierState is what the bounded project-configuration scan found:
// the recorded sources, whether any project tier exists at all, whether every
// location could be visited, and whether one existed but could not be read.
type codexProjectTierState struct {
	sources    []ConfigSource
	present    bool
	complete   bool
	unreadable bool
}

// loadCodexProjectTier snapshots every candidate project-tier location for the
// observed working directory (see codexProjectConfigPaths).
func loadCodexProjectTier(workingDir string) codexProjectTierState {
	paths, complete := codexProjectConfigPaths(workingDir)
	state := codexProjectTierState{complete: complete}
	for _, path := range paths {
		snap, denied := loadConfigSnapshot(path)
		switch {
		case snap != nil:
			state.present = true
			state.sources = append(state.sources, *snap.describe(configScopeProject))
		case denied:
			state.present = true
			state.unreadable = true
			state.sources = append(state.sources, *describeUnreadableConfig(path, "project"))
		}
	}
	return state
}

// codexHomeTierState is the user/profile half of the local configuration
// stack: the snapshots (or denials) at $CODEX_HOME.
type codexHomeTierState struct {
	userPath      string
	userSnap      *configSnapshot
	userDenied    bool
	profilePath   string
	profileSnap   *configSnapshot
	profileDenied bool
}

// loadCodexHomeTier snapshots $CODEX_HOME/config.toml and, when a valid
// profile was selected, the profile overlay beside it.
func loadCodexHomeTier(codexHome, profile string, loadProfile bool) codexHomeTierState {
	var state codexHomeTierState
	if codexHome == "" {
		return state
	}
	state.userPath = filepath.Join(codexHome, "config.toml")
	state.userSnap, state.userDenied = loadConfigSnapshot(state.userPath)
	if loadProfile {
		state.profilePath = filepath.Join(codexHome, profile+".config.toml")
		state.profileSnap, state.profileDenied = loadConfigSnapshot(state.profilePath)
	}
	return state
}

// layers returns the readable snapshots in precedence order (profile over
// user), for codexResolveConfigLayers.
func (h codexHomeTierState) layers() []codexConfigLayer {
	layers := make([]codexConfigLayer, 0, 2)
	if h.profileSnap != nil {
		layers = append(layers, codexConfigLayer{snap: h.profileSnap, label: codexProfileConfigLabel, scope: configScopeProfile})
	}
	if h.userSnap != nil {
		layers = append(layers, codexConfigLayer{snap: h.userSnap, label: codexUserConfigLabel, scope: configScopeUser})
	}
	return layers
}

// describeObservedOnly records the user/profile files without resolving
// anything from them — the shape used when a blocker withheld resolution.
func (h codexHomeTierState) describeObservedOnly() []ConfigSource {
	var sources []ConfigSource
	switch {
	case h.profileSnap != nil:
		sources = append(sources, *h.profileSnap.describe(configScopeProfile))
	case h.profileDenied:
		sources = append(sources, *describeUnreadableConfig(h.profilePath, "profile"))
	}
	switch {
	case h.userSnap != nil:
		sources = append(sources, *h.userSnap.describe(configScopeUser))
	case h.userDenied:
		sources = append(sources, *describeUnreadableConfig(h.userPath, configScopeUser))
	}
	return sources
}

// codexFileResolutionBlocker returns the warning explaining why nothing may be
// resolved from the configuration files, or "" when every tier was observed
// coherently. The order is precedence order: the first tier whose state is
// unknown blocks everything below it.
func codexFileResolutionBlocker(codexHomeKnown bool, project codexProjectTierState, home codexHomeTierState, profile string, profileSelected, profileValid bool) string {
	switch {
	case !codexHomeKnown:
		return "codex: the agent process environment could not be read, or CODEX_HOME was withheld by the run-wide redaction policy, so an override cannot be ruled out; " + codexUserConfigLabel + " and any selected profile at the fallback location are recorded as observed but not resolved."
	case !project.complete:
		return "codex: the bounded project-configuration ancestry scan could not complete, so a higher-precedence project override cannot be ruled out; user and profile configuration is recorded as observed but not resolved."
	case project.present:
		return "codex: a higher-precedence project configuration tier (a .codex/config.toml between the working directory and the project root) exists; it is recorded as observed but not resolved, and user/profile values are not resolved in its place."
	case profileSelected && !profileValid:
		return "codex: --profile carried a name outside the CLI's plain-name alphabet [A-Za-z0-9_-]; Codex rejects that selection, so no profile path was opened and no base configuration was resolved for this observed argv."
	case home.userDenied:
		return "codex: " + codexUserConfigLabel + " exists but could not be read safely, so no model or posture was resolved from the configuration stack."
	case home.userSnap != nil && !home.userSnap.tomlObjectParseable():
		return "codex: " + codexUserConfigLabel + " could not be parsed within the snapshot bound, so no model or posture was resolved from the configuration stack."
	case profileSelected && home.profileDenied:
		return "codex: --profile " + profile + " selects " + codexProfileConfigLabel + " but that file could not be read safely; base values are not resolved because the selected overlay may override them."
	case profileSelected && home.profileSnap == nil:
		return "codex: --profile " + profile + " selects " + codexProfileConfigLabel + " but no readable regular file was observed there; base values are not resolved because the selected overlay is unknown."
	case home.profileSnap != nil && !home.profileSnap.tomlObjectParseable():
		return "codex: --profile " + profile + " selects " + codexProfileConfigLabel + " but that file could not be parsed within the snapshot bound; base values are not resolved because the selected overlay is unknown."
	}
	return ""
}

// codexUserConfigLabel is the scope-relative name for the user config in
// warnings and observation Source strings. Those strings enter the signed
// predicate, and the absolute path would leak the home directory (or
// wherever $CODEX_HOME points); $CODEX_HOME defaults to ~/.codex, so the
// label reads true whether or not the override was set. The absolute path
// stays confined to ConfigSource.Path, the identity of the digested file.
const (
	codexUserConfigLabel    = "$CODEX_HOME/config.toml"
	codexProfileConfigLabel = "$CODEX_HOME/<profile>.config.toml"
)

const maxCodexProjectConfigDepth = 64

// codexProjectConfigPaths returns every filesystem location that could be a
// project tier for the observed working directory without executing git or the
// inspected agent. It stops after the default .git project marker; when no
// marker is visible, walking to the filesystem root is conservative. A custom
// project-root marker remains part of the explicitly unobservable stack caveat
// and never turns these configured values into effective-runtime claims.
//
// The result is cwd/.codex/config.toml and each parent's .codex/config.toml.
// A BARE config.toml is deliberately NOT a candidate at any level. That was
// measured, not assumed: with codex-cli 0.147.0, writing a distinctive model
// into <cwd>/config.toml or <project-root>/config.toml left `codex doctor`
// reporting the $CODEX_HOME model unchanged, while the same value in
// <cwd>/.codex/config.toml or <project-root>/.codex/config.toml was resolved
// (testdata/codex-cli-0.147.0-config-contract.txt records the runs). A bare
// config.toml is an ordinary repository file in several ecosystems, so
// treating one as a Codex tier both digested an unrelated file into signed
// evidence as Codex configuration and suppressed resolution of the user tier
// that did describe the run.
//
// The walk starts from the PHYSICAL working directory (see physicalDir), the
// same resolution projectRootFromWorkingDir uses: lexical parents of a
// symlinked working directory belong to the link's tree, not the one Codex
// ran in, so they find neither the real project layers nor the .git that
// bounds the scan. A directory that cannot be resolved yields complete=false.
//
// The count is bounded because every observed source can enter a signed
// predicate. complete=false means the caller must refuse lower-tier
// resolution.
func codexProjectConfigPaths(workingDir string) (paths []string, complete bool) {
	if workingDir == "" {
		return nil, true
	}
	abs, ok := physicalDir(workingDir)
	if !ok {
		return nil, false
	}

	dir := abs
	for depth := 0; depth < maxCodexProjectConfigDepth; depth++ {
		paths = append(paths, filepath.Join(dir, ".codex", "config.toml"))
		// The installed CLI's default project-root marker is .git. Stop after
		// including that directory's project tier so the observer does not hash
		// unrelated .codex files higher in the filesystem. A custom
		// project_root_markers setting is an unobservable-stack caveat named in
		// the configured-value warning above; it never upgrades this evidence to
		// effective posture.
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return paths, true
		} else if !os.IsNotExist(err) {
			return paths, false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return paths, true
		}
		dir = parent
	}
	return paths, false
}

type codexConfigLayer struct {
	snap   *configSnapshot
	label  string
	scope  string
	fields []string
}

// codexResolveConfigLayers consults profile then base for every key the CLI
// did not already decide. The ordered layers are already known-readable and
// parseable. fields records exactly which snapshots were consulted for which
// keys; a miss in the overlay legitimately falls through to the base.
func codexResolveConfigLayers(layers []codexConfigLayer, model *Observation, fromCLI map[string]SettingObservation, overrideFlag string) ([]ConfigSource, *Observation, map[string]SettingObservation) {
	settings := map[string]SettingObservation{}
	resolve := func(key string) (value, source string, found bool) {
		for i := range layers {
			layers[i].fields = append(layers[i].fields, key)
			if v, ok := layers[i].snap.tomlString("", key); ok {
				return v, layers[i].label, true
			}
		}
		return "", "", false
	}

	if model == nil {
		if v, source, ok := resolve("model"); ok {
			model = &Observation{Value: v, Source: source, Assurance: AssuranceConfigObserved}
		}
	}
	for _, key := range codexPostureKeys {
		if _, decided := fromCLI[key]; decided {
			continue
		}
		if overrideFlag != "" && key != "model_reasoning_effort" {
			// The posture pair was replaced by a valueless flag; see
			// resolveConfig for why the file is not consulted for it.
			continue
		}
		if v, source, ok := resolve(key); ok {
			settings[key] = SettingObservation{
				Key: key, Value: v, Source: source, Assurance: AssuranceConfigObserved,
			}
		}
	}

	sources := make([]ConfigSource, 0, len(layers))
	for i := range layers {
		sources = append(sources, *layers[i].snap.describe(layers[i].scope, layers[i].fields...))
	}
	return sources, model, settings
}

// codexMergeSettings flattens per-key resolution into one deterministic list
// in codexPostureKeys order, the CLI value winning per key.
func codexMergeSettings(fromCLI, fromConfig map[string]SettingObservation) []SettingObservation {
	settings := make([]SettingObservation, 0, len(codexPostureKeys))
	for _, key := range codexPostureKeys {
		if s, ok := fromCLI[key]; ok {
			settings = append(settings, s)
			continue
		}
		if s, ok := fromConfig[key]; ok {
			settings = append(settings, s)
		}
	}
	if len(settings) == 0 {
		return nil
	}
	return settings
}

// codexPostureOverrideFlag returns the first valueless posture-replacing flag
// present in argv before the "--" terminator, or "".
func codexPostureOverrideFlag(argv []string) string {
	for _, arg := range optionArgv(argv) {
		switch arg {
		case "--dangerously-bypass-approvals-and-sandbox", "--yolo", "--full-auto":
			return arg
		}
	}
	return ""
}

// codexPostureKeys are the non-model settings surfaced as posture evidence.
var codexPostureKeys = []string{"model_reasoning_effort", "approval_policy", "sandbox_mode"}

func codexModelFromArgv(argv []string) *Observation {
	if v, ok := argvValue(argv, "--model", "-m"); ok {
		return &Observation{Value: v, Source: sourceArgvModelFlag, Assurance: AssuranceProcessObserved}
	}
	if v, ok := codexConfigOverrideFromArgv(argv, "model"); ok {
		return &Observation{Value: v, Source: "process.argv:-c model=", Assurance: AssuranceProcessObserved}
	}
	return nil
}

// codexSettingsFromArgv resolves the posture keys from the command line,
// mirroring codexModelFromArgv: the dedicated flag is consulted before the
// generic -c/--config override, and either beats the config file. Reasoning
// effort has no dedicated flag, so only the -c form can carry it.
func codexSettingsFromArgv(argv []string) map[string]SettingObservation {
	out := map[string]SettingObservation{}

	record := func(key, value, source string) {
		out[key] = SettingObservation{
			Key: key, Value: value, Source: source, Assurance: AssuranceProcessObserved,
		}
	}
	if v, ok := argvValue(argv, "--sandbox", "-s"); ok {
		record("sandbox_mode", v, "process.argv:--sandbox")
	} else if v, ok := codexConfigOverrideFromArgv(argv, "sandbox_mode"); ok {
		record("sandbox_mode", v, "process.argv:-c sandbox_mode=")
	}
	if v, ok := argvValue(argv, "--ask-for-approval", "-a"); ok {
		record("approval_policy", v, "process.argv:--ask-for-approval")
	} else if v, ok := codexConfigOverrideFromArgv(argv, "approval_policy"); ok {
		record("approval_policy", v, "process.argv:-c approval_policy=")
	}
	if v, ok := codexConfigOverrideFromArgv(argv, "model_reasoning_effort"); ok {
		record("model_reasoning_effort", v, "process.argv:-c model_reasoning_effort=")
	}
	return out
}

// codexConfigOverrideFromArgv mirrors Codex's documented -c/--config value
// contract: parse the right-hand side as TOML and, if TOML parsing fails, use
// the raw bytes as a literal string. Recording the raw representation of a
// valid TOML string (`model="gpt-5"`) would include the quotes and escapes and
// therefore claim a different model than Codex actually selected.
//
// The fields this attestor surfaces are all string-valued. A valid TOML value
// of another type is not converted: the running CLI normally rejects that
// type for these fields, and silence is safer than inventing a coercion.
func codexConfigOverrideFromArgv(argv []string, key string) (string, bool) {
	raw, ok := argvKeyValue(argv, []string{"-c", "--config"}, key)
	if !ok {
		return "", false
	}
	var parsed map[string]any
	if err := toml.Unmarshal([]byte("value = "+raw), &parsed); err != nil {
		return raw, true
	}
	value, ok := parsed["value"].(string)
	return value, ok
}

// codexProfileSelection returns the profile carried by --profile (or clap's
// short alias -p) and whether the option was present. Presence is separate
// from the value because an explicitly empty profile is invalid, not the same
// thing as no selection.
func codexProfileSelection(argv []string) (string, bool) {
	return argvValue(argv, "--profile", "-p")
}

// validCodexProfileName mirrors the current CLI's CONFIG_PROFILE_V2
// validation, measured against `codex --help`: a non-empty plain name using
// ASCII letters, digits, underscore, or hyphen. In particular dots, slashes,
// backslashes and whitespace are rejected before Codex opens any profile file.
// Applying the same bound here prevents forged argv from turning the observer
// into an arbitrary-path config reader.
func validCodexProfileName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// collectArgvFields copies an explicit allowlist of flags out of argv. Nothing
// else from argv is serialized.
func (CodexProvider) collectArgvFields(p ProcessInfo, into map[string]string) {
	if v, ok := argvValue(p.Argv, "--model", "-m"); ok {
		into["model"] = v
	}
	if v, ok := argvValue(p.Argv, "--profile", "-p"); ok {
		into["profile"] = v
	}
	if v, ok := codexConfigOverrideFromArgv(p.Argv, "model"); ok {
		into["config_override_model"] = v
	}
	if v, ok := argvValue(p.Argv, "--sandbox", "-s"); ok {
		into["sandbox"] = v
	}
	if v, ok := argvValue(p.Argv, "--ask-for-approval", "-a"); ok {
		into["ask_for_approval"] = v
	}
	for _, arg := range optionArgv(p.Argv) {
		if arg == "--dangerously-bypass-approvals-and-sandbox" || arg == "--yolo" {
			into["dangerously_bypass_approvals_and_sandbox"] = flagTrue
		}
		if arg == "--full-auto" {
			into["full_auto"] = flagTrue
		}
	}
	if role := processTitleRole(p); role != "" {
		into["process_title_role"] = role
	}
}

// isCodexNpmShim recognizes `node .../@openai/codex/bin/codex.js`.
//
// The match is on the exact four-element TAIL of the script path —
// @openai/codex/bin/codex.js — not on "an @openai element somewhere above a
// file called codex.js". The looser rule attributed
// /tmp/@openai/unrelated/bin/codex.js to the @openai/codex package: a path an
// attacker can create, naming a package that was not there. Requiring the tail
// means the scope directory and the package directory must be adjacent and
// both exactly right, so "@openai-mirror/codex", "@openai/codex-sdk" and
// "@openai/a/b/codex" are different paths rather than near misses.
//
// This is the rule the basis vocabulary already enforces for the name
// matchers: a fingerprint may only name what actually matched.
func isCodexNpmShim(p ProcessInfo) bool {
	base := executableBase(p)
	if base != "node" && base != "node.exe" {
		return false
	}
	// ONE slot is consulted: the script node was told to run. Scanning every
	// argument attributed `node app.js /tmp/@openai/codex/bin/codex.js` to the
	// Codex package, though that path is an ARGUMENT handed to an unrelated
	// program rather than the program being run.
	return hasCodexPackageTail(pathElements(nodeScriptArg(p.Argv)))
}

// nodeScriptArg returns the path of the script an interpreter was told to run,
// or "" when that cannot be determined.
//
// The rule is deliberately strict rather than clever: the script is the first
// argument, or the one right after a bare "--". Node accepts options before the
// script, and some of them take a SEPARATE value — `node -r <path> app.js`
// — so a scan that skipped anything beginning with "-" would happily read that
// value as the script and hand an attacker the false positive back. There is no
// closed list of such options to rely on, so an argv this cannot read
// unambiguously yields "".
//
// The cost is a missed detection for an agent launched through node with
// options, and the benefit is that a miss is all it ever is. This matcher is a
// fallback for the case where only the shim is in the ancestry; refusing when
// the evidence is ambiguous is the same direction every other read in this
// package takes.
func nodeScriptArg(argv []string) string {
	if len(argv) < 2 {
		return ""
	}
	if argv[1] == optionTerminator {
		if len(argv) < 3 {
			return ""
		}
		return argv[2]
	}
	if strings.HasPrefix(argv[1], "-") {
		return ""
	}
	return argv[1]
}

// codexNpmBinDir is the directory npm installs a package's executables into.
const codexNpmBinDir = "bin"

// hasCodexPackageTail reports whether a path ends in the @openai/codex
// package's shim location. Every element is compared for exact equality.
func hasCodexPackageTail(elements []string) bool {
	const tailLen = 4
	if len(elements) < tailLen {
		return false
	}
	tail := elements[len(elements)-tailLen:]
	if tail[0] != codexNpmNamespace || tail[1] != productCodex || tail[2] != codexNpmBinDir {
		return false
	}
	return tail[3] == productCodex || tail[3] == productCodex+".js"
}

// codexVersionFromCaskPath reads the version from a Homebrew cask layout:
// .../codex/<version>/codex-<triple>.
func codexVersionFromCaskPath(path string) string {
	elements := pathElements(path)
	if len(elements) < 3 {
		return ""
	}
	if elements[len(elements)-3] != productCodex {
		return ""
	}
	candidate := elements[len(elements)-2]
	if !looksLikeVersion(candidate) {
		return ""
	}
	return candidate
}
