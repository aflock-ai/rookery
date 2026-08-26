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
	"path/filepath"
	"runtime"
	"strings"
)

// ClaudeCodeProvider identifies Anthropic's Claude Code CLI.
//
// Detection has to cope with an install shape that defeats naive basename
// matching. Measured on macOS (Claude Code 2.1.234/2.1.237):
//
//   - The executable on disk is ~/.local/share/claude/versions/<semver>, so the
//     basename of the image path is "2.1.234", not "claude".
//   - ~/.local/bin/claude is a symlink to that versioned file.
//   - The process rewrites argv[0] to a title such as "claude bg-spare", whose
//     basename is the whole string "claude bg-spare", again not "claude".
//   - cilock's nearest Claude Code ancestor is a background spare worker; its
//     parent is a pty host from the same install, and that pty host's parent is
//     PID 1. The interactive session process is not in the ancestry at all.
//
// Every fingerprint below is an exact equality test on a path element, a
// basename, or a title token. None is a substring search, so /tmp/not-claude
// and /usr/bin/claudette are not Claude Code.
type ClaudeCodeProvider struct{}

// productClaude is the executable name Claude Code installs on PATH. Compared
// for exact equality, never as a substring.
const productClaude = "claude"

// flagTrue is the recorded value for a boolean argv flag that was present.
const flagTrue = "true"

// Every fingerprint names the BASIS that fired, and the basis half is built
// from the shared constants rather than spelled out here, so a fingerprint
// cannot drift from the vocabulary the rest of the package publishes.
// TestBasisNamesAreNeverSpelledOutByHand pins that.
const (
	fpClaudeInstallLayout = "install-layout:claude/versions"
	fpClaudeExecutable    = basisExecutableBase + ":" + productClaude
	fpClaudeResolvedLink  = "resolved-symlink:claude/versions"
	fpClaudeComm          = basisKernelComm + ":" + productClaude
	fpClaudeProcessTitle  = basisArgv0Title + ":" + productClaude
)

func (ClaudeCodeProvider) Vendor() string  { return "anthropic" }
func (ClaudeCodeProvider) Product() string { return "claude-code" }

// EnvAllowlist is short on purpose.
//
// Claude Code exports CLAUDE_CODE_MESSAGING_TOKEN and
// CLAUDE_CODE_MESSAGING_SOCKET next to the variables below. The token is a
// credential and the socket is a capability handle whose path also discloses a
// temp-directory layout; neither is requested here, so neither is retained or
// serialized. The kernel still hands the whole environment block to the
// platform source — see EnvAllowlist on the Provider interface.
func (ClaudeCodeProvider) EnvAllowlist() []EnvKey {
	return []EnvKey{
		// The session identifier is the attribution anchor and appears only in
		// cilock's inherited environment. The matched daemon process does not
		// carry it.
		{Name: "CLAUDE_CODE_SESSION_ID", RecordValue: true, Scopes: []EnvScope{EnvScopeSelf}},
		{Name: "CLAUDE_CODE_CHILD_SESSION", RecordValue: true, Scopes: []EnvScope{EnvScopeSelf}},
		{Name: "CLAUDECODE", RecordValue: true, Scopes: []EnvScope{EnvScopeSelf}},
		// Points at the versioned binary; corroborates the version read from
		// the process image.
		{Name: "CLAUDE_CODE_EXECPATH", RecordValue: true, Scopes: []EnvScope{EnvScopeSelf}},
		{Name: "CLAUDE_CODE_ENTRYPOINT", RecordValue: true, Scopes: []EnvScope{EnvScopeSelf, EnvScopeAgent}},
		{Name: "CLAUDE_CODE_SESSION_KIND", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent}},
		{Name: "ANTHROPIC_MODEL", RecordValue: true, Scopes: []EnvScope{EnvScopeSelf, EnvScopeAgent}},
	}
}

func (ClaudeCodeProvider) Match(p ProcessInfo) MatchResult {
	if isClaudeVersionsLayout(p.Executable) {
		return matched(fpClaudeInstallLayout)
	}
	if base := executableBase(p); base == productClaude || base == productClaude+".exe" {
		return matched(fpClaudeExecutable)
	}
	// A MATCH-TIME resolution, and its type says so: matchTimeResolve returns
	// a fingerprintPath, which answers identity questions and nothing else. It
	// cannot be turned back into a path, so this resolution can never reach the
	// predicate or a version parser — only the executable snapshot's resolution
	// does that.
	if matchTimeResolve(p.Executable).isClaudeVersionsLayout() {
		return matchedViaResolution(fpClaudeResolvedLink)
	}
	if commBase(p) == productClaude {
		return matched(fpClaudeComm)
	}
	// Weakest fingerprint, and the only one an arbitrary process can forge for
	// free. It is last so a stronger rule claims the process first and the
	// recorded fingerprint tells a reader which one fired.
	if prog := argvProgram(p); prog == productClaude || prog == productClaude+".exe" {
		return matched(fpClaudeProcessTitle)
	}
	return MatchResult{}
}

func (c ClaudeCodeProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}

	agentEnvObs, agentEnv := collectEnv(r, EnvScopeAgent, c.EnvAllowlist())
	selfEnvObs, selfEnv := collectEnv(r, EnvScopeSelf, c.EnvAllowlist())
	out.Environment = mergeEnv(agentEnvObs, selfEnvObs)

	out.Version = c.resolveVersion(r, selfEnv)
	if out.Version == nil {
		out.Warnings = append(out.Warnings,
			"claude-code: version not observable from the process image, the vendor process chain, or CLAUDE_CODE_EXECPATH")
	}

	configs, model, modelWarnings := c.resolveModel(r, agentEnv, selfEnv)
	out.Configuration = configs
	out.Model = model
	out.Warnings = append(out.Warnings, modelWarnings...)
	switch {
	case out.Model == nil:
		out.Warnings = append(out.Warnings,
			"claude-code: effective model not observable. Claude Code does not publish the active model in argv, in its environment, or in any file this attestor reads, and the model can be changed mid-session. Absence here is not evidence a configured model was used.")
	case out.Model.Assurance == AssuranceConfigObserved:
		// A settings file states a configured default. It is NOT proof of what
		// served the session: Claude Code can be started with an override and
		// the model can be switched mid-session, neither of which touches this
		// file. Observed on this machine — the settings file said one model
		// while the session ran another.
		out.Warnings = append(out.Warnings, configuredDefaultWarning("claude-code", out.Model.Source))
	}

	if sessionID, _ := resolveEnvValue("CLAUDE_CODE_SESSION_ID", selfEnv); sessionID != "" {
		out.Session = &Observation{
			Value:     sessionID,
			Source:    "cilock-process.environment:CLAUDE_CODE_SESSION_ID",
			Assurance: AssuranceEnvironmentObserved,
		}
	}

	c.collectArgvFields(r.Process, out.ArgvFields)

	if role := processTitleRole(r.Process); role != "" {
		out.ArgvFields["process_title_role"] = role
		if isBackgroundWorkerRole(role) {
			out.Warnings = append(out.Warnings,
				"claude-code: the matched process is a background worker ("+role+
					"), not the interactive session process. On macOS the session process is typically not in cilock's ancestry at all.")
		}
	}
	return out
}

// resolveVersion tries every source that can carry an installed version, in
// descending order of directness.
//
// Every version below is graded AssuranceInferred, because every one is
// parsed out of a directory-layout convention — a versioned install path, a
// symlink target, a dotted process name — rather than read from the image
// itself. That is exactly what AssuranceInferred is defined to cover, and
// grading it process-observed would let a policy requiring process-observed
// data accept a layout guess. The Source string still says WHERE the parsed
// path came from, which is how the grades stay comparable.
//
// The "latest_version" field some agents keep in an update-check file is
// deliberately not consulted anywhere: it records what is available upstream,
// not what ran.
func (c ClaudeCodeProvider) resolveVersion(r InspectRequest, selfEnv envScope) *Observation {
	if v := claudeVersionFromPath(r.Process.Executable); v != "" {
		return &Observation{Value: v, Source: "process.executable", Assurance: AssuranceInferred}
	}
	// The snapshot's resolution, and the only one reachable from here: the
	// path below came off the same open handle the digest came from, so this
	// version and that digest cannot describe different binaries. An empty
	// resolution means the snapshot could not bind a path to the handle, and
	// parsing nothing out of it is the correct answer.
	if resolved := r.Executable.resolved(); resolved != "" && resolved != r.Process.Executable {
		if v := claudeVersionFromPath(resolved); v != "" {
			return &Observation{Value: v, Source: "process.executable(resolved symlink)", Assurance: AssuranceInferred}
		}
	}

	// The vendor chain, not the ancestry walk. It contains only processes this
	// same provider matched, so reading it cannot promote a different vendor
	// over the one that already won detection.
	for _, ancestor := range r.VendorChain[1:] {
		if v := claudeVersionFromPath(ancestor.Executable); v != "" {
			return &Observation{Value: v, Source: "vendor-chain.executable", Assurance: AssuranceInferred}
		}
		// Deliberately the FULL argv, not optionArgv: this harvests versioned
		// install paths, not flags, and the measured pty-host layout carries
		// its spawn target's path after a "--" (see optionArgv).
		for _, arg := range ancestor.Argv {
			if v := claudeVersionFromPath(arg); v != "" {
				return &Observation{Value: v, Source: "vendor-chain.argv", Assurance: AssuranceInferred}
			}
		}
	}

	// The env var supplies the PATH; the version is still parsed from the
	// path's layout, so the grade stays inferred — environment-observed would
	// overstate it as a value the environment carried directly.
	if execPath, _ := resolveEnvValue("CLAUDE_CODE_EXECPATH", selfEnv); execPath != "" {
		if v := claudeVersionFromPath(execPath); v != "" {
			return &Observation{Value: v, Source: "cilock-process.environment:CLAUDE_CODE_EXECPATH", Assurance: AssuranceInferred}
		}
	}

	// The kernel names a process after the image it exec'd. When Claude Code is
	// launched through a launcher whose own path carries no version, that name
	// is the version string. Nothing here proves the number is a Claude Code
	// version rather than a coincidentally dotted binary name.
	if comm := commBase(r.Process); looksLikeVersion(comm) {
		return &Observation{Value: comm, Source: "process.comm", Assurance: AssuranceInferred}
	}
	return nil
}

// resolveModel walks the model sources in precedence order and returns the
// configuration files it consulted, the winning observation, and any warnings.
//
// Config files are recorded whether or not they supplied the answer, because
// "the project pinned a model and the agent ignored it" is exactly the kind of
// thing a reader wants to see. Files that did not decide the outcome are marked
// with the observed role rather than effective.
//
// Settings files sit BELOW the environment in Claude Code's precedence order,
// so a file's model is not consulted at all while a higher-priority
// environment could not be READ: an ANTHROPIC_MODEL override may be sitting in
// it, and answering from the file would answer a question the evidence does not
// reach.
//
// Every file found is recorded. None is marked as the one the agent loaded,
// because that is not observable from a process tree — see ResolutionRole.
//
// The repository-scope candidates are anchored to the DISCOVERED project root
// (see projectRootFromWorkingDir), not to the working directory: cilock is
// routinely invoked from repo/subdir, where the directory itself holds no
// .claude files while the repository root's higher-precedence ones do, and
// treating the subdirectory as the root signed the user file's model as the
// configured default over a project file that outranks it. When the root
// cannot be determined at all the same fail-closed rule applies as for an
// unreadable file: which project files exist is unknown, so no settings file
// may answer.
func (c ClaudeCodeProvider) resolveModel(r InspectRequest, agentEnv, selfEnv envScope) ([]ConfigSource, *Observation, []string) {
	model, modelBlocked, warnings := claudeModelFromArgvOrEnv(r, agentEnv, selfEnv)

	root, rootKnown := projectRootFromWorkingDir(r.RepoRoot)
	if !rootKnown && model == nil && !modelBlocked {
		modelBlocked = true
		warnings = append(warnings,
			"claude-code: the project root could not be determined from the working directory, so which repository-scope settings files apply is unknown; settings files are not consulted for the model.")
	}

	sources, model, settingsWarnings := claudeModelFromSettings(claudeSettingsPaths(root), model, modelBlocked)
	return sources, model, append(warnings, settingsWarnings...)
}

// claudeModelFromArgvOrEnv resolves the model from the command line, then from
// the AGENT's own environment. The returned bool reports whether
// lower-precedence settings files are BLOCKED from answering.
func claudeModelFromArgvOrEnv(r InspectRequest, agentEnv, selfEnv envScope) (*Observation, bool, []string) {
	if v, ok := argvValue(r.Process.Argv, "--model"); ok {
		return &Observation{Value: v, Source: "process.argv:--model", Assurance: AssuranceProcessObserved}, false, nil
	}
	// The AGENT's own environment is the only one that can establish the
	// model. cilock's inherited copy is set by whatever sits between the
	// agent and this process — a shell profile export is the ordinary
	// case — and the agent demonstrably did not carry it, so promoting it
	// would sign a model the agent never resolved, under a Source string
	// naming the agent's environment. The self-scope value still appears
	// in the environment observations, labeled with the scope it actually
	// came from.
	var warnings []string
	v, blocked := resolveEnvValue("ANTHROPIC_MODEL", agentEnv)
	carried := agentEnv.carries("ANTHROPIC_MODEL")
	switch {
	case v != "":
		return &Observation{Value: v, Source: "process.environment:ANTHROPIC_MODEL", Assurance: AssuranceEnvironmentObserved},
			false, nil
	case blocked:
		warnings = append(warnings,
			"claude-code: the agent process environment could not be read, or ANTHROPIC_MODEL was withheld by the run-wide redaction policy; an override is neither ruled out nor reportable.")
	case carried:
		warnings = append(warnings,
			"claude-code: the agent process explicitly carried ANTHROPIC_MODEL with an empty value; lower-precedence settings are not promoted to the model.")
	default:
		if selfModel, _ := resolveEnvValue("ANTHROPIC_MODEL", selfEnv); selfModel != "" {
			warnings = append(warnings,
				"claude-code: ANTHROPIC_MODEL is set in cilock's own inherited environment but not in the agent process's, so it is recorded as a cilock-process environment observation only and is not promoted to the model.")
		}
	}
	return nil, blocked || (carried && v == ""), warnings
}

// claudeModelFromSettings walks the settings candidates in precedence order,
// recording every file found and answering only when nothing above blocked it.
func claudeModelFromSettings(candidates []settingsCandidate, model *Observation, modelBlocked bool) ([]ConfigSource, *Observation, []string) {
	var warnings []string
	sources := make([]ConfigSource, 0, len(candidates))
	for _, candidate := range candidates {
		// One snapshot per file: the digest recorded below is the digest of
		// the exact bytes the model value was parsed from, so a settings file
		// replaced mid-inspection cannot pair its value with another
		// version's digest.
		snap, denied := loadConfigSnapshot(candidate.path)
		if snap == nil {
			if denied {
				// The file EXISTS and could not be read. Same fail-closed
				// treatment as one that exists and does not parse: it may set
				// a model, so nothing below it may answer. Silently skipping
				// it was the defect — an unreadable higher-precedence file
				// let a lower file's model be signed as the configured
				// default.
				sources = append(sources, *describeUnreadableConfig(candidate.path, candidate.scope))
				if model == nil && !modelBlocked {
					modelBlocked = true
					warnings = append(warnings,
						"claude-code: "+candidate.label+" ("+candidate.scope+" scope) exists but could not be read, so whether it sets a model is unknown; lower-precedence settings files are not consulted for the model.")
				}
			}
			continue
		}
		value, _ := snap.jsonString("model")
		sources = append(sources, *snap.describe(candidate.scope, "model"))
		if model != nil || modelBlocked {
			continue
		}
		switch {
		case value != "":
			model = &Observation{Value: value, Source: candidate.label, Assurance: AssuranceConfigObserved}
		case !snap.jsonObjectParseable():
			// The file EXISTS but what it sets is unknown — oversize beyond
			// the snapshot bound, or unparseable content. Precedence runs
			// downward, so a higher file whose model value is unknown makes
			// every lower file unanswerable: resolving from one would claim
			// a default this file may override. Same fail-closed direction
			// as an unreadable environment. The file itself is still
			// recorded above, and the block is explained.
			modelBlocked = true
			warnings = append(warnings,
				"claude-code: "+candidate.label+" ("+candidate.scope+" scope) exists but could not be parsed within the snapshot bound, so whether it sets a model is unknown; lower-precedence settings files are not consulted for the model.")
		}
	}
	return sources, model, warnings
}

// collectArgvFields copies an explicit allowlist of flags out of argv.
//
// Raw argv is never serialized. Claude Code's own daemon argv carries a
// --spawned-by JSON blob naming the working directory of whatever session
// spawned it, which on a developer machine is routinely an unrelated project.
func (ClaudeCodeProvider) collectArgvFields(p ProcessInfo, into map[string]string) {
	if v, ok := argvValue(p.Argv, "--model"); ok {
		into["model"] = v
	}
	if v, ok := argvValue(p.Argv, "--permission-mode"); ok {
		into["permission_mode"] = v
	}
	for _, arg := range optionArgv(p.Argv) {
		if arg == "--dangerously-skip-permissions" {
			into["dangerously_skip_permissions"] = flagTrue
		}
	}
}

type settingsCandidate struct {
	path  string
	scope string

	// label is the scope-relative name for the file — ".claude/settings.json"
	// — fixed by the code that knows which well-known location it probed. It
	// is the name warnings and observation Source strings use: those strings
	// enter the signed predicate, and an absolute path there would leak the
	// home or repository directory. The absolute path stays confined to
	// ConfigSource.Path, where — paired with the digest — it is the identity
	// of the snapshotted file.
	label string
}

// claudeSettingsPaths returns Claude Code's settings files in decreasing
// precedence: managed policy first, then repo-local, then repo, then user.
func claudeSettingsPaths(repoRoot string) []settingsCandidate {
	out := make([]settingsCandidate, 0, 5)
	for _, managed := range managedClaudeSettingsPaths() {
		// The managed path is a fixed system location that carries no user or
		// repository segment, so the path is its own scope-relative label.
		out = append(out, settingsCandidate{path: managed, scope: "managed", label: managed})
	}
	if repoRoot != "" {
		out = append(out,
			settingsCandidate{path: filepath.Join(repoRoot, ".claude", "settings.local.json"), scope: "project-local", label: ".claude/settings.local.json"},
			settingsCandidate{path: filepath.Join(repoRoot, ".claude", "settings.json"), scope: "project", label: ".claude/settings.json"},
		)
	}
	if home := userHomeDir(); home != "" {
		out = append(out, settingsCandidate{path: filepath.Join(home, ".claude", "settings.json"), scope: "user", label: ".claude/settings.json"})
	}
	return out
}

func managedClaudeSettingsPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/Library/Application Support/ClaudeCode/managed-settings.json"}
	case "windows":
		return []string{filepath.Join("C:\\", "ProgramData", "ClaudeCode", "managed-settings.json")}
	default:
		return []string{"/etc/claude-code/managed-settings.json"}
	}
}

// isClaudeVersionsLayout reports whether a path sits in Claude Code's versioned
// install directory, i.e. .../claude/versions/<something>.
//
// Both directory names are compared for exact equality against a path element.
// A path merely containing the word "claude" does not qualify.
func isClaudeVersionsLayout(path string) bool {
	if path == "" {
		return false
	}
	elements := pathElements(path)
	if len(elements) < 3 {
		return false
	}
	return elements[len(elements)-2] == "versions" && elements[len(elements)-3] == productClaude
}

// claudeVersionFromPath extracts the version from a versioned install path.
// Returns "" when the path is not in that layout or the leaf is not a version.
func claudeVersionFromPath(path string) string {
	if !isClaudeVersionsLayout(path) {
		return ""
	}
	elements := pathElements(path)
	leaf := elements[len(elements)-1]
	if !looksLikeVersion(leaf) {
		return ""
	}
	return leaf
}

// processTitleRole returns the subcommand an agent published in its rewritten
// process title, e.g. "bg-spare" from "claude bg-spare".
//
// This is worth recording precisely because it disambiguates what was matched:
// a background worker is not the interactive session.
func processTitleRole(p ProcessInfo) string {
	if len(p.Argv) == 0 {
		return ""
	}
	fields := strings.Fields(p.Argv[0])
	if len(fields) < 2 {
		return ""
	}
	return strings.ToLower(fields[1])
}

func isBackgroundWorkerRole(role string) bool {
	return strings.HasPrefix(role, "bg-") || role == "daemon"
}
