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
)

// DefaultProviders returns the supported agents in the order they are consulted
// for each candidate process.
//
// Order here is not precedence between agents — the ancestry walk already
// decided that by depth. It only breaks a tie if two providers claim the same
// process, which would be a fingerprint bug.
func DefaultProviders() []Provider {
	return []Provider{
		CodexProvider{},
		ClaudeCodeProvider{},
		CursorProvider{},
		GeminiCLIProvider{},
		CopilotCLIProvider{},
		AiderProvider{},
		GooseProvider{},
		OpenCodeProvider{},
	}
}

// matchByName tests one product's executable names against the three process
// facts that can carry a name, and returns a fingerprint naming THE ONE THAT
// FIRED.
//
// This exists so that naming the basis is not a thing a provider can forget to
// do. Round 5 found Cursor, Gemini and Copilot each returning an
// executable-basename fingerprint when only the kernel comm or argv[0] had
// matched — so a binary that merely set argv[0] to "gemini" received signed
// evidence reading "gemini-cli:executable-basename", a property nobody
// observed. Each of those providers had hand-rolled the same three-way test and
// hand-written one fingerprint for all three outcomes. There is now one
// implementation, the fingerprint suffix is DERIVED from the branch that
// matched, and no provider gets to spell a basis name itself
// (TestBasisNamesAreNeverSpelledOutByHand).
//
// The bases are tested basis-major, not name-major: every name against the
// image path first, then every name against the kernel comm, then every name
// against argv[0]. That ordering is deliberate. When two bases both match, the
// STRONGEST is what gets published; the name-major loop this replaces could
// report a kernel-comm match for one alias while the image basename matched
// another, which understates the evidence. Understating is the safe direction —
// overstating is the defect — but there is no reason to do either.
func matchByName(p ProcessInfo, fpPrefix string, names ...string) MatchResult {
	for _, observed := range []struct {
		value string
		basis string
	}{
		{executableBase(p), basisExecutableBase},
		{commBase(p), basisKernelComm},
		{argvProgram(p), basisArgv0Title},
	} {
		if observed.value == "" {
			continue
		}
		for _, name := range names {
			if observed.value == name {
				return matched(fpPrefix + ":" + observed.basis)
			}
		}
	}
	return MatchResult{}
}

// basenameProvider covers agents whose install layout has not been measured on
// a real machine.
//
// These deliberately do only what can be justified: exact basename equality on
// the process image, the kernel comm, or the argv[0] title. They resolve no
// model and no version. A provider that guessed at config precedence it had not
// confirmed would produce attestations that look authoritative and are wrong,
// which is worse than an honest gap.
type basenameProvider struct {
	vendor   string
	product  string
	names    []string
	fpPrefix string
}

func (b basenameProvider) Vendor() string         { return b.vendor }
func (b basenameProvider) Product() string        { return b.product }
func (b basenameProvider) EnvAllowlist() []EnvKey { return nil }

func (b basenameProvider) Match(p ProcessInfo) MatchResult {
	return matchByName(p, b.fpPrefix, b.names...)
}

func (b basenameProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}
	if role := processTitleRole(r.Process); role != "" {
		out.ArgvFields["process_title_role"] = role
	}
	out.Warnings = append(out.Warnings,
		b.product+": identified by process fingerprint only. This attestor has not confirmed this product's install layout, version source, or config precedence, so no model, version or configuration is claimed.")
	return out
}

// CursorProvider identifies Cursor's CLI agent.
//
// Cursor's strongest model and session state lives behind editor hooks. Mode 1
// does not require hooks, so nothing about the active model is claimed here —
// the UI state that would answer it is mutable and unobservable from the
// process tree.
type CursorProvider struct{}

func (CursorProvider) Vendor() string         { return "cursor" }
func (CursorProvider) Product() string        { return "cursor" }
func (CursorProvider) EnvAllowlist() []EnvKey { return nil }

// Match tries the agent binary's own name before the editor's. Both groups run
// through matchByName, so each reports the basis that actually matched: the
// shape this replaces collapsed all three bases onto one fingerprint per group
// and published "cursor:agent-executable" for a process that had only set its
// own argv[0].
func (CursorProvider) Match(p ProcessInfo) MatchResult {
	if m := matchByName(p, "cursor-agent", "cursor-agent", "cursor-agent.exe"); m.Matched {
		return m
	}
	return matchByName(p, "cursor", "cursor", "cursor.exe")
}

func (CursorProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}
	candidates, rootKnown := userScopedSettings(r.RepoRoot, ".cursor", "cli.json", "")
	if !rootKnown {
		out.Warnings = append(out.Warnings,
			"cursor: the project root could not be determined from the working directory, so no project-scope cli.json was looked for.")
	}
	for _, candidate := range candidates {
		snap, denied := loadConfigSnapshot(candidate.path)
		switch {
		case snap != nil:
			out.Configuration = append(out.Configuration, *snap.describe(candidate.scope))
		case denied:
			// Nothing is resolved from cursor config, so there is no
			// precedence to fail closed on — but a file that exists and could
			// not be read must not vanish from the record.
			out.Configuration = append(out.Configuration, *describeUnreadableConfig(candidate.path, candidate.scope))
			out.Warnings = append(out.Warnings,
				"cursor: a "+candidate.scope+"-scope cli.json exists but could not be read.")
		}
	}
	out.Warnings = append(out.Warnings,
		"cursor: no model claimed. Cursor's active model lives in mutable editor state that is not observable from the process tree without vendor hooks, which this mode does not use.")
	return out
}

// GeminiCLIProvider identifies Google's Gemini CLI.
type GeminiCLIProvider struct{}

// The npm install layout, measured on a real install (@google/gemini-cli
// 0.57.0): the bin entry is a symlink to bundle/gemini.js inside the package.
// Whole path elements are compared for exact equality, the rule isCodexNpmShim
// spells out.
const (
	geminiNpmNamespace = "@google"
	geminiNpmPackage   = "gemini-cli"
	geminiNpmBundleDir = "bundle"
	geminiNpmScript    = "gemini.js"

	// Same vocabulary as fpCodexNpmShim: the element naming Gemini came out of
	// the one argv slot node was told to run.
	fpGeminiNpmScript = basisNodeScriptArg + ":" + geminiNpmNamespace + "/" + geminiNpmPackage
	// The script slot carried the npm bin symlink; only its resolved target
	// names the package, and the basis says the resolution happened. NOT a
	// ViaResolution match — the detector revalidates those against the digested
	// executable image, and here the image is node, not the script.
	//
	// Like every node-script rule, this is match-time identity in the argv
	// trust class, not proof of executed bytes: the resolution cannot know
	// what node loaded, and a process retargeting its own symlink forges this
	// exactly as cheaply as fabricating the direct package path or setting
	// argv[0] — the self-misrepresentation the predicate's assurance block
	// already disclaims.
	fpGeminiResolvedScript = basisNodeScriptArg + ":resolved-symlink:" + geminiNpmNamespace + "/" + geminiNpmPackage
)

func (GeminiCLIProvider) Vendor() string  { return "google" }
func (GeminiCLIProvider) Product() string { return geminiNpmPackage }
func (GeminiCLIProvider) EnvAllowlist() []EnvKey {
	return []EnvKey{
		{Name: "GEMINI_MODEL", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent, EnvScopeSelf}},
	}
}

func (GeminiCLIProvider) Match(p ProcessInfo) MatchResult {
	if m := matchByName(p, geminiNpmPackage, "gemini", "gemini.exe", "gemini-cli"); m.Matched {
		return m
	}
	return matchGeminiNodeScript(p)
}

// matchGeminiNodeScript recognizes the npm install's node process, which the
// name matchers never fire on: the kernel records executable=node, comm=node,
// argv=["node", ".../bin/gemini", ...] — no slot ever says gemini.
//
// The direct rule matches the exact package tail in the script slot. The
// measured everyday case carries only the bin SYMLINK there — a basename argv
// cannot be trusted for — so it matches nothing until match-time resolution
// shows the script IS the package file. An argv nodeScriptArg cannot read
// unambiguously is a missed detection, never a false positive.
func matchGeminiNodeScript(p ProcessInfo) MatchResult {
	if base := executableBase(p); base != "node" && base != "node.exe" {
		return MatchResult{}
	}
	script := nodeScriptArg(p.Argv)
	if script == "" {
		return MatchResult{}
	}
	if hasGeminiPackageTail(pathElements(script)) {
		return matched(fpGeminiNpmScript)
	}
	if resolved := matchTimeResolve(script); resolved.differsFrom(script) && resolved.hasGeminiPackageTail() {
		return matched(fpGeminiResolvedScript)
	}
	return MatchResult{}
}

// hasGeminiPackageTail reports whether a path ends in the @google/gemini-cli
// package's bin target. Every element is compared for exact equality.
func hasGeminiPackageTail(elements []string) bool {
	const tailLen = 4
	if len(elements) < tailLen {
		return false
	}
	tail := elements[len(elements)-tailLen:]
	return tail[0] == geminiNpmNamespace && tail[1] == geminiNpmPackage &&
		tail[2] == geminiNpmBundleDir && tail[3] == geminiNpmScript
}

func (g GeminiCLIProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}
	agentEnvObs, agentEnv := collectEnv(r, EnvScopeAgent, g.EnvAllowlist())
	selfEnvObs, selfEnv := collectEnv(r, EnvScopeSelf, g.EnvAllowlist())
	out.Environment = mergeEnv(agentEnvObs, selfEnvObs)

	if v, ok := argvValue(r.Process.Argv, "--model", "-m"); ok {
		out.Model = &Observation{Value: v, Source: sourceArgvModelFlag, Assurance: AssuranceProcessObserved}
		out.ArgvFields["model"] = v
	}
	modelBlocked := false
	if out.Model == nil {
		var envWarnings []string
		out.Model, modelBlocked, envWarnings = geminiModelFromEnv(agentEnv, selfEnv)
		out.Warnings = append(out.Warnings, envWarnings...)
	}

	candidates, rootKnown := userScopedSettings(r.RepoRoot, ".gemini", "settings.json", ".gemini/settings.json")
	if !rootKnown && out.Model == nil && !modelBlocked {
		// Which project-scope settings file applies is unknown, and it would
		// outrank the user file — so the user file may not answer either.
		modelBlocked = true
		out.Warnings = append(out.Warnings,
			"gemini-cli: the project root could not be determined from the working directory, so whether a project-scope settings file sets a model is unknown; settings files are not consulted for the model.")
	}
	configs, model, settingsWarnings := geminiModelFromSettings(candidates, out.Model, modelBlocked)
	out.Configuration = append(out.Configuration, configs...)
	out.Model = model
	out.Warnings = append(out.Warnings, settingsWarnings...)

	if out.Model == nil {
		out.Warnings = append(out.Warnings, "gemini-cli: effective model not observable")
	}
	return out
}

// geminiModelFromEnv resolves the model from the AGENT's own environment.
//
// Agent scope only: a GEMINI_MODEL sitting solely in cilock's own inherited
// environment describes cilock's launch, not the agent's — see the same rule
// in ClaudeCodeProvider.resolveModel. The self-scope value still appears in
// the environment observations under its own scope label.
//
// The returned bool reports whether lower-precedence settings files are
// BLOCKED from answering: an unreadable or policy-withheld environment may
// hold an override, and an explicitly empty value is a decision, not an
// absence.
func geminiModelFromEnv(agentEnv, selfEnv envScope) (*Observation, bool, []string) {
	var warnings []string
	v, blocked := resolveEnvValue("GEMINI_MODEL", agentEnv)
	carried := agentEnv.carries("GEMINI_MODEL")
	switch {
	case v != "":
		return &Observation{Value: v, Source: "process.environment:GEMINI_MODEL", Assurance: AssuranceEnvironmentObserved},
			false, nil
	case blocked:
		warnings = append(warnings,
			"gemini-cli: the agent process environment could not be read, or GEMINI_MODEL was withheld by the run-wide redaction policy; a value there is neither ruled out nor reportable.")
	case carried:
		warnings = append(warnings,
			"gemini-cli: the agent process explicitly carried GEMINI_MODEL with an empty value; lower-precedence settings are not promoted to the model.")
	default:
		if selfModel, _ := resolveEnvValue("GEMINI_MODEL", selfEnv); selfModel != "" {
			warnings = append(warnings,
				"gemini-cli: GEMINI_MODEL is set in cilock's own inherited environment but not in the agent process's, so it is recorded as a cilock-process environment observation only and is not promoted to the model.")
		}
	}
	return nil, blocked || (carried && v == ""), warnings
}

// geminiModelFromSettings walks the settings candidates in precedence order.
//
// Settings files sit BELOW the environment in Gemini's own precedence order. A
// file's model is therefore not consulted at all while a higher-priority
// environment could not be READ: an override may be sitting in it, and
// answering from the file would be answering a question the evidence does not
// reach. The same fail-closed rule runs DOWN the file chain: a
// higher-precedence settings file that exists but could not be read or parsed
// may set a model, so no lower file may answer for it — the guard
// ClaudeCodeProvider.resolveModel already applies.
func geminiModelFromSettings(candidates []settingsCandidate, model *Observation, modelBlocked bool) ([]ConfigSource, *Observation, []string) {
	var configs []ConfigSource
	var warnings []string
	for _, candidate := range candidates {
		// One snapshot per file: value and digest come from the same bytes.
		snap, denied := loadConfigSnapshot(candidate.path)
		if snap == nil {
			if denied {
				configs = append(configs, *describeUnreadableConfig(candidate.path, candidate.scope))
				if model == nil && !modelBlocked {
					modelBlocked = true
					warnings = append(warnings,
						"gemini-cli: the "+candidate.scope+"-scope "+candidate.label+" exists but could not be read, so whether it sets a model is unknown; lower-precedence settings files are not consulted for the model.")
				}
			}
			continue
		}
		// Settings v2 nests the model at `model.name` (per the CLI's own
		// reference); the flat `model` string is the v1 shape it migrates
		// from. The reads are disjoint — an object fails the string read and
		// vice versa — so this is a precedence, not a merge.
		value, found := snap.jsonString("model.name")
		if !found {
			value, found = snap.jsonString("model")
		}
		configs = append(configs, *snap.describe(candidate.scope, "model.name", "model"))
		if model != nil || modelBlocked {
			continue
		}
		switch {
		case found:
			model = &Observation{Value: value, Source: candidate.label, Assurance: AssuranceConfigObserved}
			warnings = append(warnings, configuredDefaultWarning("gemini-cli", candidate.label))
		case !snap.jsonObjectParseable():
			// The file EXISTS but what it sets is unknown — oversize beyond
			// the snapshot bound, or unparseable content. Answering from a
			// lower-precedence file would claim a default this file may
			// override.
			modelBlocked = true
			warnings = append(warnings,
				"gemini-cli: the "+candidate.scope+"-scope "+candidate.label+" exists but could not be parsed within the snapshot bound, so whether it sets a model is unknown; lower-precedence settings files are not consulted for the model.")
		}
	}
	return configs, model, warnings
}

// CopilotCLIProvider identifies GitHub's Copilot CLI.
type CopilotCLIProvider struct{}

func (CopilotCLIProvider) Vendor() string  { return "github" }
func (CopilotCLIProvider) Product() string { return "copilot-cli" }
func (CopilotCLIProvider) EnvAllowlist() []EnvKey {
	return []EnvKey{
		{Name: "COPILOT_MODEL", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent, EnvScopeSelf}},
	}
}

func (CopilotCLIProvider) Match(p ProcessInfo) MatchResult {
	return matchByName(p, "copilot-cli", "copilot", "copilot.exe")
}

func (c CopilotCLIProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}
	agentEnvObs, agentEnv := collectEnv(r, EnvScopeAgent, c.EnvAllowlist())
	selfEnvObs, selfEnv := collectEnv(r, EnvScopeSelf, c.EnvAllowlist())
	out.Environment = mergeEnv(agentEnvObs, selfEnvObs)

	// Agent scope only for the model, for the reason spelled out in
	// ClaudeCodeProvider.resolveModel: cilock's inherited copy describes
	// cilock's launch, not the agent's.
	if v, ok := argvValue(r.Process.Argv, "--model"); ok {
		out.Model = &Observation{Value: v, Source: sourceArgvModelFlag, Assurance: AssuranceProcessObserved}
		out.ArgvFields["model"] = v
	} else {
		v, blocked := resolveEnvValue("COPILOT_MODEL", agentEnv)
		switch {
		case v != "":
			out.Model = &Observation{Value: v, Source: "process.environment:COPILOT_MODEL", Assurance: AssuranceEnvironmentObserved}
		case blocked:
			out.Warnings = append(out.Warnings,
				"copilot-cli: the agent process environment could not be read, or COPILOT_MODEL was withheld by the run-wide redaction policy; a value there is neither ruled out nor reportable.")
		case agentEnv.carries("COPILOT_MODEL"):
			out.Warnings = append(out.Warnings,
				"copilot-cli: the agent process explicitly carried COPILOT_MODEL with an empty value; cilock's own inherited value is not promoted to the model.")
		default:
			if selfModel, _ := resolveEnvValue("COPILOT_MODEL", selfEnv); selfModel != "" {
				out.Warnings = append(out.Warnings,
					"copilot-cli: COPILOT_MODEL is set in cilock's own inherited environment but not in the agent process's, so it is recorded as a cilock-process environment observation only and is not promoted to the model.")
			}
		}
	}
	if out.Model == nil {
		out.Warnings = append(out.Warnings, "copilot-cli: effective model not observable")
	}
	return out
}

// Product identifiers for the providers matched by executable basename. Each
// value is at once the product name, the detection fingerprint prefix, and the
// binary's basename, because these tools ship a single self-named executable —
// tying them to one constant is what keeps a rename from silently splitting
// detection from the recorded product.
//
// Vendor() deliberately does NOT use these: vendor and product are different
// axes and only coincide by accident here (goose's vendor is "block").
const (
	productAider    = "aider"
	productGoose    = "goose"
	productOpenCode = "opencode"
)

// AiderProvider identifies aider.
type AiderProvider struct{}

func (AiderProvider) Vendor() string         { return "aider" }
func (AiderProvider) Product() string        { return productAider }
func (AiderProvider) EnvAllowlist() []EnvKey { return nil }

func (AiderProvider) Match(p ProcessInfo) MatchResult {
	return basenameProvider{fpPrefix: productAider, names: []string{productAider, productAider + ".exe"}}.Match(p)
}

func (AiderProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}
	if v, ok := argvValue(r.Process.Argv, "--model"); ok {
		out.Model = &Observation{Value: v, Source: sourceArgvModelFlag, Assurance: AssuranceProcessObserved}
		out.ArgvFields["model"] = v
	} else {
		out.Warnings = append(out.Warnings, "aider: effective model not observable")
	}
	return out
}

// GooseProvider identifies Block's goose.
type GooseProvider struct{}

func (GooseProvider) Vendor() string  { return "block" }
func (GooseProvider) Product() string { return productGoose }
func (GooseProvider) EnvAllowlist() []EnvKey {
	return []EnvKey{
		{Name: "GOOSE_MODEL", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent}},
		{Name: "GOOSE_PROVIDER", RecordValue: true, Scopes: []EnvScope{EnvScopeAgent}},
	}
}

func (GooseProvider) Match(p ProcessInfo) MatchResult {
	return basenameProvider{fpPrefix: productGoose, names: []string{productGoose, productGoose + ".exe"}}.Match(p)
}

func (g GooseProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}
	envObs, env := collectEnv(r, EnvScopeAgent, g.EnvAllowlist())
	out.Environment = envObs
	model, blocked := resolveEnvValue("GOOSE_MODEL", env)
	switch {
	case model != "":
		out.Model = &Observation{Value: model, Source: "process.environment:GOOSE_MODEL", Assurance: AssuranceEnvironmentObserved}
	case blocked:
		out.Warnings = append(out.Warnings,
			"goose: the agent process environment could not be read, or GOOSE_MODEL was withheld by the run-wide redaction policy; the effective model is not observable")
	default:
		out.Warnings = append(out.Warnings, "goose: effective model not observable")
	}
	return out
}

// OpenCodeProvider identifies opencode.
type OpenCodeProvider struct{}

func (OpenCodeProvider) Vendor() string         { return "opencode" }
func (OpenCodeProvider) Product() string        { return productOpenCode }
func (OpenCodeProvider) EnvAllowlist() []EnvKey { return nil }

func (OpenCodeProvider) Match(p ProcessInfo) MatchResult {
	return basenameProvider{fpPrefix: productOpenCode, names: []string{productOpenCode, productOpenCode + ".exe"}}.Match(p)
}

func (OpenCodeProvider) Inspect(_ context.Context, r InspectRequest) Inspection {
	out := Inspection{ArgvFields: map[string]string{}}
	if v, ok := argvValue(r.Process.Argv, "--model", "-m"); ok {
		out.Model = &Observation{Value: v, Source: sourceArgvModelFlag, Assurance: AssuranceProcessObserved}
		out.ArgvFields["model"] = v
	} else {
		out.Warnings = append(out.Warnings, "opencode: effective model not observable")
	}
	return out
}

// userScopedSettings builds a product's project-then-user settings candidates.
//
// The project candidate is anchored to the DISCOVERED project root, not to the
// working directory it was called with — see projectRootFromWorkingDir. The
// returned rootKnown is that discovery's completeness bit: when it is false no
// project candidate is emitted (which directory would even hold one is
// unknown), and a caller that RESOLVES values from these candidates must
// refuse to answer from the lower user tier, because an unfindable project
// file may override it.
//
// The user candidate is OMITTED when the platform cannot report a home
// directory, and that omission is the whole reason this helper exists.
// filepath.Join("", ".gemini", "settings.json") is ".gemini/settings.json" — a
// RELATIVE path, resolved against the process working directory — so an empty
// home turned a user-configuration read into a read of whatever repository
// cilock happened to be running in, and signed it at user scope. The emptiness
// check meant to catch that ran on the JOINED path, which is never empty.
//
// Absent evidence is the correct outcome: there is no user configuration to
// read if there is no home directory to read it from.
func userScopedSettings(workingDir, dir, file, label string) (candidates []settingsCandidate, rootKnown bool) {
	root, known := projectRootFromWorkingDir(workingDir)
	out := make([]settingsCandidate, 0, 2)
	if known && root != "" {
		out = append(out, settingsCandidate{
			path: filepath.Join(root, dir, file), scope: configScopeProject, label: label,
		})
	}
	if home := userHomeDir(); home != "" {
		out = append(out, settingsCandidate{
			path: filepath.Join(home, dir, file), scope: configScopeUser, label: label,
		})
	}
	return out, known
}

// configuredDefaultWarning states what a model read from a settings file is,
// and what it is not.
//
// The file says which model that product would default to. It is not a record
// of what served the session: an agent can be launched with an override and the
// model can be changed mid-run, neither of which touches the file. This is what
// the withdrawn "effective" role used to imply and never established.
func configuredDefaultWarning(product, label string) string {
	return product + ": the model above is the configured default read from " + label +
		", not a confirmed record of the model that served this session. This attestor cannot observe which configuration a running agent loaded."
}
