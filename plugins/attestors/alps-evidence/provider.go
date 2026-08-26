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

import "context"

// MatchResult is a provider's answer to "is this exact process your agent?".
//
// Match must not consult config files, environment variables, or anything
// outside the process facts it is handed. Identity that can be conjured by
// exporting a variable is not identity.
type MatchResult struct {
	Matched bool

	// Fingerprint names the specific rule that fired, e.g.
	// "executable-basename" or "argv0-process-title". It is recorded in the
	// predicate so a reader can weigh how the identification was reached: an
	// install-layout match is worth more than a self-declared process title.
	Fingerprint string

	// ViaResolution records that the fingerprint was established by resolving
	// a symlink at match time, rather than from the kernel-recorded fields
	// themselves. Such a match rests on a read the executable snapshot does
	// not share, so the detector re-confirms it against the snapshot's own
	// resolution — the one bound to the digested handle — before publishing,
	// and degrades to incomplete when no confirmation is possible.
	ViaResolution bool
}

// Matched is a convenience constructor.
func matched(fingerprint string) MatchResult {
	return MatchResult{Matched: true, Fingerprint: fingerprint}
}

// matchedViaResolution is matched for a fingerprint that a match-time symlink
// resolution established; see MatchResult.ViaResolution.
func matchedViaResolution(fingerprint string) MatchResult {
	return MatchResult{Matched: true, Fingerprint: fingerprint, ViaResolution: true}
}

// The three process facts that can carry a product's name, and the names under
// which a match on each is published.
//
// They live here, once, because two different parts of the predicate answer the
// same question with them — a provider's match fingerprint and an ancestry
// entry's program name — and both must describe the basis in the same
// vocabulary. They are NOT interchangeable evidence:
//
//   - basisExecutableBase is the kernel's record of the image that was exec'd.
//     Forging it costs an attacker a binary on disk carrying that name.
//   - basisKernelComm is the kernel's own short name for the process. It
//     follows the image the process loaded, rather than a string the process
//     chose.
//   - basisArgv0Title is written BY THE PROCESS BEING DESCRIBED. Any binary can
//     set argv[0] to "gemini" for free.
//
// Publishing the strongest-sounding of the three when a weaker one is what
// actually matched is the defect these names exist to prevent: a policy asking
// for executable evidence would be handed a self-declared title instead.
//   - basisNodeScriptArg is the ONE argv slot an interpreter was told to run.
//     It is not "somewhere in argv": a path named anywhere else in an
//     interpreter's arguments is data that program was handed, not the program
//     it is running, and attributing the process to it claims a package that is
//     merely mentioned.
const (
	basisExecutableBase = "executable-basename"
	basisKernelComm     = "kernel-comm"
	basisArgv0Title     = "argv0-process-title"
	basisNodeScriptArg  = "node-script-arg"
)

// sourceArgvModelFlag is the Observation.Source recorded when a model was read
// from the agent's own `--model` argv flag. Unlike the other Source labels —
// which name a provider-specific env var or config path and appear once each —
// this one is shared, because every CLI agent that accepts `--model` reports
// its model from the same place and a policy should be able to match them
// uniformly.
const sourceArgvModelFlag = "process.argv:--model"

// Config-layer scope names recorded in Inspection.Configuration[].Scope. This
// is ONE vocabulary shared by every provider, so a policy can select "whatever
// the user-scope config said" without knowing which agent produced the
// evidence. Keep new scopes here rather than spelling them at the call site.
const (
	configScopeManaged      = "managed"
	configScopeProject      = "project"
	configScopeProjectLocal = "project-local"
	configScopeUser         = "user"
	configScopeProfile      = "profile"
)

// EnvScope names where an environment value was read from.
type EnvScope string

const (
	// EnvScopeAgent is the identified agent process's own environment.
	EnvScopeAgent EnvScope = "agent-process"

	// EnvScopeSelf is cilock's own inherited environment — what the agent
	// actually handed to this process. For Claude Code this is the only place
	// the session identifier appears; the matched daemon process does not carry
	// it.
	EnvScopeSelf EnvScope = "cilock-process"
)

// InspectRequest is everything a provider gets after it has won detection.
type InspectRequest struct {
	// RepoRoot is the attestation working directory, used to locate
	// project-scoped configuration.
	RepoRoot string

	// Process is the exact process that matched. Identity is already settled;
	// nothing a provider does here can change which agent is attested.
	Process ProcessInfo

	// Executable is the ONE snapshot of this process's image, taken when the
	// match won and before inspection ran: resolved path, size, digest and
	// binding kind together, all from a single open handle.
	//
	// Providers take every executable-describing value from HERE. There is
	// deliberately no raw resolved-path string on this request and no
	// package-level path helper a provider can reach for — the only other
	// symlink resolution in the package returns a fingerprintPath, which no
	// parser accepts. A provider therefore cannot hold a path from one moment
	// and a digest from another, which is the defect rounds 1, 3 and 4 kept
	// re-finding in new places. r.Executable.resolved() is empty when the
	// resolution could not be bound to the digested handle; parsing nothing
	// out of it is then the correct outcome.
	Executable executableSnapshot

	// VendorChain is Process followed by the contiguous run of ancestors that
	// the SAME provider also matches, nearest first, bounded.
	//
	// This exists because "stop at the first match" and "read the version" can
	// point at different processes. On macOS, Claude Code's nearest ancestor is
	// a background spare worker whose parent is a pty host from the same
	// install; the caller's originally measured layout only exposed the version
	// in the pty host's argv. Letting a provider read its own vendor's
	// contiguous processes recovers that without weakening first-agent-wins:
	// the walk stops at the first process this provider does not match, so a
	// different vendor further out can never be reached.
	//
	// VendorChain[0] == Process always.
	VendorChain []ProcessInfo

	// Source reads additional process state, e.g. allowlisted environment.
	Source ProcessSource

	// Self is cilock's own process as the walk captured it, for reading the
	// inherited environment. A full ProcessInfo rather than a pid, because an
	// environment read must be bound to the captured instance — see
	// ProcessSource.ReadEnvironment.
	Self ProcessInfo

	// EnvValueKeep is the run-wide environment redaction policy — the
	// operator's own filter/obfuscation configuration
	// (attestation.EnvironmentCapturer), which the commandrun attestor already
	// honors for its traced processes. collectEnv consults it for every value
	// the provider allowlist and the credential backstop would otherwise
	// retain; false degrades the observation to presence-only. Nil imposes
	// nothing.
	EnvValueKeep func(key, value string) bool
}

// Inspection is what a provider learned. Every field is optional; a provider
// that can only confirm identity returns an empty Inspection and that is a
// correct, honest result.
type Inspection struct {
	Version *Observation
	Model   *Observation
	Session *Observation

	// Configuration lists config files found on disk, each marked as having
	// contributed to resolution or merely having been observed.
	Configuration []ConfigSource

	// Settings are posture values resolved within the provider's observable
	// sources, such as approval policy or sandbox mode. Provider warnings name
	// any configuration layers that remain outside that observation; these are
	// never authenticated or enforcement-grade runtime claims.
	Settings []SettingObservation

	// Environment is the allowlisted environment evidence.
	Environment []EnvObservation

	// ArgvFields is the provider's allowlisted view of the agent's argv. Only
	// what a provider puts here reaches the predicate.
	ArgvFields map[string]string

	// Warnings record what could not be established. They are the mechanism by
	// which this attestor stays honest about the limits of Mode 1.
	Warnings []string
}

// Provider identifies and inspects one coding agent product.
//
// Detection (Match) and inspection (Inspect) are deliberately separate. Match
// answers a yes/no question from process facts alone and is what the ancestry
// walk calls on every candidate. Inspect is allowed to know product-specific
// config precedence, install layouts, and environment conventions, and runs
// exactly once, for the winner.
type Provider interface {
	Vendor() string
	Product() string

	// EnvAllowlist returns the environment keys this provider may read.
	// Anything not listed is never requested from the ProcessSource and never
	// retained by it. The kernel interfaces underneath hand over the whole
	// environment block regardless — there is no per-key syscall — so this
	// bounds what is KEPT and what can be serialized, not what the kernel
	// copies out. Stating it the stronger way would be the overclaim this
	// predicate exists to avoid.
	EnvAllowlist() []EnvKey

	Match(ProcessInfo) MatchResult
	Inspect(context.Context, InspectRequest) Inspection
}

// EnvKey declares one environment variable a provider is allowed to read and
// how much of it may be recorded.
type EnvKey struct {
	Name string

	// RecordValue is false for variables whose presence is the evidence and
	// whose content is either useless or sensitive.
	RecordValue bool

	// Scopes limits which processes this key is read from.
	Scopes []EnvScope
}
