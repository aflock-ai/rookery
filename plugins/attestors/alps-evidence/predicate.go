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

import "unicode/utf8"

// maxPredicateString caps every string this attestor serializes whose bytes an
// agent can influence — observation values, posture settings, environment
// values, argv fields, config paths, and warnings that splice argv or profile
// names in.
//
// The cap exists because those bytes flow from the process being described
// into a SIGNED, STORED, TRANSMITTED predicate with no length control in
// between: a --model value is copied out of argv verbatim, and argv is the
// agent's to fill. 4KiB is two orders of magnitude above any legitimate value
// (model names, semvers, file paths) while keeping the worst case per field
// bounded. Truncation is marked in the value itself and named in a warning,
// so a capped value can never pass as a complete one.
const maxPredicateString = 4 << 10

// truncationMarker terminates every capped value. It is appended AFTER the
// cut, so a reader (and a policy) can distinguish "this is the value" from
// "this is a prefix of it".
const truncationMarker = "…[truncated]"

// capString enforces maxPredicateString on one value.
func capString(s string) (string, bool) {
	if len(s) <= maxPredicateString {
		return s, false
	}
	cut := s[:maxPredicateString]
	// Do not cut a UTF-8 sequence in half; a torn rune would make the capped
	// value invalid where the original was valid.
	for len(cut) > maxPredicateString-utf8.UTFMax && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + truncationMarker, true
}

// capStrings applies maxPredicateString across the assembled predicate, at the
// single point where observation becomes serialization (the ends of
// Attestor.observe). Applying it here rather than at each collection site
// means a new provider — or a new field — cannot forget it.
func (a *Attestor) capStrings() {
	truncated := false
	capTo := func(s *string) {
		capped, cut := capString(*s)
		*s = capped
		truncated = truncated || cut
	}
	capObs := func(o *Observation) {
		if o != nil {
			capTo(&o.Value)
			capTo(&o.Source)
		}
	}

	capObs(a.Model)
	capObs(a.Session)
	if a.Invoker != nil {
		capObs(a.Invoker.Version)
		capTo(&a.Invoker.Vendor)
		capTo(&a.Invoker.Product)
		capTo(&a.Invoker.Fingerprint)
		capTo(&a.Invoker.DetectionMethod)
		capTo(&a.Invoker.Process.StartTime)
		capTo(&a.Invoker.Process.Executable)
		capTo(&a.Invoker.Process.ExecutableResolved)
		capTo(&a.Invoker.Process.Comm)
		capTo(&a.Invoker.Process.DigestSkipped)
		capTo(&a.Invoker.Process.DigestBinding)
		capTo(&a.Invoker.Process.ArgvProgram)
		for k, v := range a.Invoker.Process.ArgvFields {
			capped, cut := capString(v)
			a.Invoker.Process.ArgvFields[k] = capped
			truncated = truncated || cut
		}
	}
	for i := range a.Settings {
		capTo(&a.Settings[i].Key)
		capTo(&a.Settings[i].Value)
		capTo(&a.Settings[i].Source)
	}
	for i := range a.Configuration {
		capTo(&a.Configuration[i].Path)
		capTo(&a.Configuration[i].Scope)
		for j := range a.Configuration[i].FieldsUsed {
			capTo(&a.Configuration[i].FieldsUsed[j])
		}
	}
	for i := range a.Environment {
		capTo(&a.Environment[i].Key)
		capTo(&a.Environment[i].Value)
		capTo(&a.Environment[i].From)
	}
	for i := range a.Ancestry {
		capTo(&a.Ancestry[i].Program)
		capTo(&a.Ancestry[i].ProgramFrom)
		capTo(&a.Ancestry[i].MatchedBy)
	}
	for i := range a.Warnings {
		capTo(&a.Warnings[i])
	}
	if truncated {
		a.Warnings = append(a.Warnings,
			"alps-evidence: one or more recorded values exceeded the per-value size cap and were truncated; truncated values end in "+truncationMarker+".")
	}
}

// Assurance grades how a single field was learned. It is deliberately coarse:
// the point is to let a policy author distinguish "the kernel told us" from
// "a file on disk said so" from "we guessed", not to express a probability.
type Assurance string

const (
	// AssuranceUnknown means the field could not be resolved at all. A field
	// carrying this grade has no value worth acting on.
	AssuranceUnknown Assurance = "unknown"

	// AssuranceProcessObserved means the value came from kernel-reported
	// process state (executable path, argv, comm) for a live process. This is
	// the strongest grade available in this mode and it is still only as
	// trustworthy as the process itself — see PredicateCaveat.
	AssuranceProcessObserved Assurance = "process-observed"

	// AssuranceEnvironmentObserved means the value came from an environment
	// variable. Any ancestor in the chain can set one, so this is weaker than
	// process-observed.
	AssuranceEnvironmentObserved Assurance = "environment-observed"

	// AssuranceConfigObserved means the value was read out of a configuration
	// file on disk. The file's digest is recorded alongside so a verifier can
	// tell whether the file changed, but nothing proves the agent actually
	// loaded it.
	AssuranceConfigObserved Assurance = "configuration-observed"

	// AssuranceInferred means the value was derived from a layout convention
	// (for example a versioned install directory) rather than read directly.
	AssuranceInferred Assurance = "inferred"
)

// ResolutionRole records what is claimed about a configuration file. There is
// exactly one value, and that is the point.
//
// This vocabulary used to carry "effective" as well, meaning the file that
// actually decided a resolved value. That claim was withdrawn: deciding it
// required implementing each product's config precedence and then asserting the
// agent had followed it, and NOTHING this attestor can observe confirms which
// file a running agent loaded. Five review rounds found a different way for
// that unverifiable claim to be wrong — an unreadable environment, an
// unresolvable $CODEX_HOME, an undeclared profile, a relative path standing in
// for a home directory — because the claim itself was beyond the evidence, not
// because any single implementation of it was careless.
//
// What remains is what was always observable: this file exists, here is its
// digest, and here are the fields that were read out of it. A consumer that
// needs to know which configuration an agent actually loaded cannot get it from
// process ancestry, and should not be handed a guess shaped like an answer.
//
// The constant is kept rather than the field dropped so the predicate says
// plainly what it is claiming, and so a reader of an older attestation can see
// the vocabulary changed.
type ResolutionRole string

const RoleObserved ResolutionRole = "observed"

// Observation is a single resolved field plus its provenance. Every non-obvious
// value in the predicate is wrapped in one of these so a policy can require,
// say, a process-observed model rather than accepting an environment claim.
type Observation struct {
	Value     string    `json:"value"`
	Source    string    `json:"source"`
	Assurance Assurance `json:"assurance"`
}

// ProcessRef is the redacted description of the process that was positively
// identified as the invoking agent.
//
// Raw argv is never serialized. On this platform an agent's argv routinely
// carries absolute paths belonging to unrelated projects (Claude Code's
// daemon passes a --spawned-by JSON blob naming another checkout's working
// directory, and shell wrappers embed shell-snapshot paths). Only the program
// token and a per-provider allowlist of flags survive into the predicate.
type ProcessRef struct {
	PID  int `json:"pid"`
	PPID int `json:"ppid"`

	// StartTime disambiguates a recycled PID. Format is platform-defined and
	// only meaningful for comparison against another reading on the same host
	// and boot.
	StartTime string `json:"start_time,omitempty"`

	// Executable is the path the kernel reports for the process image. This is
	// the invoking agent's own binary path, which is the substance of the
	// attestation, so it is recorded in full.
	Executable string `json:"executable,omitempty"`

	// ExecutableResolved is Executable with symlinks resolved, present only
	// when it differs — and only when it could be bound to the file SHA256
	// describes. Homebrew installs cilock-adjacent agents behind a symlink
	// whose target directory carries the version, so the resolution is worth
	// having; pairing it with a digest of OTHER bytes is not. It is therefore
	// established from the same open handle the digest came from: read off the
	// descriptor where the kernel can answer (Linux), otherwise resolved and
	// then checked against that handle's own fstat. When the check fails — an
	// auto-update retargeting the link mid-collection is the measured case —
	// this field is ABSENT and a warning says why, rather than naming a binary
	// the digest does not describe. DigestBinding says how strongly the whole
	// set is tied to the running process.
	ExecutableResolved string `json:"executable_resolved,omitempty"`

	// Comm is the kernel's short process name. On macOS it reflects the image
	// most recently exec'd, which can carry a version string when the path on
	// disk is a launcher shim.
	Comm string `json:"comm,omitempty"`

	// SHA256 is the digest of the executable, present only when the file was
	// readable and within DigestSizeLimit. Coding-agent binaries are routinely
	// 300MB+, so digesting is capped rather than unconditional.
	SHA256 string `json:"sha256,omitempty"`

	// SizeBytes and DigestSkipped explain an absent SHA256.
	SizeBytes     int64  `json:"size_bytes,omitempty"`
	DigestSkipped string `json:"digest_skipped,omitempty"`

	// DigestBinding says what SizeBytes and SHA256 are bound to, so a reader
	// never has to guess how strong the pairing is.
	//
	// "process-image": derived from a handle to the running image itself
	// (Linux /proc/<pid>/exe), which survives the path being replaced. There,
	// ExecutableResolved is read back off that same descriptor, so the path
	// and the digest name one inode by construction.
	//
	// "path": the recorded executable path was opened once and everything
	// derived from that single handle. Internally consistent — resolved path,
	// size and digest describe one file, because the resolution was verified
	// against the handle before being recorded — but nothing proves the path
	// still held the binary this process is executing at the moment of the
	// open. macOS offers no per-process image handle, so path-time consistency
	// is the honest ceiling there, and a reader must not upgrade it to a claim
	// about the running image.
	//
	// The same convention covers ExecutableResolved and any version parsed
	// from it: all come out of the one executable snapshot and share whichever
	// binding is named here. Absent when no size or digest was recorded.
	DigestBinding string `json:"digest_binding,omitempty"`

	// ArgvProgram is the first whitespace-delimited token of argv[0], reduced
	// to its basename. Agents that rewrite their process title publish a value
	// like "claude bg-spare" here; the token is "claude".
	ArgvProgram string `json:"argv_program,omitempty"`

	// ArgvCount is the total number of argv entries. A count discloses nothing
	// but bounds what a reader can assume about the omitted arguments.
	ArgvCount int `json:"argv_count,omitempty"`

	// ArgvFields holds only flags a provider explicitly allowlisted, such as
	// "--model". Everything else is dropped.
	ArgvFields map[string]string `json:"argv_fields,omitempty"`
}

// AncestorRef is one node of the walked ancestry. It carries basenames only.
//
// Full paths are withheld deliberately: the ancestry above the agent belongs to
// other work on the machine and leaks unrelated project locations. The purpose
// of this list is to make the detection decision auditable ("we passed a zsh
// and stopped at claude"), which basenames satisfy.
type AncestorRef struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Program string `json:"program,omitempty"`

	// ProgramFrom names WHICH process fact Program was taken from —
	// executable-basename, kernel-comm, or argv0-process-title — because the
	// three are not equally trustworthy and the name alone cannot be told
	// apart. An ancestor whose image path the kernel would not disclose
	// contributes the title it wrote for ITSELF, and a reader auditing the walk
	// has to be able to see that rather than read it as the kernel's record.
	// Same vocabulary as MatchedBy; see the basis constants in provider.go.
	ProgramFrom string `json:"program_from,omitempty"`

	Matched   bool   `json:"matched"`
	MatchedBy string `json:"matched_by,omitempty"`
}

// ConfigSource records a configuration file that was found on disk.
//
// The file content is never copied into the predicate. Only its digest, the
// scope it occupies in the product's own layout, and the fields that were read
// out of it.
//
// It does NOT record whether the agent loaded this file. That cannot be
// observed from the process tree, so it is not claimed; see ResolutionRole.
type ConfigSource struct {
	Path       string         `json:"path"`
	SHA256     string         `json:"sha256,omitempty"`
	Scope      string         `json:"scope"`
	Role       ResolutionRole `json:"role"`
	FieldsUsed []string       `json:"fields_used,omitempty"`
}

// SettingObservation is a resolved posture setting — approval policy, sandbox
// mode, reasoning effort — with the provenance of where it was read.
//
// These are separate from the model because they answer a different question:
// not "which model wrote this" but "what was this agent permitted to do".
type SettingObservation struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Source    string    `json:"source"`
	Assurance Assurance `json:"assurance"`
}

// EnvObservation is an allowlisted environment variable. Values are recorded
// only for keys a provider marked as safe; for the rest, presence alone is
// reported.
type EnvObservation struct {
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	Present   bool      `json:"present"`
	From      string    `json:"from"`
	Assurance Assurance `json:"assurance"`
}

// AgentIdentity is the invoking agent as identified by the ancestry walk.
type AgentIdentity struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`

	// Version is absent when no confirmable source carried one. It is never
	// guessed from a "latest available" update-check file.
	Version *Observation `json:"version,omitempty"`

	Process ProcessRef `json:"process"`

	// Fingerprint names the exact rule that identified this process, so a
	// reader can see whether identity rested on a real install layout or on an
	// agent-controlled process title.
	Fingerprint string `json:"fingerprint,omitempty"`

	// DetectionMethod is constant for this attestor but is written explicitly
	// so a future mode is distinguishable in stored attestations.
	DetectionMethod string `json:"detection_method"`
}

// AssuranceStatement is the standing, machine-readable disclaimer about what
// this predicate is worth. It is emitted on every run, detected or not.
type AssuranceStatement struct {
	Mode        string `json:"mode"`
	Enforcement bool   `json:"enforcement"`
	Caveat      string `json:"caveat"`
}

// ObservationStatus is the outcome of the walk itself, distinct from whether an
// agent was found.
type ObservationStatus string

const (
	// StatusDetected means a supported agent was positively identified.
	StatusDetected ObservationStatus = "detected"

	// StatusNotDetected means the walk COMPLETED — it reached a root process
	// within the depth bound with every ancestor examined — and no supported
	// agent was found. This is a normal result, not a failure: cilock may
	// legitimately be run by a human or by CI. It is a positive claim about
	// the whole ancestry, which is why a walk that ended early must never
	// carry it (see StatusIncomplete).
	StatusNotDetected ObservationStatus = "not-detected"

	// StatusIncomplete means the walk started but ended before the ancestry
	// was fully examined, or examined some of it only partially: it was
	// cancelled, hit an unreadable ancestor, met a PPID loop, ran out of depth
	// budget, or passed an ancestor whose identity sources the kernel would not
	// fully disclose (a process that exited mid-walk is the measured case). Nothing is claimed about the
	// unexamined remainder — an agent may well sit beyond the point the walk
	// stopped. Fail closed: a policy that wants "no agent was present" must
	// treat incomplete the way it treats unavailable, never as not-detected.
	// The Warnings name which of the five causes applied.
	StatusIncomplete ObservationStatus = "incomplete"

	// StatusUnavailable means the walk could not be performed on this platform
	// or the process source refused. Nothing is claimed either way.
	StatusUnavailable ObservationStatus = "unavailable"
)
