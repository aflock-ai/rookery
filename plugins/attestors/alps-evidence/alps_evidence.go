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

// Package alpsevidence implements an attestor that records which coding-agent
// process appears in cilock's ancestry.
//
// # What it does
//
// cilock is normally launched by a coding agent — the agent runs a build or a
// test and cilock wraps it. At collection time this attestor reads its own
// process ancestry from nearest parent outwards and stops at the first process
// a provider matches as a supported agent. That process is recorded as the
// observed invoker. A chain of cilock -> bash -> codex -> cursor-agent records
// Codex, not Cursor: the nearest recognized process wins, and there is no
// search for a "better" outer agent. This ordering is an observation rule, not
// proof that the matched process caused the step.
//
// # What it is worth
//
// This is observation, not enforcement.
//
// The attestor inspects a parent process running as the same user, which it
// does not control and cannot constrain. A malicious agent can name its binary
// claude, set its own argv, or interpose an extra process between itself and
// cilock. Every fingerprint here is therefore forgeable by the very party being
// described. The output is useful for attribution and fleet visibility — which
// agents are running against which repos, on which versions, with which
// approval posture — and it is not useful for stopping an agent that is lying
// about itself.
//
// Consistent with the rest of this codebase, the attestor observes and does not
// gate. It never returns an error: "no agent found" is a successful observation
// with status not-detected, and "could not look at all" is a successful
// observation with status unavailable — recorded, signed evidence either way
// (see Attest for why unavailability must not be an error).
//
// # What it deliberately does not do
//
// No daemon, no eBPF or EndpointSecurity, no vendor hooks, no continuous
// monitoring, no machine-wide process scanning. It reads its own ancestry once,
// at collection time, and stops.
//
// It also never executes the agent binary. Running `codex --version` would be a
// better version read; it is not done, because executing a process you are
// inspecting hands it control of your measurement.
//
// # Privacy
//
// Raw argv is never serialized. A coding agent's argv on a developer machine
// routinely names unrelated work: Claude Code's daemon passes a --spawned-by
// JSON blob containing another checkout's working directory, and shell wrappers
// embed shell-snapshot paths. Only a per-provider allowlist of flags survives
// into the predicate, and ancestors above the agent contribute basenames only.
// Environment reads are allowlisted per provider by key. Neither platform
// offers a per-key interface — /proc/<pid>/environ and KERN_PROCARGS2 each
// return the whole block or nothing — so the bytes of every variable the
// process holds do transit this process. What the allowlist governs is what is
// RETAINED: an unlisted variable is never converted into a value this attestor
// keeps, so it cannot reach the predicate. A credential-shaped key name is
// dropped even when a provider lists it.
package alpsevidence

import (
	_ "embed"
	"os"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	environmentattestor "github.com/aflock-ai/rookery/plugins/attestors/environment"
	"github.com/invopop/jsonschema"
)

// detectorYAML is this attestor's detection + output contract, validated by
// the catalog gate (scripts/check-detector-yamls.sh) via
// TestDetectorYAMLParses. The contract declares NO subjects, backrefs, or
// exports — see the interface assertions below for why that is load-bearing.
//
//go:embed detector.yaml
var detectorYAML []byte

const (
	Name = "alps-evidence"

	// Type is the versioned predicate identifier for the ALPS 0.1 observation.
	Type = "https://aflock.ai/attestations/alps-evidence/v0.1"

	// RunType is prematerial: the invoking agent is a property of the
	// environment the step ran in, known before any material is hashed.
	RunType = attestation.PreMaterialRunType

	// DefaultDigestSizeLimit caps executable digesting.
	//
	// Measured on macOS: the Claude Code binary is 310MB and the Codex binary
	// is 317MB. Hashing either on every cilock invocation would add seconds of
	// wall time to every build for a field nobody asked for, so digesting is
	// capped and the size is recorded instead when the cap is exceeded.
	DefaultDigestSizeLimit int64 = 64 << 20 // 64 MiB
)

// assuranceCaveat is the standing statement about what this predicate is worth.
// It is emitted on every run, including runs that detect nothing.
const assuranceCaveat = "This predicate records what cilock could observe about a parent process running as the same user. " +
	"cilock does not control that process and cannot constrain it: an agent can choose its executable name, set its own argv, " +
	"or interpose another process before invoking cilock. Treat this as attribution and fleet visibility, not as proof of which " +
	"agent ran. It does not detect and is not intended to detect an agent that misrepresents itself."

// This attestor implements attestation.Attestor and nothing else.
//
// It deliberately does NOT implement Subjecter, Materialer, Producer,
// BackReffer or Exporter. Every one of those interfaces would let this
// predicate contribute to what a policy resolves or verifies, and every field
// in this predicate is chosen by the process being described. An agent that can
// name itself could then name itself into satisfying an assertion — describing
// itself as a way of talking past policy.
//
// A subject in particular is a real hazard rather than a theoretical one:
// subjects are how `cilock verify --artifactfile` finds a collection, so an
// agent-controlled string hashed into the subject map would let self-description
// select which artifact a collection appears to be about. The interface
// assertions below are load-bearing and are pinned by a test.
var _ attestation.Attestor = (*Attestor)(nil)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() })
	detection.Register(Name, detectorYAML)
}

// Attestor records the coding-agent process observed in cilock's ancestry.
type Attestor struct {
	// Status is the outcome of the ancestry walk. Callers must read this before
	// reading Invoker: a nil Invoker with status not-detected means "we looked
	// and found nothing", while status unavailable means "we could not look".
	Status ObservationStatus `json:"status"`

	// Assurance is the standing statement about the evidentiary weight of this
	// predicate. It is present on every run.
	Assurance AssuranceStatement `json:"assurance"`

	CapturedAt time.Time `json:"captured_at"`

	// Invoker is the identified agent, absent when nothing was identified.
	Invoker *AgentIdentity `json:"invoker,omitempty"`

	// Model is the strongest model observation available, and its Assurance
	// says how it was obtained: process-observed came from the command line,
	// environment-observed from a variable that was actually read, and
	// configuration-observed from a settings file that was found on disk —
	// which is a CONFIGURED DEFAULT, not a record of what served the session.
	// Absence is common and is not evidence that no model was configured — see
	// Warnings.
	Model *Observation `json:"model,omitempty"`

	Session       *Observation         `json:"session,omitempty"`
	Settings      []SettingObservation `json:"settings,omitempty"`
	Configuration []ConfigSource       `json:"configuration,omitempty"`
	Environment   []EnvObservation     `json:"environment,omitempty"`

	// Ancestry is the redacted walk, nearest first, up to and including the
	// matched process. Basenames only.
	Ancestry []AncestorRef `json:"ancestry,omitempty"`

	// Warnings name what could not be established. They are load-bearing: this
	// attestor's value depends on a reader being able to tell a resolved field
	// from an unresolvable one.
	Warnings []string `json:"warnings,omitempty"`

	source          ProcessSource
	providers       []Provider
	selfPID         int
	digestSizeLimit int64
}

// Option customizes the attestor. Used by tests to substitute a fixture process
// tree for the live one.
type Option func(*Attestor)

// WithProcessSource overrides the platform process source.
func WithProcessSource(src ProcessSource) Option {
	return func(a *Attestor) { a.source = src }
}

// WithProviders overrides the provider set.
func WithProviders(providers []Provider) Option {
	return func(a *Attestor) { a.providers = providers }
}

// WithSelfPID overrides the PID the walk starts from.
func WithSelfPID(pid int) Option {
	return func(a *Attestor) { a.selfPID = pid }
}

// WithDigestSizeLimit overrides the executable digest cap. A limit of 0 or less
// disables digesting entirely.
func WithDigestSizeLimit(limit int64) Option {
	return func(a *Attestor) { a.digestSizeLimit = limit }
}

// New builds an attestor bound to the live process tree.
func New(opts ...Option) *Attestor {
	a := &Attestor{
		source:          NewOSProcessSource(),
		providers:       DefaultProviders(),
		selfPID:         os.Getpid(),
		digestSizeLimit: DefaultDigestSizeLimit,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(a) }

// Attest performs the ancestry walk and publishes a predicate describing THIS
// run and only this run.
//
// The freshness is structural rather than remembered. Everything is observed
// into `run`, a zero-valued Attestor carrying forward nothing but this
// attestor's configuration, and assigning it over the receiver at the end is
// what publishes it. A second Attest on an instance that previously detected
// an agent therefore cannot leak that agent's Invoker, model, session,
// settings, configuration, environment, ancestry or warnings into a run that
// detected nothing or could not look — contradictory evidence that would be
// signed as one observation. The reset costs nothing to maintain: a per-run
// field added to the struct later starts at its zero value here with no list
// to update and nothing to remember.
//
// It never returns an error. Finding no agent is a normal, successful outcome
// — cilock is legitimately run by humans and by CI runners — and a walk that
// could not be performed at all is published as StatusUnavailable rather than
// reported as a failure: the framework drops an erroring attestor's payload
// from the signed collection and fails the run, and both halves are wrong for
// this predicate. Dropping the payload deletes the one honest record of "we
// could not look", and failing the run gates the build on an observability gap
// this attestor exists only to describe (Windows and sandboxed platforms are
// the ordinary cases, not error cases). See the comment at the unavailable
// branch of observe.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	run := Attestor{
		source:          a.source,
		providers:       a.providers,
		selfPID:         a.selfPID,
		digestSizeLimit: a.digestSizeLimit,
	}
	err := run.observe(ctx)
	*a = run
	return err
}

// observe fills in one run's predicate. It is only ever called on the fresh
// value Attest builds, so it may assign rather than reset.
func (a *Attestor) observe(ctx *attestation.AttestationContext) error {
	a.CapturedAt = time.Now().UTC()
	a.Assurance = AssuranceStatement{
		Mode:        "process-ancestry-observation",
		Enforcement: false,
		Caveat:      assuranceCaveat,
	}

	detector := NewDetector(a.source, a.providers)
	detector.DigestSizeLimit = a.digestSizeLimit
	// Pre-material attestors run concurrently, so alps-evidence cannot assume
	// the environment attestor has already installed the run-wide capturer.
	// Build the same capturer from the context options when it is absent. This
	// makes --env-add-sensitive-key, --env-filter-sensitive-vars, and the
	// positive capture allowlist effective regardless of goroutine scheduling.
	capturer := ctx.EnvironmentCapturer()
	if capturer == nil {
		capturer = environmentattestor.NewCapturerFromContext(ctx)
		ctx.SetEnvironmentCapturer(capturer)
	}
	detector.EnvValueKeep = envValueKeepFunc(capturer)
	detection, err := detector.Detect(ctx.Context(), a.selfPID, ctx.WorkingDir())
	if err != nil {
		a.Status = StatusUnavailable
		a.Warnings = append(a.Warnings, err.Error())
		a.capStrings()
		// "Could not look" is NOT an attestor error here, deliberately. The
		// framework contract (see attestation.DetectionError and
		// workflow.evidenceIsRecordable) drops an erroring attestor's payload
		// from the signed collection, because for most attestors a failed
		// look leaves a partial payload that would masquerade as a clean
		// result. This predicate is the opposite case: unavailability IS its
		// complete, truthful content — StatusUnavailable plus the warning
		// naming why is exactly what a reader must see for a run on a
		// platform that hides /proc or refuses the process source. Returning
		// the error both DELETED that evidence and turned the leg fatal, so
		// `cilock run` exited 1 on platforms where the walk cannot work —
		// gating the build on an observability gap this attestor explicitly
		// promises not to gate on. A SoftError is no better: soft legs keep
		// exit 0 but their payloads are dropped from the collection too.
		// So the observation is published and the walk failure is carried
		// INSIDE it, where it is signed. TestUnavailablePredicateSurvives
		// pins both halves.
		log.Warnf("alps-evidence: could not inspect process ancestry: %v", err)
		return nil
	}

	a.Status = detection.Status
	a.Ancestry = detection.Ancestry
	a.Warnings = append(a.Warnings, detection.Warnings...)

	if detection.Status != StatusDetected || detection.Provider == nil {
		a.capStrings()
		return nil
	}

	inspection := detection.Inspection
	a.Invoker = &AgentIdentity{
		Vendor:          detection.Provider.Vendor(),
		Product:         detection.Provider.Product(),
		Version:         inspection.Version,
		Process:         processRef(detection.Process, detection.Image, inspection.ArgvFields),
		Fingerprint:     detection.Match.Fingerprint,
		DetectionMethod: detectionMethod,
	}
	a.Model = inspection.Model
	a.Session = inspection.Session
	a.Settings = inspection.Settings
	a.Configuration = inspection.Configuration
	a.Environment = inspection.Environment
	a.Warnings = append(a.Warnings, inspection.Warnings...)
	a.capStrings()
	return nil
}

// processRef redacts a ProcessInfo down to what may be published.
//
// EVERY executable field — the recorded path, the resolved path, size, digest
// and binding — is read out of the single snapshot the detector took when the
// process was matched, including the "did resolution change anything"
// comparison. The ProcessInfo supplies only what the snapshot is not about:
// pids, start time, comm, and the argv-derived fields. Nothing here looks at
// the filesystem, and nothing here pairs a path from one source with a digest
// from another.
func processRef(p ProcessInfo, snap executableSnapshot, argvFields map[string]string) ProcessRef {
	ref := ProcessRef{
		PID:           p.PID,
		PPID:          p.PPID,
		StartTime:     p.StartTime,
		Executable:    snap.recordedPath,
		Comm:          p.Comm,
		ArgvProgram:   argvProgram(p),
		ArgvCount:     len(p.Argv),
		SizeBytes:     snap.sizeBytes,
		SHA256:        snap.sha256,
		DigestBinding: snap.binding,
		DigestSkipped: snap.digestSkipped,
	}
	if len(argvFields) > 0 {
		ref.ArgvFields = argvFields
	}
	if snap.resolvedPath != "" && snap.resolvedPath != snap.recordedPath {
		ref.ExecutableResolved = snap.resolvedPath
	}
	return ref
}
