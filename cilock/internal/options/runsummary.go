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

package options

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/cilock/internal/keyguard"
)

// Attestor outcome statuses surfaced in the run summary. They map the
// internal soft/fatal error classification onto a flat vocabulary an agent
// can branch on without parsing prose.
const (
	// AttestorStatusRan — the attestor completed and contributed evidence.
	AttestorStatusRan = "ran"
	// AttestorStatusSkipped — the attestor ran but had nothing to do (a
	// "soft" error, e.g. sbom found no SBOM file). Exit code stays 0.
	AttestorStatusSkipped = "skipped"
	// AttestorStatusFailed — the attestor hit a contract violation (a
	// "fatal" error). Drives a non-zero exit.
	AttestorStatusFailed = "failed"
)

// AttestorOutcome is one attestor's result in the structured run summary.
type AttestorOutcome struct {
	Name   string `json:"name"`
	Status string `json:"status"`           // ran | skipped | failed
	Detail string `json:"detail,omitempty"` // human hint, populated for skipped/failed
}

// RunSubject is one in-toto subject the signed collection carries — the set
// an uploaded attestation is correlated by. The git `remote:<url>` subject is
// the correlation anchor a server-side product seed keys on, so it is called
// out explicitly in the human summary.
type RunSubject struct {
	Name    string            `json:"name"`
	Digests map[string]string `json:"digests,omitempty"` // alg -> hex
}

// WrappedCommand records the exit status of the command cilock wrapped, if
// any. ExitCode is the canonical machine signal an agent should branch on.
type WrappedCommand struct {
	Args     []string `json:"args,omitempty"`
	ExitCode int      `json:"exit_code"`
}

// RunSummary is the machine-readable result of a `cilock run`. It is emitted
// as a single JSON object to stdout under --json so an agent never has to grep
// "Stored in archivista as <gitoid>" out of interleaved logr text, and is the
// data behind the human-readable self-explaining summary on stderr.
//
// Every field is populated from what cilock already knows after the run — no
// extra server round-trips. Fields that don't apply to a given run (e.g.
// Gitoid/ArchivistaURL when the upload is disabled) are omitted.
// assessmentNotAssessed is what this producer reports for BOTH standards.
// cilock observes; it never self-certifies a SLSA Build level or an ALPS
// level, because both require assessing the producer and build platform,
// which a command-side tool cannot do.
const assessmentNotAssessed = "not_assessed"

type RunSummary struct {
	Step        string `json:"step"`
	WorkingDir  string `json:"working_dir,omitempty"`
	PlatformURL string `json:"platform_url,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
	Signer      string `json:"signer,omitempty"` // signer kind: file | fulcio | kms | spiffe...
	SignerEmail string `json:"signer_email,omitempty"`
	// AgentPrincipal is the SPIFFE ID of the enrolled agent that signed, as the
	// platform's credential exchange reported it. Set only for an agent run, and
	// mutually exclusive with SignerEmail: a reader never has to work out which
	// of two identities produced the signature.
	AgentPrincipal string `json:"agent_principal,omitempty"`
	// PrincipalKind names the kind of principal that signed ("agent"), per the
	// pushgate agent-policy contract's principal split. Empty when cilock has no
	// server-confirmed principal to report, which is every non-agent run today.
	PrincipalKind      string            `json:"principal_kind,omitempty"`
	TimestampAuthority []string          `json:"timestamp_authority,omitempty"`
	FulcioURL          string            `json:"fulcio_url,omitempty"`
	ArchivistaURL      string            `json:"archivista_url,omitempty"`
	Uploaded           bool              `json:"uploaded"`
	Gitoid             string            `json:"gitoid,omitempty"`
	OutFile            string            `json:"outfile,omitempty"`
	Subjects           []RunSubject      `json:"subjects,omitempty"`
	Attestors          []AttestorOutcome `json:"attestors,omitempty"`
	WrappedCommand     *WrappedCommand   `json:"wrapped_command,omitempty"`

	// KeyProtection records the in-process anti-tamper hardening that was in
	// effect during the run (read back from the kernel, never asserted). Its
	// scope is the local cilock process; it does not establish build-platform
	// isolation or standards conformance. Omitted on unsupported platforms.
	KeyProtection *keyguard.State `json:"key_protection,omitempty"`
	// WorkflowIdentity reports whether cilock installed a platform workflow OIDC
	// identity and the Fulcio signer actually used it. It says which signing path
	// ran; it does not by itself establish build-platform isolation, a SLSA Build
	// level, or an ALPS level.
	WorkflowIdentity bool `json:"workflow_identity,omitempty"`
	// Tracing records the commandrun capture mode that observed the wrapped
	// command ("ebpf", "ptrace", …), or is empty when the build was not traced.
	// Without a trace, network behavior is unknown. Set by buildRunSummary from
	// the commandrun attestor.
	Tracing string `json:"tracing,omitempty"`
	// NOT A SIGNED PREDICATE FIELD. This struct is cilock's run summary,
	// written to stdout/stderr for an operator and a CI job; nothing in this
	// repo signs it, stores it, or verifies against it. So widening what
	// counts as egress cannot retroactively change the meaning of any evidence
	// already in a store — there is none of it — and there is nothing here to
	// version. What DOES carry versioned semantics is the command-run
	// predicate, whose URI rules are stated beside V02PredicateType.
	//
	// NoExternalNetworkEgressObserved reports the narrow fact established by the
	// commandrun trace. It is not a hermeticity claim: filesystem inputs, ambient
	// descriptors, caches, time, randomness, local services, and the observer's
	// own coverage are separate parts of that assessment.
	NoExternalNetworkEgressObserved bool `json:"no_external_network_egress_observed,omitempty"`
	// UnattributedExecs counts execs the trace OBSERVED but could not tie to
	// the wrapped command's process tree — a child that exited before its
	// kernel facts could be read, so its ancestry is undecidable.
	//
	// It is surfaced here because these gaps carry NO IMAGE IDENTITY in the
	// attestation, deliberately: the report stream is machine-wide and an
	// unproven pid's owner is unknown by construction, so naming an image
	// would attribute a stranger's program to this build. The consequence is
	// that an image-deny policy has nothing to match on, and a forbidden
	// short-lived child reads as a bare pid-and-timestamp gap. A count an
	// operator can see is what keeps that from being silent; the attestation
	// carries the full list.
	//
	// Non-zero does NOT mean something is wrong. It is the measured residual
	// of a report-channel tracer on a loaded machine, which is why it is
	// reported rather than refused — refusing every trace that lost a race
	// with a fast child would make this backend unusable.
	UnattributedExecs int `json:"unattributed_execs,omitempty"`
	// ForgedReportRecords counts log records that LOOKED like kernel sandbox
	// reports but did not come from the kernel — something on the machine was
	// writing sandbox-shaped messages into the unified log while the build ran.
	//
	// The records themselves were rejected, so no evidence of this build is
	// missing and the trace is still attestable; that is why this reports
	// rather than refuses. It also must not refuse: the log stream is
	// machine-wide and os_log is an ordinary unprivileged API, so any local
	// process could otherwise break every build on the machine by emitting one
	// line. But a non-zero value is either a bug or an attempt to fabricate
	// evidence, and it reaches an operator here instead of sitting in a
	// counter nothing reads.
	ForgedReportRecords uint64 `json:"forged_report_records,omitempty"`
	// NetworkEgress lists the external destinations the trace observed
	// (hostname/address with port). Empty can mean no observed egress or no trace;
	// Tracing and NoExternalNetworkEgressObserved disambiguate those states.
	NetworkEgress []string `json:"network_egress,omitempty"`

	// SLSABuildLevel is retained for JSON compatibility with older clients. New
	// summaries deliberately leave it unset: a command-side producer cannot
	// assess the producer and build-platform requirements that define a SLSA
	// Build level.
	SLSABuildLevel      int    `json:"slsa_build_level,omitempty"`
	SLSABuildAssessment string `json:"slsa_build_assessment,omitempty"`
	// SLSAVerdict explains why the run summary did not assign a SLSA Build level.
	SLSAVerdict string `json:"slsa_verdict,omitempty"`
	// ALPS fields identify the specification whose evidence vocabulary applies.
	// Like SLSA, the producer reports observations and an independent verifier
	// derives the level; this summary never self-assigns one.
	ALPSSpecVersion string `json:"alps_spec_version,omitempty"`
	ALPSAssessment  string `json:"alps_assessment,omitempty"`
	ALPSVerdict     string `json:"alps_verdict,omitempty"`
	// AssuranceLevel echoes the platform discovery doc's assurance_level (the
	// acr the platform minted the signing identity at, e.g. "aal2"), when a
	// platform session supplied one. Empty for offline / local-key runs.
	AssuranceLevel string `json:"assurance_level,omitempty"`

	// Capture is the capture-completeness delta: which subjects an attestor's
	// contract said SHOULD have been captured but the run did not produce,
	// each with the remedy. Advisory — it never changes the exit code. This is
	// the machine-readable half of the CILOCK_CAPTURE_INCOMPLETE warnings, so
	// "where are we blind?" is answerable from capture-time data instead of by
	// querying the evidence store months later. nil when no attestor in the run
	// declared a capture expectation.
	Capture *detection.CaptureReport `json:"capture,omitempty"`
}

// ComputeStandardsAssessment records the standards this producer-side summary
// can honestly assess. SLSA Build levels are properties of a producer plus its
// build platform: L2 requires a hosted platform that generates authentic
// provenance, while L3 additionally requires control-plane generation and
// isolated, ephemeral builds. A signer kind, OIDC token, key guard, or network
// trace alone cannot establish those requirements.
//
// ALPS 0.1 follows the same separation: cilock can produce signed observations,
// but an independent verifier derives the level from authenticated identity and
// boundary evidence. The local process must never grade its own isolation.
func (s *RunSummary) ComputeStandardsAssessment(runFailed bool) {
	s.SLSABuildLevel = 0 // clear any value left by a reused summary
	s.SLSABuildAssessment = assessmentNotAssessed
	s.ALPSSpecVersion = "0.1"
	s.ALPSAssessment = assessmentNotAssessed
	if runFailed {
		s.SLSAVerdict = "SLSA Build: not assessed — the run did not complete successfully."
		s.ALPSVerdict = "ALPS 0.1: not assessed — the run did not produce complete evidence for an independent verifier."
		return
	}

	s.SLSAVerdict = "SLSA Build: not assessed — this run produced signed in-toto evidence, not a build-platform assessment."
	s.ALPSVerdict = "ALPS 0.1: not assessed — CI/lock records observations; an independent verifier assigns the level."
}

// networkEgressHint renders a short, capped summary of observed endpoints —
// never an unbounded dump.
func networkEgressHint(egress []string) string {
	const max = 3
	switch {
	case len(egress) == 0:
		return "network observed"
	case len(egress) <= max:
		return strings.Join(egress, ", ")
	default:
		return strings.Join(egress[:max], ", ") + fmt.Sprintf(", +%d more", len(egress)-max)
	}
}

// gitRemoteAnchor returns the git remote URL the collection is anchored by,
// the single most valuable correlation fact: the git attestor emits a
// `remote:<url>` subject, and a server-side product seed keys on it. Empty if
// the run carried no git remote subject (correlation will not happen by repo).
//
// The subject name is fully qualified by the git predicate URI
// (e.g. "https://aflock.ai/attestations/git/v0.1/remote:git@github.com:org/repo.git"),
// so the `remote:` token is matched as a trailing path segment, not a prefix.
func (s *RunSummary) gitRemoteAnchor() string {
	const tok = "remote:"
	for _, sub := range s.Subjects {
		idx := strings.LastIndex(sub.Name, tok)
		if idx < 0 {
			continue
		}
		// Anchor only on a genuine `remote:` segment — either the whole name
		// or one preceded by a path separator — never an arbitrary substring.
		if idx == 0 || sub.Name[idx-1] == '/' {
			return sub.Name[idx+len(tok):]
		}
	}
	return ""
}

// WriteJSON emits the summary as a single indented JSON object followed by a
// newline. This is the only thing written to stdout under --json.
func (s *RunSummary) WriteJSON(w io.Writer) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run summary: %w", err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write run summary: %w", err)
	}
	return nil
}

// WriteHuman prints the self-explaining run summary: working dir, the subjects
// being attested (especially the git remote anchor), the logged-in tenant and
// signer, and the Fulcio/TSA/Archivista destinations. Written to stderr so it
// never pollutes a machine-parseable stdout. Designed so an agent (or human)
// can verify its mental model of the run without reading cilock source.
//
// The summary is composed into a strings.Builder (whose writes never fail) and
// flushed in a single checked write, so a partial line never lands on a flaky
// writer and errcheck stays satisfied.
func (s *RunSummary) WriteHuman(w io.Writer) { //nolint:gocyclo // straight-line human report: one branch per optional summary field; intentionally flat.
	var b strings.Builder
	b.WriteString("cilock run summary:\n")
	fmt.Fprintf(&b, "  step:       %s\n", orNone(s.Step))
	if s.WorkingDir != "" {
		fmt.Fprintf(&b, "  workingdir: %s\n", s.WorkingDir)
	}
	// The anchor line — the most valuable single fact. Print it whether or
	// not it exists, because its ABSENCE is itself the signal an agent needs
	// (uploaded-but-uncorrelated is a silent failure otherwise).
	if anchor := s.gitRemoteAnchor(); anchor != "" {
		fmt.Fprintf(&b, "  anchor:     git remote %s\n", sanitizeForTerminal(anchor))
	} else {
		b.WriteString("  anchor:     (no git remote subject — attestation will NOT correlate to a repo product)\n")
	}
	if s.Tenant != "" {
		fmt.Fprintf(&b, "  tenant:     %s\n", sanitizeForTerminal(s.Tenant))
	}
	// The acting principal. An agent run names its SPIFFE ID and says plainly
	// that it is the agent and not the operator's own account, because the whole
	// point of the enrolled principal is that a reader never has to guess which
	// identity signed. buildRunSummary guarantees the two are exclusive.
	switch {
	case s.AgentPrincipal != "":
		fmt.Fprintf(&b, "  identity:   %s\n", sanitizeForTerminal(s.AgentPrincipal))
		fmt.Fprintf(&b, "  principal:  %s (enrolled agent — NOT the human session)\n", orNone(s.PrincipalKind))
	case s.SignerEmail != "":
		fmt.Fprintf(&b, "  identity:   %s\n", sanitizeForTerminal(s.SignerEmail))
	}
	fmt.Fprintf(&b, "  signer:     %s\n", orNone(s.Signer))
	if len(s.TimestampAuthority) > 0 {
		fmt.Fprintf(&b, "  tsa:        %s\n", strings.Join(s.TimestampAuthority, ", "))
	}
	if s.FulcioURL != "" {
		fmt.Fprintf(&b, "  fulcio:     %s\n", s.FulcioURL)
	}
	if s.Uploaded {
		fmt.Fprintf(&b, "  archivista: %s\n", orNone(s.ArchivistaURL))
		if s.Gitoid != "" {
			fmt.Fprintf(&b, "  gitoid:     %s\n", sanitizeForTerminal(s.Gitoid))
		}
	} else if s.ArchivistaURL != "" {
		// Say the outcome, not the setting: what the next push is judged on is
		// whether evidence exists on the platform, and here it does not.
		fmt.Fprintf(&b, "  archivista: %s (upload DISABLED — NO evidence stored; pass --enable-archivista to store)\n", s.ArchivistaURL)
	}
	if len(s.Subjects) > 0 {
		fmt.Fprintf(&b, "  subjects (%d): %s\n", len(s.Subjects), strings.Join(s.subjectNames(), ", "))
	}
	for _, a := range s.Attestors {
		// Name and Status are internal registry constants (the attestor's own
		// Name() and the ran/skipped/failed vocabulary), so they're trusted. The
		// Detail is built from attestor error messages, which can embed external
		// tool output, file paths, and other attacker-influenceable data — so it
		// is sanitized before it reaches the terminal (#5993).
		fmt.Fprintf(&b, "  attestor:   %s — %s", a.Name, a.Status)
		if a.Detail != "" {
			b.WriteString(" (" + sanitizeForTerminal(a.Detail) + ")")
		}
		b.WriteByte('\n')
	}
	if s.WrappedCommand != nil {
		fmt.Fprintf(&b, "  command exit: %d\n", s.WrappedCommand.ExitCode)
	}
	s.writeKeyGuardLine(&b)
	// Narrow network observations from command tracing. They are printed as
	// observations, never promoted into a hermeticity or standards claim.
	b.WriteString(s.buildEvidenceLine())
	// Standards assessments remain separate from authentication strength. AAL
	// describes the platform session; it is not a SLSA or ALPS level.
	if s.SLSAVerdict != "" {
		fmt.Fprintf(&b, "  %s\n", s.SLSAVerdict)
	}
	if s.ALPSVerdict != "" {
		fmt.Fprintf(&b, "  %s\n", s.ALPSVerdict)
	}
	if s.AssuranceLevel != "" {
		fmt.Fprintf(&b, "  platform authentication: %s (AAL; not a SLSA or ALPS level)\n",
			sanitizeForTerminal(s.AssuranceLevel))
	}
	_, _ = io.WriteString(w, b.String())
}

// writeKeyGuardLine appends the non-forgeability evidence line when the signer
// was hardened: dumpable==false means the signing key was unextractable from
// cilock's memory by a same-UID attacker during the run. Split out of
// WriteHuman to keep that function's branch count in check.
func (s *RunSummary) writeKeyGuardLine(b *strings.Builder) {
	kp := s.KeyProtection
	if kp == nil || !kp.Applied {
		return
	}
	fmt.Fprintf(b, "  key guard:  process protection applied (dumpable=%v, yama=%d)\n",
		kp.Dumpable, kp.YamaPtraceScope)
}

// buildEvidenceLine renders the narrow network facts the trace observed, or ""
// when the build was not traced. Zero observed egress is not hermeticity: the
// trace does not by itself cover every input and external influence.
func (s *RunSummary) buildEvidenceLine() string {
	if s.Tracing == "" {
		return ""
	}
	if s.NoExternalNetworkEgressObserved {
		return fmt.Sprintf("  network:    no external egress observed (%s trace); hermeticity not assessed\n", s.Tracing)
	}
	return fmt.Sprintf("  network:    external egress observed (%s trace: %s); hermeticity not assessed\n",
		s.Tracing, networkEgressHint(s.NetworkEgress))
}

// subjectNames returns the (sorted) subject names for the compact human line,
// trimmed of the common attestation predicate-URI prefix so the line stays
// scannable (e.g. "git/v0.1/remote:..." instead of the full
// "https://aflock.ai/attestations/git/v0.1/remote:..."). The JSON keeps the
// fully-qualified name.
func (s *RunSummary) subjectNames() []string {
	names := make([]string, 0, len(s.Subjects))
	for _, sub := range s.Subjects {
		names = append(names, sanitizeForTerminal(shortSubjectName(sub.Name)))
	}
	sort.Strings(names)
	return names
}

// attestationURIPrefix is the common predicate-URI root the witness/rookery
// attestors qualify subject names with. Trimmed from the human summary only.
const attestationURIPrefix = "https://aflock.ai/attestations/"

// shortSubjectName trims the common attestation predicate-URI prefix from a
// subject name for the human summary. Names without the prefix are returned
// unchanged.
func shortSubjectName(name string) string {
	if rest, ok := strings.CutPrefix(name, attestationURIPrefix); ok {
		return rest
	}
	return name
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// sanitizeForTerminal escapes ASCII control bytes — including the ANSI escape
// (\x1b), CR (\r), NUL (\x00), and DEL (\x7f) — in untrusted strings before
// they are written to the operator's terminal. Server-returned gitoids,
// attestation subject names, git-remote URLs, and the platform-supplied
// assurance_level are all attacker-influenceable; left raw they could carry
// ANSI/CR sequences that spoof or overwrite the run summary the operator reads
// to decide trust (#5993). Each offending byte is rendered in Go's \xNN form so
// no information is lost while no raw control byte reaches the TTY. Printable
// bytes (incl. tab and UTF-8 multibyte sequences) pass through unchanged.
func sanitizeForTerminal(s string) string {
	hasCtrl := false
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x20 && b != '\t' || b == 0x7f {
			hasCtrl = true
			break
		}
	}
	if !hasCtrl {
		return s
	}
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' || c == 0x7f {
			b.WriteString(`\x`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
