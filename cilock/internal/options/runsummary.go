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
type RunSummary struct {
	Step               string            `json:"step"`
	WorkingDir         string            `json:"working_dir,omitempty"`
	PlatformURL        string            `json:"platform_url,omitempty"`
	Tenant             string            `json:"tenant,omitempty"`
	Signer             string            `json:"signer,omitempty"` // signer kind: file | fulcio | kms | spiffe...
	SignerEmail        string            `json:"signer_email,omitempty"`
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
	// effect during the run (read back from the kernel, never asserted). It is
	// NON-FORGEABILITY evidence: dumpable==false means the signing key could
	// not be lifted from cilock's memory by a same-UID attacker mid-build, so
	// the keyless workflow identity it signed with is actually non-forgeable.
	// A policy can gate an L3 verdict on it. Omitted on unsupported platforms.
	KeyProtection *keyguard.State `json:"key_protection,omitempty"`
	// WorkflowIdentity reports whether the run signed with an isolated platform
	// workflow identity — keyless Fulcio minted via cilock's ambient-CI or stored
	// workflow-identity path (NOT a local key, NOT offline, NOT a raw
	// --signer-fulcio-token whose provenance cilock cannot attest, NOT a browser
	// session whose build ran on a developer's machine). It is the evidence gate
	// between SLSA Build L1 (forgeable provenance) and L2 (non-forgeable
	// provenance from an isolated builder). Set by buildRunSummary.
	WorkflowIdentity bool `json:"workflow_identity,omitempty"`
	// Tracing records the commandrun capture mode that observed the wrapped
	// command ("ebpf", "ptrace", …), or is empty when the build was not traced.
	// Without a trace, hermeticity is UNKNOWN and the run cannot reach L3. Set by
	// buildRunSummary from the commandrun attestor.
	Tracing string `json:"tracing,omitempty"`
	// Hermetic reports whether the TRACED build made zero external network egress
	// — i.e. pulled no undeclared network inputs during the wrapped command. Only
	// meaningful when Tracing is non-empty; it is the evidence gate between SLSA
	// Build L2 and L3.
	Hermetic bool `json:"hermetic,omitempty"`
	// NetworkEgress lists the external destinations the traced build reached
	// (hostname/address with port) — the evidence that breaks hermeticity. Empty
	// when the build was hermetic or untraced.
	NetworkEgress []string `json:"network_egress,omitempty"`

	// SLSABuildLevel is the SLSA Build track level this run ACHIEVED, derived by
	// ComputeSLSA from the EVIDENCE above (the trusted signing path + traced
	// hermeticity) — NOT from the level the slsa attestor claims, and NOT from
	// the signer-kind string. See ComputeSLSA for the L1/L2/L3 ladder.
	SLSABuildLevel int `json:"slsa_build_level,omitempty"`
	// SLSAVerdict is the human-readable one-line verdict + upgrade hint that
	// accompanies SLSABuildLevel. Empty until ComputeSLSA runs.
	SLSAVerdict string `json:"slsa_verdict,omitempty"`
	// AssuranceLevel echoes the platform discovery doc's assurance_level (the
	// acr the platform minted the signing identity at, e.g. "aal2"), when a
	// platform session supplied one. Empty for offline / local-key runs.
	AssuranceLevel string `json:"assurance_level,omitempty"`
}

// ComputeSLSA derives the achieved SLSA Build level + verdict from the EVIDENCE
// the run actually produced — never from the signer-kind string alone (a signer
// named "fulcio" proves nothing about WHERE the signing happened or whether the
// build was isolated). Two evidence gates, each requiring a positive signal;
// absent evidence keeps the level LOW rather than assuming the best:
//
//   - L1 (floor): a signed provenance attestation exists. Every cilock run.
//   - L2: the provenance is non-forgeable — signed by an isolated platform
//     workflow identity (s.WorkflowIdentity: keyless Fulcio minted via cilock's
//     ambient-CI or stored workflow-identity path). A local/KMS key, an offline
//     run, a raw --signer-fulcio-token, or a browser session whose build ran on
//     a developer's machine all stay at L1.
//   - L3: L2 AND the build is hermetic — the commandrun attestor traced the
//     wrapped command (s.Tracing) and observed zero external network egress
//     (s.Hermetic), so the build pulled no undeclared inputs. No trace ⇒
//     hermeticity is UNKNOWN ⇒ held at L2 (we never assume hermetic unobserved).
//
// This is deliberately conservative: a higher level is claimed ONLY when the run
// carries the evidence to back it, so release automation keying on
// slsa_build_level cannot be tricked into trusting non-isolated, non-hermetic
// provenance. platform is the targeted platform URL (empty ⇒ offline); it feeds
// the upgrade hint so the message names where the operator can sign.
//
// runFailed reports that the run did NOT successfully produce its signed
// evidence — a fatal signer/attestor error, or a non-zero wrapped command. The
// L1 floor is "a signed provenance attestation EXISTS", so a failed run has no
// floor to stand on: it is held at level 0 with an explicit "not assessed"
// verdict rather than claiming evidence the run never emitted (the overclaim a
// verifier or release gate keying on slsa_build_level must never be handed).
func (s *RunSummary) ComputeSLSA(platform string, runFailed bool) {
	// A failed run produced no completed, signed provenance — there is no L1
	// floor to claim. Report level 0 / not-assessed instead of overstating it.
	if runFailed {
		s.SLSABuildLevel = 0
		s.SLSAVerdict = "SLSA: not assessed — the build did not complete successfully, so no signed provenance was produced."
		return
	}

	// L1 floor: a signed provenance attestation exists.
	s.SLSABuildLevel = 1
	if !s.WorkflowIdentity {
		s.SLSAVerdict = "SLSA Build L1 (forgeable provenance — local key, offline, or an unattested signer). " +
			"For L2+ sign with an isolated platform workflow identity: " +
			"cilock login --workflow-identity --platform-url " + slsaPlatformHint(platform)
		return
	}

	// L2: non-forgeable provenance from an isolated platform workflow identity.
	s.SLSABuildLevel = 2
	if s.Tracing == "" {
		s.SLSAVerdict = "SLSA Build L2 (non-forgeable platform workflow identity). " +
			"For L3 prove the build is hermetic: re-run with --trace so cilock can attest zero network egress."
		return
	}
	if !s.Hermetic {
		s.SLSAVerdict = "SLSA Build L2 (non-forgeable platform workflow identity); the " + s.Tracing +
			"-traced build made network egress (" + slsaEgressHint(s.NetworkEgress) + ") so it is NOT hermetic. " +
			"L3 requires no undeclared network during the build."
		return
	}

	// L3: isolated workflow identity AND a traced, hermetic build.
	s.SLSABuildLevel = 3
	s.SLSAVerdict = "SLSA Build L3 (isolated, non-forgeable platform workflow identity; " +
		s.Tracing + "-traced build is hermetic — no external network egress)."
}

// slsaEgressHint renders a short, capped summary of the egress endpoints that
// broke hermeticity, for the L2 verdict — never an unbounded dump.
func slsaEgressHint(egress []string) string {
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

// slsaPlatformHint returns the platform URL to name in the L1→L3 upgrade hint,
// falling back to a readable placeholder when the run was fully offline so the
// message is still actionable.
func slsaPlatformHint(platform string) string {
	if platform == "" {
		return "<platform>"
	}
	return platform
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
		fmt.Fprintf(&b, "  anchor:     git remote %s\n", anchor)
	} else {
		b.WriteString("  anchor:     (no git remote subject — attestation will NOT correlate to a repo product)\n")
	}
	if s.Tenant != "" {
		fmt.Fprintf(&b, "  tenant:     %s\n", s.Tenant)
	}
	if s.SignerEmail != "" {
		fmt.Fprintf(&b, "  identity:   %s\n", s.SignerEmail)
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
			fmt.Fprintf(&b, "  gitoid:     %s\n", s.Gitoid)
		}
	} else if s.ArchivistaURL != "" {
		fmt.Fprintf(&b, "  archivista: %s (upload DISABLED — pass --enable-archivista to store)\n", s.ArchivistaURL)
	}
	if len(s.Subjects) > 0 {
		fmt.Fprintf(&b, "  subjects (%d): %s\n", len(s.Subjects), strings.Join(s.subjectNames(), ", "))
	}
	for _, a := range s.Attestors {
		fmt.Fprintf(&b, "  attestor:   %s — %s", a.Name, a.Status)
		if a.Detail != "" {
			b.WriteString(" (" + a.Detail + ")")
		}
		b.WriteByte('\n')
	}
	if s.WrappedCommand != nil {
		fmt.Fprintf(&b, "  command exit: %d\n", s.WrappedCommand.ExitCode)
	}
	s.writeKeyGuardLine(&b)
	// Build-isolation evidence behind the SLSA verdict (whether the wrapped
	// command was traced, and any network egress it made); empty for an untraced
	// build, which has nothing honest to say.
	b.WriteString(s.buildEvidenceLine())
	// The SLSA verdict — the achieved Build level — is the headline a user
	// needs before they over-trust a local-key signature. Print it last so it
	// is the final thing on screen. Echo the platform's assurance_level beside
	// it when a session supplied one.
	if s.SLSAVerdict != "" {
		fmt.Fprintf(&b, "  %s\n", s.SLSAVerdict)
	}
	if s.AssuranceLevel != "" {
		fmt.Fprintf(&b, "  platform assurance level: %s\n", s.AssuranceLevel)
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
	fmt.Fprintf(b, "  key guard:  signing key non-extractable (dumpable=%v, yama=%d)\n",
		kp.Dumpable, kp.YamaPtraceScope)
}

// buildEvidenceLine renders the human summary's "build:" line from the traced
// hermeticity evidence, or "" when the build was not traced (no honest claim to
// make). Split out of WriteHuman so that already-flat printer stays under the
// cognitive-complexity bar.
func (s *RunSummary) buildEvidenceLine() string {
	if s.Tracing == "" {
		return ""
	}
	if s.Hermetic {
		return fmt.Sprintf("  build:      hermetic (%s-traced, no external network egress)\n", s.Tracing)
	}
	return fmt.Sprintf("  build:      NOT hermetic (%s-traced, network egress: %s)\n", s.Tracing, slsaEgressHint(s.NetworkEgress))
}

// subjectNames returns the (sorted) subject names for the compact human line,
// trimmed of the common attestation predicate-URI prefix so the line stays
// scannable (e.g. "git/v0.1/remote:..." instead of the full
// "https://aflock.ai/attestations/git/v0.1/remote:..."). The JSON keeps the
// fully-qualified name.
func (s *RunSummary) subjectNames() []string {
	names := make([]string, 0, len(s.Subjects))
	for _, sub := range s.Subjects {
		names = append(names, shortSubjectName(sub.Name))
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
