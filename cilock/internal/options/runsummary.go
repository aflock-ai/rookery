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
func (s *RunSummary) WriteHuman(w io.Writer) {
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
	_, _ = io.WriteString(w, b.String())
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
