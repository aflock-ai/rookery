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

package detection

import (
	"fmt"
	"sort"
	"strings"
)

// Capture completeness — the RUN-TIME half of the output contract.
//
// validateOutputContract (contract.go) is a BUILD-TIME check: it proves a
// detector.yaml is internally consistent. The testkit (attestation/testkit)
// is a TEST-TIME check: it proves an attestor matches its contract against a
// recorded fixture. Neither says anything about the run the user actually
// performed.
//
// That gap has a measured cost. The oci attestor's contract declares
// manifestdigest:, tardigest:, imageid:, imagetag: and layerdiffid<NN> — none
// of which is the REGISTRY manifest digest, the value Kubernetes reports in
// imageID and the one a human pastes when asking "what do you know about this
// image?". cilock ran, exited 0, and never told anyone the evidence would be
// unfindable by the identifier the user would actually search with.
//
// CheckCapture closes that loop: after an attestor runs, compare what it
// actually emitted against what its contract says SHOULD have been captured,
// and hand the caller an actionable delta.
//
// This check NEVER fails a run. A missing subject is a coverage gap, not a
// build error; turning it into a failure would make people stop running
// cilock, which loses far more evidence than the gap it reports.

// CaptureGap is one declared-but-absent subject family: the attestor's
// contract said this SHOULD have been captured, and the run did not produce
// it. It is both the human warning (Warning) and the machine-readable record
// (JSON tags) so a CI job or the platform can answer "where are we blind?"
// from capture-time data instead of querying production months later.
type CaptureGap struct {
	// Code is the stable diagnostic code, always CodeCaptureIncomplete.
	// Carried per-gap so a consumer can filter a mixed diagnostic stream.
	Code string `json:"code"`
	// Attestor is the plugin name whose contract declared the expectation.
	Attestor string `json:"attestor"`
	// Subject is the declared subject-key PREFIX that no emitted key matched.
	Subject string `json:"subject"`
	// Expectation is always|when-available, copied from the contract.
	Expectation string `json:"expectation"`
	// AvailableWhen is the precondition under which the subject is capturable
	// (when-available only; empty for always).
	AvailableWhen string `json:"available_when,omitempty"`
	// Remedy is the action the user takes to capture it next time — always the
	// "wrap the command that produces the evidence" pattern, never a flag to
	// paste. DERIVED from the detector's own match block unless the subject
	// overrode it.
	Remedy string `json:"remedy"`
	// RemedyDerived records whether Remedy came from the detector's match block
	// (true) or a hand-written override (false). Consumers auditing catalog
	// quality care about the difference: derived guidance cannot drift from
	// what cilock actually matches on; authored guidance can.
	RemedyDerived bool `json:"remedy_derived,omitempty"`
	// Description is the SubjectClaim's one-line description, so a consumer
	// rendering the gap need not re-open the catalog.
	Description string `json:"description,omitempty"`
}

// WarningLines renders the gap as user-facing text, ONE LINE PER ELEMENT.
// Callers log each line separately: the structured loggers used here render a
// multi-line message as a single logfmt field with literal "\n" escapes, which
// makes the remedy — the most important part — unreadable at exactly the
// moment it matters.
//
// Multi-element by design: the subject and the reason fit on a line each, but a
// remedy worth printing is a concrete command, and folding it into a one-line
// summary would defeat the point of having one.
func (g CaptureGap) WarningLines() []string {
	head := fmt.Sprintf("[%s] %s: %q was not captured", g.Code, g.Attestor, g.Subject)
	if g.Description != "" {
		head += " — " + g.Description
	}
	lines := []string{head}
	switch g.Expectation {
	case CaptureWhenAvailable:
		lines = append(lines, "    available when: "+g.AvailableWhen)
	case CaptureAlways:
		lines = append(lines, "    this attestor is expected to capture it on every run — the evidence is incomplete")
	}
	if g.Remedy == "" {
		// Defensive only: validateCaptureGuidance rejects at build time any
		// capture expectation whose remedy can be neither derived nor found
		// authored. A bare "remedy:" line would be noise if one slipped past.
		return lines
	}
	return append(lines, "    remedy: "+g.Remedy)
}

// Warning is WarningLines joined with newlines, for callers that want the whole
// block as one string (tests, a report renderer). Prefer WarningLines when
// writing to a structured logger.
func (g CaptureGap) Warning() string { return strings.Join(g.WarningLines(), "\n") }

// CaptureReport is the completeness result for a whole run — the
// machine-readable artifact. Attestors records which attestors were actually
// checked (i.e. had at least one capture expectation declared), so a consumer
// can tell "no gaps because the capture was complete" from "no gaps because
// nothing declared an expectation". Without that distinction an empty Gaps
// list is indistinguishable from an unmigrated catalog, and the report would
// launder a blind spot as a clean bill of health — the same failure mode
// OutputContract.Proven exists to prevent at build time.
type CaptureReport struct {
	// Gaps is every declared-but-absent subject across the run, ordered by
	// attestor then subject prefix for stable output.
	Gaps []CaptureGap `json:"gaps"`
	// Attestors is the sorted set of attestor names that carried at least one
	// capture expectation and were therefore meaningfully checked.
	Attestors []string `json:"checked_attestors"`
}

// Complete reports whether the run captured everything that was expected of
// it. Note this is only meaningful alongside Attestors: a report over a
// catalog that declares no expectations is trivially "complete".
func (r *CaptureReport) Complete() bool { return len(r.Gaps) == 0 }

// CheckCapture compares the subject keys an attestor actually emitted against
// the capture expectations its contract declares, returning one gap per
// declared subject family that no emitted key matched.
//
// Returns nil when the attestor has no detector.yaml, no contract, or no
// subject carries a capture block — the overwhelmingly common case today, and
// the reason rolling this out per-attestor is safe. Callers should only invoke
// it for attestors that ran SUCCESSFULLY: when Attest() returned an error the
// error is the signal, and a pile of capture warnings on top of it is noise.
func (r *Registry) CheckCapture(attestor string, subjectKeys []string) []CaptureGap {
	return r.CheckCaptureSupplemented(attestor, subjectKeys, nil)
}

// CheckCaptureSupplemented is CheckCapture with subject PROVENANCE:
// attestorKeys are what the attestor itself emitted; supplemental are
// operator-supplied keys (cilock's --subjects escape hatch) that land on the
// collection rather than on any attestor. Provenance matters because the two
// expectation levels make different claims:
//
//   - when-available says "when the precondition holds, the RUN's evidence
//     should be findable by this identifier" — an operator-supplied subject
//     genuinely closes that gap, and warning past it trains people to ignore
//     the whole class of signal;
//   - always says "THIS ATTESTOR emits this subject on every run". A pasted
//     value cannot make a failed attestor emission true — counting it would
//     mask the attestor-level failure and produce a false Complete() report.
func (r *Registry) CheckCaptureSupplemented(attestor string, attestorKeys, supplemental []string) []CaptureGap {
	d, ok, err := r.Lookup(attestor)
	if err != nil || !ok || d == nil || d.Contract == nil {
		return nil
	}
	// Derive once per attestor — the same match block feeds every subject.
	derived := deriveRemedy(d)

	var gaps []CaptureGap
	for _, s := range d.Contract.Subjects {
		if s.Capture == nil {
			continue
		}
		if subjectPrefixPresent(attestorKeys, s.Prefix) {
			continue
		}
		if s.Capture.Expectation == CaptureWhenAvailable && subjectPrefixPresent(supplemental, s.Prefix) {
			continue
		}
		// Derivation is the DEFAULT path; a hand-written remedy is an override
		// for the narrow case where the subject's precondition is tighter than
		// the detector's overall match block.
		remedy, isDerived := derived, true
		if s.Capture.Remedy != "" {
			remedy, isDerived = s.Capture.Remedy, false
		}
		gaps = append(gaps, CaptureGap{
			Code:          CodeCaptureIncomplete,
			Attestor:      attestor,
			Subject:       s.Prefix,
			Expectation:   s.Capture.Expectation,
			AvailableWhen: s.Capture.AvailableWhen,
			Remedy:        remedy,
			RemedyDerived: isDerived,
			Description:   s.Description,
		})
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Subject < gaps[j].Subject })
	return gaps
}

// CheckCapture is the shorthand for Default().CheckCapture.
func CheckCapture(attestor string, subjectKeys []string) []CaptureGap {
	return defaultRegistry.CheckCapture(attestor, subjectKeys)
}

// BuildCaptureReport assembles the run-level report from a map of attestor
// name -> the subject keys that attestor emitted. Only attestors present in
// the map are considered; an attestor that failed to run should be omitted by
// the caller rather than passed with an empty slice, which would report every
// expectation as a gap.
func (r *Registry) BuildCaptureReport(emitted map[string][]string) *CaptureReport {
	return r.BuildCaptureReportSupplemented(emitted, nil)
}

// BuildCaptureReportSupplemented is BuildCaptureReport with run-level
// supplemental subjects (operator --subjects entries). They are offered to
// every attestor's check but — see CheckCaptureSupplemented — can only
// satisfy when-available expectations, never an attestor-level always.
func (r *Registry) BuildCaptureReportSupplemented(emitted map[string][]string, supplemental []string) *CaptureReport {
	rep := &CaptureReport{}
	names := make([]string, 0, len(emitted))
	for name := range emitted {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !r.hasCaptureExpectations(name) {
			continue
		}
		rep.Attestors = append(rep.Attestors, name)
		rep.Gaps = append(rep.Gaps, r.CheckCaptureSupplemented(name, emitted[name], supplemental)...)
	}
	return rep
}

// BuildCaptureReport is the shorthand for Default().BuildCaptureReport.
func BuildCaptureReport(emitted map[string][]string) *CaptureReport {
	return defaultRegistry.BuildCaptureReport(emitted)
}

// BuildCaptureReportSupplemented is the shorthand for
// Default().BuildCaptureReportSupplemented.
func BuildCaptureReportSupplemented(emitted map[string][]string, supplemental []string) *CaptureReport {
	return defaultRegistry.BuildCaptureReportSupplemented(emitted, supplemental)
}

// hasCaptureExpectations reports whether the attestor's contract declares any
// capture expectation at all — i.e. whether checking it means anything.
func (r *Registry) hasCaptureExpectations(attestor string) bool {
	d, ok, err := r.Lookup(attestor)
	if err != nil || !ok || d == nil || d.Contract == nil {
		return false
	}
	for _, s := range d.Contract.Subjects {
		if s.Capture != nil {
			return true
		}
	}
	return false
}

// subjectPrefixPresent reports whether any emitted subject key belongs to the
// declared family. Subject keys carry dynamic tails (a digest, a tag, a
// zero-padded index), so membership is by prefix — the same rule the contract
// uses everywhere else.
func subjectPrefixPresent(keys []string, prefix string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Derived guidance
// ---------------------------------------------------------------------------
//
// The directions were already in the detector.yaml. Every detector declares the
// commands that produce its evidence — that IS the guidance, and cilock's whole
// teaching is "wrap the command that produces the thing and we capture it".
//
// So a capture remedy is DERIVED from the detector's own match block rather
// than hand-authored per attestor. That is not just less typing:
//
//   - ~40 detectors get correct guidance for free as they opt in.
//   - It cannot drift. Authored copy goes stale the moment someone edits a
//     match pattern; derived text updates itself.
//   - It is honest: it states exactly what cilock looks for, not a paraphrase
//     someone wrote once.
//
// A hand-written Remedy on the subject remains available as an OVERRIDE for
// the cases derivation genuinely cannot express — specifically, a subject whose
// capture precondition is NARROWER than the detector's overall match block, so
// that the derived list would name a command that cannot in fact produce it.

// deriveRemedy renders capture guidance from a detector's pre/post match
// blocks. Returns "" when the detector declares nothing usable.
//
// argv matches and product globs are rendered DIFFERENTLY on purpose: "wrap
// this command" and "produce this artifact" are different instructions to a
// human, and a glob is not something you can wrap.
func deriveRemedy(d *DetectorYAML) string {
	if d == nil {
		return ""
	}
	cmds := map[string]bool{}
	globs := map[string]bool{}
	for _, g := range []*GateBlock{d.Pre, d.Post} {
		if g == nil {
			continue
		}
		// A conjunctive match cannot be honestly rendered by this function's
		// flat or-joined list: all_of means the user must satisfy EVERY
		// branch at once, and flattening it into alternatives would
		// recommend an action that still won't match or capture anything.
		// Refuse to derive instead — validateCaptureGuidance then makes the
		// author state the compound instruction as an explicit
		// capture.remedy at build time.
		if containsConjunction(g.Match) {
			return ""
		}
		collectMatchDirections(g.Match, cmds, globs)
	}

	var parts []string
	if len(cmds) > 0 {
		parts = append(parts, "wrap the command that produces it — cilock captures this from "+joinQuoted(sortedKeys(cmds)))
	}
	if len(globs) > 0 {
		// Patterns are quoted VERBATIM (see globGuidance); only globs with no
		// literal content at all are dropped.
		parts = append(parts, "or produce a file matching "+joinQuoted(sortedKeys(globs))+" under the working dir")
	}
	return strings.Join(parts, ", ")
}

// containsConjunction reports whether the predicate tree requires multiple
// conditions to hold at once — an all_of with two or more branches, at any
// depth. The evaluator enforces exactly one tag per node (predicateTags), so
// all_of is the only way the schema can express conjunction. Branches under
// not: are ignored, mirroring collectMatchDirections: a negation contributes
// no positive guidance either way.
func containsConjunction(p *Predicate) bool {
	if p == nil {
		return false
	}
	if len(p.AllOf) >= 2 {
		return true
	}
	for i := range p.AnyOf {
		if containsConjunction(&p.AnyOf[i]) {
			return true
		}
	}
	for i := range p.AllOf {
		if containsConjunction(&p.AllOf[i]) {
			return true
		}
	}
	return containsConjunction(p.ExecObserved)
}

// collectMatchDirections walks a predicate tree gathering the two direction
// shapes: argv prefixes (commands to wrap) and product globs (artifacts to
// produce). Negations are skipped — "don't run X" is not guidance.
func collectMatchDirections(p *Predicate, cmds, globs map[string]bool) {
	if p == nil {
		return
	}
	for i := range p.AnyOf {
		collectMatchDirections(&p.AnyOf[i], cmds, globs)
	}
	for i := range p.AllOf {
		collectMatchDirections(&p.AllOf[i], cmds, globs)
	}
	// p.Not is deliberately NOT walked: a negated branch describes what must
	// be absent, which inverted into guidance would tell the user to run the
	// one thing that stops the attestor firing.
	collectMatchDirections(p.ExecObserved, cmds, globs)

	if len(p.ArgvPrefix) > 0 {
		cmds[strings.Join(p.ArgvPrefix, " ")] = true
	}
	for _, g := range p.ProductGlob {
		if pattern := globGuidance(g); pattern != "" {
			globs[pattern] = true
		}
	}
}

// globGuidance returns the glob VERBATIM for guidance, or "" for a glob with
// no literal content at all ("*", "**", "**/*") — "produce a file matching *"
// is noise, and a detector gated only on such a glob must author its remedy
// (validateCaptureGuidance enforces that).
//
// Verbatim is deliberate and load-bearing. Two review rounds each caught a
// "readability" reduction misrecommending: stripping directory components
// told the user to produce dist/report.json at the root (which the pattern
// does not match), and collapsing a leading "*/" read a one-directory-deep
// requirement as any-depth (the matcher does not permit zero components for
// either "*/" or "**/"). Guidance derived from a pattern must never claim
// more or less than the pattern — the only transformation that cannot lie is
// none.
func globGuidance(g string) string {
	if strings.Trim(g, "*/") == "" {
		return ""
	}
	return g
}

func joinQuoted(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, s := range items {
		quoted = append(quoted, "`"+s+"`")
	}
	switch len(quoted) {
	case 1:
		return quoted[0]
	case 2:
		return quoted[0] + " or " + quoted[1]
	default:
		return strings.Join(quoted[:len(quoted)-1], ", ") + ", or " + quoted[len(quoted)-1]
	}
}
