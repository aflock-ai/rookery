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
	"fmt"
	"strconv"
	"strings"
)

const (
	// DefaultMaxDepth bounds the ancestry walk. Real layouts observed in
	// practice are 2-5 deep; 32 is generous headroom that still terminates on a
	// pathological tree.
	DefaultMaxDepth = 32

	// DefaultMaxVendorChain bounds the same-vendor extension walk a provider
	// may inspect. Claude Code's macOS daemon chain is 2 deep.
	DefaultMaxVendorChain = 8

	detectionMethod = "process-ancestry"
)

// Detector walks cilock's process ancestry and identifies the invoking agent.
type Detector struct {
	Source         ProcessSource
	Providers      []Provider
	MaxDepth       int
	MaxVendorChain int

	// DigestSizeLimit caps executable digesting in the snapshot taken for a
	// matched process. Zero or negative disables digesting, matching
	// WithDigestSizeLimit; NewDetector fills in the default.
	DigestSizeLimit int64

	// EnvValueKeep is the run-wide environment redaction policy handed to
	// providers through InspectRequest; see InspectRequest.EnvValueKeep. Nil
	// imposes nothing beyond the provider allowlists and the credential
	// backstop.
	EnvValueKeep func(key, value string) bool
}

// NewDetector builds a detector with the default bounds.
func NewDetector(src ProcessSource, providers []Provider) *Detector {
	return &Detector{
		Source:          src,
		Providers:       providers,
		MaxDepth:        DefaultMaxDepth,
		MaxVendorChain:  DefaultMaxVendorChain,
		DigestSizeLimit: DefaultDigestSizeLimit,
	}
}

// Detection is the raw outcome of a walk, before redaction.
type Detection struct {
	Status   ObservationStatus
	Provider Provider
	Process  ProcessInfo
	Match    MatchResult
	Chain    []ProcessInfo
	Ancestry []AncestorRef

	// Image is the single snapshot of the matched process's executable, taken
	// when the match won and BEFORE inspection ran. Every predicate field
	// that describes the executable — resolved path, size, digest, and any
	// version parsed from the resolved path — derives from it, so the fields
	// cannot describe different binaries. Zero-valued unless Status is
	// detected.
	//
	// Named Image rather than Executable because ProcessInfo.Executable is a
	// PATH: one name for both invited exactly the confusion the snapshot
	// exists to prevent.
	Image executableSnapshot

	Inspection Inspection
	Warnings   []string
}

// Detect walks from selfPID's parent outwards and stops at the first process a
// provider positively identifies.
//
// The stop is unconditional and is the central invariant of this attestor:
// cilock is invoked BY a coding agent, so the nearest recognized agent is the
// invoker. A chain of cilock -> bash -> codex -> cursor-agent attests Codex.
// There is no notion of a "better" outer agent, and no scoring across
// candidates at different depths — that would let an outer process claim credit
// for work an inner one actually drove.
//
// A walk that COMPLETES and finds nothing is a successful walk and reports
// not-detected. A walk that ends early — cancelled, an unreadable ancestor, a
// PPID loop, the depth budget — reports incomplete instead: not-detected is a
// positive claim about the whole ancestry, and a walk that never examined part
// of it cannot make that claim. Neither case is an error; the only error
// returned is the one case where the attestor could not look at all.
func (d *Detector) Detect(ctx context.Context, selfPID int, repoRoot string) (Detection, error) {
	var out Detection
	if d.Source == nil {
		return Detection{Status: StatusUnavailable}, fmt.Errorf("alps-evidence: no process source configured")
	}

	maxDepth := d.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}

	self, err := d.Source.ReadProcess(selfPID)
	if err != nil {
		// This is the "couldn't look" case: without our own process we have no
		// starting point. Everything downstream of here is an observation gap,
		// not a failure.
		return Detection{Status: StatusUnavailable}, fmt.Errorf("alps-evidence: read self process %d: %w", selfPID, err)
	}

	pid := self.PPID
	seen := map[int]struct{}{selfPID: {}}

	// Everything observed goes here; the verdict is computed from it at the
	// single exit below.
	var coverage walkCoverage

	for depth := 0; depth < maxDepth && pid > 0; depth++ {
		if ctx.Err() != nil {
			// A cancelled walk yields a partial observation, not a failure.
			// The collection is being torn down; reporting an error here would
			// convert an unrelated shutdown into an attestor error. It is
			// still not a completed walk, so it must not read as not-detected.
			coverage.stopped = "ancestry walk cancelled before completion"
			break
		}
		if _, dup := seen[pid]; dup {
			// A PPID chain that loops never reached a root; whatever sits
			// beyond the recycled PID was not examined.
			coverage.stopped = "ancestry loop detected; walk stopped"
			break
		}
		seen[pid] = struct{}{}

		p, perr := d.Source.ReadProcess(pid)
		if perr != nil {
			// An ancestor owned by another user, or one that exited mid-walk.
			// The ancestry beyond it was never examined, so nothing can be
			// claimed about it.
			coverage.stopped = fmt.Sprintf("ancestor pid %d not readable; walk stopped short", pid)
			break
		}

		provider, match := d.matchProviders(p)

		// An ancestor whose identity could not be fully read was not examined,
		// whatever the match said: a provider might have matched on exactly the
		// source that was missing. Recorded here and settled after the loop, so
		// the walk still CONTINUES — the agent may be further out — while the
		// not-detected verdict becomes unavailable.
		if !p.fullyExamined() {
			coverage.unexamined = append(coverage.unexamined, describeIdentityGaps(p))
		}

		program, programFrom := ancestorProgram(p)
		out.Ancestry = append(out.Ancestry, AncestorRef{
			PID:         p.PID,
			PPID:        p.PPID,
			Program:     program,
			ProgramFrom: programFrom,
			Matched:     match.Matched,
			MatchedBy:   match.Fingerprint,
		})

		if match.Matched {
			// The walk is over, but the verdict is not decided here: a match
			// found past an ancestor that could not be examined cannot claim
			// to be the NEAREST agent, and naming it would break
			// first-agent-wins. Record and fall through to the one exit.
			d.recordMatch(ctx, &out, &coverage, matchedProcess{provider: provider, process: p, match: match}, repoRoot, self)
			pid = 0
			break
		}

		if p.PPID == p.PID {
			// A process naming ITSELF as its parent is the degenerate PPID
			// cycle, not a root: real roots report PPID 0, which ends the
			// walk through the loop condition as a COMPLETED walk. This edge
			// means the chain the kernel reported never reached a root, and
			// whatever sits beyond it was not examined — so it is recorded
			// exactly like the longer loop above (the seen-map would catch
			// it one iteration later; recording it here names the pid). An
			// earlier shape of this branch treated the self-parent as a
			// root and signed not-detected: an absence claim about a walk
			// that never completed.
			coverage.stopped = fmt.Sprintf("pid %d reports itself as its own parent; ancestry loop, walk stopped", p.PID)
			pid = 0
			break
		}
		pid = p.PPID
	}

	if coverage.stopped == "" && !coverage.matched && pid > 0 {
		// The loop can only exit with a live, unexamined parent when the depth
		// budget ran out; every other early exit either cleared pid or already
		// recorded why it stopped. The agent could be one process further out,
		// so a completed-walk claim is not available.
		coverage.stopped = fmt.Sprintf("ancestry walk truncated at depth %d before reaching a root process", maxDepth)
	}

	// The single exit. Every verdict in this package is produced here.
	out.Status = coverage.verdict()
	out.Warnings = append(out.Warnings, coverage.explain()...)
	return out, nil
}

// recordMatch marks the walk's positive identification in the coverage record
// and reconciles the just-appended ancestry entry with what observeMatch could
// actually bind to the digested image.
func (d *Detector) recordMatch(ctx context.Context, out *Detection, coverage *walkCoverage, m matchedProcess, repoRoot string, self ProcessInfo) {
	coverage.matched = true
	coverage.unbound = d.observeMatch(ctx, out, m, repoRoot, self)
	entry := &out.Ancestry[len(out.Ancestry)-1]
	if coverage.unbound != "" {
		// The match could not be bound to the digested image, so the
		// verdict degrades — and the ancestry must degrade WITH it.
		// The entry above was appended with Matched:true and the
		// match-time fingerprint; leaving those in place publishes,
		// inside the signed predicate, exactly the identity claim the
		// snapshot just declined to support. The warning recorded
		// from coverage.unbound carries what happened; the entry
		// itself claims nothing.
		entry.Matched = false
		entry.MatchedBy = ""
		return
	}
	// observeMatch may have re-bound the fingerprint to the
	// snapshot's own resolution; the ancestry entry appended
	// above must name the fingerprint the predicate publishes,
	// not a superseded match-time one.
	entry.MatchedBy = out.Match.Fingerprint
}

// describeIdentityGaps renders one ancestor's unread identity sources for a
// warning. Only the pid and the source NAMES appear: a warning enters the
// signed predicate, where a path would leak a filesystem location.
func describeIdentityGaps(p ProcessInfo) string {
	gaps := p.identityGaps()
	names := make([]string, 0, len(gaps))
	for _, gap := range gaps {
		names = append(names, string(gap))
	}
	return "pid " + strconv.Itoa(p.PID) + " could not be read for " + strings.Join(names, ", ")
}

// matchedProcess is the walk's verdict: this process, claimed by this
// provider, by this rule. Grouped so observeMatch takes the decision as one
// value rather than three positional arguments that could drift apart.
type matchedProcess struct {
	provider Provider
	process  ProcessInfo
	match    MatchResult
}

// observeMatch records everything that follows from a positive identification:
// the ONE executable snapshot, the vendor chain, and the provider's
// inspection.
//
// It is separate from the walk deliberately. The walk decides WHICH process is
// the invoker; this decides what may be said about it, and the ordering here is
// load-bearing. The snapshot is taken BEFORE inspection runs, and the snapshot
// itself — not a path extracted from it — is what the provider is handed, so no
// loose path exists that a provider could pair with the wrong bytes.
//
// The returned string is empty when the match is bound to the snapshot, and
// otherwise explains why it is not; the caller records it as coverage, where
// it withholds every positive verdict (see walkCoverage.unbound).
func (d *Detector) observeMatch(ctx context.Context, out *Detection, m matchedProcess, repoRoot string, self ProcessInfo) (unbound string) {
	// Deliberately no status assignment: what was FOUND and what may be
	// CLAIMED are different questions, and only walkCoverage.verdict answers
	// the second.
	out.Provider = m.provider
	out.Process = m.process
	out.Match = m.match
	out.Image = snapshotExecutable(d.Source, m.process, d.DigestSizeLimit)
	out.Warnings = append(out.Warnings, out.Image.warnings...)

	// Match and snapshot each resolved the executable independently, and only
	// the snapshot's resolution is bound to the digested handle. A symlink
	// retargeted between the match-time readlink and the snapshot's open
	// would otherwise leave a fingerprint describing one binary beside a
	// digest describing another — so the match is REVALIDATED against the
	// snapshot's resolution, and what the predicate publishes is the
	// revalidated result. A match the digested image cannot confirm is an
	// observation gap: no agent-specific inspection runs, and the verdict
	// degrades instead of naming an invoker.
	switch resolved := out.Image.resolved(); {
	case resolved != "" && resolved != m.process.Executable:
		// Rebuilt through the identity builder rather than mutated — identity
		// fields are assigned only there (guard-pinned) — and used ONLY to ask
		// the provider whether it still claims a process whose image is the
		// snapshot's own resolution. It is never published.
		revalidated := newProcessInfo(m.process.PID, m.process.PPID, m.process.StartTime).
			executable(resolved, nil).
			comm(m.process.Comm, nil).
			argv(m.process.Argv, nil).
			build()
		rm := m.provider.Match(revalidated)
		if !rm.Matched {
			return fmt.Sprintf("pid %d matched by fingerprint %q at walk time, but the executable image that was digested does not support that identity; the match may describe a binary the process is no longer running", m.process.PID, m.match.Fingerprint)
		}
		out.Match = rm
	case resolved == "" && m.match.ViaResolution:
		return fmt.Sprintf("pid %d matched by fingerprint %q via a match-time symlink resolution that the executable snapshot could not re-establish, so the identity is not bound to any digested image", m.process.PID, m.match.Fingerprint)
	case resolved == m.process.Executable && m.match.ViaResolution:
		// A ViaResolution match means the match-time resolution DIFFERED from
		// the recorded path — that difference is what let the resolved-path
		// rule fire at all. The snapshot then resolving the recorded path to
		// ITSELF contradicts that: the symlink the fingerprint rested on was
		// swapped for a regular file between the two reads, and the file the
		// snapshot digested is not the target the match described. Publishing
		// the match-time fingerprint beside this digest would pair an
		// identity claim with bytes that do not support it — the same refusal
		// as the unresolvable case above, reached from the other side.
		return fmt.Sprintf("pid %d matched by fingerprint %q via a match-time symlink resolution, but by snapshot time the recorded path resolved to itself — the link was replaced with a regular file, and the digested image does not support the match-time identity", m.process.PID, m.match.Fingerprint)
	}

	out.Chain = d.vendorChain(m.provider, m.process)
	out.Inspection = m.provider.Inspect(ctx, InspectRequest{
		RepoRoot:     repoRoot,
		Process:      m.process,
		Executable:   out.Image,
		VendorChain:  out.Chain,
		Source:       d.Source,
		Self:         self,
		EnvValueKeep: d.EnvValueKeep,
	})
	return ""
}

// matchProviders asks every provider about one process. Providers are consulted
// in registration order; the first to claim the process wins it.
//
// Two providers claiming the same process would be a bug in their fingerprints,
// not a ranking problem, so there is deliberately no scoring here.
func (d *Detector) matchProviders(p ProcessInfo) (Provider, MatchResult) {
	for _, provider := range d.Providers {
		if m := provider.Match(p); m.Matched {
			return provider, m
		}
	}
	return nil, MatchResult{}
}

// vendorChain returns the matched process followed by the contiguous run of
// ancestors that the same provider also matches.
//
// The walk stops at the first process the provider does not claim. It can
// therefore never reach a different vendor, which is what keeps
// first-agent-wins intact while still letting a provider read state that its
// own product spread across several processes.
func (d *Detector) vendorChain(provider Provider, start ProcessInfo) []ProcessInfo {
	limit := d.MaxVendorChain
	if limit <= 0 {
		limit = DefaultMaxVendorChain
	}

	chain := []ProcessInfo{start}
	seen := map[int]struct{}{start.PID: {}}
	pid := start.PPID

	for len(chain) < limit && pid > 0 {
		if _, dup := seen[pid]; dup {
			break
		}
		seen[pid] = struct{}{}

		p, err := d.Source.ReadProcess(pid)
		if err != nil {
			break
		}
		if !provider.Match(p).Matched {
			break
		}
		chain = append(chain, p)
		if p.PPID == p.PID {
			break
		}
		pid = p.PPID
	}
	return chain
}

// ancestorProgram picks the basename to publish for an ancestor, and NAMES
// which process fact it came from.
//
// Only a basename ever escapes: an ancestor's full argv and path belong to
// other work on the machine. A measured example on macOS is Claude Code's
// daemon, whose argv carries a --spawned-by JSON blob naming an unrelated
// checkout's working directory.
//
// The basis is published because the three sources are not equally
// trustworthy and the resulting string cannot be told apart. An ancestor whose
// image path the kernel would not disclose contributes the title it wrote for
// ITSELF, and an entry reading `program: "gemini"` must not be mistaken for the
// kernel's record of what was exec'd — the same distinction the match
// fingerprints make, in the same vocabulary.
//
// The order is strongest-first for the same reason, which also corrects an
// inversion: the previous fallback preferred the self-declared argv[0] over the
// kernel's own comm.
func ancestorProgram(p ProcessInfo) (name, basis string) {
	if base := executableBase(p); base != "" {
		return base, basisExecutableBase
	}
	if comm := commBase(p); comm != "" {
		return comm, basisKernelComm
	}
	if prog := argvProgram(p); prog != "" {
		return prog, basisArgv0Title
	}
	// Nothing named the process at all. An empty basis beside an empty name
	// keeps the pair from claiming a provenance for a value that is absent.
	return "", ""
}
