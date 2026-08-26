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

// This file is the ONLY place in the package that produces a verdict about the
// ancestry.
//
// It is a separate file for the same reason fsutil.go is: a guard whose
// allowlist names the file that also contains the walk cannot tell the
// chokepoint from a bypass sitting next to it. Keeping walkCoverage here means
// TestVerdictsAreOnlyProducedByWalkCoverage fails if detector.go — or anything
// else — assigns a verdict directly.
//
// Verified by disabling the fix: with the coverage type still in detector.go,
// reintroducing `out.Status = StatusDetected` in the walk passed the guard.
// After the split it fails.

import "strings"

// walkCoverage is everything the walk OBSERVED, and the only thing a verdict is
// ever computed from.
//
// This is the binding, and it exists because the previous round bound one
// verdict and left the others. not-detected was gated on whether the ancestry
// had been fully examined; detected was assigned directly at the match site and
// returned early, bypassing the gate entirely — so a match found PAST an
// unreadable ancestor was still signed as "the invoker", even though the
// unreadable process might itself have been a nearer agent and first-agent-wins
// is this attestor's central invariant.
//
// No verdict is assigned anywhere now. Every exit path records what it saw here
// and the status is DERIVED, so a future exit path cannot emit a claim without
// its evidence: forgetting to record something yields incomplete, never a
// stronger answer. Same polarity as identityCoverage and the same reason.
// TestVerdictsAreOnlyProducedByWalkCoverage pins it.
type walkCoverage struct {
	// unexamined describes ancestors whose identity reads did not all succeed.
	// Any entry makes every positive verdict unsupportable: for not-detected
	// because an unread process might have been an agent, and for detected
	// because an unread process NEARER than the match might have been the
	// agent instead.
	unexamined []string

	// stopped explains why the walk ended before reaching a root, or "" when it
	// reached one. Stopping BECAUSE a provider matched is not an early stop:
	// everything beyond the invoker is deliberately not examined.
	stopped string

	// matched records that a provider claimed a process.
	matched bool

	// unbound explains a match whose identity the executable snapshot could
	// not confirm: the match-time fingerprint rested on a resolution the
	// digested handle does not share (a symlink retargeted between the two
	// reads, or a resolution the snapshot could not re-establish). The match
	// happened, so the walk stopped there — but naming that process as the
	// invoker would pair an identity claim with a digest that does not
	// support it, so any entry here withholds every positive verdict.
	unbound string
}

// verdict computes the status. It is the ONLY place a verdict value is
// produced.
//
// Order matters: completeness is consulted before the outcome, because an
// ancestry that was not fully examined cannot support ANY positive claim about
// which process invoked cilock — neither "it was this one" nor "there was
// none".
func (c walkCoverage) verdict() ObservationStatus {
	if c.stopped != "" || len(c.unexamined) > 0 || c.unbound != "" {
		return StatusIncomplete
	}
	if c.matched {
		return StatusDetected
	}
	return StatusNotDetected
}

// explain returns the warnings that justify the computed verdict.
func (c walkCoverage) explain() []string {
	var out []string
	if c.stopped != "" {
		out = append(out, c.stopped)
	}
	if c.unbound != "" {
		out = append(out, c.unbound)
	}
	if len(c.unexamined) > 0 {
		detail := "ancestry examined incompletely: " + strings.Join(c.unexamined, "; ") +
			". A provider may match on any of these sources, so no claim is made about whether these ancestors were agents."
		if c.matched {
			detail += " An agent was matched further out, but a nearer process could not be ruled out as the real invoker, so none is named."
		}
		out = append(out, detail)
	}
	if c.verdict() == StatusNotDetected {
		out = append(out, "no supported coding agent found in cilock's process ancestry")
	}
	return out
}
