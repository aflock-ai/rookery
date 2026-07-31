// Copyright 2026 The Archivista Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
)

// filterHubOnlyPassed applies the subject fan-out guard (see
// WithMaxSubjectFanout). Verification is anchored to the subject closure the
// workflow was dispatched for; its expected evidence set is on the order of
// ten attestations per commit. HUB digests — shared base-image layers, runner
// images, toolchain blobs — sit inside that closure too, and every other build
// in the tenant attests them, so an unguarded search admits the whole corpus
// into one verify.
//
// A closure digest named by more than maxFanout of THESE candidates is a hub.
// A candidate is admitted iff it intersects the closure on at least one
// NON-hub digest; candidates connected only through hubs are returned as
// rejections (visible in step results, never silently dropped).
//
// AUTHORIZATION IS THE CALLER'S PRECONDITION, and it is load-bearing. This
// operates on the step's FUNCTIONARY-AUTHORIZED collections only — the output
// of checkFunctionaries — so only evidence the policy authorizes FOR THIS STEP
// can classify a digest as a hub. Weaker bars are exploitable:
//
//   - Counting all candidates lets anyone who can upload an envelope naming a
//     victim's digest publish maxFanout+1 of them and suppress the victim's
//     genuine evidence.
//   - Counting merely crypto-valid candidates still lets a functionary of a
//     DIFFERENT step do it, since the policy trusts that key — privilege
//     escalation across steps.
//
// Either way the guard would become a denial-of-verification primitive, so
// hub classification rests only on evidence already authorized for this step.
//
// SOUNDNESS: this runs before the step gate's attestation checks and only ever
// removes candidates. Admitted candidates keep their verification results and
// still face the gate, so the guard can cause a false REJECT but never a false
// PASS. Evidence reachable through trust-gated BackRef expansion enters the
// closure as ordinary digests on the next depth iteration and is admitted
// unless it, too, exceeds the fan-out.
//
// A candidate with NO closure intersection is rejected (fail closed): with the
// guard active, an unmatched candidate is by definition outside the dispatch
// subject's closure. An empty closure disables the guard for that search
// (subject-agnostic whole-policy walks).
func filterHubOnlyPassed(passed []PassedCollection, closure []string, maxFanout int) (admitted []PassedCollection, rejected []RejectedCollection) {
	if maxFanout <= 0 || len(closure) == 0 || len(passed) == 0 {
		return passed, nil
	}

	admittingDigests, fanout := closureIntersections(passed, closure)

	hubs := make(map[string]struct{})
	for d, n := range fanout {
		if n > maxFanout {
			hubs[d] = struct{}{}
		}
	}

	admitted = make([]PassedCollection, 0, len(passed))
	for i, pc := range passed {
		nonHub, hubOnly := classifyAdmission(admittingDigests[i], hubs)
		if nonHub {
			admitted = append(admitted, pc)
			continue
		}
		rejected = append(rejected, RejectedCollection{
			Collection: compactHubReject(pc.Collection),
			Reason:     hubRejectReason(hubOnly, maxFanout),
		})
	}
	return admitted, rejected
}

// closureIntersections is pass 1 of the guard: for each authorized candidate,
// the set of its (matchable) subject digests that intersect the closure, plus
// the per-digest fan-out across this authorized set.
func closureIntersections(passed []PassedCollection, closure []string) ([]map[string]struct{}, map[string]int) {
	closureSet := make(map[string]struct{}, len(closure))
	for _, d := range closure {
		closureSet[d] = struct{}{}
	}

	admittingDigests := make([]map[string]struct{}, len(passed))
	fanout := make(map[string]int)
	for i, pc := range passed {
		ds := closureIntersectOne(pc.Collection.Statement.Subject, closureSet)
		admittingDigests[i] = ds
		for d := range ds {
			fanout[d]++
		}
	}
	return admittingDigests, fanout
}

// closureIntersectOne returns one candidate's matchable subject digests that
// intersect the closure set — the shared extraction behind the batch guard's
// closureIntersections and the streamed pipeline's fanoutTracker, so the two
// paths can never disagree on what counts as a candidate's closure
// connection.
func closureIntersectOne(subjects []intoto.Subject, closureSet map[string]struct{}) map[string]struct{} {
	ds := make(map[string]struct{})
	for _, sub := range subjects {
		for algorithm, digest := range sub.Digest {
			if !cryptoutil.IsMatchableSubjectDigest(algorithm, digest) {
				continue
			}
			if _, ok := closureSet[digest]; ok {
				ds[digest] = struct{}{}
			}
		}
	}
	return ds
}

// fanoutTracker is the streaming counterpart of the guard's counting pass
// (closureIntersections): it accumulates per-digest fan-out counts as
// functionary-AUTHORIZED candidates arrive, so the interleaved step pipeline
// can (a) skip gate evaluation for candidates that are ALREADY provably
// hub-only — counts only grow, so a candidate whose every closure digest has
// exceeded maxFanout can never be admitted by the final classification — and
// (b) reproduce the batch guard's end-of-set hub classification exactly
// (classifyAdmission over the final counts). The authorization precondition
// documented on filterHubOnlyPassed applies unchanged: only candidates that
// passed this step's functionary triage may be added.
type fanoutTracker struct {
	maxFanout  int
	closureSet map[string]struct{}
	fanout     map[string]int
}

// newFanoutTracker returns nil when the guard is disabled (non-positive
// limit or empty closure), mirroring filterHubOnlyPassed's no-op condition.
func newFanoutTracker(closure []string, maxFanout int) *fanoutTracker {
	if maxFanout <= 0 || len(closure) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(closure))
	for _, d := range closure {
		set[d] = struct{}{}
	}
	return &fanoutTracker{maxFanout: maxFanout, closureSet: set, fanout: map[string]int{}}
}

// add records one authorized candidate's subjects, returning its
// closure-intersection set and whether the candidate is already PROVABLY
// hub-only or closure-disjoint — a verdict later candidates can only confirm
// (fan-out counts are monotone), never reverse. Provably-rejected candidates
// need no gate evaluation: their gate verdict would be discarded by the
// final classification anyway, and skipping it bounds the guard-active
// pipeline's extra gate work at ~maxFanout evaluations per hub digest.
func (ft *fanoutTracker) add(subjects []intoto.Subject) (map[string]struct{}, bool) {
	ds := closureIntersectOne(subjects, ft.closureSet)
	provablyRejected := true
	for d := range ds {
		ft.fanout[d]++
		if ft.fanout[d] <= ft.maxFanout {
			provablyRejected = false
		}
	}
	return ds, provablyRejected
}

// hubs returns the final hub-digest set, valid once every authorized
// candidate has been added.
func (ft *fanoutTracker) hubs() map[string]struct{} {
	hubs := make(map[string]struct{})
	for d, n := range ft.fanout {
		if n > ft.maxFanout {
			hubs[d] = struct{}{}
		}
	}
	return hubs
}

// classifyAdmission reports whether any of the candidate's closure digests is
// a non-hub (admitting), and otherwise returns the sorted hub digests it
// connected through, for the rejection reason.
func classifyAdmission(digests map[string]struct{}, hubs map[string]struct{}) (nonHub bool, hubOnly []string) {
	hubOnly = make([]string, 0, len(digests))
	for d := range digests {
		if _, isHub := hubs[d]; !isHub {
			return true, nil
		}
		hubOnly = append(hubOnly, d)
	}
	sort.Strings(hubOnly)
	return false, hubOnly
}

func hubRejectReason(hubOnly []string, maxFanout int) error {
	if len(hubOnly) == 0 {
		return fmt.Errorf("subject fan-out guard: candidate attests none of the verification closure's subject digests")
	}
	return fmt.Errorf(
		"subject fan-out guard: candidate's only connection to the verification closure is hub digest(s) %s, each matched by more than %d authorized candidates — evidence from other builds sharing a hub subject is not admitted to this verify",
		strings.Join(hubOnly, ", "), maxFanout)
}

// compactHubReject strips the retained bodies from a hub-rejected result.
// Delegates to compactRejected (policy.go), the shared write-only-downstream
// compaction now applied to EVERY rejection path; relative to the original
// hub-only compaction it additionally preserves Collection.Name and Warnings,
// which judge's deny-reason extraction reads.
func compactHubReject(c source.CollectionVerificationResult) source.CollectionVerificationResult {
	return compactRejected(c)
}
