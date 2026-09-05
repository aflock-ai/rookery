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

package source

// IsDiagnosticProbe reports whether a search carrying these subject digests is
// the DIAGNOSTIC PROBE rather than a real evidence search.
//
// attestation/policy's diagnoseEmptyCollectionResult calls
// Search(ctx, stepName, nil, attestations) — an EMPTY digest set — purely to
// ask "does ANY collection exist for this step name?" after a digest-filtered
// search came back empty, so it can report ErrNoCollections or
// ErrSubjectDigestMismatch. The engine itself can never issue such a search:
// checkVerifyOpts rejects a Verify with no subject digests, so every search on
// the verification path is digest-filtered. An empty digest set therefore
// identifies the probe exactly.
//
// A seen-tracking Sourcer MUST gate BOTH halves of its seen-set on this
// predicate, and they must move together — gating one and not the other trades
// one defect for another:
//
//   - EXCLUSION. Excluding already-returned gitoids from a probe makes it
//     answer about the UNSEEN REMAINDER instead of the corpus, reporting
//     ErrNoCollections for a step whose collections exist and were merely
//     already returned — the probe misdiagnoses the exact case it was added to
//     explain.
//   - MARKING. Worse: a probe matches EVERY collection for the step name, so
//     recording them feeds the exclusion above and permanently suppresses that
//     step's legitimate evidence from every later depth iteration. Evidence
//     that only becomes reachable at a later depth (its subject digest
//     discovered via a back-reference) is then never adjudicated, and a policy
//     that should PASS fails with nothing in the logs to explain it
//     (testifysec/judge#7592).
//
// A diagnostic must not mutate what the search can still find.
//
// The rule lives here, as ONE exported predicate, because it was implemented
// twice and drifted: judge-api's EntSource gated both halves while
// ArchivistaSource gated neither, so the two sources returned different
// evidence for the same sequence of searches. Both now call this; there is a
// single definition to change and no second copy to forget.
func IsDiagnosticProbe(subjectDigests []string) bool {
	return len(subjectDigests) == 0
}
