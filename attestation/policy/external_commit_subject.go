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

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
)

// externalCommitSubjects collects, per predicate type, every commitSubject a
// policy declares, sorted and de-duplicated.
func externalCommitSubjects(externals map[string]ExternalAttestation) map[string][]string {
	out := map[string][]string{}
	for _, name := range sortedNames(externals) {
		ext := externals[name]
		if ext.CommitSubject == "" {
			continue
		}
		prefixes := out[ext.PredicateType]
		if !slices.Contains(prefixes, ext.CommitSubject) {
			prefixes = append(prefixes, ext.CommitSubject)
			sort.Strings(prefixes)
		}
		out[ext.PredicateType] = prefixes
	}
	return out
}

// searchExternal searches one predicate type. With no declared commit subject
// it is the historical SearchByPredicateType call, unchanged. With some, it
// uses the options search when the verified source offers one; a source that
// does not keeps the strict guard, so it can only admit less.
func searchExternal(ctx context.Context, vo *verifyOptions, predicateType string, declared []string) ([]source.StatementEnvelope, error) {
	if len(declared) > 0 {
		if withOpts, ok := vo.verifiedSource.(source.PredicateSearcherWithOptions); ok {
			return withOpts.SearchByPredicateTypeWithOptions(ctx, []string{predicateType}, vo.subjectDigests,
				source.PredicateSearchOptions{CommitSubjects: map[string][]string{predicateType: declared}})
		}
	}
	return vo.verifiedSource.SearchByPredicateType(ctx, []string{predicateType}, vo.subjectDigests)
}

// ExternalCandidateDiagnostic describes one external candidate that was
// refused: its reference, the subjects its payload names ("name (alg,alg)"),
// and why it was refused. It exists for error text; it is not a verdict.
type ExternalCandidateDiagnostic struct {
	Reference       string
	Subjects        []string
	SubjectsOmitted int
	Reason          string
}

// Bounds on refused-candidate diagnostics. Whoever can upload evidence
// chooses how many candidates there are and what their subjects and deny
// messages say, so the rendered text is capped at every level.
const (
	maxExternalDiagnosticCandidates = 5
	maxExternalDiagnosticReason     = 600
)

// externalCandidateDiagnostics renders at most maxExternalDiagnosticCandidates
// refused candidates, in the (canonical) order given; omitted is the rest.
func externalCandidateDiagnostics(refused []RejectedExternal) ([]ExternalCandidateDiagnostic, int) {
	n := len(refused)
	if n > maxExternalDiagnosticCandidates {
		n = maxExternalDiagnosticCandidates
	}
	out := make([]ExternalCandidateDiagnostic, 0, n)
	for _, r := range refused[:n] {
		d := ExternalCandidateDiagnostic{Reference: r.Envelope.Reference}
		payload := r.Envelope.Envelope.Payload
		if len(payload) == 0 {
			// A directly-constructed envelope: its Statement is all there is.
			if b, err := json.Marshal(r.Envelope.Statement); err == nil {
				payload = b
			}
		}
		d.Subjects, d.SubjectsOmitted = source.SignedSubjectSummary(payload)
		if r.Reason != nil {
			d.Reason = clipDiagnostic(r.Reason.Error(), maxExternalDiagnosticReason)
		}
		out = append(out, d)
	}
	return out, len(refused) - n
}

func clipDiagnostic(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("… (%d bytes omitted)", len(s)-n)
}

// writeExternalSearchDiagnostics appends what was searched, what was found and
// why each listed candidate was refused. It writes nothing when the error
// carries no diagnostics (an error built by hand), so that text is unchanged.
func writeExternalSearchDiagnostics(b *strings.Builder, requested []string, candidates int, refused []ExternalCandidateDiagnostic, omitted int) {
	if len(requested) == 0 && candidates == 0 && len(refused) == 0 {
		return
	}
	fmt.Fprintf(b, ": searched for subjects [%s]; %d candidate(s) found", strings.Join(requested, ", "), candidates)
	if candidates == 0 && slices.ContainsFunc(requested, func(s string) bool { return strings.HasPrefix(s, "sha1:") }) {
		b.WriteString(" (a sha1 digest is not collision-resistant, so it matches only the commit subject of a hardened git collection, or a subject named <commitSubject><sha> on an external attestation that declares \"commitSubject\")")
	}
	for _, d := range refused {
		subjects := strings.Join(d.Subjects, ", ")
		if d.SubjectsOmitted > 0 {
			subjects += fmt.Sprintf(", +%d more", d.SubjectsOmitted)
		}
		fmt.Fprintf(b, "; candidate %s with subjects [%s] refused: %s", d.Reference, subjects, d.Reason)
	}
	if omitted > 0 {
		fmt.Fprintf(b, "; %d more refused candidate(s) omitted", omitted)
	}
}

// declaredCommitOf reports whether an external envelope is bound to commit
// through its declared commitSubject, reading the SIGNED payload only.
//
// bound is true only when at least one subject is spelled
// <commitSubject><commit> with a sha1 digest of commit AND every subject whose
// name starts with commitSubject names that same commit validly. That is
// checkCommitBinding's "every git attestation names the commit" rule: an
// envelope that also claims another commit, or carries a malformed claim under
// the prefix, is not evidence about this commit alone.
//
// named is the first other commit claimed (for the refusal message), or ""
// when nothing under the prefix names a commit. Both are zero when the
// external declares no commitSubject, the payload is absent or undecodable, or
// the signed predicateType is not the external's own or is an attestation
// collection.
func declaredCommitOf(ext ExternalAttestation, payload []byte, commit string) (named string, bound bool) {
	if ext.CommitSubject == "" || len(payload) == 0 {
		return "", false
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return "", false
	}
	if stmt.PredicateType != ext.PredicateType ||
		stmt.PredicateType == attestation.CollectionType || stmt.PredicateType == attestation.LegacyCollectionType {
		return "", false
	}
	sawCommit := false
	for _, sub := range stmt.Subject {
		if !strings.HasPrefix(sub.Name, ext.CommitSubject) {
			continue
		}
		value, ok := sub.Digest["sha1"]
		if !ok || !cryptoutil.IsDeclaredCommitSubject(ext.CommitSubject, sub.Name, "sha1", value) {
			// A claim under the declared prefix that does not name a commit
			// validly: the envelope does not bind cleanly to anything.
			if named == "" {
				named = "(malformed " + clipDiagnostic(sub.Name, 120) + ")"
			}
			continue
		}
		if v := strings.ToLower(value); v == commit {
			sawCommit = true
		} else if named == "" {
			named = v
		}
	}
	if sawCommit && named == "" {
		return commit, true
	}
	return named, false
}
