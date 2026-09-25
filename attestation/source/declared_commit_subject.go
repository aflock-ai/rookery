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

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// PredicateSearchOptions carries per-search opt-ins for SearchByPredicateType.
// The zero value is the strict search, identical to SearchByPredicateType.
type PredicateSearchOptions struct {
	// CommitSubjects maps a statement predicateType to the commit-subject
	// prefixes a policy declared for externals of that type
	// (ExternalAttestation.commitSubject). A candidate whose SIGNED
	// predicateType is a key here, and is not an attestation collection, may
	// match a requested SHA-1 digest through a subject named exactly
	// <prefix><sha> (cryptoutil.IsDeclaredCommitSubject). Nothing else changes.
	//
	// One search can serve several externals of the same type, so a caller
	// holding more than one external must re-check each candidate against that
	// external's own prefix with MatchExternalSubjects. The policy engine does.
	CommitSubjects map[string][]string
}

func (o PredicateSearchOptions) empty() bool {
	for _, prefixes := range o.CommitSubjects {
		if len(prefixes) > 0 {
			return false
		}
	}
	return true
}

// PredicateSearcherWithOptions is implemented by sources that accept
// PredicateSearchOptions. VerifiedSource implements it at the verified layer;
// MemorySource, MultiSource and RecordingSource implement it at the Sourcer
// layer so their own pre-filter does not drop the candidate the verified
// layer would admit. A Sourcer without it is searched with the plain method,
// which can only return fewer candidates: the verified guard decides either
// way, from the signed bytes.
type PredicateSearcherWithOptions interface {
	SearchByPredicateTypeWithOptions(ctx context.Context, predicateTypes []string, subjectDigests []string, opts PredicateSearchOptions) ([]StatementEnvelope, error)
}

// searchPredicateWithOptions searches src with opts when it accepts them and
// opts is non-empty, and with the plain SearchByPredicateType otherwise, so
// the zero options always take the historical path.
func searchPredicateWithOptions(ctx context.Context, src Sourcer, predicateTypes, subjectDigests []string, opts PredicateSearchOptions) ([]StatementEnvelope, error) {
	if withOpts, ok := src.(PredicateSearcherWithOptions); ok && !opts.empty() {
		return withOpts.SearchByPredicateTypeWithOptions(ctx, predicateTypes, subjectDigests, opts)
	}
	return src.SearchByPredicateType(ctx, predicateTypes, subjectDigests)
}

// SubjectNotRequestedError is the substitution-guard refusal for one external
// candidate, carrying a human-readable reason. errors.Is matches it to
// ErrExternalSubjectNotRequested, so every existing caller keeps treating the
// candidate as unbound.
type SubjectNotRequestedError struct {
	Detail string
}

func (e *SubjectNotRequestedError) Error() string {
	if e.Detail == "" {
		return ErrExternalSubjectNotRequested.Error()
	}
	return ErrExternalSubjectNotRequested.Error() + ": " + e.Detail
}

// Is reports the sentinel, so errors.Is(err, ErrExternalSubjectNotRequested)
// holds for every refusal the guard produces.
func (e *SubjectNotRequestedError) Is(target error) bool {
	return target == ErrExternalSubjectNotRequested
}

// signedStatementFacts are the verdict-relevant facts of a signed statement,
// decoded from the SIGNATURE-VERIFIED payload.
type signedStatementFacts struct {
	predicateType string
	subjects      []intoto.Subject
	scope         cryptoutil.SubjectMatchScope
}

func decodeSignedStatementFacts(payload []byte) (signedStatementFacts, error) {
	var stmt struct {
		PredicateType string           `json:"predicateType"`
		Subject       []intoto.Subject `json:"subject"`
		Predicate     gitAttestedClaim `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return signedStatementFacts{}, err
	}
	gitAttested := bool(stmt.Predicate) && isCollectionPredicateType(stmt.PredicateType)
	return signedStatementFacts{
		predicateType: stmt.PredicateType,
		subjects:      stmt.Subject,
		scope:         cryptoutil.SubjectMatchScope{HardenedGitAttested: gitAttested},
	}, nil
}

// matchSignedExternalSubjects is the artifact-substitution guard for a bare
// external candidate. It reads everything from the signed payload. With empty
// opts it admits exactly what payloadMatchesSubjects admits; the declared
// commit-subject arm is tried only for a non-collection statement whose signed
// predicateType has declared prefixes.
func matchSignedExternalSubjects(payload []byte, subjectDigests []string, opts PredicateSearchOptions) error {
	if len(subjectDigests) == 0 {
		return nil
	}
	facts, err := decodeSignedStatementFacts(payload)
	if err != nil {
		return &SubjectNotRequestedError{Detail: fmt.Sprintf("signed payload does not decode: %v", err)}
	}
	if subjectsMatchDigests(facts.scope, facts.subjects, subjectDigests) {
		return nil
	}
	var prefixes []string
	if !isCollectionPredicateType(facts.predicateType) {
		prefixes = opts.CommitSubjects[facts.predicateType]
	}
	for _, prefix := range prefixes {
		scope := facts.scope
		scope.CommitSubjectPrefix = prefix
		if subjectsMatchDigests(scope, facts.subjects, subjectDigests) {
			return nil
		}
	}
	return &SubjectNotRequestedError{Detail: explainSubjectMismatch(facts, subjectDigests, prefixes)}
}

// MatchExternalSubjects re-runs the substitution guard on a candidate's SIGNED
// payload for ONE external: predicateType is that external's declared type and
// commitSubject its declared prefix ("" for none). It returns nil when the
// candidate names a requested digest under that external's own rules, and an
// error matching ErrExternalSubjectNotRequested otherwise.
//
// Call it only on a payload whose signature verified.
func MatchExternalSubjects(payload []byte, subjectDigests []string, predicateType, commitSubject string) error {
	opts := PredicateSearchOptions{}
	if commitSubject != "" {
		opts.CommitSubjects = map[string][]string{predicateType: {commitSubject}}
	}
	return matchSignedExternalSubjects(payload, subjectDigests, opts)
}

// Diagnostic bounds. A candidate's subjects come from whoever uploaded it, so
// every list rendered from them is capped.
const (
	maxDiagnosticSubjects   = 8
	maxDiagnosticNameLength = 200
)

// LabelSubjectDigest renders a requested subject digest as algorithm:value.
// The engine carries requested digests as bare values, so the algorithm is
// inferred from the value's shape: 40 hex is sha1, 64 hex sha256, 128 hex
// sha512; a value that already names its scheme (gitoid:…) is returned as is.
func LabelSubjectDigest(value string) string {
	if strings.Contains(value, ":") {
		return value
	}
	if isHexOnly(value) {
		switch len(value) {
		case 40:
			return "sha1:" + value
		case 64:
			return "sha256:" + value
		case 128:
			return "sha512:" + value
		}
	}
	return "unknown:" + value
}

func isHexOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// LabelSubjectDigests labels every requested digest (LabelSubjectDigest).
func LabelSubjectDigests(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, LabelSubjectDigest(v))
	}
	return out
}

func clipName(name string) string {
	if len(name) <= maxDiagnosticNameLength {
		return name
	}
	return name[:maxDiagnosticNameLength] + "…"
}

func describeSubject(sub intoto.Subject) string {
	algs := make([]string, 0, len(sub.Digest))
	for alg := range sub.Digest {
		algs = append(algs, alg)
	}
	sort.Strings(algs)
	return fmt.Sprintf("%s (%s)", clipName(sub.Name), strings.Join(algs, ","))
}

// SignedSubjectSummary describes the subjects of a statement payload as
// "name (alg,alg)" entries, capped at a fixed count; omitted is how many were
// left out. A payload that does not decode yields nothing.
func SignedSubjectSummary(payload []byte) (summary []string, omitted int) {
	facts, err := decodeSignedStatementFacts(payload)
	if err != nil {
		return nil, 0
	}
	return summarizeSubjects(facts.subjects)
}

func summarizeSubjects(subjects []intoto.Subject) ([]string, int) {
	out := make([]string, 0, min(len(subjects), maxDiagnosticSubjects))
	for i, sub := range subjects {
		if i == maxDiagnosticSubjects {
			return out, len(subjects) - i
		}
		out = append(out, describeSubject(sub))
	}
	return out, 0
}

// explainSubjectMismatch says why no signed subject anchored a requested
// digest. For a subject that carries a requested digest only as SHA-1 it names
// the policy field that would admit it and, when the name has the
// <namespace>/commithash:<sha> shape, the exact prefix to declare.
func explainSubjectMismatch(facts signedStatementFacts, subjectDigests []string, prefixes []string) string {
	requested := make(map[string]struct{}, len(subjectDigests))
	for _, d := range subjectDigests {
		requested[strings.ToLower(d)] = struct{}{}
	}
	var reasons []string
	for _, sub := range facts.subjects {
		algs := make([]string, 0, len(sub.Digest))
		for alg := range sub.Digest {
			algs = append(algs, alg)
		}
		sort.Strings(algs)
		for _, alg := range algs {
			value := sub.Digest[alg]
			if _, ok := requested[strings.ToLower(value)]; !ok {
				continue
			}
			reasons = append(reasons, explainOneSubject(facts, sub.Name, alg, value, prefixes))
			if len(reasons) == maxDiagnosticSubjects {
				break
			}
		}
		if len(reasons) == maxDiagnosticSubjects {
			break
		}
	}
	requestedLabels := strings.Join(LabelSubjectDigests(subjectDigests), ", ")
	if len(reasons) > 0 {
		return strings.Join(reasons, "; ") + fmt.Sprintf(" (requested [%s])", requestedLabels)
	}
	summary, omitted := summarizeSubjects(facts.subjects)
	listed := strings.Join(summary, ", ")
	if omitted > 0 {
		listed += fmt.Sprintf(", +%d more", omitted)
	}
	return fmt.Sprintf("signed subjects [%s] name none of the requested digests [%s]", listed, requestedLabels)
}

func explainOneSubject(facts signedStatementFacts, name, alg, value string, prefixes []string) string {
	quoted := fmt.Sprintf("%q", clipName(name))
	if alg != "sha1" && alg != "gitoid:sha1" {
		return fmt.Sprintf("subject %s carries the requested digest as %s, which is not an accepted subject-match algorithm or is malformed for it", quoted, alg)
	}
	if isCollectionPredicateType(facts.predicateType) {
		return fmt.Sprintf("subject %s carries the requested digest only as SHA-1; SHA-1 is not collision-resistant, and in an attestation collection only a hardened git commit subject may anchor it (commitSubject does not apply to collections)", quoted)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "subject %s carries the requested digest only as SHA-1, which is not collision-resistant and is refused by default", quoted)
	if len(prefixes) > 0 {
		quotedPrefixes := make([]string, 0, len(prefixes))
		for _, p := range prefixes {
			quotedPrefixes = append(quotedPrefixes, fmt.Sprintf("%q", clipName(p)))
		}
		fmt.Fprintf(&b, "; the declared commitSubject %s does not admit it (the name must be exactly <commitSubject><40-hex commit> with a matching sha1 digest)", strings.Join(quotedPrefixes, ", "))
		return b.String()
	}
	if suggestion := suggestCommitSubject(name, alg, value); suggestion != "" {
		fmt.Fprintf(&b, "; to admit it, set \"commitSubject\": %q on this external attestation in the policy", suggestion)
		return b.String()
	}
	b.WriteString("; a policy can admit a SHA-1 commit only through an external attestation's \"commitSubject\", naming the exact <namespace>/commithash: prefix of a subject spelled <prefix><40-hex commit>")
	return b.String()
}

// suggestCommitSubject returns the prefix that would admit name as a declared
// commit subject, or "" when the name does not have that shape.
func suggestCommitSubject(name, alg, value string) string {
	const hexLen = 40
	if len(name) <= hexLen {
		return ""
	}
	prefix := name[:len(name)-hexLen]
	if cryptoutil.ValidateCommitSubjectPrefix(prefix) != nil {
		return ""
	}
	if !cryptoutil.IsDeclaredCommitSubject(prefix, name, alg, value) {
		return ""
	}
	return prefix
}

// declaredCommitSubjectPrefilter reports whether an UNVERIFIED statement names
// a requested digest through a declared commit subject. It is only a source's
// pre-filter, so a candidate the verified layer would admit is not dropped
// before it is checked; the verdict is matchSignedExternalSubjects on the
// signed bytes.
func declaredCommitSubjectPrefilter(stmt intoto.Statement, subjectDigests []string, opts PredicateSearchOptions) bool {
	if isCollectionPredicateType(stmt.PredicateType) {
		return false
	}
	prefixes := opts.CommitSubjects[stmt.PredicateType]
	if len(prefixes) == 0 {
		return false
	}
	requested := make(map[string]struct{}, len(subjectDigests))
	for _, d := range subjectDigests {
		requested[d] = struct{}{}
	}
	for _, sub := range stmt.Subject {
		for alg, value := range sub.Digest {
			if _, ok := requested[value]; !ok {
				continue
			}
			for _, prefix := range prefixes {
				if cryptoutil.IsDeclaredCommitSubject(prefix, sub.Name, alg, value) {
					return true
				}
			}
		}
	}
	return false
}
