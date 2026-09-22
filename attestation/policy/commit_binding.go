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
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/source"
)

// gitAttestationType is the git attestor's predicate type. Legacy witness.dev
// spellings resolve to it through attestation.ResolveLegacyType; any other
// type, including a future git version, is not a git attestation here and
// cannot bind a witness to a commit.
const gitAttestationType = "https://aflock.ai/attestations/git/v0.1"

// WithCommitBinding makes the step gate require that every witness belongs to
// the commit under evaluation. A collection that passes the step's
// attestation and Rego checks still counts only when it carries at least one
// git attestation and EVERY git attestation's commithash equals commit
// (full hex, sha1 or sha256, compared case-folded). Anything else is moved to
// Rejected with ErrWitnessNotBoundToCommit, so it can neither satisfy the step
// nor feed a dependant step's cross-step input. Relationship edges (BackRefs)
// are no longer followed, so a parent is reached only when a caller seeds its
// digest, and even then it can never be a witness.
//
// The binding reads the attestor's commithash FIELD, never the subject
// digests. The git attestor's subjects include parenthash, so "some subject
// digest is in the seed set" would admit a child of the evaluated commit at
// depth 0.
//
// THE ZERO VALUE IS UNBOUND. Without this option (or with an empty commit)
// the engine keeps its historical behaviour: a step passes on any
// functionary-authorized collection the seed digests match. That
// is correct for verifies whose subject is not a commit, such as a registry
// or image-digest gate, and it is the HSEC1 exposure for every verify whose
// subject IS a commit. Callers that evaluate a commit must pass it.
func WithCommitBinding(commit string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.commitBinding = commit
	}
}

// ErrWitnessNotBoundToCommit is the rejection reason for a collection that
// passed the step gate but is not bound to the commit the verify evaluates.
// WitnessCommit is the first git commithash that differs from Commit, and is
// empty when the collection carries no git attestation at all.
type ErrWitnessNotBoundToCommit struct {
	Step          string
	Witness       string
	WitnessCommit string
	Commit        string
}

func (e ErrWitnessNotBoundToCommit) Error() string {
	if e.WitnessCommit == "" {
		return fmt.Sprintf("step %q: witness %s carries no git attestation, so it is not bound to commit %s", e.Step, e.Witness, e.Commit)
	}
	return fmt.Sprintf("step %q: witness %s is bound to commit %s, not %s", e.Step, e.Witness, e.WitnessCommit, e.Commit)
}

// normalizeCommitBinding validates a non-empty binding and returns its
// canonical lower-case form. Only a full sha1 (40) or sha256 (64) hex commit
// id binds: a short or padded value would otherwise fail every comparison
// silently, or invite a prefix match later.
func normalizeCommitBinding(commit string) (string, error) {
	if len(commit) != 40 && len(commit) != 64 {
		return "", fmt.Errorf("commit binding must be a full 40- or 64-character hex commit id, got %d characters", len(commit))
	}
	for _, r := range commit {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return "", fmt.Errorf("commit binding %q is not hex", commit)
		}
	}
	return strings.ToLower(commit), nil
}

// gateBound runs the step gate with the commit binding in its path. The
// binding is checked BEFORE the attestation, Rego and AI checks: a collection
// from another commit is not evidence for this verify, so it is not evaluated
// (and not disclosed to an AI provider) at all. A collection not named for the
// step is left to the gate, which skips it. With no binding this is exactly
// gateOneContext.
func (s Step) gateBound(ctx context.Context, collection source.CollectionVerificationResult, vo *verifyOptions, stepCtx map[string]interface{}) (gateOutcome, PassedCollection, RejectedCollection) {
	if vo.commitBinding != "" && collection.Collection.Name == s.Name {
		if err := checkCommitBinding(s.Name, collection, vo.commitBinding); err != nil {
			return gateRejected, PassedCollection{}, RejectedCollection{Collection: compactRejected(collection), Reason: err}
		}
	}
	return s.gateOneContext(ctx, collection, vo.aiServerURL, stepCtx, vo.aiProvider)
}

// checkCommitBinding reports whether every git attestation in the collection
// names commit, and that there is at least one. commit is already normalized.
func checkCommitBinding(step string, collection source.CollectionVerificationResult, commit string) error {
	notBound := ErrWitnessNotBoundToCommit{Step: step, Witness: collection.Reference, Commit: commit}
	hashes := witnessCommitHashes(collection)
	if len(hashes) == 0 {
		return notBound
	}
	for _, h := range hashes {
		if !strings.EqualFold(h, commit) {
			notBound.WitnessCommit = h
			if h == "" {
				notBound.WitnessCommit = "(empty commithash)"
			}
			return notBound
		}
	}
	return nil
}

// witnessCommitHashes returns the commithash of every git attestation in the
// collection, one entry per attestation (an attestation without a readable
// commithash contributes ""). It reads the SIGNED payload when one is
// retained: the decoded Collection on a CollectionEnvelope is populated by the
// source and could name a different commit than the signature covers. A
// directly-constructed result with no payload has no untrusted source behind
// it, so its Collection is the truth (the same rule as
// CollectionEnvelope.VerifiedSubjectScope).
func witnessCommitHashes(collection source.CollectionVerificationResult) []string {
	if len(collection.Envelope.Payload) > 0 {
		return signedCommitHashes(collection.Envelope.Payload)
	}
	var out []string
	for _, att := range collection.Collection.Attestations {
		if attestation.ResolveLegacyType(att.Type) != gitAttestationType {
			continue
		}
		var claim commitHashClaim
		if att.Attestation != nil {
			if body, err := json.Marshal(att.Attestation); err == nil {
				_ = claim.UnmarshalJSON(body)
			}
		}
		out = append(out, string(claim))
	}
	return out
}

// signedCommitHashes decodes only the attestation types and git commithash
// fields from a signed collection statement. A payload that does not decode
// yields no hashes, so the collection is refused as unbound (fail closed).
func signedCommitHashes(payload []byte) []string {
	var stmt struct {
		Predicate struct {
			Attestations []struct {
				Type        string          `json:"type"`
				Attestation commitHashClaim `json:"attestation"`
			} `json:"attestations"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil
	}
	var out []string
	for _, att := range stmt.Predicate.Attestations {
		if attestation.ResolveLegacyType(att.Type) == gitAttestationType {
			out = append(out, string(att.Attestation))
		}
	}
	return out
}

// commitHashClaim is the commithash field of one attestation body. It is a
// json.Unmarshaler so a body of any other shape (an array, a string, a
// non-string commithash) yields "" for that entry instead of failing the whole
// decode, and it resets at entry so duplicate keys stay last-wins.
type commitHashClaim string

func (c *commitHashClaim) UnmarshalJSON(body []byte) error {
	*c = ""
	var att struct {
		CommitHash string `json:"commithash"`
	}
	if err := json.Unmarshal(body, &att); err != nil {
		return nil //nolint:nilerr // an unreadable body is an unbound witness, not a decode failure of the statement
	}
	*c = commitHashClaim(att.CommitHash)
	return nil
}
