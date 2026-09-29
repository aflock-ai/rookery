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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
)

// Nested verification: a parent policy over child VSAs. Stock externals match
// on predicate type and pass when any envelope passes, so (a) one child's
// passing VSA satisfies every VSA external, (b) nothing bounds a child VSA's
// age, and (c) an older passing VSA masks a newer failing one. An external
// that sets ChildPolicyDigest or TimestampConstraint is decided instead by
// `externalLatest` in formal/cilock-evaluators/CilockEvaluators/Nested.lean:
//
//   - candidates: envelopes of the bound child policy whose functionary-matched
//     signature carries a TSA-verified time, whose signed timeVerified is not
//     after that time, and whose earlier of the two is inside the window;
//   - each candidate decides at its signed timeVerified (admitExternal says
//     why not at its TSA time);
//   - the external passes iff some candidate exists and every candidate at the
//     latest time passed its rego and AI policies.
//
// Older candidates never decide; they are recorded as superseded.

var childPolicyDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// latestDecides reports whether this external uses the nested semantics.
func (e ExternalAttestation) latestDecides() bool {
	return e.ChildPolicyDigest != "" || e.TimestampConstraint != nil
}

// ValidateNested checks the nested-verification fields are well formed.
func (e ExternalAttestation) ValidateNested() error {
	if e.ChildPolicyDigest != "" && !childPolicyDigestPattern.MatchString(e.ChildPolicyDigest) {
		return fmt.Errorf("childPolicyDigest %q must be 64 lower-case hex characters (sha256)", e.ChildPolicyDigest)
	}
	return e.TimestampConstraint.Validate()
}

// vsaPolicyDigest reads predicate.policy.digest.sha256 from a signed statement.
func vsaPolicyDigest(payload []byte) string {
	var st struct {
		Predicate struct {
			Policy struct {
				Digest map[string]string `json:"digest"`
			} `json:"policy"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		return ""
	}
	return st.Predicate.Policy.Digest["sha256"]
}

// externalTime is the earliest TSA-verified time among the functionary-matched
// verifiers, the same reading TimestampConstraint.Check applies to collections.
func externalTime(env source.StatementEnvelope, functionaries []cryptoutil.Verifier) []time.Time {
	out := make([]time.Time, 0)
	for _, v := range functionaries {
		if v == nil {
			continue
		}
		if kid, err := v.KeyID(); err == nil {
			out = append(out, env.VerifiedTimestampsByKeyID[kid]...)
		}
	}
	return out
}

func earliest(ts []time.Time) time.Time {
	var e time.Time
	for _, t := range ts {
		if !t.IsZero() && (e.IsZero() || t.Before(e)) {
			e = t
		}
	}
	return e
}

// admitExternal decides whether an envelope is a candidate for a nested
// external and at what time it decides. unbound is true when the envelope
// belongs to another child policy (it is not about this external); otherwise
// a non-nil error rejects it.
//
// The candidate decides at its SIGNED predicate.timeVerified, never at its
// RFC3161 time. A DSSE signature's timestamps are not covered by the
// signature, so anyone who can download an envelope can re-upload the same
// signature bytes with only a fresh token: ordered by TSA time, an old passing
// VSA re-stamped after a newer failing one would become the latest. The signed
// time is the functionary's, and the functionary is already trusted with the
// verdict. The TSA time still bounds it: a signature cannot record a verdict
// reached after the signature existed (beyond clock skew), and a candidate
// without a TSA-verified time is refused (fail-closed).
func admitExternal(ext ExternalAttestation, env source.StatementEnvelope, functionaries []cryptoutil.Verifier, now time.Time) (t time.Time, unbound bool, err error) {
	if ext.ChildPolicyDigest != "" {
		if got := vsaPolicyDigest(env.Envelope.Payload); got != ext.ChildPolicyDigest {
			return t, true, fmt.Errorf("VSA of policy %q, not the bound child policy %q", got, ext.ChildPolicyDigest)
		}
	}
	ts := externalTime(env, functionaries)
	stamped := earliest(ts)
	if stamped.IsZero() {
		return t, false, fmt.Errorf("the latest child VSA decides this external, so it needs an RFC3161 TSA-verified time; this envelope has none (fail-closed)")
	}
	signed, err := vsaTimeVerified(env.Envelope.Payload)
	if err != nil {
		return t, false, err
	}
	if signed.After(stamped.Add(maxClockSkew)) {
		return t, false, fmt.Errorf("VSA timeVerified %s is after its own RFC3161 time %s (beyond the %s clock-skew allowance); a signature cannot record a verdict reached after it existed",
			signed.Format(time.RFC3339), stamped.Format(time.RFC3339), maxClockSkew)
	}
	// The window judges both times, so a fresh token on old signature bytes
	// cannot make a stale verdict look fresh.
	if ext.TimestampConstraint != nil {
		if err := ext.TimestampConstraint.Check(ts, now); err != nil {
			return t, false, err
		}
		if err := ext.TimestampConstraint.Check([]time.Time{signed}, now); err != nil {
			return t, false, fmt.Errorf("VSA signed timeVerified %s is outside the window (judged as a trusted time): %w", signed.Format(time.RFC3339), err)
		}
	}
	return signed, false, nil
}

// vsaTimeVerified reads predicate.timeVerified (RFC 3339) from a signed
// statement. Absent or malformed is a refusal: the candidate has no signed
// time to be ordered by.
func vsaTimeVerified(payload []byte) (time.Time, error) {
	var st struct {
		Predicate struct {
			TimeVerified string `json:"timeVerified"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		return time.Time{}, fmt.Errorf("the latest child VSA decides this external, and this envelope's statement does not decode: %w", err)
	}
	t, err := time.Parse(time.RFC3339, st.Predicate.TimeVerified)
	if err != nil {
		return time.Time{}, fmt.Errorf("the latest child VSA decides this external, so it needs a signed RFC 3339 predicate.timeVerified; got %q (fail-closed)", st.Predicate.TimeVerified)
	}
	return t, nil
}

type latestCandidate struct {
	key    string
	at     time.Time
	passed bool
}

func envelopeKey(env source.StatementEnvelope) string {
	h := sha256.Sum256(env.Envelope.Payload)
	return env.Reference + "\x00" + hex.EncodeToString(h[:])
}

// decideLatest applies the nested semantics to an external's result: only
// candidates at the latest verified time may stay Passed, and if any of them
// failed, none do. Every demoted pass is recorded as a rejection with why.
func decideLatest(er *ExternalResult, cands []latestCandidate) {
	var latest time.Time
	for _, c := range cands {
		if c.at.After(latest) {
			latest = c.at
		}
	}
	latestFailed := false
	for _, c := range cands {
		if c.at.Equal(latest) && !c.passed {
			latestFailed = true
		}
	}
	at := make(map[string]time.Time, len(cands))
	for _, c := range cands {
		at[c.key] = c.at
	}
	kept := er.Passed[:0:0]
	for _, p := range er.Passed {
		t := at[envelopeKey(p.Envelope)]
		switch {
		case latestFailed:
			er.Rejected = append(er.Rejected, RejectedExternal{Envelope: p.Envelope, AiResponses: p.AiResponses,
				Reason: fmt.Errorf("a child VSA verified at %s failed; the latest VSA decides, so this passing one (at %s) does not count", latest.Format(time.RFC3339), t.Format(time.RFC3339))})
		case !t.Equal(latest):
			er.Rejected = append(er.Rejected, RejectedExternal{Envelope: p.Envelope, AiResponses: p.AiResponses,
				Reason: fmt.Errorf("superseded: a newer child VSA was verified at %s (this one at %s)", latest.Format(time.RFC3339), t.Format(time.RFC3339))})
		default:
			kept = append(kept, p)
		}
	}
	er.Passed = kept
}
