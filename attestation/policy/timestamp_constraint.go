// Copyright 2026 The Witness Contributors
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
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// maxClockSkew is the tolerance applied when judging whether a verified TSA
// timestamp lies in the future relative to the verifier's clock during a
// maxAge check. Real TSA/verifier clock drift is sub-second; five minutes is
// generous without opening a useful window for future-dating attacks.
const maxClockSkew = 5 * time.Minute

// TimestampConstraint expresses a first-class time-interval requirement on a
// step's evidence, evaluated against the RFC3161 TSA-VERIFIED signing time —
// never against self-asserted attestor wall-clock fields (which any signer can
// forge). This is the FedRAMP-20x "evidence must be recent" primitive: a step
// can require that its attestations were countersigned by a trusted timestamp
// authority within a date window and/or within a maximum age relative to
// verification time.
//
// Semantics:
//   - The constraint is checked against the EARLIEST verified TSA timestamp
//     across the collection's passing signatures. An RFC3161 token proves the
//     signature EXISTED at genTime ("not after" — an upper bound), so the
//     earliest token is the conservative anchor: when an older token is
//     present it always governs, and presenting an additional fresh token
//     cannot advance the anchor.
//
// Threat model — what this does and does not prove:
//   - An RFC3161 timestamp cannot prove a LOWER bound on when content was
//     created; a holder of old signature bytes could obtain a fresh token for
//     them and omit the original. This confers NO additional power to a
//     malicious functionary: anyone trusted to sign for the step could equally
//     re-SIGN stale content with a brand-new (honestly fresh) signature.
//     Signatures establish provenance, not truth. The constraint therefore
//     targets the real compliance failure mode — honest pipelines serving
//     stale evidence (a scanner that stopped running, a cached attestation
//     being replayed) — where signing and timestamping happen together at
//     evidence-creation time, making genTime ≈ signing time. Deliberate
//     evidence fraud by a trusted functionary is out of scope here and is the
//     domain of functionary constraints, key custody, and audit.
//   - FAIL-CLOSED: when a constraint is set and the collection carries NO
//     verified TSA timestamp, the collection is rejected. Untimestamped
//     evidence has no trustworthy time and cannot satisfy a time constraint.
//   - MaxAge is evaluated relative to the verifier's clock at evaluation time.
//     Offline verification uses the same semantics — the verifying host's
//     clock is the reference, exactly as it already is for certificate
//     expiry and Policy.Expires.
//
// +kubebuilder:object:generate=true
type TimestampConstraint struct {
	// NotBefore rejects evidence whose verified TSA time is before this instant.
	NotBefore *metav1.Time `json:"notBefore,omitempty" jsonschema:"title=Not Before,description=Reject evidence whose RFC3161 TSA-verified signing time is before this RFC3339 instant"`
	// NotAfter rejects evidence whose verified TSA time is after this instant.
	NotAfter *metav1.Time `json:"notAfter,omitempty" jsonschema:"title=Not After,description=Reject evidence whose RFC3161 TSA-verified signing time is after this RFC3339 instant"`
	// MaxAge rejects evidence whose verified TSA time is older than this Go
	// duration (e.g. "720h" for 30 days) relative to evaluation time.
	MaxAge string `json:"maxAge,omitempty" jsonschema:"title=Max Age,description=Reject evidence whose RFC3161 TSA-verified signing time is older than this Go duration (e.g. 720h = 30 days) relative to verification time"`
}

// Validate checks the constraint is well-formed: at least one field set,
// MaxAge parses as a positive Go duration, and NotBefore <= NotAfter when
// both are present.
func (c *TimestampConstraint) Validate() error {
	if c == nil {
		return nil
	}
	if c.NotBefore == nil && c.NotAfter == nil && c.MaxAge == "" {
		return fmt.Errorf("timestampConstraint must set at least one of notBefore, notAfter, maxAge")
	}
	if c.MaxAge != "" {
		d, err := time.ParseDuration(c.MaxAge)
		if err != nil {
			return fmt.Errorf("timestampConstraint maxAge %q is not a valid Go duration: %w", c.MaxAge, err)
		}
		if d <= 0 {
			return fmt.Errorf("timestampConstraint maxAge %q must be positive", c.MaxAge)
		}
	}
	if c.NotBefore != nil && c.NotAfter != nil && c.NotBefore.After(c.NotAfter.Time) {
		return fmt.Errorf("timestampConstraint notBefore %s is after notAfter %s", c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// Check evaluates the constraint against the collection's verified TSA
// timestamps. now is the evaluation-time reference for MaxAge. Returns nil
// when the constraint is satisfied; a descriptive error otherwise.
// Fail-closed: an empty verifiedTimestamps slice is always a rejection.
func (c *TimestampConstraint) Check(verifiedTimestamps []time.Time, now time.Time) error {
	if c == nil {
		return nil
	}
	if len(verifiedTimestamps) == 0 {
		return fmt.Errorf("step requires a timestampConstraint but the collection carries no verified RFC3161 TSA timestamp; untimestamped evidence cannot satisfy a time constraint (fail-closed)")
	}

	earliest := verifiedTimestamps[0]
	for _, ts := range verifiedTimestamps[1:] {
		if ts.Before(earliest) {
			earliest = ts
		}
	}

	if c.NotBefore != nil && earliest.Before(c.NotBefore.Time) {
		return fmt.Errorf("verified TSA timestamp %s is before the policy's notBefore bound %s",
			earliest.Format(time.RFC3339), c.NotBefore.Format(time.RFC3339))
	}
	if c.NotAfter != nil && earliest.After(c.NotAfter.Time) {
		return fmt.Errorf("verified TSA timestamp %s is after the policy's notAfter bound %s",
			earliest.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
	}
	if c.MaxAge != "" {
		maxAge, err := time.ParseDuration(c.MaxAge)
		if err != nil {
			// Validate() should have caught this; fail closed regardless.
			return fmt.Errorf("timestampConstraint maxAge %q is not a valid Go duration: %w", c.MaxAge, err)
		}
		// A future-dated TSA timestamp must NOT satisfy a freshness bound —
		// otherwise a token dated T_future stays "fresh" until T_future+maxAge,
		// defeating the constraint. Tolerate only small TSA/verifier clock skew.
		if earliest.After(now.Add(maxClockSkew)) {
			return fmt.Errorf("verified TSA timestamp %s is in the future relative to verification time %s (beyond the %s clock-skew allowance); future-dated evidence cannot satisfy maxAge (fail-closed)",
				earliest.Format(time.RFC3339), now.Format(time.RFC3339), maxClockSkew)
		}
		if age := now.Sub(earliest); age > maxAge {
			return fmt.Errorf("verified TSA timestamp %s is %s old, exceeding the policy's maxAge %s",
				earliest.Format(time.RFC3339), age.Round(time.Second), maxAge)
		}
	}
	return nil
}
