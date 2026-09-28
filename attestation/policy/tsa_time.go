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
	"encoding/json"
	"strconv"
	"time"

	"github.com/aflock-ai/rookery/attestation/source"
)

// regoTSATimeKey names the verified signing time in the rego input, both as
// input.collection.tsaTime and as input.steps.<step>.collections[].tsaTime.
const regoTSATimeKey = "tsaTime"

// currentCollectionContextKey carries the collection under evaluation's
// verifier-derived fields from gateOneContext to buildRegoInput, which lifts
// them to input.collection. Like externalAttestationsContextKey it is not a
// valid step name, so it cannot collide with a dependency.
const currentCollectionContextKey = "__collection__"

// functionaryTimestamps returns the RFC 3161 TSA times, verified against the
// policy's timestamp authorities, on the signatures whose verifiers matched a
// step functionary. In a multi-signature envelope a token riding on some
// other signature must not speak for the trusted one.
func functionaryTimestamps(c source.CollectionVerificationResult) []time.Time {
	out := make([]time.Time, 0)
	for _, v := range c.ValidFunctionaries {
		if v == nil {
			continue
		}
		if kid, err := v.KeyID(); err == nil {
			out = append(out, c.VerifiedTimestampsByKeyID[kid]...)
		}
	}
	return out
}

// regoTSATime is the earliest functionary-scoped verified TSA time as Unix
// nanoseconds, in the json.Number form the rest of the rego input uses. ok is
// false when there is none; callers then omit the field so a rule reading it
// is refused (#9820) instead of seeing a zero.
func regoTSATime(c source.CollectionVerificationResult) (json.Number, bool) {
	var earliest time.Time
	for _, ts := range functionaryTimestamps(c) {
		if ts.IsZero() {
			continue
		}
		if earliest.IsZero() || ts.Before(earliest) {
			earliest = ts
		}
	}
	if earliest.IsZero() {
		return "", false
	}
	return json.Number(strconv.FormatInt(earliest.UnixNano(), 10)), true
}

// withCurrentCollection returns stepContext plus the collection's own
// verified fields for input.collection. stepContext is shared by every
// collection of the step, so it is copied, never written. A nil context
// (the plain, unwrapped input shape) stays nil: there the whole input is the
// signer's attestor JSON and has no engine-owned key to put the time under.
func withCurrentCollection(stepContext map[string]interface{}, c source.CollectionVerificationResult) map[string]interface{} {
	if stepContext == nil {
		return nil
	}
	ts, ok := regoTSATime(c)
	if !ok {
		return stepContext
	}
	out := make(map[string]interface{}, len(stepContext)+1)
	for k, v := range stepContext {
		out[k] = v
	}
	out[currentCollectionContextKey] = map[string]interface{}{regoTSATimeKey: ts}
	return out
}
