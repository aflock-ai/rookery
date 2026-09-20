// Copyright 2025 The Witness Contributors
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
	"bytes"
	"encoding/json"
	"fmt"
)

// Strict decoding for decision bodies.
//
// Every member of a decision body is an ASSERTION. Go's default decoder drops
// a member it does not recognise, which converts "the author asserted
// something" into "the engine asserted nothing" with no diagnostic — the same
// vacuous pass the assertion-free validation rule exists to prevent, arriving
// through the decoder instead of the validator. So these types refuse what
// they cannot act on.
//
// This is safe for existing signed policies: `decision` and everything under
// it is new, so no policy in the wild carries these bodies at all. It is the
// correct direction for a policy language besides — a verifier that does not
// understand every clause of a gate must refuse the gate, not evaluate the
// part it recognised.

// decodeStrict decodes data into target, refusing unknown members. target must
// be a pointer to a type with no UnmarshalJSON of its own, or this recurses.
func decodeStrict(data []byte, target interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(target)
}

// UnmarshalJSON refuses a yes/no body carrying `minConfidence`.
//
// The model reports a confidence for a choice and for a score, and never for a
// yes/no — the yes/no answer IS a probability, which is what
// minProbability/maxProbability assert on. A `minConfidence` here is therefore
// not merely unsupported, it is unimplementable, and silently dropping it
// would leave a gate that reads as a confidence floor while asserting nothing.
func (y *AiYesNo) UnmarshalJSON(data []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if _, present := probe["minConfidence"]; present {
		return fmt.Errorf(`yesNo decision does not support "minConfidence": a confidence is returned only for choice and score answers, never for a yes/no — assert on "minProbability"/"maxProbability" instead`)
	}

	type alias AiYesNo
	var a alias
	if err := decodeStrict(data, &a); err != nil {
		return fmt.Errorf("yesNo decision: %w", err)
	}
	*y = AiYesNo(a)
	return nil
}

// UnmarshalJSON refuses a choice body carrying a member it cannot act on.
func (c *AiChoice) UnmarshalJSON(data []byte) error {
	type alias AiChoice
	var a alias
	if err := decodeStrict(data, &a); err != nil {
		return fmt.Errorf("choice decision: %w", err)
	}
	*c = AiChoice(a)
	return nil
}

// UnmarshalJSON refuses a score body carrying a member it cannot act on.
func (s *AiScore) UnmarshalJSON(data []byte) error {
	type alias AiScore
	var a alias
	if err := decodeStrict(data, &a); err != nil {
		return fmt.Errorf("score decision: %w", err)
	}
	*s = AiScore(a)
	return nil
}

// UnmarshalJSON refuses a decision carrying a member it cannot act on, such as
// an assertion written one level too high (`{"yesNo": {...}, "minScore": 1}`).
//
// Note what this does NOT catch: Go matches JSON member names
// case-insensitively, so `yesno` is accepted as `yesNo` and is not an unknown
// member. That is checked by TestDecisionBodiesRejectUnknownFields — the first
// draft of that test asserted the opposite and was wrong.
func (d *AiDecision) UnmarshalJSON(data []byte) error {
	type alias AiDecision
	var a alias
	if err := decodeStrict(data, &a); err != nil {
		return fmt.Errorf("decision: %w", err)
	}
	*d = AiDecision(a)
	return nil
}
