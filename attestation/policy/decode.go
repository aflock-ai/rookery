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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// policyVersion is the predicate version a Policy was decoded under. Only
// DecodePolicyEnvelope sets it (Policy.payloadVersion).
type policyVersion uint8

const (
	// policyVersionUnknown is the zero value: a Policy that did not come from
	// DecodePolicyEnvelope. It is never v0.2.
	policyVersionUnknown policyVersion = iota
	policyVersionV01
	policyVersionV02
)

// The reasons a policy is refused before any evidence is read. Keep them
// byte-identical: operators and consumers key on these strings.
const (
	// ReasonAboutNeedsPolicyV02: a step declares about, and the policy was not
	// decoded from a policy v0.2 envelope.
	ReasonAboutNeedsPolicyV02 = "about-needs-policy-v0.2"
	// ReasonAboutUnknownValue: a step's about is not StepAboutSource.
	ReasonAboutUnknownValue = "about-unknown-value"
	// ReasonPolicyTypeUnknown: the envelope's PayloadType is not aflock
	// v0.1, the legacy witness v0.1 alias or aflock v0.2.
	ReasonPolicyTypeUnknown = "policy-type-unknown"
)

// ErrPolicyRefused is a policy refused before verification: nothing was
// searched and no step was evaluated. Reason is one of the Reason constants.
type ErrPolicyRefused struct {
	Reason string
	Detail string
}

func (e ErrPolicyRefused) Error() string {
	return e.Reason + ": " + e.Detail
}

// DecodePolicyEnvelope decodes a signed policy envelope's payload under its
// PayloadType. It is the one way a verifier should turn policy bytes into a
// Policy, because the engine never sees the envelope:
//
//   - the type allowlist: aflock v0.1 and the legacy witness v0.1 alias decode
//     leniently, exactly as json.Unmarshal always did, so no signed v0.1 policy
//     changes meaning; aflock v0.2 decodes strictly (an unknown member is an
//     error, at every depth); every other type, the empty one included, is
//     refused (ReasonPolicyTypeUnknown). A policy written for a later version
//     therefore fails closed here instead of being verified with the clauses
//     this verifier does not know silently dropped.
//   - the version stamp: the returned Policy records which version it was
//     decoded under. The stamp is unexported and never serialized; Verify
//     honours Step.About only on a v0.2 stamp, and a Policy built or decoded
//     any other way carries the zero value, which is never v0.2.
//
// Refusing a type happens before a byte of the payload is decoded. The error
// for a refused type is ErrPolicyRefused; a malformed payload returns the
// decoder's error.
func DecodePolicyEnvelope(payloadType string, payload []byte) (Policy, error) {
	switch payloadType {
	case PolicyPredicate, LegacyPolicyPredicate:
		var p Policy
		if err := json.Unmarshal(payload, &p); err != nil {
			return Policy{}, err
		}
		p.payloadVersion = policyVersionV01
		return p, nil
	case PolicyPredicateV02:
		p, err := decodePolicyV02(payload)
		if err != nil {
			return Policy{}, fmt.Errorf("policy %s: %w", PolicyPredicateV02, err)
		}
		p.payloadVersion = policyVersionV02
		return p, nil
	default:
		return Policy{}, ErrPolicyRefused{
			Reason: ReasonPolicyTypeUnknown,
			Detail: fmt.Sprintf("policy envelope PayloadType %q is not %s, %s or %s",
				payloadType, PolicyPredicate, LegacyPolicyPredicate, PolicyPredicateV02),
		}
	}
}

// decodePolicyV02 decodes with DisallowUnknownFields, refuses anything after
// the one JSON value (json.Unmarshal refuses it too), and re-checks the
// members of each external attestation: ExternalAttestation has its own
// UnmarshalJSON, and a custom unmarshaler is not reached by the outer
// decoder's DisallowUnknownFields.
func decodePolicyV02(payload []byte) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("unexpected data after the policy object")
	}

	var externals struct {
		ExternalAttestations map[string]json.RawMessage `json:"externalAttestations"`
	}
	if err := json.Unmarshal(payload, &externals); err != nil {
		return Policy{}, err
	}
	names := make([]string, 0, len(externals.ExternalAttestations))
	for name := range externals.ExternalAttestations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// externalAttestationMembers has ExternalAttestation's fields and none
		// of its methods, so this decode is strict all the way down.
		type externalAttestationMembers ExternalAttestation
		var members externalAttestationMembers
		inner := json.NewDecoder(bytes.NewReader(externals.ExternalAttestations[name]))
		inner.DisallowUnknownFields()
		if err := inner.Decode(&members); err != nil {
			return Policy{}, fmt.Errorf("external attestation %q: %w", name, err)
		}
	}
	return p, nil
}

// checkStepAbout refuses, before any evidence is read, a policy whose steps
// declare About where this engine cannot give it v0.2 meaning: any value but
// StepAboutSource (so a later value such as "seed" is never half-honoured),
// and any About at all unless the policy carries DecodePolicyEnvelope's v0.2
// stamp. Steps are checked in key order so the refusal is deterministic.
func (p Policy) checkStepAbout() error {
	for _, name := range p.sortedStepNames() {
		about := p.Steps[name].About
		if about == "" {
			continue
		}
		if about != StepAboutSource {
			return ErrPolicyRefused{
				Reason: ReasonAboutUnknownValue,
				Detail: fmt.Sprintf("step %q declares about %q; the only value is %q", name, about, StepAboutSource),
			}
		}
		if p.payloadVersion != policyVersionV02 {
			return ErrPolicyRefused{
				Reason: ReasonAboutNeedsPolicyV02,
				Detail: fmt.Sprintf("step %q declares about, which only a policy decoded from a %s envelope "+
					"(policy.DecodePolicyEnvelope) may carry", name, PolicyPredicateV02),
			}
		}
	}
	return nil
}
