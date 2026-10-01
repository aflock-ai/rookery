// Copyright 2026 The Aflock Authors
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
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/sigstore/fulcio/pkg/certificate"
)

// slsaProvenanceV1Type is the SLSA v1.0 predicate type.
const slsaProvenanceV1Type = "https://slsa.dev/provenance/v1"

// slsaProvenanceLegacyType is the non-spec spelling cilock emitted before
// #9827. It is not accepted anywhere (Cole, 2026-09-29: no deprecation
// window): evidence that carries it is refused by name, so a customer sees why
// and re-attests as SLSA v1.
const slsaProvenanceLegacyType = "https://slsa.dev/provenance/v1.0"

// ErrSLSALegacyProvenanceType refuses SLSA provenance recorded, signed or
// asked for under the pre-#9827 predicate type.
type ErrSLSALegacyProvenanceType struct{}

func (ErrSLSALegacyProvenanceType) Error() string {
	return "slsa provenance predicateType " + slsaProvenanceLegacyType + " is no longer accepted; re-attest with SLSA v1 (" + slsaProvenanceV1Type + ")"
}

// ErrSLSABuilderIdentityUnbacked rejects SLSA provenance whose builder.id
// names a CI workflow identity (the isolated provenance signer's reusable
// workflow, for example) that no authorized signer's certificate carries as
// its Fulcio Build Signer URI (OID 1.3.6.1.4.1.57264.1.9). The provenance
// body is written by whoever ran the attestor; only the Fulcio extension is
// stamped by the CA from the CI platform's own OIDC token, so a builder.id
// that claims a workflow identity is trusted only when the two agree.
type ErrSLSABuilderIdentityUnbacked struct {
	BuilderID string
}

func (e ErrSLSABuilderIdentityUnbacked) Error() string {
	return fmt.Sprintf("slsa provenance builder.id %q names a CI workflow identity, but no authorized signer's certificate carries it as the Fulcio Build Signer URI (1.3.6.1.4.1.57264.1.9)", e.BuilderID)
}

// ErrSLSABuilderKeyAmbiguous rejects SLSA provenance that spells a key on the
// runDetails.builder.id path more than once, or only in another case
// ("rundetails", "ID"). Readers disagree on such a body: encoding/json matches
// struct fields case-insensitively and keeps the last match, a first-wins
// parser keeps the first, and Rego keeps "runDetails" and "rundetails" as
// distinct keys. The builder check and the policy would then judge different
// builder ids, so the body is refused rather than resolved one way.
type ErrSLSABuilderKeyAmbiguous struct {
	Key string
}

func (e ErrSLSABuilderKeyAmbiguous) Error() string {
	return fmt.Sprintf("slsa provenance spells %q more than once or in another case; refusing a builder.id that readers would resolve differently", e.Key)
}

// builderIDClaimsWorkflowIdentity reports whether a builder.id names a CI
// workflow identity: the "<host>/<owner>/<repo>/.github/workflows/<file>@<ref>"
// form Fulcio stamps as the Build Signer URI for GitHub Actions (github.com
// and GHES alike). The match is case-insensitive so a respelled host or path
// cannot slip past the check while still reading as the workflow.
//
// Other builder ids are out of scope: cilock's inline ids
// (https://aflock.ai/cilock/inline/...) and the legacy aflock.ai ids claim no
// platform identity, and third-party builders (Tekton Chains, for example)
// are commonly key-signed and are left to policy. GitLab's Build Signer URI
// form is not covered yet.
func builderIDClaimsWorkflowIdentity(id string) bool {
	return strings.Contains(strings.ToLower(id), "/.github/workflows/")
}

// checkSLSAProvenance runs the verifier's SLSA provenance checks on one
// attestation. predicateTypes are the type names the attestation is known by
// (its recorded type; for an external, the type the policy asked for and the
// envelope's statement type). Any of them being the pre-#9827 spelling is
// ErrSLSALegacyProvenanceType. For SLSA provenance v1 it then enforces
// ErrSLSABuilderIdentityUnbacked; signers are the verifiers that satisfied the
// policy's functionaries, not every signature on the envelope.
func checkSLSAProvenance(att attestation.Attestor, signers []cryptoutil.Verifier, predicateTypes ...string) error {
	isProvenance := false
	for _, pt := range predicateTypes {
		if pt == slsaProvenanceLegacyType {
			return ErrSLSALegacyProvenanceType{}
		}
		if pt == slsaProvenanceV1Type {
			isProvenance = true
		}
	}
	if !isProvenance || att == nil {
		return nil
	}

	raw, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("slsa provenance: cannot read builder.id: %w", err)
	}
	id, err := slsaBuilderID(raw)
	if err != nil {
		return err
	}
	if !builderIDClaimsWorkflowIdentity(id) {
		return nil
	}

	for _, signer := range signers {
		x509Verifier, ok := signer.(*cryptoutil.X509Verifier)
		if !ok {
			continue
		}
		ext, err := certificate.ParseExtensions(x509Verifier.Certificate().Extensions)
		if err != nil {
			continue
		}
		if ext.BuildSignerURI == id {
			return nil
		}
	}
	return ErrSLSABuilderIdentityUnbacked{BuilderID: id}
}

// slsaBuilderID reads runDetails.builder.id from a provenance body by exact
// key, the way Rego's input.runDetails.builder.id does, and refuses any
// object on that path that also carries the key in another spelling or a
// second time (ErrSLSABuilderKeyAmbiguous). An absent or null runDetails,
// builder or id yields "" (no claim); a body, runDetails or builder that is
// not an object, or an id that is not a string, is malformed.
func slsaBuilderID(raw []byte) (string, error) {
	cur := json.RawMessage(raw)
	for _, key := range []string{"runDetails", "builder", "id"} {
		members, ok := jsonObjectMembers(cur)
		if !ok {
			return "", fmt.Errorf("slsa provenance: cannot read builder.id: the value holding %q is not a JSON object", key)
		}
		var val json.RawMessage
		for _, m := range members {
			if !strings.EqualFold(m.key, key) {
				continue
			}
			if m.key != key || val != nil {
				return "", ErrSLSABuilderKeyAmbiguous{Key: key}
			}
			val = m.val
		}
		if val == nil || string(bytes.TrimSpace(val)) == "null" {
			return "", nil
		}
		cur = val
	}
	var id string
	if err := json.Unmarshal(cur, &id); err != nil {
		return "", fmt.Errorf("slsa provenance: cannot read builder.id: %w", err)
	}
	return id, nil
}

type jsonMember struct {
	key string
	val json.RawMessage
}

// jsonObjectMembers lists an object's members in document order, repeats
// included, which a decode into a map or a struct would collapse. ok is false
// for anything that is not a well-formed JSON object.
func jsonObjectMembers(raw json.RawMessage) ([]jsonMember, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var members []jsonMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := tok.(string)
		if !ok {
			return nil, false
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, false
		}
		members = append(members, jsonMember{key: key, val: val})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	return members, true
}
