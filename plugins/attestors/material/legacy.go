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

package material

// Verify-only decoder for the historical v0.1 material predicate shape.
// Same design rationale as plugins/attestors/product/legacy.go.

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	legacyV01Name = "material-v0.1"

	// LegacyV01Type is the v0.1 predicate URI we accept for verification.
	LegacyV01Type = "https://aflock.ai/attestations/material/v0.1"
)

var errLegacyDecodeOnly = errors.New("legacy material attestor is verify-only: use v0.3 to produce new attestations")

func init() {
	attestation.RegisterAttestation(
		legacyV01Name,
		LegacyV01Type,
		attestation.MaterialRunType,
		func() attestation.Attestor { return newLegacyDecoder() },
	)
}

// LegacyDecoder is the verify-only decoder for v0.1 material predicates.
// Reads the historical (path -> DigestSet) map directly and exposes
// per-file subjects for policy evaluation.
type LegacyDecoder struct {
	materials map[string]cryptoutil.DigestSet
}

func newLegacyDecoder() *LegacyDecoder { return &LegacyDecoder{} }

func (a *LegacyDecoder) Name() string                 { return legacyV01Name }
func (a *LegacyDecoder) Type() string                 { return LegacyV01Type }
func (a *LegacyDecoder) RunType() attestation.RunType { return attestation.MaterialRunType }

func (a *LegacyDecoder) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(map[string]cryptoutil.DigestSet{})
}

func (a *LegacyDecoder) Attest(_ *attestation.AttestationContext) error {
	return errLegacyDecodeOnly
}

func (a *LegacyDecoder) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.materials)
}

func (a *LegacyDecoder) UnmarshalJSON(data []byte) error {
	mats := make(map[string]cryptoutil.DigestSet)
	if err := json.Unmarshal(data, &mats); err != nil {
		return fmt.Errorf("legacy material: decode predicate: %w", err)
	}
	a.materials = mats
	return nil
}

// Subjects emits one entry per recorded material file so the policy engine
// can match by per-file digest at verify time. Matches v0.1's
// `file:<path>` convention.
func (a *LegacyDecoder) Subjects() map[string]cryptoutil.DigestSet {
	out := make(map[string]cryptoutil.DigestSet, len(a.materials))
	for path, ds := range a.materials {
		if ds == nil {
			continue
		}
		out["file:"+path] = ds
	}
	return out
}

// BackRefs is empty for the same explosion-prevention reason as the
// product decoder. See plugins/attestors/product/legacy.go.
func (a *LegacyDecoder) BackRefs() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{}
}

// Materials exposes the decoded map for in-process consumers (slsa, link)
// that historically read material data via this interface.
func (a *LegacyDecoder) Materials() map[string]cryptoutil.DigestSet {
	return a.materials
}
