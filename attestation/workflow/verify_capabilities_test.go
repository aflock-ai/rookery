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

package workflow

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/invopop/jsonschema"
)

// capabilityRecorder is an attestor that latches every optional verify
// capability the workflow can set, the way policyverify does.
type capabilityRecorder struct {
	fanout          int
	lazy            bool
	manifests       map[string][]byte
	inventoryLookup func(string) ([]byte, bool)
}

func (c *capabilityRecorder) Name() string                                 { return "recorder" }
func (c *capabilityRecorder) Type() string                                 { return "https://example.test/recorder" }
func (c *capabilityRecorder) RunType() attestation.RunType                 { return attestation.VerifyRunType }
func (c *capabilityRecorder) Attest(*attestation.AttestationContext) error { return nil }
func (c *capabilityRecorder) Schema() *jsonschema.Schema                   { return nil }
func (c *capabilityRecorder) SetMaxSubjectFanout(n int)                    { c.fanout = n }
func (c *capabilityRecorder) SetLazyWitness(enabled bool)                  { c.lazy = enabled }
func (c *capabilityRecorder) SetMaterialManifests(m map[string][]byte)     { c.manifests = m }
func (c *capabilityRecorder) SetInventoryLookup(lookup func(string) ([]byte, bool)) {
	c.inventoryLookup = lookup
}

// A verify option that is NOT supplied must clear the attestor's state, not
// leave the previous call's value in place. The setters used to run only when
// the option was set, so an attestor configured twice — once with detached
// manifests, once without — kept the first call's manifests and could hydrate
// a later verification from evidence that verification never loaded (the same
// hazard for the fan-out cap and the lazy-witness switch). The workflow owns
// the attestor's option state: every call writes every knob.
func TestApplyOptionalVerifyCapabilitiesClearsStateTheSecondCallDoesNotSupply(t *testing.T) {
	rec := &capabilityRecorder{}

	first := verifyOptions{
		maxSubjectFanout:  7,
		lazyWitness:       true,
		materialManifests: map[string][]byte{"deadbeef": []byte(`{}`)},
		inventoryLookup:   func(string) ([]byte, bool) { return nil, false },
	}
	applyOptionalVerifyCapabilities(rec, &first)
	if rec.fanout != 7 || !rec.lazy || len(rec.manifests) != 1 || rec.inventoryLookup == nil {
		t.Fatalf("first call did not apply every knob: %+v", rec)
	}

	second := verifyOptions{}
	applyOptionalVerifyCapabilities(rec, &second)
	if rec.fanout != 0 {
		t.Errorf("fan-out cap survived a call that did not set it: %d", rec.fanout)
	}
	if rec.lazy {
		t.Errorf("lazy witness survived a call that did not set it")
	}
	if len(rec.manifests) != 0 {
		t.Errorf("material manifests survived a call that did not supply any: %v", rec.manifests)
	}
	if rec.inventoryLookup != nil {
		t.Error("inventory lookup survived a call that did not supply it")
	}
}
