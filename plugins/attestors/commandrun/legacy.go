// Copyright 2026 The Rookery Contributors
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

// V2 Phase 4: verify-only decoder for v0.1 command-run attestations.
//
// Follows the pattern from `plugins/attestors/product/legacy.go`. The
// v0.1 attestor remains the producer in this commit because the v0.2
// emitter isn't yet wired into the attestation framework's Attest()
// path (that's a follow-up). When v0.2 takes over the producer role,
// THIS decoder takes over the v0.1 verify path so existing envelopes
// in production keep validating.
//
// Registration: legacyV01Name `command-run-v0.1`, distinct from the
// producer name `command-run`. cilock run --attestations command-run
// selects the producer; verifiers handed a v0.1 envelope route to
// this decoder by predicate-type URI.

package commandrun

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	legacyV01Name = "command-run-v0.1"
	// LegacyV01Type is the predicate URI of pre-v0.2 attestations.
	LegacyV01Type = "https://aflock.ai/attestations/command-run/v0.1"
)

// errLegacyDecodeOnly mirrors product/legacy.go's contract: a verify-only
// decoder must REFUSE Attest() so an accidental producer-mode call
// fails loudly. The producer is the v0.2 attestor (when wired in a
// follow-up) registered under `command-run`.
var errLegacyDecodeOnly = errors.New(
	"legacy command-run attestor is verify-only: use v0.2 to produce new attestations",
)

// LegacyDecoder parses a v0.1 command-run predicate body for
// verification. It deliberately re-uses the existing CommandRun
// struct (which IS the v0.1 wire shape) — no separate type alias.
// This keeps the decoder's behavior matched to what producer-side
// v0.1 actually emitted, byte-for-byte.
type LegacyDecoder struct {
	predicateType string
	cmd           *CommandRun
}

func newLegacyDecoder(predicateType string) *LegacyDecoder {
	return &LegacyDecoder{
		predicateType: predicateType,
		cmd:           New(),
	}
}

func (a *LegacyDecoder) Name() string                 { return legacyV01Name }
func (a *LegacyDecoder) Type() string                 { return a.predicateType }
func (a *LegacyDecoder) RunType() attestation.RunType { return attestation.ExecuteRunType }
func (a *LegacyDecoder) Schema() *jsonschema.Schema   { return jsonschema.Reflect(&CommandRun{}) }
func (a *LegacyDecoder) Attest(_ *attestation.AttestationContext) error {
	return errLegacyDecodeOnly
}

// MarshalJSON re-emits the inner CommandRun exactly as v0.1 did, so
// a verifier round-tripping a decoded attestation produces byte-
// identical output (modulo Go map ordering — semantically equivalent).
func (a *LegacyDecoder) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.cmd)
}

// UnmarshalJSON decodes the v0.1 predicate body into the inner
// CommandRun.
func (a *LegacyDecoder) UnmarshalJSON(data []byte) error {
	cmd := New()
	if err := json.Unmarshal(data, cmd); err != nil {
		return fmt.Errorf("legacy command-run (%s): decode: %w", a.predicateType, err)
	}
	a.cmd = cmd
	return nil
}

// Subjects emits per-file subjects so the policy engine's subject
// graph can match v0.1 attestations by digest. v0.1 didn't emit
// subjects from CommandRun directly (the file subjects came from
// the material/product attestors), but verify-time policy still
// expects them; we synthesize from OpenedFiles for consistency
// with the v0.3 product attestor's pattern.
func (a *LegacyDecoder) Subjects() map[string]cryptoutil.DigestSet {
	if a.cmd == nil {
		return nil
	}
	out := make(map[string]cryptoutil.DigestSet, 64)
	for i := range a.cmd.Processes {
		for path, ds := range a.cmd.Processes[i].OpenedFiles {
			if ds == nil {
				continue
			}
			out["file:"+path] = ds
		}
	}
	return out
}

// BackRefs is empty by design — see product/legacy.go for the
// per-file BackRefs explosion rationale. Verify-time per-file
// lookups go through Subjects.
func (a *LegacyDecoder) BackRefs() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{}
}

// Data exposes the decoded CommandRun for in-process consumers
// (link, slsa, policy) that read trace data via this interface.
func (a *LegacyDecoder) Data() *CommandRun { return a.cmd }
