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

package slsa

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

// TrustedBuilder is one roots-of-trust entry: a builder.id and the highest
// SLSA Build level a verifier may grant provenance naming it, once the
// verifier has checked what Requires says. SLSA v1.2 "verifying artifacts":
// the level comes from this map, never from a claim inside the provenance.
type TrustedBuilder struct {
	// ID is the builder.id without its "@<ref or version>" suffix.
	ID       string `json:"id"`
	MaxLevel int    `json:"maxLevel"`
	// Mode is how cilock ran: "isolated-provenance-workflow" or "inline".
	Mode string `json:"mode"`
	// Requires is what a verifier must check before granting MaxLevel.
	Requires string `json:"requires"`
	// Proof names the Lean theorem the grant rests on.
	Proof string `json:"proof"`
}

//go:embed trusted-builders.json
var trustedBuildersJSON []byte

var trustedBuilders = sync.OnceValue(func() []TrustedBuilder {
	var out []TrustedBuilder
	if err := json.Unmarshal(trustedBuildersJSON, &out); err != nil {
		panic("slsa: trusted-builders.json: " + err.Error()) // compiled-in data; TestTrustedBuildersCatalog covers it
	}
	return out
})

// TrustedBuilders returns a copy of the catalog.
func TrustedBuilders() []TrustedBuilder {
	return append([]TrustedBuilder(nil), trustedBuilders()...)
}

// BuilderMaxLevel is the highest SLSA Build level the catalog allows for
// builderID ("<id>@<ref>"), or 0 when the builder is unknown. The match on the
// part before the first "@" is exact: no case folding, prefix or glob.
func BuilderMaxLevel(builderID string) int {
	id, ref, ok := strings.Cut(builderID, "@")
	if !ok || ref == "" {
		return 0
	}
	for _, b := range trustedBuilders() {
		if b.ID == id {
			return b.MaxLevel
		}
	}
	return 0
}
