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

package commandrun

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSchemaCarriesScripts pins that the published schema exposes every field
// the signed predicate can carry, `scripts` included.
//
// This exists because "you added a predicate field without updating Schema()"
// is a reasonable thing to suspect and an expensive thing to re-check by
// reading. Schema() is jsonschema.Reflect over the struct, so the field is
// derived rather than hand-listed — but that is a property of the CURRENT
// implementation, not a guarantee. Someone replacing Reflect with a
// hand-maintained schema would silently drop `scripts` from what verifiers
// see while the attestor kept emitting it.
//
// Asserting on the rendered schema rather than on the use of Reflect is the
// point: it holds whichever way the schema is produced.
func TestSchemaCarriesScripts(t *testing.T) {
	a := New()
	schema := a.Schema()
	if schema == nil {
		t.Fatal("Schema() returned nil")
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	rendered := string(raw)

	// Sanity-check the probe before trusting a hit: a schema that somehow
	// rendered as an empty object would "not contain" anything and every
	// absence assertion below would pass vacuously.
	for _, anchor := range []string{"exitcode", "cmd"} {
		if !strings.Contains(rendered, anchor) {
			t.Fatalf("schema does not mention %q — the probe is broken, not the schema: %s",
				anchor, truncateForMsg(rendered))
		}
	}

	if !strings.Contains(rendered, "scripts") {
		t.Errorf("the signed predicate carries `scripts` but the published schema does not "+
			"mention it: a verifier reading this schema cannot constrain the new evidence. "+
			"schema=%s", truncateForMsg(rendered))
	}
}

func truncateForMsg(s string) string {
	const max = 600
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
