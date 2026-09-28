// jade:ring local

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

package baseancestry

// formal:differential
//
// Binds the base-ancestry half of the redaction model (formal/security-backlog,
// SecBacklog/Redact.lean, `requiredBase`, #9181) to sanitizeRemoteURL. Each
// vector is the text after "https://"; a kept remote must equal the model's
// output and a refused one must be refused. Only '/' is used as the
// terminator: sanitizeRemoteURL also cuts the query and fragment after
// classification, which the model leaves out.
//
// There is no `asbuilt` column for this redactor: main's url.Parse is not
// modelled (a documented gap in docs/design/security-backlog.md), so this test
// lands with the fix.
//
// The vectors live in the Judge monorepo, so this test skips when rookery is
// built on its own, unless JADE_FORMAL_DIFFERENTIAL=1.

import (
	"encoding/json"
	"os"
	"testing"
)

const formalRedactVectors = "../../../../../formal/security-backlog/vectors/redact.json"

func TestFormalRedactDifferential(t *testing.T) {
	raw, err := os.ReadFile(formalRedactVectors)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var f struct {
		Cases [][]*string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range f.Cases {
		in := "https://" + *c[0]
		got, ok := sanitizeRemoteURL(in)
		if c[3] == nil {
			if ok {
				t.Errorf("sanitizeRemoteURL(%q) kept %q; the model refuses it", in, got)
			}
			continue
		}
		if want := "https://" + *c[3]; !ok || got != want {
			t.Errorf("sanitizeRemoteURL(%q) = %q, %v; the model keeps %q", in, got, ok, want)
		}
	}
}
