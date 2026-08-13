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
	"crypto"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// sectionExempt lists V02Predicate fields that legitimately do not appear as
// sections in MarshalV02WithSections.
var sectionExempt = map[string]bool{
	"_meta": true, // the section index itself; emitted separately
}

// TestEverySignedFieldHasASection is a structural guard on the section
// encoder's hand-maintained spec list.
//
// MarshalV02WithSections emits ONLY the sections named in `specs`. A field
// added to V02Predicate but forgotten there is silently dropped from the SIGNED
// body — the attestor collects the evidence, the operator believes it exists,
// and nothing anywhere fails. That is strictly worse than never collecting it.
//
// This test derives the expected set from the struct by reflection rather than
// restating it, so it cannot drift the way the list it guards can. It caught a
// real drop when `scripts` was added.
func TestEverySignedFieldHasASection(t *testing.T) {
	emitted := emittedSectionNames(t)

	rt := reflect.TypeOf(V02Predicate{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" {
			continue // unexported: never marshalled
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" || sectionExempt[name] {
			continue
		}
		if !emitted[name] {
			t.Errorf("V02Predicate field %q (json:%q) has no entry in the "+
				"MarshalV02WithSections spec list — it will be SILENTLY DROPPED "+
				"from the signed predicate. Add it to specs, or to sectionExempt "+
				"with a reason.", f.Name, name)
		}
	}
}

// emittedSectionNames drives the real encoder with every field populated and
// reports which sections it actually wrote.
//
// It asserts against encoder OUTPUT rather than reading the source list,
// because a guard that re-parses the thing it guards shares its defects.
func emittedSectionNames(t *testing.T) map[string]bool {
	t.Helper()

	p := &V02Predicate{
		Summary:   &TraceSummary{CaptureMode: "test"},
		Digests:   []V02DigestEntry{{Digests: map[string]string{"sha256": "aa"}}},
		Paths:     []string{"/tmp/x"},
		Comms:     []string{"bash"},
		Cmdlines:  []string{"bash -x"},
		Processes: []V02Process{{ProcessID: 1}},
		Cmd:       []string{"bash", "x.sh"},
		ExitCode:  7,
		Stdout:    "out",
		Stderr:    "err",
		Scripts:   []ScriptRef{{Path: "/tmp/x.sh", Role: RoleInterpreterOperand}},
	}

	_, out, err := MarshalV02WithSections(p)
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	if len(out.Meta.Sections) == 0 {
		t.Fatal("encoder produced no sections at all — guard cannot function")
	}
	got := make(map[string]bool, len(out.Meta.Sections))
	for name := range out.Meta.Sections {
		got[name] = true
	}
	return got
}

// TestEverySignedFieldSurvivesRoundTrip is the end-to-end form of the guard
// above, and the one that matters.
//
// Carrying a field through the wire requires it to appear in THREE independent
// hand-maintained lists: the MarshalV02WithSections spec table, ToV02, and the
// field-by-field copy in CommandRun.UnmarshalJSON. Adding `scripts` initially
// missed two of the three, and neither omission failed anything — the evidence
// was collected, signed away, and silently discarded on read-back.
//
// Reflection over a fully-populated CommandRun catches all three at once,
// without restating any of the lists it guards.
func TestEverySignedFieldSurvivesRoundTrip(t *testing.T) {
	// Fields whose absence after a round trip is by design.
	roundTripExempt := map[string]bool{
		// Processes reconstruct through the interning tables and are covered
		// by the dedicated v0.2 interning tests.
		"processes": true,
	}

	orig := &CommandRun{
		Cmd:      []string{"bash", "build.sh"},
		ExitCode: 3,
		Stdout:   "stdout-marker",
		Stderr:   "stderr-marker",
		Summary:  &TraceSummary{CaptureMode: "roundtrip-marker"},
		Scripts: []ScriptRef{{
			Path: "/tmp/build.sh",
			Role: RoleInterpreterOperand,
			Digest: cryptoutil.DigestSet{
				cryptoutil.DigestValue{Hash: crypto.SHA256}: strings.Repeat("a", 64),
			},
			SizeBytes: 42,
		}},
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back CommandRun
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rv, bv := reflect.ValueOf(*orig), reflect.ValueOf(back)
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" {
			continue // unexported config, not wire state
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" || roundTripExempt[name] {
			continue
		}
		want, got := rv.Field(i), bv.Field(i)
		if want.IsZero() {
			t.Fatalf("fixture leaves %q zero — the guard cannot detect a drop "+
				"of a field it never populated", name)
		}
		if got.IsZero() {
			t.Errorf("field %q (json:%q) was DROPPED by the marshal/unmarshal "+
				"round trip. Check all three: the MarshalV02WithSections spec "+
				"list, ToV02, and CommandRun.UnmarshalJSON.", f.Name, name)
		}
	}
}
