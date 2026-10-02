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

package policy

import (
	"strings"
	"testing"
)

// Onboarding-simulator runs fullblind45 and one other: the agent wrote a rego
// module as a bare string where the schema wants {"name", "module"}, and every
// command answered with the decoder's "cannot unmarshal string into Go struct
// field attestation.steps.attestations.regopolicies of type
// policy.regoPolicy", which names neither the element nor the shape to write.
const regoAsString = `{
  "expires": "2030-01-01T00:00:00Z",
  "steps": {"build": {"name": "build", "functionaries": [{"type": "root"}],
    "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1",
      "regopolicies": ["cGFja2FnZSB4"]}]}}
}`

func TestShapeErrorsNameTheElementAndTheExpectedShape(t *testing.T) {
	got := ShapeErrors([]byte(regoAsString))
	want := `steps.build.attestations[0].regopolicies[0] must be an object {"name": "<rule name>", "module": "<base64 rego>"}; got a string`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("ShapeErrors:\n got %q\nwant [%q]", got, want)
	}
}

func TestShapeErrorsCoversEveryObjectPositionOnTheRegoPath(t *testing.T) {
	for name, tc := range map[string]struct{ doc, want string }{
		"regopolicies not an array": {
			`{"steps":{"s":{"attestations":[{"type":"t","regopolicies":{"name":"a","module":"b"}}]}}}`,
			`steps.s.attestations[0].regopolicies must be an array of objects [{"name": "<rule name>", "module": "<base64 rego>"}]; got an object`,
		},
		"module not a string": {
			`{"steps":{"s":{"attestations":[{"type":"t","regopolicies":[{"name":"a","module":{"x":1}}]}]}}}`,
			`steps.s.attestations[0].regopolicies[0].module must be a string (the rego module, base64-encoded); got an object`,
		},
		"name not a string": {
			`{"steps":{"s":{"attestations":[{"type":"t","regopolicies":[{"name":7,"module":"b"}]}]}}}`,
			`steps.s.attestations[0].regopolicies[0].name must be a string; got a number`,
		},
		"attestation not an object": {
			`{"steps":{"s":{"attestations":["https://aflock.ai/attestations/git/v0.1"]}}}`,
			`steps.s.attestations[0] must be an object {"type": "<predicate type>", "regopolicies": [...]}; got a string`,
		},
		"attestations not an array": {
			`{"steps":{"s":{"attestations":"git"}}}`,
			`steps.s.attestations must be an array of objects [{"type": "<predicate type>", "regopolicies": [...]}]; got a string`,
		},
		"functionary not an object": {
			`{"steps":{"s":{"functionaries":["root"]}}}`,
			`steps.s.functionaries[0] must be an object {"type": "root", "certConstraint": {...}} or {"type": "publickey", "publickeyid": "..."}; got a string`,
		},
		"step not an object": {
			`{"steps":{"s":[]}}`,
			`steps.s must be an object {"name": "s", "functionaries": [...], "attestations": [...]}; got an array`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := ShapeErrors([]byte(tc.doc))
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("ShapeErrors:\n got %q\nwant [%q]", got, tc.want)
			}
		})
	}
}

// The explainer only describes what the decoder already refuses. A shape the
// decoder accepts (null elements, an absent list) must produce nothing, or it
// would add a refusal the verifier never had.
func TestShapeErrorsIsSilentOnWhatTheDecoderAccepts(t *testing.T) {
	for _, doc := range []string{
		`{"steps":{"s":{"attestations":[{"type":"t"}]}}}`,
		`{"steps":{"s":{"attestations":[{"type":"t","regopolicies":null}]}}}`,
		`{"steps":{"s":{"attestations":[{"type":"t","regopolicies":[null]}]}}}`,
		`{"steps":{"s":{"attestations":null,"functionaries":null}}}`,
		`{"steps":null}`,
		`not json`,
	} {
		if got := ShapeErrors([]byte(doc)); len(got) != 0 {
			t.Errorf("%s: want no shape errors, got %q", doc, got)
		}
	}
}

// A step name is author text; it must not carry a control character to the
// terminal through the path.
func TestShapeErrorsQuotesAnUnprintableStepName(t *testing.T) {
	got := ShapeErrors([]byte("{\"steps\":{\"a\\u001b[31m\":{\"attestations\":\"x\"}}}"))
	if len(got) != 1 || strings.ContainsRune(got[0], '\x1b') {
		t.Fatalf("want one error with the escape quoted, got %q", got)
	}
}

// Every decode path that verify and sign reach must say the same thing.
func TestDecodePolicyEnvelopeExplainsTheShape(t *testing.T) {
	for _, pt := range []string{PolicyPredicate, PolicyPredicateV02} {
		_, err := DecodePolicyEnvelope(pt, []byte(regoAsString))
		if err == nil {
			t.Fatalf("%s: a string rego policy must still be refused", pt)
		}
		if !strings.Contains(err.Error(), `steps.build.attestations[0].regopolicies[0] must be an object {"name": "<rule name>", "module": "<base64 rego>"}; got a string`) {
			t.Errorf("%s: the refusal must name the element and its shape, got: %v", pt, err)
		}
	}
}
