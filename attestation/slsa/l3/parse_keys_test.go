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

package l3

import (
	"bytes"
	"testing"
)

// The statement is decoded into Go structs, and encoding/json matches a key
// to a field case-insensitively and keeps the last match. An exact-key reader
// (Rego, a JavaScript verifier, a map decode) resolves "subject" beside
// "Subject", or a repeated "id", to a different value, so the L3 verdict and
// every other reader of the same envelope would judge different subjects,
// builders or parameters. Any object in the payload with two keys equal up to
// case is refused (the sibling of Codex #10633's builder.id finding).
func TestStatementFromPayloadRefusesCollidingKeys(t *testing.T) {
	good := statementJSON(t, ProvenancePredicateType,
		[]testSubject{{Name: "app", Digest: map[string]string{"sha256": subjectHex}}},
		provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://github.com/acme/app/actions/runs/42", "acme/app", commit))
	if _, err := StatementFromPayload(good); err != nil {
		t.Fatalf("the unmodified payload must parse: %v", err)
	}
	const evilHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	inject := func(t *testing.T, at, extra string) []byte {
		t.Helper()
		if bytes.Count(good, []byte(at)) != 1 {
			t.Fatalf("%q must occur once in %s", at, good)
		}
		return bytes.Replace(good, []byte(at), []byte(extra+at), 1)
	}
	cases := map[string]struct{ at, extra string }{
		"Subject beside subject":          {`"subject":`, `"Subject":[{"name":"evil","digest":{"sha256":"` + evilHex + `"}}],`},
		"_type repeated":                  {`"_type":`, `"_type":"https://in-toto.io/Statement/v1",`},
		"PredicateType beside the type":   {`"predicateType":`, `"PredicateType":"https://slsa.dev/provenance/v1",`},
		"rundetails beside runDetails":    {`"runDetails":`, `"rundetails":{"builder":{"id":"https://github.com/evil/x/.github/workflows/y.yml@refs/tags/v1"}},`},
		"Builder beside builder":          {`"builder":`, `"Builder":{"id":"https://github.com/evil/x/.github/workflows/y.yml@refs/tags/v1"},`},
		"id repeated":                     {`"id":`, `"id":"https://github.com/evil/x/.github/workflows/y.yml@refs/tags/v1",`},
		"InvocationId beside the run":     {`"invocationId":`, `"InvocationId":"https://github.com/evil/x/actions/runs/1",`},
		"workflow repeated in parameters": {`"workflow":`, `"workflow":{"repository":"https://github.com/evil/x","path":"a","ref":"b"},`},
		"Digest beside a dependency's":    {`"digest":{"gitCommit"`, `"Digest":{"gitCommit":"2222222222222222222222222222222222222222"},`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			payload := inject(t, tc.at, tc.extra)
			if s, err := StatementFromPayload(payload); err == nil {
				t.Fatalf("parsed %+v from %s, want an error", s, payload)
			}
			if _, err := decodeStatement(payload); err == nil {
				t.Fatalf("decodeStatement accepted %s", payload)
			}
		})
	}
}

// Keys that differ in more than case are unaffected, and so is a key that
// only one object on the path carries.
func TestStatementFromPayloadKeepsDistinctKeys(t *testing.T) {
	good := statementJSON(t, ProvenancePredicateType,
		[]testSubject{{Name: "app", Digest: map[string]string{"sha256": subjectHex, "SHA1": "abc", "sha1": "abc"}}},
		provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://github.com/acme/app/actions/runs/42", "acme/app", commit))
	// A digest map is data, not schema: "sha1" beside "SHA1" is a collision
	// too, and is refused like any other.
	if _, err := StatementFromPayload(good); err == nil {
		t.Fatal("a digest map with sha1 and SHA1 must be refused")
	}
	ok := statementJSON(t, ProvenancePredicateType,
		[]testSubject{{Name: "app", Digest: map[string]string{"sha256": subjectHex, "sha512": "abc"}}},
		provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://github.com/acme/app/actions/runs/42", "acme/app", commit))
	if _, err := StatementFromPayload(ok); err != nil {
		t.Fatalf("distinct keys must parse: %v", err)
	}
}
