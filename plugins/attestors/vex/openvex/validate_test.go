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

package openvex

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// zeroTime is the value a `"timestamp": ""`-style document decodes to —
// present in the struct, meaningless as a time.
var zeroTime time.Time

// validDoc is the control every rejection case below mutates. It is the
// minimum a consumer needs: an attributable, ordered, identified document
// carrying one joinable, fully-stated claim.
func validDoc() *VEX {
	ts := fixedClock()()
	return &VEX{
		Metadata: Metadata{
			Context:   Context,
			ID:        "https://openvex.dev/docs/public/vex-test",
			Author:    "cilock",
			Timestamp: &ts,
			Version:   1,
		},
		Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2024-12345"},
			Products:      []Product{{Component: Component{ID: "pkg:golang/example.com/mod@v1.2.3"}}},
			Status:        StatusFixed,
		}},
	}
}

func TestValidateAcceptsMinimalDocument(t *testing.T) {
	if err := Validate(validDoc()); err != nil {
		t.Fatalf("Validate rejected the control document: %v", err)
	}
}

// TestValidateRejects is the spec floor. Each case breaks the control
// document in exactly one way, so a passing subtest attributes the
// rejection to that one field.
func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*VEX){
		"empty document":       func(d *VEX) { *d = VEX{} },
		"no context":           func(d *VEX) { d.Context = "" },
		"foreign context":      func(d *VEX) { d.Context = "https://example.com/not-vex" },
		"lookalike context":    func(d *VEX) { d.Context = "https://openvex.dev/nsfw/v0.2.0" },
		"no id":                func(d *VEX) { d.ID = "" },
		"no author":            func(d *VEX) { d.Author = "  " },
		"no timestamp":         func(d *VEX) { d.Timestamp = nil },
		"zero timestamp":       func(d *VEX) { d.Timestamp = &zeroTime },
		"no version":           func(d *VEX) { d.Version = 0 },
		"negative version":     func(d *VEX) { d.Version = -1 },
		"no statements":        func(d *VEX) { d.Statements = nil },
		"empty statement list": func(d *VEX) { d.Statements = []Statement{} },
		"no vulnerability":     func(d *VEX) { d.Statements[0].Vulnerability.Name = "" },
		"no products":          func(d *VEX) { d.Statements[0].Products = nil },
		"unidentifiable product": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{Supplier: "acme"}}}
		},
		// Presence is not identity. Each of the following is a NON-EMPTY
		// hash or identifier map, so a `len(...) > 0` check credits it as
		// a joinable product — and signs a suppression that joins to no
		// finding at all.
		"empty hash value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{Hashes: map[Algorithm]Hash{SHA256: ""}}}}
		},
		"whitespace hash value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{Hashes: map[Algorithm]Hash{SHA256: "   "}}}}
		},
		"truncated hash value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{Hashes: map[Algorithm]Hash{SHA256: "d0d0caca"}}}}
		},
		// Right length, wrong alphabet: a "sha256:"-prefixed value is the
		// most likely real-world spelling, and it is not the digest.
		"prefixed hash value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Hashes: map[Algorithm]Hash{SHA256: Hash("sha256:" + testDigest)},
			}}}
		},
		"malformed hash alongside a good id": func(d *VEX) {
			d.Statements[0].Products[0].Hashes = map[Algorithm]Hash{SHA256: "nope"}
		},
		"empty identifier value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{PURL: ""},
			}}}
		},
		"whitespace identifier value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{PURL: "  "},
			}}}
		},
		"purl without a pkg scheme": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{PURL: "golang/example.com/mod@v1.2.3"},
			}}}
		},
		"unidentifiable subcomponent": func(d *VEX) {
			d.Statements[0].Products[0].Subcomponents = []Subcomponent{{Component: Component{Supplier: "acme"}}}
		},
		"subcomponent with an empty hash": func(d *VEX) {
			d.Statements[0].Products[0].Subcomponents = []Subcomponent{{
				Component: Component{Hashes: map[Algorithm]Hash{SHA256: ""}},
			}}
		},
		// Validation reads the decoded struct while the attestor signs the
		// authored BYTES verbatim. A value that only passes after
		// TrimSpace is therefore a value whose signed form was never
		// validated — and for join keys (context, id, digests,
		// identifiers) the padded spelling is not reliably joinable at
		// all. The floor rejects non-canonical whitespace instead of
		// quietly validating a document other than the one it signs.
		"padded context":         func(d *VEX) { d.Context = " " + Context },
		"trailing-space context": func(d *VEX) { d.Context = Context + " " },
		"padded id":              func(d *VEX) { d.ID = " https://openvex.dev/docs/public/vex-test" },
		"padded author":          func(d *VEX) { d.Author = " cilock " },
		"padded vulnerability name": func(d *VEX) {
			d.Statements[0].Vulnerability.Name = " CVE-2024-12345"
		},
		"padded component id": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{ID: "pkg:golang/example.com/mod@v1.2.3 "}}}
		},
		"whitespace-only component id alongside a valid purl": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				ID:          "  ",
				Identifiers: map[IdentifierType]string{PURL: "pkg:golang/example.com/mod@v1.2.3"},
			}}}
		},
		"padded hash value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Hashes: map[Algorithm]Hash{SHA256: Hash(" " + testDigest)},
			}}}
		},
		"padded purl value": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{PURL: "pkg:golang/example.com/mod@v1.2.3 "},
			}}}
		},
		// A declared identifier TYPE and its value must agree: a 2.3
		// formatted string under the cpe22 key (or the reverse) is signed
		// evidence whose label disagrees with its content, and a consumer
		// keying on the declared type would parse it with the wrong
		// binding.
		"cpe22 key carrying a 2.3 formatted string": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{CPE22: "cpe:2.3:a:acme:api:1.0:*:*:*:*:*:*:*"},
			}}}
		},
		"cpe23 key carrying a 2.2 uri": func(d *VEX) {
			d.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{CPE23: "cpe:/a:acme:api"},
			}}}
		},
		"no status":      func(d *VEX) { d.Statements[0].Status = "" },
		"unknown status": func(d *VEX) { d.Statements[0].Status = "safe" },
		"miscased status": func(d *VEX) {
			d.Statements[0].Status = "FIXED"
		},
		"not_affected without a reason": func(d *VEX) {
			d.Statements[0].Status = StatusNotAffected
		},
		"unknown justification": func(d *VEX) {
			d.Statements[0].Status = StatusNotAffected
			d.Statements[0].Justification = "trust_me"
		},
		"affected without an action statement": func(d *VEX) {
			d.Statements[0].Status = StatusAffected
		},
		"justification on fixed": func(d *VEX) {
			d.Statements[0].Justification = ComponentNotPresent
		},
		"second statement invalid": func(d *VEX) {
			bad := d.Statements[0]
			bad.Status = StatusAffected
			d.Statements = append(d.Statements, bad)
		},
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			breakIt(doc)
			if err := Validate(doc); err == nil {
				t.Fatal("Validate accepted a document that is not usable evidence")
			}
		})
	}
}

// TestValidateAcceptsSpecAlternatives pins the shapes a not_affected
// statement may legitimately take. Both of them carry a justification —
// that is the point of the rule, and this test previously asserted the
// opposite.
func TestValidateAcceptsSpecAlternatives(t *testing.T) {
	// An impact_statement is SUPPLEMENTAL to the justification, never a
	// substitute for it: OpenVEX says a not_affected statement MUST carry
	// a status justification and MAY carry an impact statement. Both
	// together is the richest form and must validate.
	doc := validDoc()
	doc.Statements[0].Status = StatusNotAffected
	doc.Statements[0].Justification = VulnerableCodeNotInExecutePath
	doc.Statements[0].ImpactStatement = "the vulnerable parser is unreachable from the request path"
	if err := Validate(doc); err != nil {
		t.Fatalf("Validate rejected a fully-specified not_affected statement: %v", err)
	}

	// A justification on its own is the minimum, and is enough.
	doc = validDoc()
	doc.Statements[0].Status = StatusNotAffected
	doc.Statements[0].Justification = ComponentNotPresent
	if err := Validate(doc); err != nil {
		t.Fatalf("Validate rejected a not_affected statement carrying only a justification: %v", err)
	}
}

// TestImpactStatementIsNotAJustification is the regression bar for the
// rule this validator got wrong.
//
// A not_affected statement suppresses a finding, and the thing that makes
// it actionable is the FIXED justification value — one of a closed
// enumeration a consumer can match on. An impact_statement is free prose.
// Accepting prose in place of the enumeration let a suppression through
// that no automated consumer could interpret, on both the product-scan
// and --attestor-vex-file paths.
func TestImpactStatementIsNotAJustification(t *testing.T) {
	doc := validDoc()
	doc.Statements[0].Status = StatusNotAffected
	doc.Statements[0].ImpactStatement = "the vulnerable parser is unreachable from the request path"
	if err := Validate(doc); err == nil {
		t.Fatal("Validate accepted a not_affected statement whose only reason was free prose")
	}

	// The same claim must be refused at authoring, so the two sides of
	// the tool cannot disagree about what a suppression requires.
	_, err := Build(DocSpec{
		Author: "cilock",
		Now:    fixedClock(),
		Statements: []StatementSpec{{
			Vulns:           []string{"CVE-2024-12345"},
			Products:        []string{"pkg:golang/example.com/mod@v1.2.3"},
			Status:          StatusNotAffected,
			ImpactStatement: "the vulnerable parser is unreachable",
		}},
	})
	if err == nil {
		t.Fatal("Build authored a not_affected statement with no justification")
	}
}

// TestStatusFieldMatrixIsEnforced walks the whole applicability matrix
// rather than the one cell a reviewer happened to name. Every status has
// something to say about all three status-specific fields, and checking
// one status for one field is how these rules drifted before.
func TestStatusFieldMatrixIsEnforced(t *testing.T) {
	forbidden := map[string]func(*Statement){
		"action_statement on not_affected": func(s *Statement) {
			s.Status = StatusNotAffected
			s.Justification = ComponentNotPresent
			s.ActionStatement = "upgrade"
		},
		"impact_statement on affected": func(s *Statement) {
			s.Status = StatusAffected
			s.ActionStatement = "upgrade to v1.2.4"
			s.ImpactStatement = "reachable from the request path"
		},
		"impact_statement on fixed": func(s *Statement) {
			s.Status = StatusFixed
			s.ImpactStatement = "no longer reachable"
		},
		"action_statement on fixed": func(s *Statement) {
			s.Status = StatusFixed
			s.ActionStatement = "already upgraded"
		},
		"impact_statement on under_investigation": func(s *Statement) {
			s.Status = StatusUnderInvestigation
			s.ImpactStatement = "looking into it"
		},
		"action_statement on under_investigation": func(s *Statement) {
			s.Status = StatusUnderInvestigation
			s.ActionStatement = "will triage"
		},
		"justification on affected": func(s *Statement) {
			s.Status = StatusAffected
			s.ActionStatement = "upgrade to v1.2.4"
			s.Justification = ComponentNotPresent
		},
	}
	for name, apply := range forbidden {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			apply(&doc.Statements[0])
			if err := Validate(doc); err == nil {
				t.Error("Validate accepted a field the status cannot carry")
			}
		})
	}

	required := map[string]func(*Statement){
		"not_affected without justification": func(s *Statement) {
			s.Status = StatusNotAffected
		},
		"affected without action_statement": func(s *Statement) {
			s.Status = StatusAffected
		},
	}
	for name, apply := range required {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			apply(&doc.Statements[0])
			if err := Validate(doc); err == nil {
				t.Error("Validate accepted a status missing a field it requires")
			}
		})
	}
}

// TestValidateAcceptsWellFormedIdentities is the other side of the
// identifier rules: tightening them to catch `{"sha-256":""}` must not
// start rejecting the identities real documents actually carry.
func TestValidateAcceptsWellFormedIdentities(t *testing.T) {
	cases := map[string]Component{
		"bare sha256 digest": {Hashes: map[Algorithm]Hash{SHA256: testDigest}},
		"uppercase hex digest": {Hashes: map[Algorithm]Hash{
			SHA256: Hash("D0D0CACA00000000000000000000000000000000000000000000000000000000"),
		}},
		"sha512 digest": {Hashes: map[Algorithm]Hash{
			SHA512: Hash(testDigest + testDigest),
		}},
		"purl identifier": {Identifiers: map[IdentifierType]string{
			PURL: "pkg:golang/example.com/mod@v1.2.3",
		}},
		"cpe23 identifier": {Identifiers: map[IdentifierType]string{
			CPE23: "cpe:2.3:a:acme:api:1.2.3:*:*:*:*:*:*:*",
		}},
		"id plus digest": {
			ID:     "ghcr.io/acme/api@sha256:" + testDigest,
			Hashes: map[Algorithm]Hash{SHA256: testDigest},
		},
		// An algorithm outside the 0.2.0 set can't be format-checked by
		// this build, so it must not hard-fail a component that also
		// carries an identity this build DOES understand — the @context
		// rule already admits later spec revisions.
		"unknown algorithm alongside a purl": {
			Hashes:      map[Algorithm]Hash{Algorithm("sha4-512"): "whatever-a-future-spec-says"},
			Identifiers: map[IdentifierType]string{PURL: "pkg:golang/example.com/mod@v1.2.3"},
		},
	}

	for name, component := range cases {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			doc.Statements[0].Products = []Product{{Component: component}}
			if err := Validate(doc); err != nil {
				t.Fatalf("Validate rejected a well-formed product identity: %v", err)
			}

			// The same identity has to be acceptable one level down.
			doc = validDoc()
			doc.Statements[0].Products[0].Subcomponents = []Subcomponent{{Component: component}}
			if err := Validate(doc); err != nil {
				t.Fatalf("Validate rejected a well-formed subcomponent identity: %v", err)
			}
		})
	}
}

// TestValidateComponentErrorIsDeterministic pins the fix for map-order
// dependence: a component with several malformed identifiers must report
// the SAME failure every run, or a CI failure reproduces as a different
// message than the one an operator was handed.
func TestValidateComponentErrorIsDeterministic(t *testing.T) {
	component := Component{
		Hashes:      map[Algorithm]Hash{SHA256: "", SHA512: "", MD5: "", SHA1: ""},
		Identifiers: map[IdentifierType]string{PURL: "", CPE22: "", CPE23: ""},
	}

	doc := validDoc()
	doc.Statements[0].Products = []Product{{Component: component}}
	first := Validate(doc)
	if first == nil {
		t.Fatal("Validate accepted a product whose every identifier is empty")
	}
	for i := 0; i < 50; i++ {
		again := validDoc()
		again.Statements[0].Products = []Product{{Component: component}}
		if got := Validate(again); got == nil || got.Error() != first.Error() {
			t.Fatalf("error text varies by map iteration order: %v vs %v", got, first)
		}
	}
}

// TestBuildOutputPassesValidate is the contract between the two halves:
// anything this package authors must be ingestible by the attestor that
// reads it back. Without it, Build and Validate can drift and `cilock
// attest vex` starts emitting documents its own attestor refuses.
func TestBuildOutputPassesValidate(t *testing.T) {
	specs := map[string]StatementSpec{
		"not_affected": {
			Vulns:         []string{"CVE-2024-12345"},
			Products:      []string{"ghcr.io/acme/api@sha256:" + testDigest},
			Status:        StatusNotAffected,
			Justification: VulnerableCodeNotInExecutePath,
		},
		"affected": {
			Vulns:           []string{"CVE-2024-12345", "GHSA-jfh8-c2jp-5v3q"},
			Products:        []string{"pkg:golang/example.com/mod@v1.2.3", testDigest},
			Status:          StatusAffected,
			ActionStatement: "upgrade to v1.2.4",
		},
		"fixed": {
			Vulns:    []string{"CVE-2024-12345"},
			Products: []string{"pkg:golang/example.com/mod@v1.2.3"},
			Status:   StatusFixed,
		},
		"under_investigation": {
			Vulns:    []string{"CVE-2024-12345"},
			Products: []string{testDigest},
			Status:   StatusUnderInvestigation,
		},
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			doc, err := Build(baseSpec(spec))
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if err := Validate(doc); err != nil {
				t.Fatalf("Build emitted a document Validate rejects: %v", err)
			}

			// And it must survive the wire form the attestor reads back.
			raw, err := Marshal(doc)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var decoded VEX
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if err := Validate(&decoded); err != nil {
				t.Fatalf("round-tripped document fails Validate: %v", err)
			}
		})
	}
}

// TestValidatePURLRejectsStructurallyEmptyIdentifiers is the regression
// bar for finding "pkg: is not a package URL": the scheme alone, or a
// type with no package, identifies nothing. Both used to pass Build AND
// Validate, so `--product pkg:` produced signed evidence naming a
// product no consumer could ever join a finding to.
func TestValidatePURLRejectsStructurallyEmptyIdentifiers(t *testing.T) {
	bad := []string{
		"pkg:",
		"pkg:/",
		"pkg:golang",              // type, no name
		"pkg:golang/",             // type, empty name
		"pkg:/name",               // empty type
		"pkg:golang/example.com/", // namespace, empty name
		"pkg:@v1.2.3",             // version only
		"pkg:golang@v1.2.3",       // type + version, no name
		"pkg:?arch=amd64",         // qualifiers only
		"pkg:#subpath",            // subpath only
		"golang/example.com/mod",  // no scheme
		"",
	}
	for _, raw := range bad {
		t.Run(raw, func(t *testing.T) {
			if err := ValidatePURL(raw); err == nil {
				t.Errorf("ValidatePURL(%q) accepted an identifier that names no package", raw)
			}
			// Whatever the standalone rule says, the document-level
			// floor must agree — otherwise a document can carry what
			// the authoring side would have refused.
			doc := validDoc()
			doc.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{PURL: raw},
			}}}
			if err := Validate(doc); err == nil {
				t.Errorf("Validate accepted a product identified only by %q", raw)
			}
		})
	}
}

// TestValidatePURLAcceptsRealIdentifiers keeps the new structural rule
// from rejecting the purls real documents carry.
func TestValidatePURLAcceptsRealIdentifiers(t *testing.T) {
	good := []string{
		"pkg:golang/example.com/mod@v1.2.3",
		"pkg:golang/github.com/testifysec/judge/judge-api",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/%40angular/animation@12.3.1", // scoped npm: '@' is percent-encoded
		"pkg:oci/judge-api@sha256:6b5a8e9c",
		"pkg:deb/debian/curl@7.50.3-1?arch=i386",
		"pkg:golang/example.com/mod@v1.2.3?go-version=1.26#cmd/tool",
		"pkg:maven/org.apache.commons/io@1.3.4",
	}
	for _, raw := range good {
		t.Run(raw, func(t *testing.T) {
			if err := ValidatePURL(raw); err != nil {
				t.Errorf("ValidatePURL(%q) rejected a well-formed package URL: %v", raw, err)
			}
			doc := validDoc()
			doc.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{PURL: raw},
			}}}
			if err := Validate(doc); err != nil {
				t.Errorf("Validate rejected a product identified by %q: %v", raw, err)
			}
		})
	}
}

// TestBuildRejectsStructurallyEmptyPURLProducts closes the authoring
// side: a rejected identifier must never reach a signer.
func TestBuildRejectsStructurallyEmptyPURLProducts(t *testing.T) {
	for _, raw := range []string{"pkg:", "pkg:golang", "pkg:golang/"} {
		t.Run(raw, func(t *testing.T) {
			_, err := Build(DocSpec{
				Author: "cilock",
				Now:    fixedClock(),
				Statements: []StatementSpec{{
					Vulns:    []string{"CVE-2024-12345"},
					Products: []string{raw},
					Status:   StatusFixed,
				}},
			})
			if err == nil {
				t.Errorf("Build accepted --product %q", raw)
			}
		})
	}
}

// TestUnknownIdentityKindsAreNotCredited is the regression bar for the
// third round of "identity credited from something the validator could
// not check".
//
// The rule is one rule: credit only what this build can verify. A
// component whose ONLY identity is a kind this build has no rule for
// must be rejected — an unverifiable claim can never be the reason a
// product passes validation, because a consumer has no more idea what
// {"bogus":"x"} means than this validator does.
//
// The hash side already behaved this way; the identifier side credited
// any unknown type. Both now run through countVerifiableIdentity, so
// this table covers BOTH — the half-application is what the structure is
// meant to prevent, so the test has to exercise both halves.
func TestUnknownIdentityKindsAreNotCredited(t *testing.T) {
	onlyUnverifiable := map[string]Component{
		"unknown identifier type": {
			Identifiers: map[IdentifierType]string{"bogus": "x"},
		},
		"several unknown identifier types": {
			Identifiers: map[IdentifierType]string{"bogus": "x", "alsobogus": "y"},
		},
		"unknown hash algorithm": {
			Hashes: map[Algorithm]Hash{"sha4-512": "whatever"},
		},
		"unknown kinds on both sides": {
			Hashes:      map[Algorithm]Hash{"sha4-512": "whatever"},
			Identifiers: map[IdentifierType]string{"bogus": "x"},
		},
		// A future-looking spelling of a type we DO know is still not
		// that type: nothing here can check it.
		"lookalike identifier type": {
			Identifiers: map[IdentifierType]string{"purl2": "pkg:golang/example.com/mod@v1.2.3"},
		},
	}

	for name, component := range onlyUnverifiable {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			doc.Statements[0].Products = []Product{{Component: component}}
			if err := Validate(doc); err == nil {
				t.Error("Validate accepted a product whose only identity is a kind this build cannot verify")
			}

			// Same bar one level down.
			doc = validDoc()
			doc.Statements[0].Products[0].Subcomponents = []Subcomponent{{Component: component}}
			if err := Validate(doc); err == nil {
				t.Error("Validate accepted a subcomponent whose only identity is unverifiable")
			}
		})
	}
}

// TestUnknownIdentityKindsRideAlongsideVerifiedOnes is the other half of
// the same rule: an unknown kind must not REJECT a document that
// identifies itself some way this build does understand. The @context
// rule admits later OpenVEX revisions, so a document carrying a new
// identifier type plus a purl is still perfectly usable evidence.
func TestUnknownIdentityKindsRideAlongsideVerifiedOnes(t *testing.T) {
	withVerifiedIdentity := map[string]Component{
		"unknown identifier type beside a purl": {
			Identifiers: map[IdentifierType]string{
				"bogus": "x",
				PURL:    "pkg:golang/example.com/mod@v1.2.3",
			},
		},
		"unknown hash beside a real digest": {
			Hashes: map[Algorithm]Hash{"sha4-512": "whatever", SHA256: testDigest},
		},
		"unknown identifier type beside an @id": {
			ID:          "pkg:golang/example.com/mod@v1.2.3",
			Identifiers: map[IdentifierType]string{"bogus": "x"},
		},
		// An empty value under a kind we cannot check is not something
		// this build can call malformed — it just is not identity. The
		// purl is what carries the component, exactly as an unknown hash
		// algorithm rides alongside a real digest.
		"empty value under an unknown type beside a purl": {
			Identifiers: map[IdentifierType]string{
				"bogus": "",
				PURL:    "pkg:golang/example.com/mod@v1.2.3",
			},
		},
	}

	for name, component := range withVerifiedIdentity {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			doc.Statements[0].Products = []Product{{Component: component}}
			if err := Validate(doc); err != nil {
				t.Errorf("Validate rejected a component carrying verifiable identity: %v", err)
			}
		})
	}
}

// TestUnsupportedContextVersionsAreRejected is the regression bar for the
// root of the credit-only-what-you-can-verify family.
//
// @context declares the semantics the rest of the document is written in.
// The check used to accept "https://openvex.dev/ns/<anything>", so a
// document claiming any revision — including ones that do not exist —
// passed. Decoding here uses fixed 0.2.0 structs and encoding/json drops
// unknown fields silently, so such a document would be read through 0.2.0
// eyes with whatever that revision added discarded, then signed as though
// it had been understood.
func TestUnsupportedContextVersionsAreRejected(t *testing.T) {
	unsupported := []string{
		"https://openvex.dev/ns/v0.1.0",  // real, but go-vex has no parser for it either
		TypeURI,                          // bare context: go-vex reads this as v0.0.1
		"https://openvex.dev/ns/v0.3.0",  // plausible future revision
		"https://openvex.dev/ns/v9.9.9",  // does not exist
		"https://openvex.dev/ns/",        // version-shaped but empty
		"https://openvex.dev/ns/vX",      // not a version at all
		"https://openvex.dev/ns/v0.2.0/", // trailing slash is a different IRI
		"https://openvex.dev/nsfw/v0.2.0",
		"https://example.com/not-vex",
		"",
	}
	for _, ctx := range unsupported {
		t.Run(ctx, func(t *testing.T) {
			doc := validDoc()
			doc.Context = ctx
			if err := Validate(doc); err == nil {
				t.Errorf("Validate accepted @context %q, whose semantics this build cannot decode", ctx)
			}
		})
	}
}

// TestSupportedContextsAreAccepted pins the other side: the two contexts
// this build genuinely decodes must keep working, or every real document
// stops validating.
func TestSupportedContextsAreAccepted(t *testing.T) {
	for _, ctx := range []string{Context} {
		t.Run(ctx, func(t *testing.T) {
			doc := validDoc()
			doc.Context = ctx
			if err := Validate(doc); err != nil {
				t.Errorf("Validate rejected the supported context %q: %v", ctx, err)
			}
		})
	}

	// Whatever Build emits must be in the supported set, or the tool
	// authors documents its own attestor refuses.
	if !supportedContexts[Context] {
		t.Error("Build emits a context that Validate does not support")
	}
}

// TestValidateCPERejectsStructurallyEmptyNames is the CPE half of the
// rule ValidatePURL already enforced. The purl branch was made structural
// two rounds earlier; the CPE branch sitting beside it stayed a bare
// "cpe:" prefix check, so "cpe:" and "cpe:not-a-cpe" could be the sole
// verified identity on a signed suppression.
func TestValidateCPERejectsStructurallyEmptyNames(t *testing.T) {
	bad := []string{
		"cpe:",
		"cpe:/",
		"cpe:not-a-cpe",
		"cpe:2.3:",
		"cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", // matches everything = identifies nothing
		"cpe:2.3:a:vendor:product",      // too few components
		"cpe:2.3:x:vendor:product:*:*:*:*:*:*:*:*",   // bad part, wrong count
		"cpe:2.3:x:vendor:product:*:*:*:*:*:*:*:*:*", // bad part
		"cpe:/x:vendor:product",                      // bad part
		"cpe:/a",                                     // part only, names nothing
		"cpe:/a::",                                   // empty vendor and product
		"not-a-cpe-at-all",
		"",
	}
	for _, raw := range bad {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateCPE(raw); err == nil {
				t.Errorf("ValidateCPE(%q) accepted a name that identifies nothing", raw)
			}
			// The document-level floor must agree, on both CPE types.
			for _, typ := range []IdentifierType{CPE22, CPE23} {
				doc := validDoc()
				doc.Statements[0].Products = []Product{{Component: Component{
					Identifiers: map[IdentifierType]string{typ: raw},
				}}}
				if err := Validate(doc); err == nil {
					t.Errorf("Validate accepted a product identified only by %s=%q", typ, raw)
				}
			}
		})
	}
}

// TestValidateCPEAcceptsRealNames keeps the new structural rule from
// rejecting the CPEs real advisories carry.
func TestValidateCPEAcceptsRealNames(t *testing.T) {
	good := []string{
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*",
		"cpe:2.3:h:cisco:asr_9000:-:*:*:*:*:*:*:*",
		"cpe:2.3:a:*:log4j:2.14.1:*:*:*:*:*:*:*", // wildcard vendor, concrete product
		"CPE:2.3:A:Apache:Log4j:2.14.1:*:*:*:*:*:*:*",
		"cpe:/a:apache:log4j:2.14.1",
		"cpe:/o:linux:linux_kernel",
		"cpe:/a:apache:log4j",
		// The URI binding packs an edition into "~"-separated subfields
		// and percent-encodes extras, so a real name can carry more
		// colon-separated pieces than the binding nominally lists. A
		// component-count ceiling would refuse these for no security
		// gain — the part and vendor/product rules already reject the
		// names that identify nothing.
		"cpe:/a:vendor:product:1:2:3:4:5",
		"cpe:/a:microsoft:internet_explorer:8.%02:sp%01",
		"cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~",
		// An escaped colon inside a component must not be miscounted as
		// a component separator.
		`cpe:2.3:a:vendor:product\:name:1.0:*:*:*:*:*:*:*`,
	}
	for _, raw := range good {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateCPE(raw); err != nil {
				t.Errorf("ValidateCPE(%q) rejected a well-formed CPE: %v", raw, err)
			}
			// Key each name under its OWN binding: the keyed rules are
			// binding-specific, so a URI name under the cpe23 key is a
			// declared-type/value mismatch and is rejected by design
			// (see TestValidateRejects).
			typ := CPE23
			if strings.HasPrefix(strings.ToLower(raw), "cpe:/") {
				typ = CPE22
			}
			doc := validDoc()
			doc.Statements[0].Products = []Product{{Component: Component{
				Identifiers: map[IdentifierType]string{typ: raw},
			}}}
			if err := Validate(doc); err != nil {
				t.Errorf("Validate rejected a product identified by %s=%q: %v", typ, raw, err)
			}
		})
	}
}
