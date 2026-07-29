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
	"strings"
	"testing"
	"time"
)

// fixedClock is the hermetic clock every test builds against.
func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) }
}

const testDigest = "d0d0caca00000000000000000000000000000000000000000000000000000000"

func baseSpec(s StatementSpec) DocSpec {
	return DocSpec{
		Author:     "cilock",
		AuthorRole: "Automated triage",
		Tooling:    "cilock/test",
		Statements: []StatementSpec{s},
		Now:        fixedClock(),
	}
}

func TestBuildNotAffectedWithJustification(t *testing.T) {
	doc, err := Build(baseSpec(StatementSpec{
		Vulns:           []string{"CVE-2024-12345"},
		Products:        []string{"ghcr.io/acme/api@sha256:" + testDigest},
		Status:          StatusNotAffected,
		Justification:   VulnerableCodeNotInExecutePath,
		ImpactStatement: "the parser is never reached from the request path",
	}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if doc.Context != Context {
		t.Errorf("context = %q, want %q", doc.Context, Context)
	}
	if !strings.HasPrefix(doc.ID, docIDPrefix) {
		t.Errorf("@id = %q, want prefix %q", doc.ID, docIDPrefix)
	}
	if doc.Version != initialDocumentVersion {
		t.Errorf("version = %d, want %d", doc.Version, initialDocumentVersion)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statements))
	}
	st := doc.Statements[0]
	if st.Status != StatusNotAffected {
		t.Errorf("status = %q", st.Status)
	}
	if st.Justification != VulnerableCodeNotInExecutePath {
		t.Errorf("justification = %q", st.Justification)
	}
	if st.Vulnerability.Name != "CVE-2024-12345" {
		t.Errorf("vulnerability = %q", st.Vulnerability.Name)
	}
	if got := st.Products[0].Hashes[SHA256]; got != Hash(testDigest) {
		t.Errorf("product hash = %q, want %q", got, testDigest)
	}
}

// TestBuildRejects is the fail-closed table: every one of these would
// produce a document that suppresses a finding without justifying it.
func TestBuildRejects(t *testing.T) {
	tests := []struct {
		name    string
		spec    StatementSpec
		wantErr string
	}{
		{
			name: "not_affected without justification",
			spec: StatementSpec{
				Vulns:    []string{"CVE-2024-12345"},
				Products: []string{"sha256:" + testDigest},
				Status:   StatusNotAffected,
			},
			wantErr: "requires --justification",
		},
		{
			name: "affected without action statement",
			spec: StatementSpec{
				Vulns:    []string{"CVE-2024-12345"},
				Products: []string{"sha256:" + testDigest},
				Status:   StatusAffected,
			},
			wantErr: "requires --action-statement",
		},
		{
			name: "unknown status",
			spec: StatementSpec{
				Vulns:    []string{"CVE-2024-12345"},
				Products: []string{"sha256:" + testDigest},
				Status:   Status("probably_fine"),
			},
			wantErr: "unknown status",
		},
		{
			name: "unknown justification",
			spec: StatementSpec{
				Vulns:         []string{"CVE-2024-12345"},
				Products:      []string{"sha256:" + testDigest},
				Status:        StatusNotAffected,
				Justification: Justification("we_looked_at_it"),
			},
			wantErr: "unknown justification",
		},
		{
			name: "justification on a status that cannot carry one",
			spec: StatementSpec{
				Vulns:         []string{"CVE-2024-12345"},
				Products:      []string{"sha256:" + testDigest},
				Status:        StatusFixed,
				Justification: ComponentNotPresent,
			},
			wantErr: "does not apply to status",
		},
		{
			name: "malformed vulnerability id",
			spec: StatementSpec{
				Vulns:    []string{"CVE-24-1"},
				Products: []string{"sha256:" + testDigest},
				Status:   StatusFixed,
			},
			wantErr: "not a valid vulnerability ID",
		},
		{
			name: "no vulnerability",
			spec: StatementSpec{
				Products: []string{"sha256:" + testDigest},
				Status:   StatusFixed,
			},
			wantErr: "at least one --vuln",
		},
		{
			name: "no product",
			spec: StatementSpec{
				Vulns:  []string{"CVE-2024-12345"},
				Status: StatusFixed,
			},
			wantErr: "at least one --product",
		},
		{
			name: "unusable product reference",
			spec: StatementSpec{
				Vulns:    []string{"CVE-2024-12345"},
				Products: []string{"ghcr.io/acme/api:v1.2.3"},
				Status:   StatusFixed,
			},
			wantErr: "not a sha256 digest",
		},
		{
			name: "non-sha256 digest algorithm",
			spec: StatementSpec{
				Vulns:    []string{"CVE-2024-12345"},
				Products: []string{"ghcr.io/acme/api@sha512:" + testDigest},
				Status:   StatusFixed,
			},
			wantErr: "unsupported digest algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Build(baseSpec(tt.spec))
			if err == nil {
				t.Fatalf("Build succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestBuildRequiresAuthor(t *testing.T) {
	spec := baseSpec(StatementSpec{
		Vulns:    []string{"CVE-2024-12345"},
		Products: []string{"sha256:" + testDigest},
		Status:   StatusFixed,
	})
	spec.Author = "   "
	if _, err := Build(spec); err == nil || !strings.Contains(err.Error(), "author is required") {
		t.Fatalf("err = %v, want author required", err)
	}
}

// TestDigestCanonicalization is the join-key test: every accepted
// spelling of the same sha256 must land on identical bare lowercase hex,
// because that is how judge stores an image digest.
func TestDigestCanonicalization(t *testing.T) {
	upper := strings.ToUpper(testDigest)
	forms := []string{
		testDigest,
		upper,
		"sha256:" + upper,
		"SHA256:" + upper,
		"ghcr.io/acme/api@sha256:" + upper,
	}

	for _, form := range forms {
		t.Run(form, func(t *testing.T) {
			doc, err := Build(baseSpec(StatementSpec{
				Vulns:    []string{"CVE-2024-12345"},
				Products: []string{form},
				Status:   StatusFixed,
			}))
			if err != nil {
				t.Fatalf("Build(%q): %v", form, err)
			}
			got := doc.Statements[0].Products[0].Hashes[SHA256]
			if got != Hash(testDigest) {
				t.Errorf("hash = %q, want %q", got, testDigest)
			}
		})
	}
}

func TestPurlProduct(t *testing.T) {
	const purl = "pkg:golang/github.com/example/mod@v1.2.3"
	doc, err := Build(baseSpec(StatementSpec{
		Vulns:    []string{"GHSA-jfh8-c2jp-5v3q"},
		Products: []string{purl},
		Status:   StatusUnderInvestigation,
	}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p := doc.Statements[0].Products[0]
	if p.ID != purl {
		t.Errorf("@id = %q, want %q", p.ID, purl)
	}
	if p.Identifiers[PURL] != purl {
		t.Errorf("identifiers[purl] = %q, want %q", p.Identifiers[PURL], purl)
	}
}

// TestMultiVulnMultiProduct pins the fan-out: N vulns × M products
// becomes N statements each carrying all M products, sorted.
func TestMultiVulnMultiProduct(t *testing.T) {
	other := strings.Repeat("ab", 32)
	doc, err := Build(baseSpec(StatementSpec{
		// Deliberately unsorted and duplicated on input.
		Vulns:           []string{"CVE-2024-99999", "CVE-2024-11111", "CVE-2024-99999"},
		Products:        []string{"ghcr.io/acme/web@sha256:" + other, "ghcr.io/acme/api@sha256:" + testDigest},
		Status:          StatusAffected,
		ActionStatement: "upgrade to 2.1.4",
	}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d, want 2 (deduped)", len(doc.Statements))
	}
	if doc.Statements[0].Vulnerability.Name != "CVE-2024-11111" {
		t.Errorf("statements not sorted by vulnerability: %q first", doc.Statements[0].Vulnerability.Name)
	}
	for i, st := range doc.Statements {
		if len(st.Products) != 2 {
			t.Fatalf("statement %d products = %d, want 2", i, len(st.Products))
		}
		if st.Products[0].ID >= st.Products[1].ID {
			t.Errorf("statement %d products not sorted: %q then %q", i, st.Products[0].ID, st.Products[1].ID)
		}
		if st.ActionStatement != "upgrade to 2.1.4" {
			t.Errorf("statement %d lost the action statement", i)
		}
	}
}

// TestDeterministicUnderFixedClock is the reproducibility bar: same spec
// + same clock ⇒ identical bytes, including the content-addressed @id.
// Input ordering must not leak into the output.
func TestDeterministicUnderFixedClock(t *testing.T) {
	other := strings.Repeat("ab", 32)
	first := baseSpec(StatementSpec{
		Vulns:         []string{"CVE-2024-11111", "CVE-2024-99999"},
		Products:      []string{"ghcr.io/acme/api@sha256:" + testDigest, "ghcr.io/acme/web@sha256:" + other},
		Status:        StatusNotAffected,
		Justification: ComponentNotPresent,
	})
	second := baseSpec(StatementSpec{
		Vulns:         []string{"CVE-2024-99999", "CVE-2024-11111"},
		Products:      []string{"ghcr.io/acme/web@sha256:" + strings.ToUpper(other), "ghcr.io/acme/api@sha256:" + testDigest},
		Status:        StatusNotAffected,
		Justification: ComponentNotPresent,
	})

	docA, err := Build(first)
	if err != nil {
		t.Fatalf("Build first: %v", err)
	}
	docB, err := Build(second)
	if err != nil {
		t.Fatalf("Build second: %v", err)
	}

	rawA, err := Marshal(docA)
	if err != nil {
		t.Fatalf("Marshal first: %v", err)
	}
	rawB, err := Marshal(docB)
	if err != nil {
		t.Fatalf("Marshal second: %v", err)
	}

	if string(rawA) != string(rawB) {
		t.Errorf("output is not deterministic:\n--- a ---\n%s\n--- b ---\n%s", rawA, rawB)
	}
	if docA.ID != docB.ID {
		t.Errorf("@id differs: %q vs %q", docA.ID, docB.ID)
	}
	if !strings.Contains(string(rawA), `"timestamp": "2026-07-27T12:00:00Z"`) {
		t.Errorf("clock was not honored:\n%s", rawA)
	}
}

// TestGHSAAlphabetIsEnforced is the regression bar for accepting
// identifiers that merely LOOK like advisories.
//
// GHSA IDs are base32 with the vowels and visually ambiguous characters
// removed, so "0", "1", "a", "e" and friends can never appear in a real
// one. The pattern used to accept [0-9a-z], which admitted strings like
// GHSA-0000-aaaa-bbbb: they match nothing in GitHub's database, so a
// statement carrying one suppresses a vulnerability that does not exist
// under that ID — signed evidence that silently applies to nothing.
func TestGHSAAlphabetIsEnforced(t *testing.T) {
	build := func(vuln string) error {
		_, err := Build(baseSpec(StatementSpec{
			Vulns:    []string{vuln},
			Products: []string{"pkg:golang/example.com/mod@v1.2.3"},
			Status:   StatusUnderInvestigation,
		}))
		return err
	}

	// Every one of these carries a character outside the GHSA alphabet.
	for _, bad := range []string{
		"GHSA-0000-aaaa-bbbb",
		"GHSA-aaaa-bbbb-cccc",
		"GHSA-1234-abcd-5678",
		"GHSA-jfh8-c2jp-5v3o", // 'o' is excluded (reads as zero)
		"GHSA-jfh8-c2jp-5v3l", // 'l' is excluded (reads as one)
		"GHSA-jfh8-c2jp-5v3i",
		"GHSA-jfh8-c2jp-5v3u",
		"GHSA-jfh8-c2jp", // too few groups
		"GHSA-jfh8-c2jp-5v3q-extra",
		"GHSA-jfh-c2jp-5v3q", // short group
	} {
		t.Run(bad, func(t *testing.T) {
			if err := build(bad); err == nil {
				t.Errorf("Build accepted %q, which is not a GHSA identifier", bad)
			}
		})
	}

	// Real advisories must still work, in either case.
	for _, good := range []string{
		"GHSA-jfh8-c2jp-5v3q", // log4shell
		"ghsa-jfh8-c2jp-5v3q",
		"GHSA-2m7h-8p6q-3v4w",
	} {
		t.Run(good, func(t *testing.T) {
			if err := build(good); err != nil {
				t.Errorf("Build rejected the real advisory %q: %v", good, err)
			}
		})
	}
}
