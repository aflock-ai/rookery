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

package standards

import (
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	cats, err := Catalogs()
	if err != nil {
		t.Fatal(err)
	}
	for _, std := range []string{StandardSLSABuild, StandardALPS} {
		if len(cats[std].Steps) == 0 {
			t.Fatalf("%s: no steps", std)
		}
	}
	// ALPS 3 is future and has no action (Cole, 2026-09-24).
	for _, l := range cats[StandardALPS].Levels {
		if l.Level == "ALPS-3" && (l.Status != StatusFuture || !strings.Contains(l.Requires, "cilockd (not yet available)")) {
			t.Fatalf("ALPS-3 must be future and require cilockd: %+v", l)
		}
	}
	// The L3 provenance workflow is referenced from exactly one entry.
	n := 0
	for _, c := range cats {
		for _, s := range c.Steps {
			if strings.Contains(s.Snippet, "provenance.yml") {
				n++
			}
		}
	}
	if n != 1 {
		t.Fatalf("the provenance workflow must be referenced by exactly one catalog entry, found %d", n)
	}
}

const minimalHeader = `schema: cilock.standards-catalog/v1
standard: slsa_build
title: t
spec: s
spec_url: u
levels:
  - {level: L1, status: available, requires: r, observed_by: o}
  - {level: L3, status: future, requires: r, observed_by: o}
`

func TestCatalogValidationRefuses(t *testing.T) {
	cases := map[string]string{
		"unknown observation": `steps:
  - {id: a, target_level: L1, status: available, closes: vibes, when: any, why: w, action: a, agent_action: a}`,
		"step for a future level": `steps:
  - {id: a, target_level: L3, status: planned, closes: trusted_builder, when: any, why: w, action: a, agent_action: a}`,
		"future step": `steps:
  - {id: a, target_level: L1, status: future, closes: provenance, when: any, why: w, action: a, agent_action: a}`,
		"available and unpinned": `steps:
  - {id: a, target_level: L1, status: available, closes: provenance, when: any, why: w, action: a, agent_action: a, snippet: "uses: x@{{pin}}"}`,
		"short pin": `steps:
  - {id: a, target_level: L1, status: planned, closes: provenance, when: any, why: w, action: a, agent_action: a, pin: abc}`,
		"builder identity without @": `steps:
  - {id: a, target_level: L1, status: planned, closes: provenance, when: any, why: w, action: a, agent_action: a, builder_identity: "https://github.com/x/y.yml"}`,
		"unknown field": `steps:
  - {id: a, target_level: L1, status: available, closes: provenance, when: any, why: w, action: a, agent_action: a, level: 3}`,
		"missing agent action": `steps:
  - {id: a, target_level: L1, status: available, closes: provenance, when: any, why: w, action: a}`,
	}
	for name, steps := range cases {
		if _, err := ParseCatalog([]byte(minimalHeader + steps)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPinnedSnippetRenders(t *testing.T) {
	s := Step{Snippet: "uses: x@{{pin}}", Pin: strings.Repeat("a", 40)}
	if got := s.RenderedSnippet(); got != "uses: x@"+strings.Repeat("a", 40) {
		t.Fatalf("got %q", got)
	}
	s.Pin = ""
	if got := s.RenderedSnippet(); got != "" {
		t.Fatalf("unpinned snippet rendered as %q", got)
	}
}

func TestLeafTrustedBuilderIsExact(t *testing.T) {
	const wf = "https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml@"
	for uri, want := range map[string]bool{
		wf + "refs/tags/v1":                             true,
		wf + "0123456789abcdef0123456789abcdef01234567": true,
		"https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml.evil.yml@x": false,
		"https://github.com/tenant/repo/.github/workflows/build.yml@refs/heads/main":             false,
		"": false,
	} {
		if got := (Leaf{BuildSignerURI: uri}).IsTrustedBuilder(); got != want {
			t.Errorf("%q: trusted=%v want %v", uri, got, want)
		}
	}
}

func TestLeafPrincipal(t *testing.T) {
	spiffe, _ := url.Parse("spiffe://platform/agent/1")
	if p := LeafFromCertificate(&x509.Certificate{URIs: []*url.URL{spiffe}, EmailAddresses: []string{"a@b"}}).Principal; p != PrincipalAgent {
		t.Fatalf("SPIFFE leaf: %q", p)
	}
	if p := LeafFromCertificate(&x509.Certificate{EmailAddresses: []string{"a@b"}}).Principal; p != PrincipalHuman {
		t.Fatalf("email leaf: %q", p)
	}
	if p := LeafFromCertificate(&x509.Certificate{}).Principal; p != PrincipalUnknown {
		t.Fatalf("bare leaf promoted to %q", p)
	}
	if _, ok := LeafFromPEM([]byte("not pem")); ok {
		t.Fatal("garbage parsed as a leaf")
	}
}
