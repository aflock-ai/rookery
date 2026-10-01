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
	"testing"

	"github.com/sigstore/fulcio/pkg/certificate"
)

const subjectHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Requirement 1 and 3: every Ext field is the literal extension value Fulcio
// wrote, with the attempt dropped from the run (requirement 6).
func TestExtFromCertificateReadsFulcioExtensions(t *testing.T) {
	ca := newTestCA(t, "platform")
	cert, _ := ca.leaf(t, githubExtensions(WorkflowPath+"@"+pinned, pinned, "acme/app", commit, "42", "3", "push", "github-hosted"))
	x, err := ExtFromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	want := Ext{
		SignerPath: WorkflowPath, SignerRef: pinned, SignerDigest: pinned,
		SourceRepo: "acme/app", SourceDigest: commit, RunID: "42", Trigger: "push", Hosted: true,
	}
	if x != want {
		t.Fatalf("got %+v\nwant %+v", x, want)
	}
}

// Requirement 4 at the parse layer: only the literal "github-hosted" is hosted.
func TestExtFromCertificateHostedIsLiteral(t *testing.T) {
	ca := newTestCA(t, "platform")
	for _, runner := range []string{"self-hosted", "github-hosted*", "GitHub-Hosted", ""} {
		cert, _ := ca.leaf(t, githubExtensions(WorkflowPath+"@"+pinned, pinned, "acme/app", commit, "1", "1", "push", runner))
		x, err := ExtFromCertificate(cert)
		if err == nil && x.Hosted {
			t.Errorf("runner %q read as hosted", runner)
		}
	}
}

// Requirement 3: a missing or malformed extension is an error, never a
// wildcard.
func TestExtFromCertificateRefusesMissingOrMalformed(t *testing.T) {
	ca := newTestCA(t, "platform")
	good := githubExtensions(WorkflowPath+"@"+pinned, pinned, "acme/app", commit, "1", "1", "push", "github-hosted")
	type mut struct {
		name  string
		apply func(e *certificate.Extensions)
	}
	for _, m := range []mut{
		{"issuer", func(e *certificate.Extensions) { e.Issuer = "https://accounts.google.com" }},
		{"no signer uri", func(e *certificate.Extensions) { e.BuildSignerURI = "" }},
		{"signer uri off github", func(e *certificate.Extensions) {
			e.BuildSignerURI = "https://gitlab.com/" + WorkflowPath + "@" + pinned
		}},
		{"signer uri without ref", func(e *certificate.Extensions) { e.BuildSignerURI = "https://github.com/" + WorkflowPath }},
		{"signer uri with empty ref", func(e *certificate.Extensions) { e.BuildSignerURI = "https://github.com/" + WorkflowPath + "@" }},
		{"no signer digest", func(e *certificate.Extensions) { e.BuildSignerDigest = "" }},
		{"no source digest", func(e *certificate.Extensions) { e.SourceRepositoryDigest = "" }},
		{"no trigger", func(e *certificate.Extensions) { e.BuildTrigger = "" }},
		{"repo with extra path", func(e *certificate.Extensions) { e.SourceRepositoryURI = "https://github.com/acme/app/extra" }},
		{"run of another repo", func(e *certificate.Extensions) {
			e.RunInvocationURI = "https://github.com/mallory/tool/actions/runs/1/attempts/1"
		}},
		{"run id not a number", func(e *certificate.Extensions) {
			e.RunInvocationURI = "https://github.com/acme/app/actions/runs/1a/attempts/1"
		}},
		{"run without attempt", func(e *certificate.Extensions) { e.RunInvocationURI = "https://github.com/acme/app/actions/runs/1" }},
	} {
		t.Run(m.name, func(t *testing.T) {
			e := good
			m.apply(&e)
			cert, _ := ca.leaf(t, e)
			if x, err := ExtFromCertificate(cert); err == nil {
				t.Fatalf("parsed %+v, want an error", x)
			}
		})
	}
}

func TestStatementFromPayload(t *testing.T) {
	payload := statementJSON(t, ProvenancePredicateType,
		[]testSubject{{Name: "app", Digest: map[string]string{"sha256": subjectHex, "sha1": "abc"}}},
		provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://github.com/acme/app/actions/runs/42/attempts/1", "acme/app", commit))
	s, err := StatementFromPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if s.BuilderPath != WorkflowPath || s.BuilderRef != pinned || s.Repo != "acme/app" || s.Commit != commit || s.RunID != "42" {
		t.Fatalf("got %+v", s)
	}
	if len(s.Subjects) != 1 || s.Subjects[0] != "sha256:"+subjectHex {
		t.Fatalf("subjects %v", s.Subjects)
	}
}

func TestStatementFromPayloadRefuses(t *testing.T) {
	good := func() ([]testSubject, map[string]any) {
		return []testSubject{{Name: "app", Digest: map[string]string{"sha256": subjectHex}}},
			provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://github.com/acme/app/actions/runs/42", "acme/app", commit)
	}
	cases := map[string]func() []byte{
		"legacy predicate type": func() []byte {
			s, p := good()
			return statementJSON(t, "https://slsa.dev/provenance/v1.0", s, p)
		},
		"subject without sha256": func() []byte {
			_, p := good()
			return statementJSON(t, ProvenancePredicateType, []testSubject{{Name: "app", Digest: map[string]string{"sha1": "abc"}}}, p)
		},
		"malformed sha256": func() []byte {
			_, p := good()
			return statementJSON(t, ProvenancePredicateType, []testSubject{{Name: "app", Digest: map[string]string{"sha256": "zz"}}}, p)
		},
		"builder off github": func() []byte {
			s, _ := good()
			return statementJSON(t, ProvenancePredicateType, s, provenancePredicate("https://aflock.ai/cilock/inline/github-actions@v1", "https://github.com/acme/app/actions/runs/42", "acme/app", commit))
		},
		"two commits": func() []byte {
			s, p := good()
			bd := p["buildDefinition"].(map[string]any)
			bd["resolvedDependencies"] = append(bd["resolvedDependencies"].([]any), map[string]any{"digest": map[string]string{"sha1": "2222222222222222222222222222222222222222"}})
			return statementJSON(t, ProvenancePredicateType, s, p)
		},
		"no commit": func() []byte {
			s, p := good()
			p["buildDefinition"].(map[string]any)["resolvedDependencies"] = []any{}
			return statementJSON(t, ProvenancePredicateType, s, p)
		},
		"invocation off github": func() []byte {
			s, _ := good()
			return statementJSON(t, ProvenancePredicateType, s, provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://example.com/acme/app/actions/runs/42", "acme/app", commit))
		},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if s, err := StatementFromPayload(payload()); err == nil {
				t.Fatalf("parsed %+v, want an error", s)
			}
		})
	}
}
