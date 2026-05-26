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

package workflow

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

// ---- Test doubles ----

// fakeParent is a minimal Subjecter that doesn't export — it
// represents a parent attestor (git, material, product) whose
// subjects should propagate into sidecar envelopes via
// collectParentSubjects.
type fakeParent struct {
	name     string
	typ      string
	runType  attestation.RunType
	subjects map[string]cryptoutil.DigestSet
}

func (a *fakeParent) Name() string                                   { return a.name }
func (a *fakeParent) Type() string                                   { return a.typ }
func (a *fakeParent) RunType() attestation.RunType                   { return a.runType }
func (a *fakeParent) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(&struct{}{}) }
func (a *fakeParent) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *fakeParent) Subjects() map[string]cryptoutil.DigestSet      { return a.subjects }

// fakeExporter implements Subjecter + Exporter — its sidecar
// envelope must end up signed with parent ∪ own subjects.
type fakeExporter struct {
	name     string
	typ      string
	runType  attestation.RunType
	export   bool
	subjects map[string]cryptoutil.DigestSet
}

func (a *fakeExporter) Name() string                                   { return a.name }
func (a *fakeExporter) Type() string                                   { return a.typ }
func (a *fakeExporter) RunType() attestation.RunType                   { return a.runType }
func (a *fakeExporter) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(&struct{}{}) }
func (a *fakeExporter) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *fakeExporter) Subjects() map[string]cryptoutil.DigestSet      { return a.subjects }
func (a *fakeExporter) Export() bool                                   { return a.export }

// ---- Tests ----

// TestExportSidecarInheritsParentSubjects is the regression guard for
// the cilock verify "external attestation not found" bug surfaced by
// the prometheus blind UX test:
//
// Before this fix, an exporter's sidecar envelope was signed only
// with subjecter.Subjects() (the predicate's own internal subjects —
// e.g. for sbom, the file: and name: of the SBOM doc). Those subjects
// don't overlap with the seed subjects users pass to
// `cilock verify -s sha1:<commit>`, so verify's ExternalAttestation
// lookup returned 0 envelopes even when the sidecar was on disk and
// trusted. Result: silent verification failure or — worse — a step
// that "passes" by skipping the sidecar entirely.
//
// After the fix, sidecar envelopes are signed with parent subjects
// ∪ exporter's own subjects, so the subject graph walks cleanly from
// the seed to the sidecar.
func TestExportSidecarInheritsParentSubjects(t *testing.T) {
	signer := newTestSigner(t)
	parentDigest := strings.Repeat("aa", 32)   // sha256 of pretend commit
	exporterDigest := strings.Repeat("bb", 32) // sha256 of pretend SBOM file

	parent := &fakeParent{
		name:    "fake-git",
		typ:     "https://example.com/git/v1",
		runType: attestation.PreMaterialRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"commit:abc123": {
				cryptoutil.DigestValue{Hash: crypto.SHA256}: parentDigest,
			},
		},
	}
	exporter := &fakeExporter{
		name:    "fake-sbom",
		typ:     "https://example.com/sbom/v1",
		runType: attestation.PostProductRunType,
		export:  true,
		subjects: map[string]cryptoutil.DigestSet{
			"file:sbom.spdx.json": {
				cryptoutil.DigestValue{Hash: crypto.SHA256}: exporterDigest,
			},
		},
	}

	results, err := RunWithExports(
		"merge-step",
		RunWithAttestors([]attestation.Attestor{parent, exporter}),
		RunWithSigners(signer),
	)
	if err != nil {
		t.Fatalf("RunWithExports: %v", err)
	}

	// Find the exported sidecar's RunResult (matches by attestor name).
	var sidecar *RunResult
	for i := range results {
		if results[i].AttestorName == exporter.name {
			sidecar = &results[i]
			break
		}
	}
	if sidecar == nil {
		t.Fatalf("expected one RunResult for %q export; got attestor names: %s",
			exporter.name, attestorNames(results))
	}

	// Decode the signed envelope's payload to read the in-toto subject set.
	if len(sidecar.SignedEnvelope.Payload) == 0 {
		t.Fatal("sidecar envelope has empty payload")
	}
	payload, err := base64.StdEncoding.DecodeString(string(sidecar.SignedEnvelope.Payload))
	if err != nil {
		// Some DSSE encoders may emit the payload as raw JSON without
		// base64 — try that path too.
		payload = sidecar.SignedEnvelope.Payload
	}
	var stmt struct {
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("decode sidecar in-toto statement: %v", err)
	}

	gotNames := make(map[string]string)
	for _, s := range stmt.Subject {
		gotNames[s.Name] = s.Digest["sha256"]
	}

	if gotNames["commit:abc123"] != parentDigest {
		t.Errorf("sidecar must inherit parent subject 'commit:abc123'; got subjects=%v", gotNames)
	}
	if gotNames["file:sbom.spdx.json"] != exporterDigest {
		t.Errorf("sidecar must retain its own subject 'file:sbom.spdx.json'; got subjects=%v", gotNames)
	}
}

// TestCollectParentSubjects_ExcludesExporters guards the corollary
// invariant: collectParentSubjects must NOT include subjects from
// attestors that opt out via Exporter+Export(). Including them would
// cause the parent subject pool to contain the sidecar's own digests,
// creating a circular subject graph in the sidecar (it would claim
// to be evidence about itself).
func TestCollectParentSubjects_ExcludesExporters(t *testing.T) {
	signer := newTestSigner(t)
	parentDigest := strings.Repeat("aa", 32)
	exporterDigest := strings.Repeat("bb", 32)

	parent := &fakeParent{
		name: "fake-git", typ: "https://example.com/git/v1",
		runType: attestation.PreMaterialRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"commit:abc": {cryptoutil.DigestValue{Hash: crypto.SHA256}: parentDigest},
		},
	}
	exporter := &fakeExporter{
		name: "fake-sbom", typ: "https://example.com/sbom/v1",
		runType: attestation.PostProductRunType, export: true,
		subjects: map[string]cryptoutil.DigestSet{
			"file:s.json": {cryptoutil.DigestValue{Hash: crypto.SHA256}: exporterDigest},
		},
	}

	results, err := RunWithExports("excl-step",
		RunWithAttestors([]attestation.Attestor{parent, exporter}),
		RunWithSigners(signer),
	)
	if err != nil {
		t.Fatalf("RunWithExports: %v", err)
	}

	// Decode the wrapping collection envelope's subjects.
	collection := results[len(results)-1]
	if collection.Collection.Name != "excl-step" {
		t.Fatalf("expected last result to be the collection, got Name=%q", collection.Collection.Name)
	}
	// The collection's CollectionSubjects should contain the parent's
	// subject (under its type-prefixed key — that's how
	// attestation.NewCollection scopes attestor subjects), and must
	// NOT contain the exporter's subject (since the exporter is split
	// into its own sidecar envelope).
	const parentKey = "https://example.com/git/v1/commit:abc"
	const exporterKey = "https://example.com/sbom/v1/file:s.json"
	if _, ok := collection.CollectionSubjects[parentKey]; !ok {
		t.Errorf("collection must carry parent subject %q; got=%v",
			parentKey, keysOf(collection.CollectionSubjects))
	}
	if _, ok := collection.CollectionSubjects[exporterKey]; ok {
		t.Errorf("collection must NOT carry exporter subject %q (it lives in the sidecar envelope); got=%v",
			exporterKey, keysOf(collection.CollectionSubjects))
	}
	// Note: the exporter's subjects WILL still appear in the collection's
	// in-toto statement subjects (since attestation.NewCollection
	// gathers subjects from all included attestors). The key invariant
	// is that the EXPORT SIDECAR's subjects include the parent's
	// subjects — that's covered by TestExportSidecarInheritsParentSubjects.
	// This test confirms the collection path still works.
}

func attestorNames(rs []RunResult) string {
	names := make([]string, 0, len(rs))
	for _, r := range rs {
		names = append(names, r.AttestorName)
	}
	return strings.Join(names, ", ")
}
