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

package vex

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/vex/openvex"
	"github.com/invopop/jsonschema"
)

const roundTripDigest = "d0d0caca00000000000000000000000000000000000000000000000000000000"

// authoredDocument writes a document built by the openvex builder — the
// exact bytes `cilock attest vex` emits — into a temp dir and returns its
// path.
func authoredDocument(t *testing.T) string {
	t.Helper()

	doc, err := openvex.Build(openvex.DocSpec{
		Author:     "cilock",
		AuthorRole: "Automated triage",
		Tooling:    "cilock/test",
		Now:        func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) },
		Statements: []openvex.StatementSpec{{
			Vulns:           []string{"CVE-2024-12345"},
			Products:        []string{"ghcr.io/acme/api@sha256:" + roundTripDigest},
			Status:          openvex.StatusNotAffected,
			Justification:   openvex.VulnerableCodeNotInExecutePath,
			ImpactStatement: "the vulnerable parser is unreachable from the request path",
		}},
	})
	if err != nil {
		t.Fatalf("openvex.Build: %v", err)
	}

	raw, err := openvex.Marshal(doc)
	if err != nil {
		t.Fatalf("openvex.Marshal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "vex.openvex.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}
	return path
}

// productShim feeds a file into ctx.Products() the same way the product
// attestor does, so getCandidate's product-scan path can be exercised
// without running a wrapped command.
type productShim struct {
	products map[string]attestation.Product
}

func (p *productShim) Name() string                                 { return "product-shim" }
func (p *productShim) Type() string                                 { return "product-shim" }
func (p *productShim) RunType() attestation.RunType                 { return attestation.ProductRunType }
func (p *productShim) Attest(*attestation.AttestationContext) error { return nil }
func (p *productShim) Products() map[string]attestation.Product     { return p.products }
func (p *productShim) Schema() *jsonschema.Schema                   { return jsonschema.Reflect(&p) }

// assertRoundTripped checks the attestor captured the authored document
// rather than an empty predicate.
//
// wantReportName is the name expected in the SIGNED predicate, which is
// deliberately not the absolute path the bytes were read from — see
// stableReportName.
func assertRoundTripped(t *testing.T, a *Attestor, wantReportName string) {
	t.Helper()

	if a.ReportFile != wantReportName {
		t.Errorf("ReportFile = %q, want %q", a.ReportFile, wantReportName)
	}
	if filepath.IsAbs(a.ReportFile) {
		t.Errorf("ReportFile %q is an absolute host path — it is signed, so it must not vary by machine", a.ReportFile)
	}
	if len(a.ReportDigestSet) == 0 {
		t.Error("ReportDigestSet is empty — nothing anchors the predicate to the bytes")
	}
	if a.VEXDocument.Context != openvex.Context {
		t.Errorf("@context = %q, want %q", a.VEXDocument.Context, openvex.Context)
	}
	if a.VEXDocument.Author != "cilock" {
		t.Errorf("author = %q, want %q", a.VEXDocument.Author, "cilock")
	}
	if len(a.VEXDocument.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(a.VEXDocument.Statements))
	}
	st := a.VEXDocument.Statements[0]
	if st.Vulnerability.Name != "CVE-2024-12345" {
		t.Errorf("vulnerability = %q", st.Vulnerability.Name)
	}
	if st.Status != openvex.StatusNotAffected {
		t.Errorf("status = %q", st.Status)
	}
	if st.Justification != openvex.VulnerableCodeNotInExecutePath {
		t.Errorf("justification = %q", st.Justification)
	}
	if len(st.Products) != 1 || st.Products[0].Hashes[openvex.SHA256] != openvex.Hash(roundTripDigest) {
		t.Errorf("products did not survive the round trip: %+v", st.Products)
	}
}

// TestAuthoredDocumentRoundTripsAsProduct is the acceptance bar: a
// document authored by the builder must be consumable by the attestor's
// normal product-scan path — the one a `cilock run -a vex` uses.
func TestAuthoredDocumentRoundTripsAsProduct(t *testing.T) {
	path := authoredDocument(t)

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	if err != nil {
		t.Fatalf("digest authored document: %v", err)
	}

	// Keyed the way the product attestor really keys it: relative to the
	// working directory, not absolute.
	shim := &productShim{products: map[string]attestation.Product{
		filepath.Base(path): {MimeType: "application/json", Digest: digest},
	}}
	vexAttestor := New()

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{shim, vexAttestor},
		attestation.WithHashes(hashes),
		attestation.WithWorkingDir(filepath.Dir(path)),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors: %v", err)
	}

	assertRoundTripped(t, vexAttestor, filepath.Base(path))
}

// TestAuthoredDocumentRoundTripsViaExplicitFile covers the path
// `cilock attest vex` itself uses: the document was authored before the
// (no-op) wrapped command, so it is a material rather than a product and
// has to be named explicitly.
func TestAuthoredDocumentRoundTripsViaExplicitFile(t *testing.T) {
	path := authoredDocument(t)

	vexAttestor := New()
	WithVEXFile(path)(vexAttestor)

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(filepath.Dir(path)),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	assertRoundTripped(t, vexAttestor, filepath.Base(path))
}

// TestExplicitFileResolvesRelativeToWorkingDir mirrors the sbom
// attestor's contract for relative paths.
func TestExplicitFileResolvesRelativeToWorkingDir(t *testing.T) {
	path := authoredDocument(t)

	vexAttestor := New()
	WithVEXFile(filepath.Base(path))(vexAttestor)

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(filepath.Dir(path)),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	assertRoundTripped(t, vexAttestor, filepath.Base(path))
}

// TestExplicitFileFailsClosed: an operator who names a file explicitly
// must get an error, not a silently empty predicate.
func TestExplicitFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "not-vex.json")
	if err := os.WriteFile(junk, []byte("this is not json"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}

	for name, file := range map[string]string{
		"missing file":   filepath.Join(dir, "absent.json"),
		"not a document": junk,
	} {
		t.Run(name, func(t *testing.T) {
			vexAttestor := New()
			WithVEXFile(file)(vexAttestor)

			ctx, err := attestation.NewContext("test",
				[]attestation.Attestor{vexAttestor},
				attestation.WithWorkingDir(dir),
			)
			if err != nil {
				t.Fatalf("NewContext: %v", err)
			}
			if err := vexAttestor.Attest(ctx); err == nil {
				t.Fatal("Attest succeeded on an unusable --attestor-vex-file")
			}
		})
	}
}

// validDocumentJSON is a minimal document that must be ACCEPTED. It is the
// control for the rejection table below: every invalid case differs from
// it in exactly one way, so a rejection can only be attributed to that
// difference.
const validDocumentJSON = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-test",
  "author": "cilock",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2024-12345"},
      "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ],
  "timestamp": "2026-07-27T12:00:00Z"
}`

// invalidDocuments are documents encoding/json ACCEPTS but that are not
// usable VEX evidence.
//
// This is the hole an unmarshal-only check leaves: `{}` decodes into a
// zero-valued openvex.VEX, and Go's decoder ignores unknown fields, so an
// unrelated JSON object decodes into that same empty document. Before
// openvex.Validate ran on this path, every one of these was read, digested,
// and SIGNED — a signed attestation of the type "https://openvex.dev/ns"
// asserting nothing, or asserting a suppression the spec says is
// incomplete (not_affected with no justification, affected with no
// remediation).
var invalidDocuments = map[string]string{
	"empty object":   `{}`,
	"unrelated json": `{"name":"package.json","dependencies":{"left-pad":"1.0.0"}}`,
	"no statements": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z", "statements": []}`,
	"foreign context": `{
	  "@context": "https://example.com/not-vex", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "fixed"}]}`,
	"no author": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "fixed"}]}`,
	"no timestamp": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1,
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "fixed"}]}`,
	"no version": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "fixed"}]}`,
	"statement without a vulnerability": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "fixed"}]}`,
	"statement without products": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"}, "status": "fixed"}]}`,
	"unidentifiable product": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"supplier": "acme"}], "status": "fixed"}]}`,
	"unknown status": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "safe"}]}`,
	"not_affected without justification or impact": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "not_affected"}]}`,
	"affected without an action statement": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "affected"}]}`,
	"unknown justification": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "not_affected",
	    "justification": "trust_me"}]}`,
	"justification on a status that cannot carry one": `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-test",
	  "author": "cilock", "version": 1, "timestamp": "2026-07-27T12:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2024-12345"},
	    "products": [{"@id": "pkg:golang/example.com/mod@v1.2.3"}], "status": "fixed",
	    "justification": "component_not_present"}]}`,
}

// writeDoc drops raw into a temp dir and returns the path.
func writeDoc(t *testing.T, name, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// attestExplicit runs the attestor against an explicitly named file.
func attestExplicit(t *testing.T, path string) error {
	t.Helper()

	vexAttestor := New()
	WithVEXFile(path)(vexAttestor)

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(filepath.Dir(path)),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err != nil {
		return err
	}
	// Attest reported success, so the predicate is about to be signed.
	// Say what it actually contains, since that is what the signature
	// would cover.
	t.Logf("signed predicate would be: statements=%d author=%q context=%q",
		len(vexAttestor.VEXDocument.Statements), vexAttestor.VEXDocument.Author, vexAttestor.VEXDocument.Context)
	return nil
}

// TestExplicitFileRejectsInvalidDocuments is the regression bar for the
// --attestor-vex-file path: valid JSON is not the same thing as a VEX
// document, and only a document the spec would accept may be signed.
func TestExplicitFileRejectsInvalidDocuments(t *testing.T) {
	// Control: the shape everything below is derived from must pass, so a
	// rejection below is attributable to the single field that differs.
	if err := attestExplicit(t, writeDoc(t, "valid.openvex.json", validDocumentJSON)); err != nil {
		t.Fatalf("control document rejected: %v", err)
	}

	for name, raw := range invalidDocuments {
		t.Run(name, func(t *testing.T) {
			if err := attestExplicit(t, writeDoc(t, "vex.openvex.json", raw)); err == nil {
				t.Fatal("Attest succeeded — invalid evidence would have been signed")
			}
		})
	}
}

// TestProductScanSkipsNonVEXDocuments covers the same hole on the
// product-scan path. Any JSON product used to satisfy "is this a VEX
// document?", so an unrelated artifact in the product set (a package.json,
// a scanner report) became the signed predicate.
func TestProductScanSkipsNonVEXDocuments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"api","dependencies":{"left-pad":"1.0.0"}}`), 0o600); err != nil {
		t.Fatalf("write product: %v", err)
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	if err != nil {
		t.Fatalf("digest product: %v", err)
	}

	shim := &productShim{products: map[string]attestation.Product{
		path: {MimeType: "application/json", Digest: digest},
	}}
	vexAttestor := New()

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{shim, vexAttestor},
		attestation.WithHashes(hashes),
		attestation.WithWorkingDir(dir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors: %v", err)
	}

	if vexAttestor.ReportFile != "" {
		t.Errorf("ReportFile = %q — a non-VEX product was adopted as the VEX document", vexAttestor.ReportFile)
	}
	if len(vexAttestor.VEXDocument.Statements) != 0 || vexAttestor.VEXDocument.Context != "" {
		t.Errorf("predicate was populated from a non-VEX product: %+v", vexAttestor.VEXDocument)
	}
}

// TestProductScanIsDeterministic pins the selection rule when a build
// produces more than one valid VEX document.
//
// getCandidate used to range directly over ctx.Products(), and Go
// randomizes map iteration — so with two valid documents in the product
// set, which one got signed was decided by the runtime. Two runs over an
// identical tree could emit different evidence, and nothing in the
// resulting attestation would explain the difference. Sorting the
// candidate paths makes the choice a property of the inputs.
func TestProductScanIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Names chosen so the sorted-first candidate is NOT the one a
	// creation-ordered or length-ordered scan would land on.
	products := map[string]attestation.Product{}
	for _, name := range []string{"zulu.openvex.json", "alpha.openvex.json", "mike.openvex.json"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(validDocumentJSON), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
		if err != nil {
			t.Fatalf("digest %s: %v", name, err)
		}
		products[path] = attestation.Product{MimeType: "application/json", Digest: digest}
	}

	// The stable name, not the absolute path the bytes were read from —
	// ReportFile is signed, so it never carries the build host's layout.
	want := "alpha.openvex.json"
	for i := 0; i < 50; i++ {
		vexAttestor := New()
		ctx, err := attestation.NewContext("test",
			[]attestation.Attestor{&productShim{products: products}, vexAttestor},
			attestation.WithHashes(hashes),
			attestation.WithWorkingDir(dir),
		)
		if err != nil {
			t.Fatalf("NewContext: %v", err)
		}
		if err := ctx.RunAttestors(); err != nil {
			t.Fatalf("RunAttestors: %v", err)
		}
		if vexAttestor.ReportFile != want {
			t.Fatalf("iteration %d signed %q, want %q — selection depends on map order",
				i, vexAttestor.ReportFile, want)
		}
	}
}

// TestProductScanResolvesRelativePathsAgainstWorkingDir is the real-world
// shape of the product set, and the case TestProductScanIsDeterministic
// above does NOT cover: the product attestor keys its map on paths
// RELATIVE to the working directory (fromDigestMap keys on the relative
// name while stat'ing workingDir+name), not absolute ones.
//
// getCandidate used to hand those bare keys to os.Open, which resolves
// them against the process working directory instead. A
// `cilock run --workingdir build -a vex` therefore looked for the
// document beside the binary rather than beside the build — finding
// nothing, or worse, finding a same-named file that was never the
// product that was hashed.
//
// t.Chdir moves the process cwd somewhere the relative key CANNOT
// resolve, so the test fails unless the working dir is actually applied.
func TestProductScanResolvesRelativePathsAgainstWorkingDir(t *testing.T) {
	workingDir := t.TempDir()
	elsewhere := t.TempDir()
	t.Chdir(elsewhere)

	const relName = "vex.openvex.json"
	full := filepath.Join(workingDir, relName)
	if err := os.WriteFile(full, []byte(validDocumentJSON), 0o600); err != nil {
		t.Fatalf("write product: %v", err)
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	digest, err := cryptoutil.CalculateDigestSetFromFile(full, hashes)
	if err != nil {
		t.Fatalf("digest product: %v", err)
	}

	// The relative key is what the product attestor actually records.
	shim := &productShim{products: map[string]attestation.Product{
		relName: {MimeType: "application/json", Digest: digest},
	}}
	vexAttestor := New()

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{shim, vexAttestor},
		attestation.WithHashes(hashes),
		attestation.WithWorkingDir(workingDir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors: %v", err)
	}

	if len(vexAttestor.VEXDocument.Statements) != 1 {
		t.Fatalf("relative product key was not resolved against the working dir: statements=%d, ReportFile=%q",
			len(vexAttestor.VEXDocument.Statements), vexAttestor.ReportFile)
	}
	if len(vexAttestor.ReportDigestSet) == 0 {
		t.Error("ReportDigestSet is empty — nothing anchors the predicate to the bytes")
	}
}

// TestProductScanDoesNotAdoptAnUnverifiedReplacement is the TOCTOU bar.
//
// getCandidate used to hash the file, then REOPEN it to parse. Anything
// that replaced the file between those two reads would be parsed and
// signed while ReportDigestSet still described the bytes that were
// hashed — a signature over content nobody verified. Reading once and
// deriving both the digest and the predicate from that single buffer
// closes the window.
//
// The check here is the invariant that makes the window unexploitable:
// the digest recorded MUST be the digest of the bytes that produced the
// predicate. A mismatched product digest must be skipped, never signed.
func TestProductScanDoesNotAdoptAnUnverifiedReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vex.openvex.json")
	if err := os.WriteFile(path, []byte(validDocumentJSON), 0o600); err != nil {
		t.Fatalf("write product: %v", err)
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	staleDigest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	if err != nil {
		t.Fatalf("digest product: %v", err)
	}

	// Stand in for the replacement: the product set carries the digest
	// of the ORIGINAL bytes while the file on disk now holds a different
	// (still perfectly valid) document.
	swapped := strings.Replace(validDocumentJSON, "CVE-2024-12345", "CVE-2024-99999", 1)
	if swapped == validDocumentJSON {
		t.Fatal("test setup: document was not modified")
	}
	if err := os.WriteFile(path, []byte(swapped), 0o600); err != nil {
		t.Fatalf("replace product: %v", err)
	}

	shim := &productShim{products: map[string]attestation.Product{
		path: {MimeType: "application/json", Digest: staleDigest},
	}}
	vexAttestor := New()

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{shim, vexAttestor},
		attestation.WithHashes(hashes),
		attestation.WithWorkingDir(dir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors: %v", err)
	}

	if vexAttestor.ReportFile != "" || len(vexAttestor.VEXDocument.Statements) != 0 {
		t.Fatalf("a document whose digest does not match the product set was adopted: file=%q statements=%d",
			vexAttestor.ReportFile, len(vexAttestor.VEXDocument.Statements))
	}
}

// TestProductScanRecordsOnlySelfComputedDigests pins the other half of
// the TOCTOU fix: the recorded digest must be one the attestor computed
// from the bytes it actually parsed — never a value handed to it.
//
// getCandidate used to store the PRODUCT ATTESTOR's digest
// (a.ReportDigestSet = product.Digest) after an Equal() cross-check. But
// DigestSet.Equal only compares the strongest recognized SHARED class
// and tolerates algorithms present in one set and not the other, so any
// extra entry rode into signed evidence unverified. Here the product
// carries a correct sha256 alongside a deliberately WRONG sha512: the
// Equal() check passes on sha256, and the pre-fix code recorded the
// bogus sha512 as though the attestor had vouched for it.
func TestProductScanRecordsOnlySelfComputedDigests(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vex.openvex.json")
	if err := os.WriteFile(path, []byte(validDocumentJSON), 0o600); err != nil {
		t.Fatalf("write product: %v", err)
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	if err != nil {
		t.Fatalf("digest product: %v", err)
	}

	const bogusSHA512 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	poisoned := cryptoutil.DigestSet{}
	for k, v := range digest {
		poisoned[k] = v
	}
	poisoned[cryptoutil.DigestValue{Hash: crypto.SHA512}] = bogusSHA512

	shim := &productShim{products: map[string]attestation.Product{
		path: {MimeType: "application/json", Digest: poisoned},
	}}
	vexAttestor := New()

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{shim, vexAttestor},
		attestation.WithHashes(hashes),
		attestation.WithWorkingDir(dir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors: %v", err)
	}
	if len(vexAttestor.VEXDocument.Statements) != 1 {
		t.Fatalf("test setup: the document was not adopted (statements=%d)",
			len(vexAttestor.VEXDocument.Statements))
	}

	// Every recorded digest must be reproducible from the file itself.
	for dv, got := range vexAttestor.ReportDigestSet {
		want, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{dv})
		if err != nil {
			t.Fatalf("recompute %v: %v", dv.Hash, err)
		}
		if want[dv] != got {
			t.Errorf("ReportDigestSet carries an entry the attestor never computed from the signed bytes: %v = %q, file is %q",
				dv.Hash, got, want[dv])
		}
	}
}

// TestReportFileIsStableAcrossWorkingDirectories is the regression bar
// for leaking machine state into signed evidence.
//
// ReportFile is part of the signed predicate. Round 3 changed it to the
// RESOLVED path so the attestor could read a working-dir-relative
// product key — which fixed the read but made the signed output depend
// on where the build happened: the same document under two checkouts
// produced two different attestations, each publishing the host's
// directory layout. Resolve for I/O, record what is stable.
//
// Building the identical document in two different directories must
// therefore produce the identical ReportFile, on both ingestion paths.
func TestReportFileIsStableAcrossWorkingDirectories(t *testing.T) {
	viaProductScan := func(t *testing.T) string {
		t.Helper()
		path := authoredDocument(t)
		hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
		digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		vexAttestor := New()
		shim := &productShim{products: map[string]attestation.Product{
			filepath.Base(path): {MimeType: "application/json", Digest: digest},
		}}
		ctx, err := attestation.NewContext("test",
			[]attestation.Attestor{shim, vexAttestor},
			attestation.WithHashes(hashes),
			attestation.WithWorkingDir(filepath.Dir(path)),
		)
		if err != nil {
			t.Fatalf("NewContext: %v", err)
		}
		if err := ctx.RunAttestors(); err != nil {
			t.Fatalf("RunAttestors: %v", err)
		}
		return vexAttestor.ReportFile
	}

	viaExplicitFile := func(t *testing.T) string {
		t.Helper()
		// The absolute path is what `cilock attest vex` really hands the
		// attestor, so this is the shape that leaked.
		path := authoredDocument(t)
		vexAttestor := New()
		WithVEXFile(path)(vexAttestor)
		ctx, err := attestation.NewContext("test",
			[]attestation.Attestor{vexAttestor},
			attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
			attestation.WithWorkingDir(filepath.Dir(path)),
		)
		if err != nil {
			t.Fatalf("NewContext: %v", err)
		}
		if err := vexAttestor.Attest(ctx); err != nil {
			t.Fatalf("Attest: %v", err)
		}
		return vexAttestor.ReportFile
	}

	for name, build := range map[string]func(*testing.T) string{
		"product scan":  viaProductScan,
		"explicit file": viaExplicitFile,
	} {
		t.Run(name, func(t *testing.T) {
			// authoredDocument allocates a FRESH temp dir per call, so
			// these two runs genuinely happen in different directories.
			first := build(t)
			second := build(t)

			if first != second {
				t.Errorf("ReportFile varies with the build directory: %q vs %q", first, second)
			}
			if filepath.IsAbs(first) {
				t.Errorf("ReportFile %q is an absolute host path in signed evidence", first)
			}
			if strings.Contains(first, string(filepath.Separator)) {
				t.Errorf("ReportFile %q carries directory structure from the build host", first)
			}
			if first != "vex.openvex.json" {
				t.Errorf("ReportFile = %q, want the document's stable name", first)
			}
		})
	}
}

// TestReportFileUsesBasenameForFilesOutsideTheWorkingDir covers the
// out-of-tree branch of stableReportName.
//
// This branch has now been wrong twice, in opposite directions: first it
// recorded the absolute path (leaking the host layout outright), then it
// recorded the ".."-climbing relative form — which is still a function of
// the checkout's depth and the directory names between the file and the
// tree, so identical documents produced different signed evidence on
// different runners. The rule that survives both failures: only an
// in-tree path has a machine-independent spelling; anything outside the
// working directory is recorded by its basename alone.
func TestReportFileUsesBasenameForFilesOutsideTheWorkingDir(t *testing.T) {
	root := t.TempDir()
	workingDir := filepath.Join(root, "build")
	if err := os.MkdirAll(workingDir, 0o750); err != nil {
		t.Fatalf("mkdir working dir: %v", err)
	}

	// The document sits BESIDE the working directory, not inside it.
	outside := filepath.Join(root, "vex.openvex.json")
	if err := os.WriteFile(outside, []byte(validDocumentJSON), 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}

	vexAttestor := New()
	WithVEXFile(outside)(vexAttestor) // absolute, as the CLI passes it

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(workingDir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	got := vexAttestor.ReportFile
	if filepath.IsAbs(got) {
		t.Fatalf("ReportFile = %q — an absolute host path in signed evidence", got)
	}
	if want := "vex.openvex.json"; got != want {
		t.Errorf("ReportFile = %q, want the bare basename %q", got, want)
	}
	if strings.Contains(got, string(filepath.Separator)) || strings.Contains(got, "..") {
		t.Errorf("ReportFile %q carries directory structure — for an out-of-tree file every path component is machine-specific", got)
	}
	if strings.Contains(got, root) {
		t.Errorf("ReportFile %q leaks the build host's directory layout", got)
	}
}

// TestStableReportNameNeverReturnsAnAbsolutePath exercises the helper
// directly, branch by branch, rather than only through the two ingestion
// paths that call it.
//
// Both ReportFile sites now share this helper, so its branches are the
// real surface of the "resolve for I/O, record what is stable" rule — and
// the out-of-tree branch is precisely the one that leaked an absolute
// path after the in-tree branch had already been fixed. The property that
// has to hold on EVERY branch is the same: whatever comes back is a name,
// never this machine's path to the file.
func TestStableReportNameNeverReturnsAnAbsolutePath(t *testing.T) {
	root := t.TempDir()
	workingDir := filepath.Join(root, "build")

	cases := map[string]struct {
		workingDir string
		resolved   string
		want       string
	}{
		"inside the working dir": {
			workingDir, filepath.Join(workingDir, "vex.openvex.json"), "vex.openvex.json",
		},
		// The want is a LITERAL forward slash, not filepath.Join: the
		// recorded name goes into signed evidence, so it must be spelled
		// identically on every OS — filepath.Join would make this test
		// (and the predicate) expect a backslash on Windows.
		"nested inside the working dir": {
			workingDir, filepath.Join(workingDir, "out", "vex.openvex.json"),
			"out/vex.openvex.json",
		},
		"the working dir itself": {
			workingDir, workingDir, ".",
		},
		// Out-of-tree paths collapse to the basename: the ".."-climbing
		// relative form is a function of the checkout's depth, so "one
		// level outside" and "five levels outside" must record the SAME
		// name for the same file or the evidence varies by runner.
		"one level outside": {
			workingDir, filepath.Join(root, "vex.openvex.json"),
			"vex.openvex.json",
		},
		"two levels outside": {
			filepath.Join(workingDir, "deep"), filepath.Join(root, "vex.openvex.json"),
			"vex.openvex.json",
		},
		"outside under a host-specific directory": {
			workingDir, filepath.Join(root, "secret-project", "vex.openvex.json"),
			"vex.openvex.json",
		},
		// A relative --workingdir is resolved against the process cwd
		// before the comparison, so the answer does not depend on which
		// spelling the operator used.
		"relative working dir": {
			".", filepath.Join(mustGetwd(t), "vex.openvex.json"), "vex.openvex.json",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := stableReportName(tc.workingDir, tc.resolved)
			if filepath.IsAbs(got) {
				t.Fatalf("stableReportName(%q, %q) = %q — an absolute host path", tc.workingDir, tc.resolved, got)
			}
			if strings.Contains(got, "..") {
				t.Fatalf("stableReportName(%q, %q) = %q — a ..-climbing name encodes the checkout depth, which is machine-specific", tc.workingDir, tc.resolved, got)
			}
			if got != tc.want {
				t.Errorf("stableReportName(%q, %q) = %q, want %q", tc.workingDir, tc.resolved, got, tc.want)
			}
		})
	}
}

// TestVEXBytesNeverTouchTheFilesystem pins the TOCTOU-free property of
// the WithVEXBytes path: validation, digest, predicate, and name all come
// from the caller's buffer. The named path deliberately does NOT exist —
// if any part of the load were to read from disk, Attest would fail.
func TestVEXBytesNeverTouchTheFilesystem(t *testing.T) {
	raw := []byte(validDocumentJSON)
	ghost := filepath.Join(t.TempDir(), "never-written.openvex.json")

	vexAttestor := New()
	WithVEXBytes(raw, ghost)(vexAttestor)

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes(hashes),
		attestation.WithWorkingDir(filepath.Dir(ghost)),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err != nil {
		t.Fatalf("Attest read from disk (the path does not exist): %v", err)
	}

	wantDigest, err := cryptoutil.CalculateDigestSetFromBytes(raw, hashes)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !vexAttestor.ReportDigestSet.Equal(wantDigest) {
		t.Error("ReportDigestSet does not match the supplied bytes")
	}
	if vexAttestor.ReportFile != "never-written.openvex.json" {
		t.Errorf("ReportFile = %q, want the stable in-tree name", vexAttestor.ReportFile)
	}
	if len(vexAttestor.VEXDocument.Statements) != 1 {
		t.Errorf("statements = %d, want 1", len(vexAttestor.VEXDocument.Statements))
	}
}

// TestVEXBytesFailClosed: the in-memory path enforces the same validation
// wall as both file paths — `{}` decodes but must never become a signed
// predicate, and bytes take precedence over a valid file already on disk.
func TestVEXBytesFailClosed(t *testing.T) {
	path := authoredDocument(t) // a VALID document sits at this path

	vexAttestor := New()
	WithVEXBytes([]byte(`{}`), path)(vexAttestor)

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(filepath.Dir(path)),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err == nil {
		t.Fatal("Attest accepted `{}` bytes — either validation is gone or the attestor fell back to the (valid) file on disk")
	}
	if len(vexAttestor.ReportDigestSet) != 0 || vexAttestor.ReportFile != "" {
		t.Error("a rejected document left predicate fields populated")
	}
}

// TestVEXBytesEmptyNeverFallsBackToTheFile pins the configured-bytes
// contract: once WithVEXBytes is called, the buffer IS the signing input,
// even when it is empty. The old `len(vexBytes) > 0` dispatch treated
// empty configured bytes as "not configured" and silently fell back to
// re-reading the courtesy path from disk — reopening exactly the TOCTOU
// window the bytes channel exists to close, against a file an attacker
// can swap. Empty bytes are a caller bug and must be an error, never a
// fallback.
func TestVEXBytesEmptyNeverFallsBackToTheFile(t *testing.T) {
	for name, raw := range map[string][]byte{"empty": {}, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			path := authoredDocument(t) // a VALID document sits at this path

			vexAttestor := New()
			WithVEXBytes(raw, path)(vexAttestor)

			ctx, err := attestation.NewContext("test",
				[]attestation.Attestor{vexAttestor},
				attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
				attestation.WithWorkingDir(filepath.Dir(path)),
			)
			if err != nil {
				t.Fatalf("NewContext: %v", err)
			}
			if err := vexAttestor.Attest(ctx); err == nil {
				t.Fatal("Attest accepted empty configured bytes — it fell back to signing the (valid) file on disk")
			}
			if len(vexAttestor.ReportDigestSet) != 0 || vexAttestor.ReportFile != "" || len(vexAttestor.VEXDocument.Statements) != 0 {
				t.Error("empty configured bytes left predicate fields populated")
			}
		})
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}
