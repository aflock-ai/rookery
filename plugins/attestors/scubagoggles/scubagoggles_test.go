// Copyright 2022 The Witness Contributors
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

package scubagoggles

import (
	"bytes"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

func loadSample(t *testing.T) Predicate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "scubaresults-sample.json")) //nolint:gosec // fixed test fixture path
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p, err := buildPredicate(b)
	if err != nil {
		t.Fatalf("buildPredicate: %v", err)
	}
	return *p
}

// TestBuildPredicate_FromScubaResults verifies we extract the RAW config from
// the `Raw` section (not the verdict) and pull the right identifiers.
func TestBuildPredicate_FromScubaResults(t *testing.T) {
	p := loadSample(t)

	if p.Tool != "ScubaGoggles" || p.ToolVersion != "0.6.0" {
		t.Errorf("tool/version = %q/%q", p.Tool, p.ToolVersion)
	}
	if p.CollectedAt != "2025-10-10T20:08:58.871Z" {
		t.Errorf("collectedAt = %q", p.CollectedAt)
	}
	if p.TenantID != "C0153amby" || p.DomainName != "example.org" || p.DisplayName != "Example Org" {
		t.Errorf("identity = %q/%q/%q", p.TenantID, p.DomainName, p.DisplayName)
	}

	wantDomains := []string{"alias.example.org", "example.org"}
	if !reflect.DeepEqual(p.Domains, wantDomains) {
		t.Errorf("domains = %v, want %v", p.Domains, wantDomains)
	}
	wantOUs := []string{"Engineering", "Suspended"}
	if !reflect.DeepEqual(p.OrgUnits, wantOUs) {
		t.Errorf("orgUnits = %v, want %v", p.OrgUnits, wantOUs)
	}

	// Config must be the RAW provider object (the rego `input`) — it carries
	// policies/super_admins, and must NOT be the verdict (no "Results" key).
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(p.Config, &cfg); err != nil {
		t.Fatalf("config not a JSON object: %v", err)
	}
	for _, k := range []string{"tenant_info", "policies", "super_admins", "dkim_records"} {
		if _, ok := cfg[k]; !ok {
			t.Errorf("config missing raw key %q", k)
		}
	}
	if _, ok := cfg["Results"]; ok {
		t.Error("config leaked the verdict (Results) — attestor must capture facts only")
	}
	if bytes.Contains(p.Config, []byte(`"Result"`)) && bytes.Contains(p.Config, []byte(`"Pass"`)) {
		t.Error("config appears to contain per-control verdicts")
	}
}

// TestBuildPredicate_BareProviderExport accepts a top-level provider object
// (ProviderSettingsExport) with no MetaData/Raw wrapper.
func TestBuildPredicate_BareProviderExport(t *testing.T) {
	body := `{
		"tenant_info": {"ID": "C0xyz", "domain": "bare.example", "topLevelOU": "Bare"},
		"domains": ["bare.example"],
		"organizational_unit_names": ["", "Sales"],
		"policies": {}
	}`
	p, err := buildPredicate([]byte(body))
	if err != nil {
		t.Fatalf("buildPredicate(bare): %v", err)
	}
	if p.TenantID != "C0xyz" || p.DomainName != "bare.example" {
		t.Errorf("identity = %q/%q", p.TenantID, p.DomainName)
	}
	if p.Tool != "ScubaGoggles" {
		t.Errorf("tool default = %q", p.Tool)
	}
	if !reflect.DeepEqual(p.OrgUnits, []string{"Sales"}) {
		t.Errorf("orgUnits = %v", p.OrgUnits)
	}
}

func TestSubjects(t *testing.T) {
	a := &Attestor{Predicate: loadSample(t)}
	subjects := a.Subjects()
	want := []string{
		"googleworkspace:tenant:C0153amby",
		"googleworkspace:domain:example.org",
		"googleworkspace:domain:alias.example.org",
		"googleworkspace:orgunit:Engineering",
		"googleworkspace:orgunit:Suspended",
	}
	for _, k := range want {
		if _, ok := subjects[k]; !ok {
			t.Errorf("missing subject %q", k)
		}
	}
	if len(subjects) != len(want) {
		t.Errorf("subject count = %d, want %d (%v)", len(subjects), len(want), subjectKeys(subjects))
	}
}

func TestBuildPredicate_RejectsNonProvider(t *testing.T) {
	cases := map[string]string{
		"prowler-array":     `[{"CheckID":"x","Provider":"aws","Status":"PASS"}]`,
		"no-tenant-info":    `{"Raw": {"policies": {}, "domains": ["x"]}}`,
		"verdict-only":      `{"MetaData":{"Tool":"ScubaGoggles"},"Results":{"gmail":[]}}`,
		"empty-tenant-info": `{"tenant_info": {"ID": "", "domain": ""}}`,
		"not-json":          `nope`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := buildPredicate([]byte(body)); err == nil {
				t.Errorf("expected rejection for %s, got nil", name)
			}
		})
	}
}

func TestMetadata(t *testing.T) {
	a := New()
	if a.Name() != "scubagoggles" {
		t.Errorf("Name = %q", a.Name())
	}
	if a.Type() != "https://aflock.ai/attestations/scubagoggles/v0.1" {
		t.Errorf("Type = %q", a.Type())
	}
	if a.RunType() != attestation.PostProductRunType {
		t.Errorf("RunType = %v", a.RunType())
	}
}

func subjectKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// defaultHashes mirrors the hash set an AttestationContext uses by default.
func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256, GitOID: true},
		{Hash: crypto.SHA1, GitOID: true},
	}
}

// fakeProducer registers files as products so the attestation context exposes
// them to PostProduct attestors such as scubagoggles.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (fp *fakeProducer) Name() string                                   { return "fake-producer" }
func (fp *fakeProducer) Type() string                                   { return "fake-type" }
func (fp *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                     { return nil }
func (fp *fakeProducer) Products() map[string]attestation.Product       { return fp.products }

// writeProduct writes content under dir and returns (relativeKey, absPath, digest)
// so a test can register the file as a product keyed relative to the working dir.
func writeProduct(t *testing.T, dir, name, content string) (relKey, absPath string, digest cryptoutil.DigestSet) {
	t.Helper()
	absPath = filepath.Join(dir, name)
	if err := os.WriteFile(absPath, []byte(content), 0600); err != nil {
		t.Fatalf("write product %s: %v", name, err)
	}
	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(content), defaultHashes())
	if err != nil {
		t.Fatalf("digest product %s: %v", name, err)
	}
	return name, absPath, ds
}

// contextWithProducts builds an AttestationContext rooted at wd and runs the
// fakeProducer so its products are exposed to PostProduct attestors.
func contextWithProducts(t *testing.T, wd string, products map[string]attestation.Product) *attestation.AttestationContext {
	t.Helper()
	prod := &fakeProducer{products: products}
	ctx, err := attestation.NewContext("test", []attestation.Attestor{prod},
		attestation.WithWorkingDir(wd),
		attestation.WithHashes(defaultHashes()),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors: %v", err)
	}
	return ctx
}

// TestResolveProductPath guards the regression where product paths (recorded
// relative to the attestation working directory) were opened relative to the
// process CWD instead. That broke discovery whenever cilock was invoked with
// --workingdir/-d pointing somewhere other than the CWD.
func TestResolveProductPath(t *testing.T) {
	wd := t.TempDir()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(wd))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}

	// A relative product path must resolve against the working dir.
	if got, want := resolveProductPath(ctx, "ScubaResults.json"), filepath.Join(wd, "ScubaResults.json"); got != want {
		t.Errorf("relative path: got %q, want %q", got, want)
	}

	// Absolute paths pass through unchanged.
	abs := filepath.Join(wd, "abs.json")
	if got := resolveProductPath(ctx, abs); got != abs {
		t.Errorf("absolute path: got %q, want %q", got, abs)
	}
}

// TestGetCandidate_ResolvesRelativeProductAgainstWorkingDir reproduces the bug
// the reviewer flagged: a product key recorded relative to the working dir must
// be opened relative to that dir, not the process CWD. With the fix, the file is
// found and the predicate is built; without it, getCandidate errors.
func TestGetCandidate_ResolvesRelativeProductAgainstWorkingDir(t *testing.T) {
	wd := t.TempDir()
	bare := `{"tenant_info":{"ID":"C0wd","domain":"wd.example","topLevelOU":"WD"},"policies":{}}`
	relKey, _, digest := writeProduct(t, wd, "ScubaResults.json", bare)

	ctx := contextWithProducts(t, wd, map[string]attestation.Product{
		relKey: {MimeType: "application/json", Digest: digest},
	})

	a := New()
	if err := a.getCandidate(ctx); err != nil {
		t.Fatalf("getCandidate with relative product key failed: %v", err)
	}
	if a.Predicate.TenantID != "C0wd" {
		t.Errorf("tenantID = %q, want C0wd", a.Predicate.TenantID)
	}
	if a.Predicate.SourceFile != relKey {
		t.Errorf("sourceFile = %q, want %q (the product key, not the resolved path)", a.Predicate.SourceFile, relKey)
	}
}

// TestGetCandidate_Deterministic ensures that when multiple parseable provider
// configs are present, the attested source is selected deterministically (sorted
// product key), not by Go's randomized map iteration order — signed evidence
// must be reproducible.
func TestGetCandidate_Deterministic(t *testing.T) {
	wd := t.TempDir()
	// Two distinct, equally-valid candidates. Sorted, "a-export.json" wins.
	a1 := `{"tenant_info":{"ID":"C0aaa","domain":"a.example","topLevelOU":"A"},"policies":{}}`
	z1 := `{"tenant_info":{"ID":"C0zzz","domain":"z.example","topLevelOU":"Z"},"policies":{}}`
	aKey, _, aDigest := writeProduct(t, wd, "a-export.json", a1)
	zKey, _, zDigest := writeProduct(t, wd, "z-export.json", z1)

	products := map[string]attestation.Product{
		aKey: {MimeType: "application/json", Digest: aDigest},
		zKey: {MimeType: "application/json", Digest: zDigest},
	}

	// Run many times: with map-order iteration this would flap; sorted iteration
	// is stable, so the chosen tenant must be the same every time.
	const iterations = 50
	for i := 0; i < iterations; i++ {
		ctx := contextWithProducts(t, wd, products)
		a := New()
		if err := a.getCandidate(ctx); err != nil {
			t.Fatalf("getCandidate: %v", err)
		}
		if a.Predicate.TenantID != "C0aaa" {
			t.Fatalf("iteration %d: tenantID = %q, want C0aaa (sorted first candidate a-export.json)", i, a.Predicate.TenantID)
		}
		if a.Predicate.SourceFile != aKey {
			t.Fatalf("iteration %d: sourceFile = %q, want %q", i, a.Predicate.SourceFile, aKey)
		}
	}
}
