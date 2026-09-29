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

package semgrep

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unit fixture testdata/unit/semgrep.json is the REAL output of
// `semgrep --config p/python --json` (Semgrep OSS 1.119.0) on a file that calls
// subprocess with shell=True — one finding with full registry metadata. These
// values are read off that file, not hand-typed.
const (
	fixtureVersion = "1.119.0"
	fixtureRuleID  = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
	fixturePath    = "vuln.py"
	fixtureCWE     = "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
)

func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

func sha256Hex(t *testing.T, b []byte) string {
	t.Helper()
	d, err := cryptoutil.CalculateDigestSetFromBytes(b, defaultHashes())
	require.NoError(t, err)
	return d[cryptoutil.DigestValue{Hash: crypto.SHA256}]
}

// fakeProducer registers files as products, mirroring cilock's product attestor.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (fp *fakeProducer) Name() string                                   { return "fake-producer" }
func (fp *fakeProducer) Type() string                                   { return "fake" }
func (fp *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                     { return nil }
func (fp *fakeProducer) Products() map[string]attestation.Product       { return fp.products }

// fakeMaterialer registers files as materials, mirroring cilock's material
// attestor recording the scanned inputs before the command runs.
type fakeMaterialer struct {
	materials map[string]cryptoutil.DigestSet
}

func (fm *fakeMaterialer) Name() string                                   { return "fake-materialer" }
func (fm *fakeMaterialer) Type() string                                   { return "fake-material" }
func (fm *fakeMaterialer) RunType() attestation.RunType                   { return attestation.MaterialRunType }
func (fm *fakeMaterialer) Attest(_ *attestation.AttestationContext) error { return nil }
func (fm *fakeMaterialer) Schema() *jsonschema.Schema                     { return nil }
func (fm *fakeMaterialer) Materials() map[string]cryptoutil.DigestSet     { return fm.materials }

// contextWithFiles writes rel-path→bytes files under a temp working dir,
// registers each as an application/json product, and returns the run context.
// No materials are recorded — the case of a scan whose inputs cilock did not
// observe.
func contextWithFiles(t *testing.T, files map[string][]byte) *attestation.AttestationContext {
	t.Helper()
	return contextWith(t, files, nil)
}

// contextWith is contextWithFiles plus recorded materials: each rel-path→bytes
// in materials is written under the working dir and registered with its real
// content digest, the way the material attestor records scan inputs.
func contextWith(t *testing.T, products, materials map[string][]byte) *attestation.AttestationContext {
	t.Helper()
	return contextWithIn(t, t.TempDir(), products, materials)
}

// contextWithIn is contextWith over a caller-chosen working dir, for tests
// whose report bytes must mention that directory (absolute finding paths).
func contextWithIn(t *testing.T, dir string, products, materials map[string][]byte) *attestation.AttestationContext {
	t.Helper()
	prods := map[string]attestation.Product{}
	for rel, data := range products {
		abs := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
		require.NoError(t, os.WriteFile(abs, data, 0o600))
		digest, err := cryptoutil.CalculateDigestSetFromFile(abs, defaultHashes())
		require.NoError(t, err)
		prods[rel] = attestation.Product{MimeType: "application/json", Digest: digest}
	}
	mats := map[string]cryptoutil.DigestSet{}
	for rel, data := range materials {
		abs := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
		require.NoError(t, os.WriteFile(abs, data, 0o600))
		digest, err := cryptoutil.CalculateDigestSetFromBytes(data, defaultHashes())
		require.NoError(t, err)
		mats[rel] = digest
	}
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{&fakeMaterialer{materials: mats}, &fakeProducer{products: prods}},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

func scannedSource(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", "python-registry", "recording-input", "vuln.py"))
	require.NoError(t, err)
	return data
}

// contextWithMistrustedProduct writes fileBytes but records the digest of
// DIFFERENT bytes — a file swapped after cilock hashed it.
func contextWithMistrustedProduct(t *testing.T, path string, fileBytes []byte) *attestation.AttestationContext {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, path)
	require.NoError(t, os.WriteFile(abs, fileBytes, 0o600))
	stale, err := cryptoutil.CalculateDigestSetFromBytes([]byte("the trusted bytes cilock hashed"), defaultHashes())
	require.NoError(t, err)
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{&fakeProducer{products: map[string]attestation.Product{
			path: {MimeType: "application/json", Digest: stale},
		}}},
		attestation.WithWorkingDir(dir), attestation.WithHashes(defaultHashes()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "unit", "semgrep.json"))
	require.NoError(t, err)
	return data
}

// semgrepDoc synthesizes a schema-shaped report so tests can drive edge cases
// the recorded fixture does not cover.
func semgrepDoc(t *testing.T, results []map[string]any, errs []map[string]any) []byte {
	t.Helper()
	if results == nil {
		results = []map[string]any{}
	}
	if errs == nil {
		errs = []map[string]any{}
	}
	b, err := json.Marshal(map[string]any{
		"version": fixtureVersion,
		"results": results,
		"errors":  errs,
		"paths":   map[string]any{"scanned": []string{"a.py", "b.py"}},
	})
	require.NoError(t, err)
	return b
}

// result builds one results[] entry; extra is merged into "extra".
func result(rule, path string, line, col int, severity, msg string, extra map[string]any) map[string]any {
	e := map[string]any{
		"message":     msg,
		"metadata":    map[string]any{},
		"severity":    severity,
		"fingerprint": "requires login",
		"lines":       "requires login",
	}
	for k, v := range extra {
		e[k] = v
	}
	return map[string]any{
		"check_id": rule,
		"path":     path,
		"start":    map[string]any{"line": line, "col": col, "offset": 0},
		"end":      map[string]any{"line": line, "col": col + 4, "offset": 4},
		"extra":    e,
	}
}

func attest(t *testing.T, ctx *attestation.AttestationContext) *Attestor {
	t.Helper()
	a := New()
	require.NoError(t, a.Attest(ctx))
	return a
}

// ---------------------------------------------------------------------------

func TestAttest_RealFixture(t *testing.T) {
	raw := fixtureBytes(t)
	src := scannedSource(t)
	// The scanned file is a recorded material, as in a real run.
	ctx := contextWith(t, map[string][]byte{"out/semgrep.json": raw}, map[string][]byte{"vuln.py": src})
	a := attest(t, ctx)

	s := a.Summary
	assert.Equal(t, fixtureVersion, s.SemgrepVersion)
	assert.True(t, s.ScanComplete)
	assert.Equal(t, 1, s.TotalFindings)
	assert.Equal(t, 0, s.IgnoredCount)
	assert.Equal(t, 1, s.FilesScanned)
	assert.Equal(t, SeverityBreakdown{High: 1}, s.BySeverity, "registry rule emits deprecated ERROR → high")
	assert.Empty(t, s.Errors)

	require.Len(t, s.Findings, 1)
	f := s.Findings[0]
	assert.Equal(t, fixtureRuleID, f.RuleID)
	assert.Equal(t, fixturePath, f.Path)
	assert.Equal(t, 12, f.StartLine)
	assert.Equal(t, 47, f.StartCol)
	assert.Equal(t, 12, f.EndLine)
	assert.Equal(t, 51, f.EndCol)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "ERROR", f.RawSeverity)
	assert.Equal(t, []string{fixtureCWE}, f.CWE)
	assert.Len(t, f.OWASP, 3)
	assert.Contains(t, f.OWASP, "A03:2021 - Injection")
	assert.Equal(t, "security", f.Category)
	assert.Equal(t, "MEDIUM", f.Confidence)
	assert.Equal(t, "HIGH", f.Likelihood)
	assert.Equal(t, "LOW", f.Impact)
	assert.Equal(t, "OSS", f.EngineKind)
	assert.Equal(t, "NO_VALIDATOR", f.ValidationState)
	assert.False(t, f.IsIgnored)
	assert.False(t, f.HasDataflowTrace, "OSS engine emits no dataflow_trace")
	assert.Len(t, f.ID, 64, "computed id is a sha256 hex")

	// The verbatim report and its binding to the product.
	assert.JSONEq(t, string(raw), string(a.Report))
	assert.Equal(t, "out/semgrep.json", a.ReportFile)
	assert.Equal(t, sha256Hex(t, raw), a.ReportDigestSet[cryptoutil.DigestValue{Hash: crypto.SHA256}])

	subj := a.Subjects()
	assert.Contains(t, subj, "semgrep:finding:"+f.ID)
	assert.Equal(t, f.ID, subj["semgrep:finding:"+f.ID][cryptoutil.DigestValue{Hash: crypto.SHA256}])
	assert.Contains(t, subj, "semgrep:rule:"+fixtureRuleID)
	// The file subject is the scanned file's CONTENT digest — the material
	// cilock recorded — not a hash of its name.
	require.Contains(t, subj, "semgrep:file:"+fixturePath)
	assert.Equal(t, sha256Hex(t, src), subj["semgrep:file:"+fixturePath][cryptoutil.DigestValue{Hash: crypto.SHA256}])
	assert.Equal(t, sha256Hex(t, src), f.FileDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])
	assert.Len(t, subj, 3)
}

// A finding binds to the bytes of the file it names only when cilock recorded
// that file as a material. A path with no material gets no file subject —
// never a name-hash standing in for evidence — while the finding itself stays.
func TestAttest_FileSubjectBoundToMaterialDigest(t *testing.T) {
	doc := semgrepDoc(t, []map[string]any{
		result("r.a", "a.py", 1, 1, "HIGH", "m", nil),
		result("r.b", "b.py", 1, 1, "HIGH", "m", nil),
	}, nil)
	srcA := []byte("import os\n")
	a := attest(t, contextWith(t, map[string][]byte{"semgrep.json": doc}, map[string][]byte{"a.py": srcA}))

	subj := a.Subjects()
	require.Contains(t, subj, "semgrep:file:a.py")
	assert.Equal(t, sha256Hex(t, srcA), subj["semgrep:file:a.py"][cryptoutil.DigestValue{Hash: crypto.SHA256}])
	assert.NotContains(t, subj, "semgrep:file:b.py", "an unobserved file must not get a subject")

	require.Len(t, a.Summary.Findings, 2)
	assert.NotEmpty(t, a.Summary.Findings[0].FileDigest, "a.py is bound")
	assert.Empty(t, a.Summary.Findings[1].FileDigest, "b.py is unbound but still reported")
	assert.Equal(t, "b.py", a.Summary.Findings[1].Path)
	assert.Len(t, subj, 2+2+1, "2 findings + 2 rules + 1 bound file")
}

// Semgrep's OSS CLI writes the literal "requires login" where its fingerprint
// would be. It must never surface as identity.
func TestAttest_LoginPlaceholderNeverASubject(t *testing.T) {
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": fixtureBytes(t)}))
	for key, ds := range a.Subjects() {
		assert.NotContains(t, key, "requires login", "subject key %q", key)
		for _, v := range ds {
			assert.NotContains(t, v, "requires login")
		}
	}
	blob, err := json.Marshal(a.Summary)
	require.NoError(t, err)
	assert.NotContains(t, string(blob), "requires login", "the placeholder must not be lifted into the summary")
}

func TestAttest_NoProducts(t *testing.T) {
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithHashes(defaultHashes()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	err = New().Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no products")
}

// A JSON product that is not a Semgrep report is skipped, and with nothing else
// to attest the outcome is SOFT ("nothing to do") and names the fix. bandit's
// report has results[] and errors[] too, but no paths member and no check_id.
func TestAttest_ForeignJSONIgnored(t *testing.T) {
	for name, doc := range map[string]string{
		"unrelated":     `{"totally":"unrelated","results":"not an array"}`,
		"bandit-shaped": `{"errors":[],"results":[{"filename":"a.py","test_id":"B602","line_number":3}]}`,
		"sarif":         `{"version":"2.1.0","runs":[{"results":[{"ruleId":"r"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := New().Attest(contextWithFiles(t, map[string][]byte{"other.json": []byte(doc)}))
			require.Error(t, err)
			assert.True(t, attestation.IsSoftError(err), "foreign JSON is nothing to do, not a failed scan: %v", err)
			assert.Contains(t, err.Error(), "no semgrep JSON")
			assert.Contains(t, err.Error(), "--json --output")
		})
	}
}

// requireRefused asserts a HARD refusal: a plain error, which drops this
// attestor's payload from the signed collection and fails the run. A soft
// error here would let a broken report pass as "semgrep did not run".
func requireRefused(t *testing.T, err error, contains string) {
	t.Helper()
	require.Error(t, err)
	assert.False(t, attestation.IsSoftError(err), "a broken Semgrep report must be refused, not skipped: %v", err)
	assert.Contains(t, err.Error(), contains)
}

// A report cut off mid-write (a killed scan, a full disk) must never be signed
// and must never read as "no report". Every prefix of the real report that is
// not itself valid JSON is tried: none may attest, and once the prefix shows a
// Semgrep marker (the first result's check_id) the refusal must be hard.
func TestAttest_TruncatedReportRefused(t *testing.T) {
	full := fixtureBytes(t)
	marker := strings.Index(string(full), `"check_id"`) + len(`"check_id"`)
	require.Greater(t, marker, len(`"check_id"`))
	for cut := 1; cut < len(full); cut++ {
		prefix := full[:cut]
		if json.Valid(prefix) {
			continue
		}
		a := New()
		err := a.Attest(contextWithFiles(t, map[string][]byte{"semgrep.json": prefix}))
		require.Error(t, err, "a report cut at byte %d was attested", cut)
		if cut >= marker {
			require.False(t, attestation.IsSoftError(err), "a report cut at byte %d was skipped, not refused: %v", cut, err)
			assert.Contains(t, err.Error(), "semgrep.json")
		}
		assert.Empty(t, a.Summary.Findings)
		assert.Nil(t, a.Report)
	}
}

// A document that claims to be Semgrep output but lacks a member the schema
// requires is refused. An absent member is never read as an empty one.
func TestAttest_ReportMissingRequiredMemberRefused(t *testing.T) {
	finding := `{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH"}}`
	for name, doc := range map[string]string{
		"no errors":       `{"results":[` + finding + `],"paths":{"scanned":["a.py"]}}`,
		"no paths":        `{"results":[` + finding + `],"errors":[]}`,
		"null results":    `{"results":null,"errors":[],"paths":{"scanned":["a.py"]}}`,
		"null errors":     `{"results":[],"errors":null,"paths":{"scanned":["a.py"]}}`,
		"no scanned":      `{"results":[],"errors":[],"paths":{}}`,
		"null scanned":    `{"results":[],"errors":[],"paths":{"scanned":null}}`,
		"results not arr": `{"results":{},"errors":[],"paths":{"scanned":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := New().Attest(contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(doc)}))
			requireRefused(t, err, "semgrep.json")
		})
	}
}

// encoding/json matches member names case-insensitively and keeps the LAST of
// a repeated member. A report that repeats a member, or spells one in another
// case, would sign a Summary built from different members than a verifier
// reading the verbatim report sees. Such a report is refused.
func TestAttest_AmbiguousMembersRefused(t *testing.T) {
	finding := `{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH"}}`
	tail := `"errors":[],"paths":{"scanned":["a.py"]}`
	for name, doc := range map[string]string{
		"repeated results":  `{"results":[` + finding + `],` + tail + `,"results":[]}`,
		"case variant":      `{"Results":[],"results":[` + finding + `],` + tail + `}`,
		"repeated severity": `{"results":[{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH","SEVERITY":"INFO"}}],` + tail + `}`,
		"repeated path":     `{"results":[{"check_id":"r","path":"a.py","path":"b.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m"}}],` + tail + `}`,
		"repeated scanned":  `{"results":[],"errors":[],"paths":{"scanned":["a.py"],"scanned":[]}}`,
		"trailing document": `{"results":[],` + tail + `}{"results":[]}`,
		// encoding/json folds member names with bytes.EqualFold, so a container
		// spelled in another case still decodes into its field; its members
		// must be checked, not skipped as an unknown path.
		"case variant container": `{"results":[{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"Extra":{"message":"m","severity":"HIGH","severity":"INFO"}}],` + tail + `}`,
		"case variant alone":     `{"Results":[` + finding + `],` + tail + `}`,
		"unicode fold (long s)":  `{"results":[{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","ſeverity":"INFO"}}],` + tail + `}`,
		"unicode fold (kelvin)":  `{"results":[{"check_id":"r","chec` + "K" + `_id":"r2","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m"}}],` + tail + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := New().Attest(contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(doc)}))
			requireRefused(t, err, "semgrep.json")
		})
	}

	// Rule metadata is the rule author's free-form JSON, read leniently and by
	// exact key: repeated keys there are not ambiguous to this attestor.
	doc := `{"results":[{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH","metadata":{"cwe":"CWE-1","CWE":"CWE-2"}}}],` + tail + `}`
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(doc)}))
	assert.Equal(t, []string{"CWE-1"}, a.Summary.Findings[0].CWE)
}

// The sniff constrains EVERY result, not just the first: a document whose
// later entries lack a rule id, a path, or a real line must not yield findings
// or subjects built from empty identity. It claims to be a Semgrep report, so
// it is refused, not skipped.
func TestAttest_ResultMissingIdentityRejected(t *testing.T) {
	good := result("r.ok", "a.py", 1, 1, "HIGH", "m", nil)
	for name, bad := range map[string]map[string]any{
		"no check_id": {"check_id": "", "path": "a.py", "start": map[string]any{"line": 2, "col": 1}, "end": map[string]any{"line": 2, "col": 5}, "extra": map[string]any{"message": "m", "metadata": map[string]any{}, "severity": "HIGH"}},
		"no path":     {"check_id": "r.bad", "path": "", "start": map[string]any{"line": 2, "col": 1}, "end": map[string]any{"line": 2, "col": 5}, "extra": map[string]any{"message": "m", "metadata": map[string]any{}, "severity": "HIGH"}},
		"line zero":   {"check_id": "r.bad", "path": "a.py", "start": map[string]any{"line": 0, "col": 1}, "end": map[string]any{"line": 0, "col": 5}, "extra": map[string]any{"message": "m", "metadata": map[string]any{}, "severity": "HIGH"}},
	} {
		t.Run(name, func(t *testing.T) {
			doc := semgrepDoc(t, []map[string]any{good, bad}, nil)
			err := New().Attest(contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
			requireRefused(t, err, "semgrep.json")
		})
	}
}

// Codex critical: the Semgrep markers are recognized under the decoder's own
// name folding. A findings report spelled with "Paths" and "CHECK_ID" still
// decodes as Semgrep output, so it must claim (and then be refused for its
// spelling), never drop out as "not a report" beside a clean one.
func TestAttest_CaseVariantMarkersStillClaim(t *testing.T) {
	variant := `{"results":[{"CHECK_ID":"r.hit","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH"}}],"errors":[],"Paths":{"scanned":["a.py"]}}`
	for name, doc := range map[string]string{
		"both markers":            variant,
		"paths only":              `{"results":[],"errors":[],"PATHS":{"scanned":["a.py"]}}`,
		"check_id only (cut off)": `{"version":"1.119.0","results":[{"Check_Id":"r.hit","path":"a.py"`,
	} {
		t.Run(name, func(t *testing.T) {
			a := New()
			err := a.Attest(contextWithFiles(t, map[string][]byte{
				"a.json": []byte(doc),
				"b.json": semgrepDoc(t, nil, nil), // a clean report beside it
			}))
			requireRefused(t, err, "a.json")
			assert.Nil(t, a.Report)
		})
	}
}

// Codex critical: classification must never read less than the decoder does.
// A number the token walker cannot convert (1e400) sat before the markers and
// stopped the walk, so a findings report that encoding/json decodes fine
// dropped out as "not a report" beside a clean one.
func TestAttest_ReportTheDecoderReadsAlwaysClaims(t *testing.T) {
	findings := `{"x":1e400,"results":[{"check_id":"r.hit","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH"}}],"errors":[],"paths":{"scanned":["a.py"]}}`
	var probe cliOutput
	require.NoError(t, json.Unmarshal([]byte(findings), &probe), "encoding/json reads this report")

	a := New()
	err := a.Attest(contextWithFiles(t, map[string][]byte{
		"a.json": []byte(findings),
		"b.json": semgrepDoc(t, nil, nil),
	}))
	requireRefused(t, err, "a.json, b.json")
	assert.Nil(t, a.Report)

	// Found by FuzzReportAttest: a repeated member inside an unknown member
	// used to stop the parse before a later "pAths" marker the stock decoder
	// reads. A repeat is recorded, never a reason to stop reading.
	repeatFirst := `{"":[{"":"","":""}],"pAths":{}}`
	require.True(t, decodesAsSemgrep([]byte(repeatFirst)))
	a = New()
	err = a.Attest(contextWithFiles(t, map[string][]byte{
		"a.json": []byte(repeatFirst),
		"b.json": semgrepDoc(t, nil, nil),
	}))
	requireRefused(t, err, "a.json")
	assert.Nil(t, a.Report)
}

// Codex critical: a marker claims wherever it appears in the bytes, even in a
// member a later repeat overwrites. The stock decoder keeps the last member,
// so {"results":[<finding>],"results":[{}]} decodes without a marker; the
// report must still be refused, never skipped beside a clean one.
func TestAttest_OverwrittenMarkerStillClaims(t *testing.T) {
	for name, doc := range map[string]string{
		"results overwritten":  `{"results":[{"check_id":"r","path":"a.py","start":{"line":1}}],"results":[{}],"errors":[]}`,
		"paths overwritten":    `{"paths":{"scanned":["a.py"]},"results":[],"errors":[],"paths":null}`,
		"case-variant repeat":  `{"Results":[{"check_id":"r","path":"a.py","start":{"line":1}}],"results":[],"errors":[]}`,
		"check_id overwritten": `{"results":[{"check_id":"r","path":"a.py","start":{"line":1},"check_id":""}],"errors":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			a := New()
			err := a.Attest(contextWithFiles(t, map[string][]byte{
				"a.json": []byte(doc),
				"b.json": semgrepDoc(t, nil, nil),
			}))
			requireRefused(t, err, "a.json")
			assert.Nil(t, a.Report)
		})
	}
}

// is_ignored is read by value, never by its bytes: a JSON-escaped spelling of
// "true" (backslash, u0074, rue) is the string "true", and whitespace or
// escapes must not change whether a
// finding counts as live. The signed summary equals a stock decode.
func TestAttest_IsIgnoredReadByValue(t *testing.T) {
	esc := "\\" // built at runtime so the source holds no literal escape sequence
	for name, raw := range map[string]string{
		"escaped string":  "\"" + esc + "u0074rue\"",
		"plain string":    `"true"`,
		"bool":            `true`,
		"escaped false":   "\"" + esc + "u0066alse\"",
		"bool false":      `false`,
		"string TRUE":     `"TRUE"`,
		"number one":      `1`,
		"object":          `{"true":true}`,
		"null":            `null`,
		"spaced bool":     ` true `,
		"escaped quote t": "\"t" + esc + "u0072ue\"",
	} {
		t.Run(name, func(t *testing.T) {
			doc := `{"results":[{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH","is_ignored":` + raw + `}}],"errors":[],"paths":{"scanned":["a.py"]}}`
			a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(doc)}))
			var stock cliOutput
			require.NoError(t, json.Unmarshal([]byte(doc), &stock))
			want := buildSummary(stock, nil, "")
			assert.Equal(t, want.IgnoredCount, a.Summary.IgnoredCount)
			assert.Equal(t, want.BySeverity, a.Summary.BySeverity)
		})
	}
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(`{"results":[{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"HIGH","is_ignored":` + "\"" + esc + "u0074rue\"" + `}}],"errors":[],"paths":{"scanned":["a.py"]}}`)}))
	assert.Equal(t, 1, a.Summary.IgnoredCount, "an escaped true is the string true")
}

// A raw JSON value copied into the summary (an error's structured type) must
// not depend on the report's whitespace: the signed summary equals a stock
// decode of the verbatim report, whatever its formatting.
func TestAttest_RawValuesIgnoreFormatting(t *testing.T) {
	doc := `{"results":[],"errors":[{"code":2,"level":"warn","type":[ "Timeout",  "a.py" ],"message":"m"}],"paths":{"scanned":["a.py"]}}`
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(doc)}))
	require.Len(t, a.Summary.Errors, 1)
	assert.Equal(t, `["Timeout","a.py"]`, a.Summary.Errors[0].Type)

	var stock cliOutput
	require.NoError(t, json.Unmarshal([]byte(doc), &stock))
	want := buildSummary(stock, nil, "")
	assert.Equal(t, want.Errors, a.Summary.Errors, "a stock decode of the verbatim report yields the same signed errors")

	// Object members sort, as the tree re-encoding sorts them.
	objDoc := `{"results":[],"errors":[{"code":2,"level":"warn","type":{"b":1, "a":2},"message":"m"}],"paths":{"scanned":[]}}`
	a = attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(objDoc)}))
	assert.Equal(t, `{"a":2,"b":1}`, a.Summary.Errors[0].Type)
	stock = cliOutput{}
	require.NoError(t, json.Unmarshal([]byte(objDoc), &stock))
	assert.Equal(t, buildSummary(stock, nil, "").Errors, a.Summary.Errors)
}

// Codex critical: a product's bytes are verified BEFORE they are classified.
// Replacing a captured findings report with `{}` after capture must not let
// it drop out as "not a report" while a clean report beside it is signed.
func TestAttest_SubstitutedProductRefusedBeforeClassification(t *testing.T) {
	dir := t.TempDir()
	findings := semgrepDoc(t, []map[string]any{result("r.hit", "a.py", 1, 1, "HIGH", "m", nil)}, nil)
	clean := semgrepDoc(t, nil, nil)
	captured, err := cryptoutil.CalculateDigestSetFromBytes(findings, defaultHashes())
	require.NoError(t, err)
	cleanDigest, err := cryptoutil.CalculateDigestSetFromBytes(clean, defaultHashes())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{}`), 0o600)) // swapped after capture
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), clean, 0o600))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{&fakeProducer{products: map[string]attestation.Product{
			"a.json": {MimeType: "application/json", Digest: captured},
			"b.json": {MimeType: "application/json", Digest: cleanDigest},
		}}},
		attestation.WithWorkingDir(dir), attestation.WithHashes(defaultHashes()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	a := New()
	requireRefused(t, a.Attest(ctx), "a.json")
	assert.Nil(t, a.Report, "the clean report must not be signed beside a substituted one")
}

// A report changed after cilock hashed it must not be signed (RACE/TOCTOU),
// and must not pass as "no report" either.
func TestAttest_TamperedBytesRefused(t *testing.T) {
	ctx := contextWithMistrustedProduct(t, "semgrep.json", fixtureBytes(t))
	err := New().Attest(ctx)
	requireRefused(t, err, "recorded product digest")
}

// results: [] with no errors is a complete, clean scan — attested, no subjects.
func TestAttest_EmptyResultsIsCleanAndComplete(t *testing.T) {
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": semgrepDoc(t, nil, nil)}))
	assert.True(t, a.Summary.ScanComplete)
	assert.Equal(t, 0, a.Summary.TotalFindings)
	assert.Equal(t, 2, a.Summary.FilesScanned)
	assert.Empty(t, a.Subjects())
}

// An errors[] entry of level "error" means Semgrep did not fully run. Zero
// findings must then read as INCOMPLETE, never as clean (fail closed).
func TestAttest_ErrorLevelMarksScanIncomplete(t *testing.T) {
	doc := semgrepDoc(t, nil, []map[string]any{
		{"code": 2, "level": "error", "type": "SemgrepError", "rule_id": "bad.rule", "message": "rule failed to parse"},
	})
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	assert.False(t, a.Summary.ScanComplete, "level=error must mark the scan incomplete")
	assert.Equal(t, 0, a.Summary.TotalFindings)
	require.Len(t, a.Summary.Errors, 1)
	assert.Equal(t, ScanError{Code: 2, Level: "error", Type: "SemgrepError", RuleID: "bad.rule", Message: "rule failed to parse"}, a.Summary.Errors[0])
}

// Codex critical: a timed-out or partially parsed file reduces coverage even
// though Semgrep logs it at level "warn". Any errors[] entry, at any level,
// must mark the scan incomplete — otherwise a policy requiring completeness
// and zero findings would accept unfinished analysis.
func TestAttest_AnyErrorEntryMarksScanIncomplete(t *testing.T) {
	for name, entry := range map[string]map[string]any{
		"warn timeout":         {"code": 0, "level": "warn", "type": "Timeout", "path": "slow.py", "message": "one file timed out"},
		"warn partial parsing": {"code": 0, "level": "warn", "type": "PartialParsing", "path": "b.py", "message": "Syntax error"},
		"info":                 {"code": 0, "level": "info", "type": "Note", "message": "skipped a file"},
		"error rule":           {"code": 2, "level": "error", "type": "SemgrepError", "rule_id": "bad.rule", "message": "rule failed to parse"},
	} {
		t.Run(name, func(t *testing.T) {
			// A finding is present too: incomplete must not mean "no findings".
			doc := semgrepDoc(t, []map[string]any{result("r", "a.py", 1, 1, "HIGH", "m", nil)}, []map[string]any{entry})
			a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
			assert.False(t, a.Summary.ScanComplete, "%s must mark the scan incomplete", name)
			assert.Len(t, a.Summary.Errors, 1)
			assert.Equal(t, 1, a.Summary.TotalFindings)
		})
	}
}

// Codex critical: rule metadata is raw_json — a rule author's `confidence:
// 0.9` or a metadata that is not an object must cost only that field, never
// the whole report (which, with one report per step, means every finding).
func TestAttest_MetadataShapesNeverDropTheReport(t *testing.T) {
	for name, md := range map[string]any{
		"confidence number": map[string]any{"confidence": 0.9, "cwe": "CWE-89"},
		"category bool":     map[string]any{"category": true},
		"impact object":     map[string]any{"impact": map[string]any{"x": 1}, "owasp": []string{"A03"}},
		"metadata null":     nil,
		"metadata list":     []any{"not", "an", "object"},
		"metadata string":   "just text",
		"metadata number":   42,
		"cwe object":        map[string]any{"cwe": map[string]any{"id": "CWE-89"}},
	} {
		t.Run(name, func(t *testing.T) {
			doc := semgrepDoc(t, []map[string]any{
				result("r1", "a.py", 1, 1, "HIGH", "m", map[string]any{"metadata": md}),
				result("r2", "a.py", 2, 1, "HIGH", "m", nil),
			}, nil)
			a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
			assert.Equal(t, 2, a.Summary.TotalFindings, "metadata shape %s must not drop findings", name)
			require.Len(t, a.Summary.Findings, 2)
		})
	}

	// Scalars of the wrong type are kept as their literal text; the typed
	// fields that did decode are intact.
	doc := semgrepDoc(t, []map[string]any{
		result("r1", "a.py", 1, 1, "HIGH", "m", map[string]any{"metadata": map[string]any{"confidence": 0.9, "category": true, "cwe": "CWE-89", "impact": map[string]any{"x": 1}}}),
	}, nil)
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	f := a.Summary.Findings[0]
	assert.Equal(t, "0.9", f.Confidence)
	assert.Equal(t, "true", f.Category)
	assert.Equal(t, "", f.Impact, "an object is not a scalar")
	assert.Equal(t, []string{"CWE-89"}, f.CWE)
}

// is_ignored is a schema boolean, but a re-encoding tool may emit "true".
func TestAttest_IsIgnoredShapes(t *testing.T) {
	doc := semgrepDoc(t, []map[string]any{
		result("r1", "a.py", 1, 1, "HIGH", "m", map[string]any{"is_ignored": true}),
		result("r2", "a.py", 2, 1, "HIGH", "m", map[string]any{"is_ignored": "true"}),
		result("r3", "a.py", 3, 1, "HIGH", "m", map[string]any{"is_ignored": "yes"}),
		result("r4", "a.py", 4, 1, "HIGH", "m", map[string]any{"is_ignored": 1}),
	}, nil)
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	require.Len(t, a.Summary.Findings, 4)
	assert.True(t, a.Summary.Findings[0].IsIgnored)
	assert.True(t, a.Summary.Findings[1].IsIgnored)
	assert.False(t, a.Summary.Findings[2].IsIgnored)
	assert.False(t, a.Summary.Findings[3].IsIgnored)
	assert.Equal(t, 2, a.Summary.IgnoredCount)
}

// Codex critical: the sort must be a TOTAL order. Entries that agree on the
// leading keys but differ elsewhere (errors: same code/rule/message, different
// path; findings: same start, different end) must land in the same order
// whichever way Semgrep listed them.
func TestAttest_SortIsTotalOrderUnderReversal(t *testing.T) {
	errA := map[string]any{"code": 0, "level": "warn", "type": "Timeout", "rule_id": "r", "path": "a.py", "message": "timed out"}
	errB := map[string]any{"code": 0, "level": "warn", "type": "Timeout", "rule_id": "r", "path": "b.py", "message": "timed out"}
	fA := result("r", "a.py", 1, 1, "HIGH", "m", nil)
	fB := result("r", "a.py", 1, 1, "HIGH", "m", nil)
	fB["end"] = map[string]any{"line": 9, "col": 9, "offset": 99} // same start, different end

	forward := semgrepDoc(t, []map[string]any{fA, fB}, []map[string]any{errA, errB})
	reversed := semgrepDoc(t, []map[string]any{fB, fA}, []map[string]any{errB, errA})

	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": forward}))
	b := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": reversed}))

	ja, err := json.Marshal(a.Summary)
	require.NoError(t, err)
	jb, err := json.Marshal(b.Summary)
	require.NoError(t, err)
	assert.Equal(t, string(ja), string(jb), "summary must not depend on input order")

	require.Len(t, a.Summary.Errors, 2)
	assert.Equal(t, "a.py", a.Summary.Errors[0].Path)
	assert.Equal(t, "b.py", a.Summary.Errors[1].Path)
	require.Len(t, a.Summary.Findings, 2)
	assert.Equal(t, 1, a.Summary.Findings[0].EndLine)
	assert.Equal(t, 9, a.Summary.Findings[1].EndLine)
}

// Both severity vocabularies normalize to one bucket set; the deprecated
// ERROR/WARNING map per the schema's own notes.
func TestNormalizeSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info",
		"ERROR": "high", "WARNING": "medium",
		"error": "high", " High ": "high",
		"EXPERIMENT": "unknown", "": "unknown", "bogus": "unknown",
	} {
		assert.Equal(t, want, normalizeSeverity(in), "input %q", in)
	}
}

func TestAttest_SeverityBucketsCountLiveFindingsOnly(t *testing.T) {
	doc := semgrepDoc(t, []map[string]any{
		result("r.crit", "a.py", 1, 1, "CRITICAL", "m", nil),
		result("r.err", "a.py", 2, 1, "ERROR", "m", nil),
		result("r.warn", "a.py", 3, 1, "WARNING", "m", nil),
		result("r.low", "a.py", 4, 1, "LOW", "m", nil),
		result("r.ign", "a.py", 5, 1, "HIGH", "m", map[string]any{"is_ignored": true}),
	}, nil)
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	assert.Equal(t, 5, a.Summary.TotalFindings)
	assert.Equal(t, 1, a.Summary.IgnoredCount)
	assert.Equal(t, SeverityBreakdown{Critical: 1, High: 1, Medium: 1, Low: 1}, a.Summary.BySeverity,
		"ignored finding must not be counted in the live buckets")
}

// metadata is raw_json: cwe/owasp arrive as a string or a list; a malformed
// value yields an empty list, never an error.
func TestStringList(t *testing.T) {
	var s stringList
	require.NoError(t, json.Unmarshal([]byte(`"CWE-89"`), &s))
	assert.Equal(t, stringList{"CWE-89"}, s)

	require.NoError(t, json.Unmarshal([]byte(`["CWE-89","CWE-78"]`), &s))
	assert.Equal(t, stringList{"CWE-89", "CWE-78"}, s)

	require.NoError(t, json.Unmarshal([]byte(`["CWE-89", 42, null]`), &s))
	assert.Equal(t, stringList{"CWE-89"}, s, "non-string members dropped")

	require.NoError(t, json.Unmarshal([]byte(`{"not":"a list"}`), &s))
	assert.Empty(t, s)

	require.NoError(t, json.Unmarshal([]byte(`null`), &s))
	assert.Empty(t, s)
}

func TestAttest_CWEAsStringAndList(t *testing.T) {
	doc := semgrepDoc(t, []map[string]any{
		result("r1", "a.py", 1, 1, "HIGH", "m", map[string]any{"metadata": map[string]any{"cwe": "CWE-89", "owasp": []string{"A03:2021"}}}),
		result("r2", "a.py", 2, 1, "HIGH", "m", map[string]any{"metadata": map[string]any{"cwe": []string{"CWE-78", "CWE-77"}}}),
	}, nil)
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	require.Len(t, a.Summary.Findings, 2)
	assert.Equal(t, []string{"CWE-89"}, a.Summary.Findings[0].CWE)
	assert.Equal(t, []string{"A03:2021"}, a.Summary.Findings[0].OWASP)
	assert.Equal(t, []string{"CWE-78", "CWE-77"}, a.Summary.Findings[1].CWE)
}

// engine_kind is "OSS" | "PRO" | ["PRO_REQUIRED", feature].
func TestAttest_EngineKindForms(t *testing.T) {
	doc := semgrepDoc(t, []map[string]any{
		result("r1", "a.py", 1, 1, "HIGH", "m", map[string]any{"engine_kind": "PRO"}),
		result("r2", "a.py", 2, 1, "HIGH", "m", map[string]any{"engine_kind": []any{"PRO_REQUIRED", "interfile_taint"}}),
		result("r3", "a.py", 3, 1, "HIGH", "m", nil),
	}, nil)
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	assert.Equal(t, "PRO", a.Summary.Findings[0].EngineKind)
	assert.Equal(t, "PRO_REQUIRED", a.Summary.Findings[1].EngineKind)
	assert.Equal(t, "", a.Summary.Findings[2].EngineKind)
}

func TestAttest_DataflowTracePresenceOnly(t *testing.T) {
	doc := semgrepDoc(t, []map[string]any{
		result("r1", "a.py", 1, 1, "HIGH", "m", map[string]any{"dataflow_trace": map[string]any{"taint_source": []any{}}}),
		result("r2", "a.py", 2, 1, "HIGH", "m", map[string]any{"dataflow_trace": nil}),
		result("r3", "a.py", 3, 1, "HIGH", "m", nil),
	}, nil)
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	assert.True(t, a.Summary.Findings[0].HasDataflowTrace)
	assert.False(t, a.Summary.Findings[1].HasDataflowTrace)
	assert.False(t, a.Summary.Findings[2].HasDataflowTrace)
	blob, err := json.Marshal(a.Summary)
	require.NoError(t, err)
	assert.NotContains(t, string(blob), "taint_source", "trace contents live only in the raw report")
}

// Ignored (nosemgrep) findings are recorded as a waiver but mint no subjects —
// an all-ignored scan is indexable by nothing.
func TestAttest_IgnoredFindingMintsNoSubject(t *testing.T) {
	doc := semgrepDoc(t, []map[string]any{
		result("r.ign", "a.py", 5, 1, "HIGH", "m", map[string]any{"is_ignored": true}),
	}, nil)
	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": doc}))
	assert.Equal(t, 1, a.Summary.IgnoredCount)
	require.Len(t, a.Summary.Findings, 1)
	assert.True(t, a.Summary.Findings[0].IsIgnored)
	assert.Empty(t, a.Subjects())
}

// Signed output must be byte-identical for the same input regardless of the
// order Semgrep listed the results in.
func TestAttest_Deterministic(t *testing.T) {
	forward := []map[string]any{
		result("r.a", "a.py", 1, 1, "HIGH", "m1", nil),
		result("r.b", "a.py", 1, 1, "HIGH", "m2", nil),
		result("r.a", "a.py", 9, 1, "HIGH", "m", nil),
		result("r.z", "b.py", 1, 1, "LOW", "m", nil),
	}
	reversed := []map[string]any{forward[3], forward[2], forward[1], forward[0]}

	a := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": semgrepDoc(t, forward, nil)}))
	b := attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": semgrepDoc(t, reversed, nil)}))

	ja, err := json.Marshal(a.Summary)
	require.NoError(t, err)
	jb, err := json.Marshal(b.Summary)
	require.NoError(t, err)
	assert.Equal(t, string(ja), string(jb), "summary must not depend on input order")

	want := []string{"a.py:1:1:r.a:m1", "a.py:1:1:r.b:m2", "a.py:9:1:r.a:m", "b.py:1:1:r.z:m"}
	got := make([]string, 0, len(a.Summary.Findings))
	for _, f := range a.Summary.Findings {
		got = append(got, strings.Join([]string{f.Path, itoa(f.StartLine), itoa(f.StartCol), f.RuleID, f.Message}, ":"))
	}
	assert.Equal(t, want, got)
}

// The finding id is stable for the same finding and changes when any component
// of its identity changes.
func TestFindingIDStableAndDistinct(t *testing.T) {
	base := cliMatch{CheckID: "r", Path: "a.py", Start: position{Line: 1, Col: 2}, End: position{Line: 1, Col: 6}, Extra: cliMatchExtra{Message: "m"}}
	same := base
	assert.Equal(t, findingID(base), findingID(same))
	assert.Len(t, findingID(base), 64)

	moved := base
	moved.Start.Line = 2
	assert.NotEqual(t, findingID(base), findingID(moved))

	reworded := base
	reworded.Extra.Message = "m2"
	assert.NotEqual(t, findingID(base), findingID(reworded))

	// NUL separation: shifting bytes across a field boundary is a different id.
	shifted := cliMatch{CheckID: "ra", Path: ".py", Start: base.Start, End: base.End, Extra: base.Extra}
	assert.NotEqual(t, findingID(base), findingID(shifted))
}

// No cap feeds a count: every result is attested and the totals agree.
func TestAttest_TotalFindingsNotCapped(t *testing.T) {
	const n = 250
	results := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		results = append(results, result("r", "a.py", i+1, 1, "HIGH", "m", nil))
	}
	a := attest(t, contextWith(t, map[string][]byte{"semgrep.json": semgrepDoc(t, results, nil)}, map[string][]byte{"a.py": []byte("x = 1\n")}))
	assert.Equal(t, n, a.Summary.TotalFindings)
	assert.Len(t, a.Summary.Findings, n)
	assert.Equal(t, n, a.Summary.BySeverity.High)
	assert.Len(t, a.Subjects(), n+2, "n finding subjects + one rule + one bound file")
}

// Two reports in one step are refused, as govulncheck refuses two streams:
// signing one would drop the other's findings, and no rule for choosing one
// is safe. A broken report beside a good one is refused too, never skipped.
func TestAttest_MultipleReportsRefused(t *testing.T) {
	first := semgrepDoc(t, []map[string]any{result("r.first", "a.py", 1, 1, "HIGH", "m", nil)}, nil)
	second := semgrepDoc(t, []map[string]any{result("r.second", "a.py", 1, 1, "HIGH", "m", nil)}, nil)

	a := New()
	err := a.Attest(contextWithFiles(t, map[string][]byte{
		"z/semgrep.json": second, "a/semgrep.json": first,
		"other.json": []byte(`{"not":"semgrep"}`), // does not count as a report
	}))
	requireRefused(t, err, "a/semgrep.json, z/semgrep.json")
	assert.Nil(t, a.Report, "a refused step signs no report")

	err = New().Attest(contextWithFiles(t, map[string][]byte{
		"a/semgrep.json": first, "b/semgrep.json": second[:len(second)/2],
	}))
	requireRefused(t, err, "b/semgrep.json")

	// One report beside foreign JSON attests normally.
	a = attest(t, contextWithFiles(t, map[string][]byte{"semgrep.json": first, "other.json": []byte(`{"not":"semgrep"}`)}))
	assert.Equal(t, "semgrep.json", a.ReportFile)
}

// Codex critical: Semgrep echoes the target as it was given — ./src/a.py, or
// /work/src/a.py for an absolute target — while materials are keyed relative
// to the working directory. Paths are normalized before lookup so a recorded
// file binds regardless of spelling; only a path OUTSIDE the working directory
// stays unbound.
func TestAttest_FindingPathNormalizedForMaterialLookup(t *testing.T) {
	src := []byte("import os\n")
	for name, spell := range map[string]func(dir string) string{
		"relative":         func(string) string { return "src/a.py" },
		"dot-relative":     func(string) string { return "./src/a.py" },
		"absolute inside":  func(dir string) string { return filepath.Join(dir, "src", "a.py") },
		"unclean absolute": func(dir string) string { return filepath.Join(dir, "src", "..", "src", "a.py") },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			doc := semgrepDoc(t, []map[string]any{result("r", spell(dir), 1, 1, "HIGH", "m", nil)}, nil)
			a := attest(t, contextWithIn(t, dir, map[string][]byte{"semgrep.json": doc}, map[string][]byte{"src/a.py": src}))
			require.Len(t, a.Summary.Findings, 1)
			f := a.Summary.Findings[0]
			assert.Equal(t, "src/a.py", f.Path, "path is stored normalized")
			assert.Equal(t, sha256Hex(t, src), f.FileDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}], "%s must bind to the material", name)
			assert.Contains(t, a.Subjects(), "semgrep:file:src/a.py")
		})
	}

	// The finding id is computed from the normalized path, so the same finding
	// has the same identity however the target was spelled.
	dir := t.TempDir()
	rel := attest(t, contextWithIn(t, dir, map[string][]byte{"semgrep.json": semgrepDoc(t, []map[string]any{result("r", "src/a.py", 1, 1, "HIGH", "m", nil)}, nil)}, map[string][]byte{"src/a.py": src}))
	abs := attest(t, contextWithIn(t, dir, map[string][]byte{"semgrep.json": semgrepDoc(t, []map[string]any{result("r", filepath.Join(dir, "src", "a.py"), 1, 1, "HIGH", "m", nil)}, nil)}, map[string][]byte{"src/a.py": src}))
	assert.Equal(t, rel.Summary.Findings[0].ID, abs.Summary.Findings[0].ID)

	t.Run("absolute outside the working dir stays unbound", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "b.py")
		doc := semgrepDoc(t, []map[string]any{result("r", outside, 1, 1, "HIGH", "m", nil)}, nil)
		a := attest(t, contextWithIn(t, dir, map[string][]byte{"semgrep.json": doc}, map[string][]byte{"src/a.py": src}))
		f := a.Summary.Findings[0]
		assert.Equal(t, outside, f.Path, "an outside path is kept as reported")
		assert.Empty(t, f.FileDigest)
		for key := range a.Subjects() {
			assert.False(t, strings.HasPrefix(key, "semgrep:file:"), "no file subject for an unobserved file, got %s", key)
		}
	})

	t.Run("parent-relative path stays unbound", func(t *testing.T) {
		doc := semgrepDoc(t, []map[string]any{result("r", "../x.py", 1, 1, "HIGH", "m", nil)}, nil)
		a := attest(t, contextWith(t, map[string][]byte{"semgrep.json": doc}, map[string][]byte{"src/a.py": src}))
		assert.Equal(t, "../x.py", a.Summary.Findings[0].Path)
		assert.Empty(t, a.Summary.Findings[0].FileDigest)
	})
}

func TestSchemaIsReflectable(t *testing.T) {
	assert.NotNil(t, New().Schema())
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// decodesAsSemgrep is the oracle for the one-view rule: the STOCK decoder's
// reading of the markers reportParser.member records. Classification must never
// read less than encoding/json does, so a document it reads as Semgrep output
// is never skipped as "not a report" (see FuzzReportAttest).
func decodesAsSemgrep(b []byte) bool {
	var o cliOutput
	if json.Unmarshal(b, &o) != nil {
		return false
	}
	if o.Paths != nil {
		return true
	}
	if o.Results != nil {
		for _, m := range *o.Results {
			if m.CheckID != "" {
				return true
			}
		}
	}
	return false
}
