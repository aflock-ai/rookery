// steampipe_validate_test.go runs an end-to-end exercise of the steampipe
// attestor against a real steampipe query output file. The validator is
// not a unit test — it's the proof-of-life harness called out in the Phase
// 3 plan ("Sandbox proof has already been demonstrated against
// testifysec/judge — re-run via cilock run to confirm").
//
// Usage:
//
//	# Capture a real steampipe query first
//	steampipe query --output json "select id, name_with_owner from github_my_repository limit 3" \
//	    > /tmp/steampipe-validate/repos.json
//	go test -tags validate -run TestValidateAgainstRealOutput \
//	    github.com/aflock-ai/rookery/plugins/attestors/steampipe
//
// The build tag keeps the harness out of regular CI (it's an integration
// test that depends on a pre-captured file on disk). The companion shell
// snippet in this directory's README documents the capture step.

//go:build validate

package steampipe

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

// fakeProducer is a minimal attestor whose only job is to inject the
// pre-captured steampipe JSON file into the AttestationContext as a
// Product. The steampipe attestor's Attest() then walks Products() and
// finds it. This mirrors the real-world flow where a `commandrun` step
// produces the JSON and the steampipe attestor runs in PostProductRunType
// to seal it.
type fakeProducer struct {
	path   string
	digest cryptoutil.DigestSet
}

func (f *fakeProducer) Name() string                                   { return "fake-producer" }
func (f *fakeProducer) Type() string                                   { return "https://aflock.ai/test/v0.1" }
func (f *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (f *fakeProducer) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(f) }
func (f *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fakeProducer) Products() map[string]attestation.Product {
	return map[string]attestation.Product{
		f.path: {MimeType: "application/json", Digest: f.digest},
	}
}

func TestValidateAgainstRealOutput(t *testing.T) {
	inputPath := os.Getenv("STEAMPIPE_VALIDATE_INPUT")
	if inputPath == "" {
		inputPath = "/tmp/steampipe-validate/repos.json"
	}
	if _, err := os.Stat(inputPath); err != nil {
		t.Skipf("validate input %s not present: %v\n"+
			"capture one with: steampipe query --output json \"select id, name_with_owner from github_my_repository limit 3\" > %s",
			inputPath, err, inputPath)
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	digest, err := cryptoutil.CalculateDigestSetFromFile(inputPath, hashes)
	if err != nil {
		t.Fatalf("digest input: %v", err)
	}

	producer := &fakeProducer{path: inputPath, digest: digest}
	// Simulate the recipe driver: stamp the parsed .sql frontmatter onto
	// the attestor before it runs. This is the routing key the Phase 4
	// workflow reads to match envelopes to KSIValidation rows.
	target := New()
	WithFrontmatter(QueryFrontmatter{
		ID:       "github-branch-protect",
		Task:     "Capture branch-protection settings on every non-archived repo's default branch",
		KSIs:     []string{"KSI-CMT-SCR", "KSI-CMT-CSC"},
		NIST:     []string{"cm-3", "cm-3.6", "sa-15"},
		Plugin:   "github",
		Severity: "high",
	})(target)
	WithSQL("select id, name_with_owner, visibility, is_archived from github_my_repository where is_archived = false limit 3")(target)

	ctx, err := attestation.NewContext(
		"steampipe-validate",
		[]attestation.Attestor{producer, target},
		attestation.WithHashes(hashes),
	)
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("run attestors: %v", err)
	}

	// --- Verify the predicate shape ---
	if len(target.Predicate.Results) == 0 {
		t.Fatalf("predicate.Results is empty — attestor did not consume the steampipe output")
	}
	r := target.Predicate.Results[0]
	if r.RowCount == 0 {
		t.Errorf("Results[0].RowCount = 0; want >0 (the steampipe query returned rows)")
	}
	if r.ResultHash == "" {
		t.Error("Results[0].ResultHash is empty; want a sha256 digest")
	}
	// The frontmatter injected via WithFrontmatter MUST survive onto the
	// result — without it the Phase 4 workflow can't route envelopes to
	// KSIValidation rows.
	if r.Frontmatter.ID != "github-branch-protect" {
		t.Errorf("Frontmatter.ID = %q, want %q (recipe-driver injection broken)", r.Frontmatter.ID, "github-branch-protect")
	}
	wantKSIs := map[string]bool{"KSI-CMT-SCR": true, "KSI-CMT-CSC": true}
	for _, k := range r.Frontmatter.KSIs {
		delete(wantKSIs, k)
	}
	if len(wantKSIs) > 0 {
		t.Errorf("Frontmatter.KSIs missing: %v (got %v)", wantKSIs, r.Frontmatter.KSIs)
	}
	if r.SQL == "" {
		t.Error("Results[0].SQL is empty; recipe driver injected SQL did not survive")
	}

	// --- Subjects ---
	// Convention-driven from frontmatter.Plugin + column conventions.
	// For the github plugin, every `name_with_owner` value becomes a
	// `github:repo:<value>` subject with digest = sha256(value).
	// Matches prowler / aws-config / asff digest convention so
	// cross-attestation graph traversal joins on the same digests.
	subjects := target.Subjects()
	if len(subjects) == 0 {
		t.Fatal("Subjects() returned empty — convention extractor produced no identity subjects")
	}
	const wantSubject = "github:repo:hobbyfarm/tf-module-vsphere"
	if _, ok := subjects[wantSubject]; !ok {
		t.Errorf("missing convention-keyed subject %q; got keys: %v", wantSubject, keysOf(subjects))
	}
	// Position-keyed `:row:N` and envelope-level `steampipe:query:<id>`
	// subjects MUST be gone — they didn't match any other attestor's
	// pattern and broke cross-attestor joins.
	for k := range subjects {
		if strings.Contains(k, ":row:") || strings.HasPrefix(k, "steampipe:query:") {
			t.Errorf("legacy non-conforming subject key surfaced: %q", k)
		}
	}
	// Identity-string digest invariant — sha256("hobbyfarm/tf-module-vsphere"),
	// not a row-state hash. The digest convention is what makes cross-
	// attestation joins work in policyverify's graph traversal.
	wantDigest := sha256.Sum256([]byte("hobbyfarm/tf-module-vsphere"))
	wantHex := hex.EncodeToString(wantDigest[:])
	for hv, got := range subjects[wantSubject] {
		if hv.Hash != crypto.SHA256 {
			continue
		}
		if got != wantHex {
			t.Errorf("digest for %s = %s; want sha256(identity_string) = %s", wantSubject, got, wantHex)
		}
	}

	// --- BackRefs: NONE expected ---
	// Steampipe is a state-reporting attestor (same class as prowler,
	// aws-config, asff, sarif, sbom, docker-bench, kube-bench, oscap,
	// inspec — every one of which implements Subjecter but NOT
	// BackReffer). BackReffer is exclusively for CI/build-context
	// attestors (git, github, gitlab, jenkins, githubwebhook,
	// aws-codebuild). If a future change accidentally re-introduces
	// BackReffer here, that's a precedent violation worth catching.
	if _, ok := any(target).(attestation.BackReffer); ok {
		t.Error("steampipe Attestor implements BackReffer — that's a state-reporting attestor inventing a CI-only pattern")
	}

	// --- Materials ---
	if _, ok := target.Materials()[inputPath]; !ok {
		t.Errorf("Materials() does not include the input file %s; got %v", inputPath, target.Materials())
	}

	// --- Predicate is JSON-serializable (it has to go into a DSSE statement) ---
	if _, err := json.Marshal(target.Predicate); err != nil {
		t.Errorf("predicate is not JSON-serializable: %v", err)
	}

	t.Logf("validated: query=%s rows=%d subjects=%d",
		target.Predicate.Results[0].Frontmatter.ID,
		target.Predicate.Results[0].RowCount,
		len(subjects),
	)
}

func keysOf(m map[string]cryptoutil.DigestSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRenderHTMLViewer reuses the same pipeline as
// TestValidateAgainstRealOutput but writes an HTML viewer to
// STEAMPIPE_VIEWER_OUT (default /tmp/steampipe-validate/viewer.html) so a
// human can see the predicate + subjects + materials in Chrome.
// STEAMPIPE_VALIDATE_FIXTURE selects the recipe to render: "github"
// (default) or "aws" — picks the input file + frontmatter + SQL.
func TestRenderHTMLViewer(t *testing.T) {
	fixture := os.Getenv("STEAMPIPE_VALIDATE_FIXTURE")
	if fixture == "" {
		fixture = "github"
	}
	var (
		inputPath string
		fm        QueryFrontmatter
		sql       string
	)
	switch fixture {
	case "aws":
		inputPath = envOr("STEAMPIPE_VALIDATE_INPUT", "/tmp/steampipe-validate/iam_users.json")
		fm = QueryFrontmatter{
			ID:       "aws-iam-users",
			Task:     "Enumerate IAM users (KSI-IAM-MFA precursor — full user list to derive subject coverage)",
			KSIs:     []string{"KSI-IAM-MFA"},
			NIST:     []string{"ia-2", "ia-2.1", "ia-2.2"},
			Plugin:   "aws",
			Severity: "high",
		}
		sql = "select account_id, user_id, name, arn, mfa_enabled, create_date from aws_iam_user limit 5"
	default:
		inputPath = envOr("STEAMPIPE_VALIDATE_INPUT", "/tmp/steampipe-validate/repos.json")
		fm = QueryFrontmatter{
			ID:       "github-branch-protect",
			Task:     "Capture branch-protection on every non-archived repo's default branch",
			KSIs:     []string{"KSI-CMT-SCR", "KSI-CMT-CSC"},
			NIST:     []string{"cm-3", "cm-3.6", "sa-15"},
			Plugin:   "github",
			Severity: "high",
		}
		sql = "select id, name_with_owner, visibility, is_archived from github_my_repository where is_archived = false limit 3"
	}
	if _, err := os.Stat(inputPath); err != nil {
		t.Skipf("validate input %s not present: %v", inputPath, err)
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	dig, err := cryptoutil.CalculateDigestSetFromFile(inputPath, hashes)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	target := New()
	WithFrontmatter(fm)(target)
	WithSQL(sql)(target)

	ctx, err := attestation.NewContext("render-viewer",
		[]attestation.Attestor{&fakeProducer{path: inputPath, digest: dig}, target},
		attestation.WithHashes(hashes),
	)
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("run: %v", err)
	}

	predBytes, _ := json.MarshalIndent(target.Predicate, "", "  ")
	subKeys := keysOf(target.Subjects())
	sort.Strings(subKeys)
	subjectsView := make([]map[string]any, 0, len(subKeys))
	for _, k := range subKeys {
		dsm := make(map[string]string)
		for hv, h := range target.Subjects()[k] {
			dsm[hashName(hv.Hash)] = h
		}
		subjectsView = append(subjectsView, map[string]any{"key": k, "digest": dsm})
	}
	subBytes, _ := json.MarshalIndent(subjectsView, "", "  ")

	matView := make(map[string]map[string]string, len(target.Materials()))
	for k, ds := range target.Materials() {
		dsm := make(map[string]string, len(ds))
		for hv, h := range ds {
			dsm[hashName(hv.Hash)] = h
		}
		matView[k] = dsm
	}
	matBytes, _ := json.MarshalIndent(matView, "", "  ")
	// in-toto statement = what gets base64-encoded as the DSSE payload.
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": Type,
		"subject":       subjectsView,
		"predicate":     target.Predicate,
	}
	stmtBytes, _ := json.MarshalIndent(stmt, "", "  ")

	out := os.Getenv("STEAMPIPE_VIEWER_OUT")
	if out == "" {
		out = "/tmp/steampipe-validate/viewer.html"
	}
	body := renderViewerHTML(string(predBytes), string(subBytes), string(matBytes), string(stmtBytes))
	if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
		t.Fatalf("write viewer: %v", err)
	}
	t.Logf("wrote viewer: %s (open file://%s in Chrome)", out, out)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA512:
		return "sha512"
	}
	return fmt.Sprintf("hash-%d", h)
}

// renderViewerHTML lays out predicate / subjects / materials /
// DSSE-payload statement side-by-side. Locked to a single high-contrast
// scheme so it reads well in either Chrome theme.
func renderViewerHTML(pred, subs, mats, stmt string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Steampipe attestor — captured envelope</title>
<style>
  /* Single high-contrast theme: light cards on a neutral bg with dark
     code blocks. Reads identically in light and dark Chrome — avoids the
     prefers-color-scheme half-applying that left the original viewer
     unreadable. */
  :root { color-scheme: only light; }
  html, body { background: #f3f4f6 !important; color: #111827 !important; }
  body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 1180px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 18px; margin: 0 0 6px; padding-bottom: 12px;
       border-bottom: 1px solid #e5e7eb; color: #111827 !important; }
  .sub { color: #4b5563 !important; font-size: 12px; margin-bottom: 24px; }
  section { background: #ffffff !important; border: 1px solid #e5e7eb;
            border-radius: 8px; padding: 16px 18px; margin-bottom: 18px;
            color: #111827 !important; }
  h2 { font-size: 13px; font-weight: 700; text-transform: uppercase;
       letter-spacing: .06em; color: #374151 !important; margin: 0 0 10px; }
  .lbl { font-size: 12px; color: #6b7280 !important; font-weight: 600;
         margin-bottom: 4px; }
  /* Code blocks: VS Code-style dark, always. */
  pre { background: #1f2937 !important; color: #f9fafb !important;
        border: 1px solid #111827; border-radius: 6px;
        padding: 14px 16px; overflow-x: auto;
        font: 12px/1.5 ui-monospace, "SF Mono", "Menlo", monospace;
        margin: 0; max-height: 520px; }
  code { background: #f3f4f6; color: #111827; padding: 1px 5px;
         border-radius: 3px; font: 12px ui-monospace, monospace; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .badges { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
  .badge { display: inline-flex; padding: 4px 10px; border-radius: 12px;
           font-size: 11px; font-weight: 700; background: #dbeafe;
           color: #1e3a8a !important; }
  .badge.ksi { background: #fef3c7; color: #78350f !important; }
  .badge.nist { background: #d1fae5; color: #064e3b !important;
                font-family: ui-monospace, monospace; }
</style></head><body>
<h1>Steampipe attestor — captured envelope</h1>
<div class="sub">
  Real Steampipe → GitHub query → rookery attestor → DSSE-ready statement.
  Captured against the live <code>github_my_repository</code> table, 3 rows.
</div>

<section>
  <h2>Routing labels (recipe frontmatter)</h2>
  <div class="badges">
    <span class="badge">github-branch-protect</span>
    <span class="badge">plugin: github</span>
    <span class="badge">severity: high</span>
    <span class="badge ksi">KSI-CMT-SCR</span>
    <span class="badge ksi">KSI-CMT-CSC</span>
    <span class="badge nist">cm-3</span>
    <span class="badge nist">cm-3.6</span>
    <span class="badge nist">sa-15</span>
  </div>
  <div class="lbl">How Phase 4 routes this envelope</div>
  <div style="font-size:13px;color:inherit">
    The <code>scanKSIProjection</code> workflow reads <code>Frontmatter.KSIs</code>
    and updates the matching <code>KSIValidation</code> rows for the SSP.
    Per-row subjects (<code>steampipe:query:&lt;id&gt;:row:N</code>) let
    policyverify VSAs pin verdicts to specific rows.
  </div>
</section>

<section>
  <h2>In-toto statement (DSSE payload)</h2>
  <div class="lbl">What gets base64-encoded into the DSSE envelope <code>payload</code> field. The Sigstore Fulcio signer wraps this and uploads to Archivista.</div>
  <pre>` + html.EscapeString(stmt) + `</pre>
</section>

<section>
  <h2>Subjects — discovery surface</h2>
  <div class="lbl">Convention-driven from <code>Frontmatter.plugin</code> + Steampipe column names. Digest = sha256(identity string), matching prowler / aws-config / asff so cross-attestation graph traversal joins on the same digest values. The framework prefixes these with <code>steampipe/</code> at the collection level — no within-graph collisions with other attestors. No BackRefs: steampipe is a state-reporting attestor like prowler / aws-config / asff, none of which implement BackReffer — that interface is reserved for CI/build-context attestors (git, github, gitlab, jenkins) that have a workflow-run identity to anchor.</div>
  <pre>` + html.EscapeString(subs) + `</pre>
</section>

<section>
  <h2>Materials</h2>
  <div class="lbl">The source file the attestor sealed, with its SHA-256 digest. Verifiers re-digest to confirm bytes haven't drifted.</div>
  <pre>` + html.EscapeString(mats) + `</pre>
</section>

<section>
  <h2>Predicate (full)</h2>
  <div class="lbl">The signed payload — includes the canonical SQL, run timestamp, every row, and the result hash. The auditor's primary artifact.</div>
  <pre>` + html.EscapeString(pred) + `</pre>
</section>

</body></html>`
}
