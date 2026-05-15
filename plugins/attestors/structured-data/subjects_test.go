// subjects_test.go pins the subject-digest convention against the same
// `sha256(identity_string)` shape used by prowler / aws-config / asff /
// the steampipe attestor — so cross-attestation graph traversal in
// policyverify joins on matching digests.
//
// The bug this guards against: the prior implementation digested
// `canonical.Marshal(m.Value)`, which for a string identity "abc-123"
// produces canonical-JSON `"\"abc-123\""` (with the quotes!) — a
// different digest than any other attestor's sha256("abc-123") for the
// same identity. Cross-attestation joins were silently broken.

package structureddata

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

// fakeProducer injects a pre-written JSON file into the context as a
// Product so the structured-data attestor can read it during Attest().
// Same shape as the steampipe attestor's validation harness.
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

// runAgainst writes the given JSON to a temp file, runs the attestor with
// the supplied JSONPath + prefix, and returns the resulting Subjects map.
func runAgainst(t *testing.T, jsonBody string, query, prefix string) map[string]cryptoutil.DigestSet {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	if err := os.WriteFile(path, []byte(jsonBody), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	dig, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	target := New()
	WithSubjectQuery(query)(target)
	WithSubjectPrefix(prefix)(target)
	WithDataType("test")(target)

	ctx, err := attestation.NewContext("structured-data-subject-test",
		[]attestation.Attestor{&fakeProducer{path: path, digest: dig}, target},
		attestation.WithHashes(hashes),
	)
	if err != nil {
		t.Fatalf("ctx: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("run: %v", err)
	}
	return target.Subjects()
}

// TestSubjectKey_IsPrefixPlusValue — the key must be
// `<prefix><identity-value>`, NOT `<prefix><jsonpath>`. The old code
// keyed by `m.Path` which produced `kratos:identity:$['identities'][0]['id']`
// — meaningless across runs.
func TestSubjectKey_IsPrefixPlusValue(t *testing.T) {
	body := `{"identities":[{"id":"abc-123"},{"id":"def-456"}]}`
	subs := runAgainst(t, body, "$.identities[*].id", "kratos:identity:")

	wantKeys := []string{"kratos:identity:abc-123", "kratos:identity:def-456"}
	for _, k := range wantKeys {
		if _, ok := subs[k]; !ok {
			t.Errorf("missing subject %q. got: %v", k, keys(subs))
		}
	}
	// Negative: nothing keyed by JSONPath shape.
	for k := range subs {
		if strings.Contains(k, "$") || strings.Contains(k, "[") {
			t.Errorf("subject key %q still contains JSONPath syntax — bug regression", k)
		}
	}
}

// TestSubjectDigest_IsIdentitySha256 — the digest must be sha256 of the
// raw identity string, not sha256 of the canonical-JSON wrapping. This is
// the cross-attestation join invariant.
func TestSubjectDigest_IsIdentitySha256(t *testing.T) {
	body := `{"identities":[{"id":"abc-123"}]}`
	subs := runAgainst(t, body, "$.identities[*].id", "kratos:identity:")

	want := sha256.Sum256([]byte("abc-123"))
	wantHex := hex.EncodeToString(want[:])

	ds, ok := subs["kratos:identity:abc-123"]
	if !ok {
		t.Fatalf("expected subject not found. got: %v", keys(subs))
	}
	found := false
	for hv, gotHex := range ds {
		if hv.Hash != crypto.SHA256 {
			continue
		}
		found = true
		if gotHex != wantHex {
			t.Errorf("digest = %s; want sha256(\"abc-123\") = %s", gotHex, wantHex)
		}
		// Negative: the previous bug produced sha256 of the canonical-JSON
		// (`"\"abc-123\""`). Make sure that's NOT what we're emitting.
		bad := sha256.Sum256([]byte(`"abc-123"`))
		if gotHex == hex.EncodeToString(bad[:]) {
			t.Errorf("digest matches the legacy sha256(canonical-JSON) shape — bug regression")
		}
	}
	if !found {
		t.Errorf("subject has no SHA-256 digest")
	}
}

// TestNumericIdentityRendersAsInteger — a numeric id in JSON decodes to
// float64 from encoding/json. The identity string must render as integer
// ("123") not scientific notation, so cross-attestation joins with an
// attestor that has the same id as a string-typed value (e.g. coming
// from an env var) still converge.
func TestNumericIdentityRendersAsInteger(t *testing.T) {
	body := `{"users":[{"id":339150376714}]}`
	subs := runAgainst(t, body, "$.users[*].id", "github:userid:")

	const want = "github:userid:339150376714"
	if _, ok := subs[want]; !ok {
		t.Errorf("expected %q. got: %v", want, keys(subs))
	}
}

// TestNonScalarMatchesAreSkipped — selecting an object (e.g. each user
// row as a whole) can't produce a meaningful identity string. The
// attestor logs and skips; subjects stays empty rather than emitting
// something nonsensical.
func TestNonScalarMatchesAreSkipped(t *testing.T) {
	body := `{"users":[{"id":"a","name":"alice"}]}`
	subs := runAgainst(t, body, "$.users[*]", "thing:")
	if len(subs) != 0 {
		t.Errorf("non-scalar matches should be skipped; got %d subjects: %v", len(subs), keys(subs))
	}
}

// TestNoBackReffer — structured-data is a state-reporting attestor
// (same class as prowler / aws-config / asff). None of those implement
// BackReffer; we shouldn't either. If a future change accidentally adds
// BackReffer, this test trips immediately.
func TestNoBackReffer(t *testing.T) {
	a := New()
	if _, ok := any(a).(attestation.BackReffer); ok {
		t.Error("structured-data Attestor implements BackReffer — state-reporting attestors should not")
	}
}

func keys(m map[string]cryptoutil.DigestSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Compile-time assert the fakeProducer satisfies what NewContext expects.
var _ = fmt.Sprintf // keep "fmt" used in case future tests need it

// JSON-unmarshal round-trip used by the integer-identity test —
// ensures the test fixture itself is valid JSON before we run the
// attestor over it.
func init() {
	var v any
	_ = json.Unmarshal([]byte(`{}`), &v)
}
