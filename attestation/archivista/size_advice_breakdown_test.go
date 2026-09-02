package archivista

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fixtures: real envelope shape, so the decoder is exercised end to end rather
// than through a stub that agrees with it by construction.
// ---------------------------------------------------------------------------

type fixtureLeaf struct {
	Path       string `json:"path"`
	FileDigest string `json:"fileDigest"`
	LeafHash   string `json:"leafHash"`
}

type fixtureAttestation struct {
	Type       string
	MerkleRoot string
	Leaves     []fixtureLeaf
}

// buildEnvelope renders the DSSE envelope exactly as Client.Store marshals it:
// a JSON object with a base64 payload holding an in-toto statement whose
// predicate is the attestation collection.
func buildEnvelope(t *testing.T, atts []fixtureAttestation) []byte {
	t.Helper()
	type collAtt struct {
		Type        string `json:"type"`
		Attestation any    `json:"attestation"`
	}
	entries := make([]collAtt, 0, len(atts))
	for _, a := range atts {
		pred := map[string]any{
			"merkleRoot":    a.MerkleRoot,
			"treeSize":      len(a.Leaves),
			"hashAlgorithm": "sha256",
			"construction":  "rfc6962",
		}
		if a.Leaves != nil {
			pred["leaves"] = a.Leaves
		}
		entries = append(entries, collAtt{Type: a.Type, Attestation: pred})
	}
	stmt := map[string]any{
		"_type":     "https://in-toto.io/Statement/v0.1",
		"predicate": map[string]any{"name": "push-tests", "attestations": entries},
	}
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	env, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(raw),
		"signatures":  []map[string]string{{"keyid": "fulcio", "sig": fixtureSignature}},
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return env
}

// fixtureSignature stands in for a keyless DSSE signature: the base64 of a
// signature plus its certificate chain and timestamp, a few KiB that never
// shrink whatever happens to the payload.
var fixtureSignature = base64.StdEncoding.EncodeToString(make([]byte, 3<<10))

// fixesIfUntracked is the conditional promise the remedy makes when the
// arithmetic says deletion would clear the cap. It is never unconditional,
// because the envelope cannot say whether a tree is tracked.
const fixesIfUntracked = "fixes it if they are untracked"

// decodedPayloadLen is the byte length of the envelope's decoded payload, the
// denominator the OLD proportional saving used; tests that show why that was
// wrong need it, the advice no longer does.
func decodedPayloadLen(t *testing.T, body []byte) int {
	t.Helper()
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("fixture envelope: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("fixture payload: %v", err)
	}
	return len(raw)
}

func leavesUnder(prefix string, n int) []fixtureLeaf {
	out := make([]fixtureLeaf, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fixtureLeaf{
			Path:       prefix + "f" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + ".js",
			FileDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			LeafHash:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		})
	}
	return out
}

const (
	materialType = "https://witness.dev/attestations/material/v0.3"
	productType  = "https://witness.dev/attestations/product/v0.3"
	gitType      = "https://witness.dev/attestations/git/v0.1"
)

// dependencyShape is the measured 34.5 MiB case: untracked dependency trees in
// the working directory. The operator can delete these.
func dependencyShape(t *testing.T) []byte {
	t.Helper()
	leaves := leavesUnder("site/website/node_modules/pkg-a/lib/", 400)
	leaves = append(leaves, leavesUnder("salespot/deploy/node_modules/pkg-b/lib/", 190)...)
	leaves = append(leaves, leavesUnder("subtrees/rookery/attestation/", 20)...)
	return buildEnvelope(t, []fixtureAttestation{
		{Type: materialType, MerkleRoot: "aaa", Leaves: leaves},
		{Type: gitType, MerkleRoot: "bbb"},
		{Type: productType, MerkleRoot: "ccc", Leaves: leavesUnder("bin/", 1)},
	})
}

// trackedSourceShape is the measured 4.95 MiB case: the leaves are genuinely
// the repository's own tracked files. There is nothing to delete.
func trackedSourceShape(t *testing.T) []byte {
	t.Helper()
	leaves := leavesUnder("subtrees/rookery/attestation/", 300)
	leaves = append(leaves, leavesUnder("judge-api/pkg/policy/", 250)...)
	leaves = append(leaves, leavesUnder("web/src/components/", 100)...)
	return buildEnvelope(t, []fixtureAttestation{
		{Type: materialType, MerkleRoot: "aaa", Leaves: leaves},
		{Type: gitType, MerkleRoot: "bbb"},
	})
}

// ---------------------------------------------------------------------------
// The core property: two material-dominant envelopes, OPPOSITE remedies.
// ---------------------------------------------------------------------------

// TestSizeAdvice_DiscriminatesTwoMaterialDominantShapes is the whole point of
// this change and is written as a CONTROL PAIR: the variable is the leaf paths
// and nothing else. Both shapes are material-dominant, so an advice keyed to
// the attestor name alone would produce identical text for both and pass any
// single-shape test. It must not.
func TestSizeAdvice_DiscriminatesTwoMaterialDominantShapes(t *testing.T) {
	depBody := dependencyShape(t)

	// Size the envelope so that removing the dependency trees genuinely clears
	// the cap. An arbitrary constant here would be testing nothing: the remedy
	// now depends on whether removal actually helps, so the fixture has to state
	// which side of that crossing it is on.
	depContribs := envelopeBreakdown(depBody)
	depDeletable := deletableGroups(depContribs[0].Groups).NamedBytes
	size := largeEnvelopeBytes + depDeletable - 1

	dep := sizeAdviceMeasured(size, depBody)
	src := sizeAdviceMeasured(size, trackedSourceShape(t))

	if dep == src {
		t.Fatal("two material-dominant envelopes with different contents produced identical advice; " +
			"the message is still keyed to the attestor, not to the measurement")
	}

	// The dependency shape must name the exact directories to delete.
	for _, want := range []string{"site/website/node_modules/", "salespot/deploy/node_modules/"} {
		if !strings.Contains(dep, want) {
			t.Errorf("dependency shape must name %q as a contributor; got:\n%s", want, dep)
		}
	}
	if !strings.Contains(dep, fixesIfUntracked) {
		t.Errorf("dependency shape whose removal clears the cap must say removing the trees would "+
			"fix it; got:\n%s", dep)
	}

	// The tracked-source shape must NOT tell the operator to delete anything,
	// and must admit the gap instead.
	if strings.Contains(src, "node_modules") {
		t.Errorf("tracked-source shape must not mention node_modules; got:\n%s", src)
	}
	if !strings.Contains(src, "nothing worth deleting") {
		t.Errorf("tracked-source shape must say there is nothing worth deleting; got:\n%s", src)
	}
	if !strings.Contains(src, "#8410") {
		t.Errorf("tracked-source shape must name the detached-manifest issue; got:\n%s", src)
	}
	for _, want := range []string{"subtrees/rookery/", "judge-api/pkg/"} {
		if !strings.Contains(src, want) {
			t.Errorf("tracked-source shape must name %q as a contributor; got:\n%s", want, src)
		}
	}
}

// TestSizeAdvice_TinyDependencyTreesDoNotBecomeTheRemedy is a regression test
// for a bug that only the REAL binary exposed: running cilock against this
// repository produced a table whose top contributors were subtrees/kratos/,
// subtrees/rookery/ and judge-api/pkg/ — tracked source — while the remedy
// underneath told the operator to delete
// bootstrap/act/pkg/runner/testdata/actions/node12/node_modules/ and five
// siblings. Those are committed test fixtures worth a fraction of a percent.
//
// The remedy scanned EVERY group for a dependency segment, so any repository
// containing a single vendored fixture got "removing them is the fix" — the
// exact failure this whole change exists to stop, reintroduced one layer down.
// Deletion may only be prescribed when it would actually move the number.
func TestSizeAdvice_TinyDependencyTreesDoNotBecomeTheRemedy(t *testing.T) {
	leaves := leavesUnder("subtrees/kratos/", 900)
	leaves = append(leaves, leavesUnder("subtrees/rookery/", 800)...)
	leaves = append(leaves, leavesUnder("judge-api/pkg/", 700)...)
	// A committed fixture tree: real, matches a dependency segment, negligible.
	leaves = append(leaves, leavesUnder("bootstrap/act/pkg/runner/testdata/actions/node12/node_modules/", 6)...)
	leaves = append(leaves, leavesUnder("deploy/dist/", 4)...)

	got := sizeAdviceMeasured(34<<20, buildEnvelope(t, []fixtureAttestation{
		{Type: materialType, MerkleRoot: "aaa", Leaves: leaves},
	}))

	if strings.Contains(got, "fixes it") {
		t.Errorf("a handful of committed fixture directories must not be prescribed as the fix "+
			"for a tracked-source-dominated envelope; got:\n%s", got)
	}
	if !strings.Contains(got, "#8410") {
		t.Errorf("a tracked-source-dominated envelope must still name the structural fix; got:\n%s", got)
	}
}

// TestSizeAdvice_PreUploadWarningCarriesNoEnvelopeDetail pins the disclosure
// boundary. The up-front warning fires before the FIRST attempt, so it also
// fires on uploads that go on to succeed. Rendering the contents breakdown
// there would log repository structure on the happy path — which the success
// path never promised, and which the retrier's own docblock claims it does not
// do. Only the failure form may carry detail.
func TestSizeAdvice_PreUploadWarningCarriesNoEnvelopeDetail(t *testing.T) {
	pre := sizeAdvice(34 << 20)
	if pre == "" {
		t.Fatal("an oversized envelope must still warn up front")
	}
	if !strings.Contains(pre, "34.0 MiB") {
		t.Errorf("the up-front warning must name the size; got:\n%s", pre)
	}
	for _, forbidden := range []string{"measured contents", "node_modules", "material/v0.3", "leaves"} {
		if strings.Contains(pre, forbidden) {
			t.Errorf("the up-front warning must carry no envelope-derived detail, found %q; got:\n%s",
				forbidden, pre)
		}
	}
	// The failure form is where detail is allowed.
	post := sizeAdviceMeasured(34<<20, dependencyShape(t))
	if !strings.Contains(post, "measured contents") {
		t.Errorf("the failure form must carry the breakdown; got:\n%s", post)
	}
}

// TestSizeAdvice_PathsCannotForgeLogRecords is the log-injection guard. Leaf
// paths come from a walk of the working directory — in a supply-chain tool that
// is data an attacker may influence — and the prefixes derived from them are
// interpolated into a log line. A directory named with an embedded newline
// could otherwise forge an entire log record inside our own output.
func TestSizeAdvice_PathsCannotForgeLogRecords(t *testing.T) {
	evil := "eviltree\nlevel=info msg=\"archivista upload succeeded\"\rmore/"
	leaves := leavesUnder(evil, 400)
	leaves = append(leaves, leavesUnder("subtrees/rookery/", 5)...)
	got := sizeAdviceMeasured(34<<20, buildEnvelope(t, []fixtureAttestation{
		{Type: materialType, MerkleRoot: "aaa", Leaves: leaves},
	}))

	if strings.Contains(got, "eviltree\nlevel=info") {
		t.Errorf("a raw newline from a path reached the output — a path can forge a log record:\n%s", got)
	}
	if strings.ContainsRune(got, '\r') {
		t.Errorf("a raw carriage return from a path reached the output:\n%s", got)
	}
	// The prefix must still be REPORTED, just quoted — it is the diagnostic.
	if !strings.Contains(got, "eviltree") {
		t.Errorf("the offending prefix must still be shown (quoted), not dropped; got:\n%s", got)
	}
}

func TestSafeText(t *testing.T) {
	for _, in := range []string{"subtrees/rookery/", "material/v0.3", "(unnamed)"} {
		if got := safeText(in); got != in {
			t.Errorf("an ordinary value must pass through unquoted, got %q", got)
		}
	}
	for _, in := range []string{"a\nb/", "a\rb/", "a\x1b[31mb/", "a\tb/", `a"b/`} {
		got := safeText(in)
		if strings.ContainsAny(got, "\n\r\t\x1b") {
			t.Errorf("safeText(%q) = %q still carries a control character", in, got)
		}
	}
}

// TestSizeAdvice_DeletableListIsBounded pins the cap the reviewer asked for:
// however many dependency groups a tree contains, the remedy names a bounded
// few rather than emitting an unbounded inventory into a log line.
func TestSizeAdvice_DeletableListIsBounded(t *testing.T) {
	var leaves []fixtureLeaf
	for i := 0; i < 25; i++ {
		leaves = append(leaves, leavesUnder("pkg"+strconv.Itoa(i)+"/node_modules/", 40)...)
	}
	got := sizeAdviceMeasured(34<<20, buildEnvelope(t, []fixtureAttestation{
		{Type: materialType, MerkleRoot: "aaa", Leaves: leaves},
	}))
	// Count only within the remedy sentence: the table above it legitimately
	// lists its own, separately capped, contributors.
	at := strings.Index(got, "remedy:")
	if at < 0 {
		t.Fatalf("no remedy in advice:\n%s", got)
	}
	if n := strings.Count(got[at:], "/node_modules/"); n > maxNamedDeletable {
		t.Errorf("the remedy named %d dependency directories, want at most %d; got:\n%s",
			n, maxNamedDeletable, got[at:])
	}
}

// mixedShape returns an envelope whose dominant attestor holds both dependency
// trees and tracked source, plus the deletable byte count, so a test can place
// the envelope size exactly either side of the crossing.
func mixedShape(t *testing.T, depLeaves, srcLeaves int) ([]byte, int) {
	t.Helper()
	leaves := leavesUnder("web/node_modules/", depLeaves)
	leaves = append(leaves, leavesUnder("judge-api/pkg/", srcLeaves)...)
	body := buildEnvelope(t, []fixtureAttestation{
		{Type: materialType, MerkleRoot: "aaa", Leaves: leaves},
	})
	contribs := envelopeBreakdown(body)
	if len(contribs) == 0 {
		t.Fatal("fixture did not decode")
	}
	del := deletableGroups(contribs[0].Groups)
	if del.NamedBytes <= 0 || del.NamedBytes != del.TotalBytes {
		t.Fatalf("fixture must hold exactly one deletable tree, got %+v", del)
	}
	return body, del.NamedBytes
}

// sizeLeaving returns an envelope size for which removing delBytes of
// attestation payload leaves exactly `remaining` envelope bytes under the
// remedy's own arithmetic, so a test can sit one byte either side of the cap
// without re-deriving the base64 growth by hand.
func sizeLeaving(delBytes, remaining int) int {
	return remaining + envelopeSaving(delBytes)
}

// TestSizeAdvice_DeletionIsTheFixOnlyWhenItClearsTheCap tests the BOUNDARY,
// which is exactly what the previous flat-share rule could not express.
//
// The old rule asked "are dependency trees >= 50% of the attestor?" — a proxy.
// The question that decides whether the advice is TRUE is "does removing them
// get the envelope under the cap?", which is arithmetic on numbers already in
// hand. The two real measured cases sat at 4% and ~90%, so neither exercised
// any boundary and nothing could have caught a wrong one.
//
// Two sizes, one byte either side of the crossing, everything else identical.
func TestSizeAdvice_DeletionIsTheFixOnlyWhenItClearsTheCap(t *testing.T) {
	body, delBytes := mixedShape(t, 300, 300)

	// removal leaves largeEnvelopeBytes-1 of envelope -> it clears the cap.
	clears := sizeAdviceMeasured(sizeLeaving(delBytes, largeEnvelopeBytes-1), body)
	// removal leaves largeEnvelopeBytes+1 -> it does NOT clear it.
	misses := sizeAdviceMeasured(sizeLeaving(delBytes, largeEnvelopeBytes+1), body)

	if clears == misses {
		t.Fatal("advice is identical either side of the cap crossing; the remedy is still keyed " +
			"to a share rather than to whether removal actually helps")
	}
	if !strings.Contains(clears, fixesIfUntracked) {
		t.Errorf("removal that clears the cap must be called the fix (conditionally); got:\n%s", clears)
	}
	if strings.Contains(misses, "fixes it") {
		t.Errorf("removal that does NOT clear the cap must not be called the fix; got:\n%s", misses)
	}
	if !strings.Contains(misses, "#8410") {
		t.Errorf("when removal cannot clear the cap the structural remedy must be named; got:\n%s", misses)
	}
	// Both arms keep the share as context; it just no longer decides.
	for name, got := range map[string]string{"clears": clears, "misses": misses} {
		if !strings.Contains(got, "% of it") {
			t.Errorf("%s arm must still report the dependency share as context; got:\n%s", name, got)
		}
	}
}

// TestSizeAdvice_LargeShareThatStillMissesTheCapIsNotAFix is the case the flat
// 50% rule got WRONG: dependency trees are the overwhelming majority of the
// attestor, so the old rule promised "removing them is the fix", but the
// envelope is so far over the cap that removing every one of them still leaves
// it oversized. Promising a fix there sends the operator to do real work for
// nothing.
func TestSizeAdvice_LargeShareThatStillMissesTheCapIsNotAFix(t *testing.T) {
	// Well above the old 50% threshold, but not so much of the payload that
	// removing it could not help: the envelope size below is derived from the
	// body so the arithmetic is the real one, and a 99%-deletable payload would
	// genuinely clear any cap once base64 is accounted for.
	body, delBytes := mixedShape(t, 600, 400) // ~60% dependency by share

	contribs := envelopeBreakdown(body)
	share := deletableShare(t, contribs[0])
	if share < 0.5 {
		t.Fatalf("fixture must have a dependency share above the old threshold, got %.2f", share)
	}

	// Sized so that removing every deletable byte still leaves twice the cap.
	got := sizeAdviceMeasured(sizeLeaving(delBytes, largeEnvelopeBytes*2), body)
	if strings.Contains(got, "fixes it") {
		t.Errorf("a large dependency share that still leaves the envelope over the cap must not be "+
			"promised as the fix; got:\n%s", got)
	}
	if !strings.Contains(got, "still") {
		t.Errorf("the advice must say removal still leaves it over the cap; got:\n%s", got)
	}
	if !strings.Contains(got, "#8410") {
		t.Errorf("it must point at the structural remedy instead; got:\n%s", got)
	}
}

// TestSizeAdvice_SmallShareThatClearsTheCapIsAFix is the mirror image, and the
// case named in my own report as most likely wrong: a minority share whose
// removal nonetheless drops the envelope under the cap. The old rule called
// this "would save little" and sent the operator to #8410 for a problem they
// could have fixed by deleting a directory.
func TestSizeAdvice_SmallShareThatClearsTheCapIsAFix(t *testing.T) {
	body, delBytes := mixedShape(t, 60, 940) // small dependency share

	contribs := envelopeBreakdown(body)
	share := deletableShare(t, contribs[0])
	if share >= 0.5 {
		t.Fatalf("fixture must have a dependency share below the old threshold, got %.2f", share)
	}

	got := sizeAdviceMeasured(largeEnvelopeBytes+delBytes-1, body)
	if !strings.Contains(got, fixesIfUntracked) {
		t.Errorf("a minority share whose removal clears the cap IS the fix and must be reported as "+
			"one (share=%.3f); got:\n%s", share, got)
	}
}

// TestSizeAdvice_ReportsPerAttestorBreakdown pins the table itself: the
// attestor names, a byte count, and a share.
func TestSizeAdvice_ReportsPerAttestorBreakdown(t *testing.T) {
	got := sizeAdviceMeasured(34<<20, dependencyShape(t))
	for _, want := range []string{"measured contents", "material/v0.3", "product/v0.3", "git/v0.1", "leaves"} {
		if !strings.Contains(got, want) {
			t.Errorf("breakdown missing %q; got:\n%s", want, got)
		}
	}
	// Largest first: material must be reported above product.
	if strings.Index(got, "material/v0.3") > strings.Index(got, "product/v0.3") {
		t.Errorf("attestors must be ordered largest-first; got:\n%s", got)
	}
	// The size line is preserved.
	if !strings.Contains(got, "34.0 MiB") {
		t.Errorf("advice must still name the envelope size; got:\n%s", got)
	}
	// The 4 MiB edge-fallback cap and the platform-verdict separation survive.
	if !strings.Contains(got, "4.0 MiB") || !strings.Contains(got, "platform verdict path is unaffected") {
		t.Errorf("the three-way consequence separation must be preserved; got:\n%s", got)
	}
}

// TestSizeAdvice_ProductDominantGetsTheGlobRemedy covers the rare arm where
// the product attestor really is the bulk — the only case where the exclude
// glob is the right lever.
func TestSizeAdvice_ProductDominantGetsTheGlobRemedy(t *testing.T) {
	env := buildEnvelope(t, []fixtureAttestation{
		{Type: productType, MerkleRoot: "ccc", Leaves: leavesUnder("out/bundle/", 500)},
		{Type: materialType, MerkleRoot: "aaa", Leaves: leavesUnder("cmd/", 3)},
	})
	got := sizeAdviceMeasured(34<<20, env)
	if !strings.Contains(got, "--attestor-product-exclude-glob") {
		t.Errorf("product-dominant advice must name the exclude glob; got:\n%s", got)
	}
	if !strings.Contains(got, "last-one-wins") {
		t.Errorf("product-dominant advice must warn the flag is not repeatable; got:\n%s", got)
	}
	if !strings.Contains(got, "{**/,}") {
		t.Errorf("the example glob must carry the {**/,} prefix that makes it match at the root; got:\n%s", got)
	}
	// It must not tell a product-dominant operator to delete their build output.
	if strings.Contains(got, "removing them before attesting") {
		t.Errorf("product-dominant advice must not prescribe deleting build output; got:\n%s", got)
	}
}

// ---------------------------------------------------------------------------
// The error path must never fail.
// ---------------------------------------------------------------------------

// TestSizeAdvice_DegradesWhenPayloadUndecodable covers every way the decode can
// fail. Each must fall back to the size-only message, and none may panic — this
// runs while an error is already being rendered.
func TestSizeAdvice_DegradesWhenPayloadUndecodable(t *testing.T) {
	cases := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"not json":         []byte("this is not json at all"),
		"no payload field": []byte(`{"payloadType":"x","signatures":[]}`),
		"payload not b64":  []byte(`{"payload":"!!!! not base64 !!!!"}`),
		"payload not json": []byte(`{"payload":"` + base64.StdEncoding.EncodeToString([]byte("nope")) + `"}`),
		"no attestations":  []byte(`{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"predicate":{}}`)) + `"}`),
		"truncated":        []byte(`{"payload":"eyJwcmVkaWNhdGUi`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got := sizeAdviceMeasured(34<<20, body)
			if got == "" {
				t.Fatal("advice must still be produced when the payload cannot be decoded")
			}
			if !strings.Contains(got, "34.0 MiB") {
				t.Errorf("fallback must still name the size; got:\n%s", got)
			}
			if !strings.Contains(got, "guess") {
				t.Errorf("fallback must mark its suspects as a guess, not a measurement; got:\n%s", got)
			}
			if strings.Contains(got, "measured contents") {
				t.Errorf("fallback must not claim to have measured anything; got:\n%s", got)
			}
		})
	}
}

// TestSizeAdvice_LeavesAbsentDegradesToBytes is the forward-compatibility case:
// once the detached material manifest (#8410) lands, the predicate carries no
// inline leaves. The per-attestor table must still render; only the path block
// disappears.
func TestSizeAdvice_LeavesAbsentDegradesToBytes(t *testing.T) {
	env := buildEnvelope(t, []fixtureAttestation{
		{Type: materialType, MerkleRoot: "aaa"},
		{Type: gitType, MerkleRoot: "bbb"},
	})
	got := sizeAdviceMeasured(34<<20, env)
	if !strings.Contains(got, "material/v0.3") {
		t.Errorf("a leafless predicate must still be reported by bytes; got:\n%s", got)
	}
	if strings.Contains(got, "leaves)") {
		t.Errorf("a leafless predicate must not report a leaf count; got:\n%s", got)
	}
}

// ---------------------------------------------------------------------------
// Remedy ordering: re-mint leads, and the superstitions are not prescribed.
// ---------------------------------------------------------------------------

// TestSizeAdvice_RemedyLeadsWithReMint pins the ordering that the measurement
// earned: the budget_exhausted failures were TRANSIENT — the same 34.5 MB
// payload that failed twice re-uploaded clean with no flags. Anything that
// presents a flag as "the fix" is teaching a superstition.
func TestSizeAdvice_RemedyLeadsWithReMint(t *testing.T) {
	for name, body := range map[string][]byte{
		"dependency":    dependencyShape(t),
		"trackedSource": trackedSourceShape(t),
	} {
		t.Run(name, func(t *testing.T) {
			got := sizeAdviceMeasured(34<<20, body)
			if !strings.Contains(got, "re-mint once") {
				t.Errorf("remedy must lead with re-minting; got:\n%s", got)
			}
			// The retry budget must not be sold as the fix for size.
			if strings.Contains(got, "--archivista-upload-retry-budget") {
				t.Errorf("the retry budget is not evidence-backed as a size remedy and must not be "+
					"prescribed; got:\n%s", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// leafGroup: the prefix depth is a measured choice, not a preference.
// ---------------------------------------------------------------------------

// TestLeafGroup_DepthDiscriminatesBothShapes checks the grouping rule against
// BOTH measured shapes. A fixed depth of 1 would collapse the dependency shape
// into "site/" and hide the actionable directory; a fixed depth of 2 would
// report "site/website/" and still not name node_modules.
func TestLeafGroup_DepthDiscriminatesBothShapes(t *testing.T) {
	cases := []struct{ path, want string }{
		// Dependency shape: truncate AT the dependency segment, however deep.
		{"site/website/node_modules/react/index.js", "site/website/node_modules/"},
		{"salespot/deploy/node_modules/a/b/c.js", "salespot/deploy/node_modules/"},
		{"node_modules/left-pad/index.js", "node_modules/"},
		{"api/.venv/lib/python3.11/x.py", "api/.venv/"},
		{"svc/vendor/github.com/pkg/errors/e.go", "svc/vendor/"},
		// Tracked-source shape: two segments, which keeps these apart.
		{"subtrees/rookery/attestation/x.go", "subtrees/rookery/"},
		{"judge-api/pkg/policy/y.go", "judge-api/pkg/"},
		{"web/src/components/z.tsx", "web/src/"},
		// Degenerate paths.
		{"CLAUDE.md", "(repository root)"},
		{"jade/main.go", "jade/"},
		{"", "(unknown)"},
		{"./web/src/a.ts", "web/src/"},
	}
	for _, c := range cases {
		if got := leafGroup(c.path); got != c.want {
			t.Errorf("leafGroup(%q) = %q, want %q", c.path, got, c.want)
		}
	}

	// The discrimination claim, stated directly: the two shapes must not
	// collapse to the same group.
	if leafGroup("site/website/node_modules/react/index.js") == leafGroup("subtrees/rookery/attestation/x.go") {
		t.Fatal("the two measured shapes must not share a group")
	}
}

func TestShortAttestorName(t *testing.T) {
	cases := map[string]string{
		"https://witness.dev/attestations/material/v0.3": "material/v0.3",
		"https://witness.dev/attestations/product/v0.3":  "product/v0.3",
		"https://witness.dev/attestations/git/v0.1":      "git/v0.1",
		"material/v0.3": "material/v0.3",
		"single":        "single",
		"":              "(unnamed)",
	}
	for in, want := range cases {
		if got := shortAttestorName(in); got != want {
			t.Errorf("shortAttestorName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCommas(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 999: "999", 1000: "1,000",
		17152: "17,152", 3976288: "3,976,288", 612443: "612,443", -1234: "-1,234"}
	for in, want := range cases {
		if got := commas(in); got != want {
			t.Errorf("commas(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestSizeAdvice_SavingMatchesARealEnvelopeShrinking pins the unit conversion
// against a MEASUREMENT rather than a ratio: the same envelope built twice,
// with and without one dependency tree, and the predicted saving held to the
// byte difference between the two.
//
// The envelope is a wrapper, the base64 payload, and the signatures. Only the
// base64 shrinks when payload is removed; the signatures — a keyless one is
// several KiB of certificate chain and timestamp — do not move by a byte. The
// first version scaled the removed bytes by size/payload, which spreads that
// fixed overhead across the payload and over-promises by its share. The
// fixture carries a realistic signature so the proportional estimate is
// visibly above what deletion actually saves.
func TestSizeAdvice_SavingMatchesARealEnvelopeShrinking(t *testing.T) {
	const depLeaves, srcLeaves = 300, 300
	dep := leavesUnder("web/node_modules/", depLeaves)
	src := leavesUnder("judge-api/pkg/", srcLeaves)
	before := buildEnvelope(t, []fixtureAttestation{{Type: materialType, MerkleRoot: "aaa", Leaves: append(dep, src...)}})
	after := buildEnvelope(t, []fixtureAttestation{{Type: materialType, MerkleRoot: "aaa", Leaves: src}})

	contribs := envelopeBreakdown(before)
	del := deletableGroups(contribs[0].Groups)
	if del.TotalBytes <= 0 || del.More != 0 {
		t.Fatalf("fixture must hold exactly one deletable tree, got %+v", del)
	}
	measured := len(before) - len(after)
	predicted := envelopeSaving(del.TotalBytes)

	// Never over-promise: the prediction may fall short of the measurement,
	// never exceed it.
	if predicted > measured {
		t.Fatalf("predicted saving %d exceeds the measured %d: the remedy would promise more than deletion delivers", predicted, measured)
	}
	// And not by much: what the prediction leaves out is the JSON separator
	// that goes with each leaf (base64-grown), the treeSize digits, and the
	// base64 quantum at either end.
	if slack := measured - predicted; slack > 4*depLeaves/3+16 {
		t.Errorf("predicted %d is %d bytes short of the measured %d; more than the separators and the base64 quantum account for", predicted, slack, measured)
	}

	// The proportional estimate is the bug: on this envelope it claims more
	// than the measurement. A fixture where it did not would not be testing
	// the finding.
	naive := del.TotalBytes * len(before) / decodedPayloadLen(t, before)
	if naive <= measured {
		t.Fatalf("fixture: the proportional estimate %d does not exceed the measured %d, so the signature overhead is too small to expose the over-promise", naive, measured)
	}

	// The rendered advice uses the honest number: one byte under the cap after
	// the measured saving is "clears", one byte over the naive saving is not.
	if got := sizeAdviceMeasured(largeEnvelopeBytes+predicted-1, before); !strings.Contains(got, fixesIfUntracked) {
		t.Errorf("removal that clears the cap by the measured saving must be the fix; got:\n%s", got)
	}
	if got := sizeAdviceMeasured(largeEnvelopeBytes+naive-1, before); strings.Contains(got, "fixes it") {
		t.Errorf("an envelope that only the over-estimate says deletion would clear must not be promised a fix; got:\n%s", got)
	}
}

// deletableShare is the share of an attestor's bytes held by every
// dependency-shaped tree it contains, computed the way the remedy computes it.
func deletableShare(t *testing.T, c attestorContribution) float64 {
	t.Helper()
	if c.Bytes <= 0 {
		t.Fatal("fixture attestor has no bytes")
	}
	return float64(deletableGroups(c.Groups).TotalBytes) / float64(c.Bytes)
}

// manyTreesShape is an envelope whose dominant attestor holds more
// dependency-shaped trees than the remedy will name, with the unnamed ones
// large enough that the two predictions — remove the named, remove all —
// render as visibly different sizes. Returns the body and what
// deletableGroups found, checked against the fixture's own expectations so a
// test that reads the result is not agreeing with itself by construction.
func manyTreesShape(t *testing.T) ([]byte, deletableTrees) {
	t.Helper()
	var leaves []fixtureLeaf
	for i := 0; i < 5; i++ {
		leaves = append(leaves, leavesUnder("pkg"+strconv.Itoa(i)+"/node_modules/", 400*(i+1))...)
	}
	body := buildEnvelope(t, []fixtureAttestation{{Type: materialType, MerkleRoot: "aaa", Leaves: leaves}})
	contribs := envelopeBreakdown(body)
	del := deletableGroups(contribs[0].Groups)
	if len(del.Names) != maxNamedDeletable || del.More != 2 {
		t.Fatalf("names=%v more=%d, want %d names and 2 unnamed", del.Names, del.More, maxNamedDeletable)
	}
	named, total := 0, 0
	for _, g := range contribs[0].Groups {
		total += g.Bytes
		for _, n := range del.Names {
			if safeText(g.Prefix) == n {
				named += g.Bytes
			}
		}
	}
	if del.NamedBytes != named {
		t.Fatalf("NamedBytes=%d, want the %d bytes of the three named trees only", del.NamedBytes, named)
	}
	if del.TotalBytes != total {
		t.Fatalf("TotalBytes=%d, want the %d bytes of all five trees", del.TotalBytes, total)
	}
	return body, del
}

// TestDeletableGroups_KeepsNamedAndTotalBytesApart pins the two counts to the
// two questions they answer. Five dependency trees, three named: NamedBytes
// is the three named trees' bytes (the prediction an operator who removes
// exactly what was listed can hold us to), TotalBytes is all five, and the
// remedy says two went unnamed.
func TestDeletableGroups_KeepsNamedAndTotalBytesApart(t *testing.T) {
	body, del := manyTreesShape(t)
	if del.TotalBytes <= del.NamedBytes {
		t.Fatalf("TotalBytes %d must exceed NamedBytes %d when trees went unnamed", del.TotalBytes, del.NamedBytes)
	}
	got := sizeAdviceMeasured(largeEnvelopeBytes+envelopeSaving(del.NamedBytes)-1, body)
	if !strings.Contains(got, "2 smaller dependency trees not named") {
		t.Errorf("the remedy must say how many matching trees it did not name; got:\n%s", got)
	}
	if !strings.Contains(got, "removing the 3 named before attesting") || !strings.Contains(got, fixesIfUntracked) {
		t.Errorf("when the named trees alone clear the cap, removing exactly those is the fix; got:\n%s", got)
	}
}

// TestSizeAdvice_UnnamedTreesStillDecideTheRemedy is the boundary the display
// bound used to hide. The remedy names at most three trees, and the first
// version of it decided "can deletion clear the cap" from those three alone —
// so a tree whose fourth and fifth node_modules held the difference was told
// "removing all of them still leaves it over the cap" and sent to a structural
// issue, when deleting all of them would have worked. The list may be bounded;
// the decision may not.
//
// Sized so that removing every deletable tree leaves exactly one byte under
// the cap, while removing only the three named ones does not.
func TestSizeAdvice_UnnamedTreesStillDecideTheRemedy(t *testing.T) {
	body, del := manyTreesShape(t)
	size := sizeLeaving(del.TotalBytes, largeEnvelopeBytes-1)
	if namedLeft := size - envelopeSaving(del.NamedBytes); namedLeft < largeEnvelopeBytes {
		t.Fatalf("fixture: the named trees alone must NOT clear the cap (leave %d)", namedLeft)
	}

	got := sizeAdviceMeasured(size, body)
	if strings.Contains(got, "would still leave") {
		t.Errorf("deletion clears the cap once the unnamed trees are counted, so the remedy must "+
			"not say removal still leaves it over; got:\n%s", got)
	}
	if !strings.Contains(got, fixesIfUntracked) {
		t.Errorf("removing every dependency tree clears the cap and must be called the fix; got:\n%s", got)
	}
	// It must not overstate the bounded list either: removing only the named
	// three does not get there, and the message has to say so.
	if !strings.Contains(got, "Removing only the 3 named") || !strings.Contains(got, "still over the") {
		t.Errorf("the message must say the named trees alone fall short; got:\n%s", got)
	}
	if !strings.Contains(got, "the 2 smaller ones included") {
		t.Errorf("the message must tell the operator the unnamed trees are part of the fix; got:\n%s", got)
	}
	// The list stays bounded: counting the unnamed trees is not the same as
	// naming them.
	at := strings.Index(got, "remedy:")
	if n := strings.Count(got[at:], "/node_modules/"); n > maxNamedDeletable {
		t.Errorf("the remedy named %d directories, want at most %d; got:\n%s", n, maxNamedDeletable, got[at:])
	}
}

// TestSizeAdvice_StructuralFixWhenEveryTreeStillMissesTheCap is the mirror:
// with more trees than the remedy names, the structural advice is still
// produced when even removing all of them leaves the envelope over the cap —
// and the "still leaves about" figure is computed from ALL deletable bytes,
// not the named three, since the sentence says "every one of them".
func TestSizeAdvice_StructuralFixWhenEveryTreeStillMissesTheCap(t *testing.T) {
	body, del := manyTreesShape(t)
	size := sizeLeaving(del.TotalBytes, largeEnvelopeBytes*2)
	allLeft := humanBytes(largeEnvelopeBytes * 2)
	namedLeft := humanBytes(size - envelopeSaving(del.NamedBytes))
	if allLeft == namedLeft {
		t.Fatalf("fixture: the two predictions render identically (%s); the unnamed trees are too small to discriminate", allLeft)
	}

	got := sizeAdviceMeasured(size, body)
	if strings.Contains(got, "fixes it") {
		t.Errorf("no deletion clears the cap here, so none may be called the fix; got:\n%s", got)
	}
	if !strings.Contains(got, "#8410") {
		t.Errorf("when every tree removed still misses the cap the structural remedy must be named; got:\n%s", got)
	}
	if !strings.Contains(got, "would still leave about "+allLeft) {
		t.Errorf("the remaining size must be computed over every deletable tree (%s); got:\n%s", allLeft, got)
	}
	if strings.Contains(got, "would still leave about "+namedLeft) {
		t.Errorf("the remaining size must not be the named-trees-only figure (%s); got:\n%s", namedLeft, got)
	}
}

// TestSizeAdvice_LargeCommittedFixtureTreeIsNotPrescribedUnconditionally is
// the case the segment list cannot see. This repository commits node_modules
// fixtures under bootstrap/act/…/testdata; a material leaf carries a path, a
// digest and a leaf hash, and the git attestor's status lists only changed
// files, so from the envelope a large committed fixture tree is
// indistinguishable from an untracked dependency tree. The remedy may still
// do the arithmetic — it is right that deleting the tree WOULD clear the cap —
// but it may not tell the operator to delete attested content as "the fix".
// It states the condition, names the one-line check, and keeps the structural
// fix as the answer for a committed tree.
func TestSizeAdvice_LargeCommittedFixtureTreeIsNotPrescribedUnconditionally(t *testing.T) {
	const fixture = "bootstrap/act/pkg/runner/testdata/actions/node12/node_modules/"
	leaves := leavesUnder(fixture, 900)
	leaves = append(leaves, leavesUnder("judge-api/pkg/", 100)...)
	body := buildEnvelope(t, []fixtureAttestation{{Type: materialType, MerkleRoot: "aaa", Leaves: leaves}})
	contribs := envelopeBreakdown(body)
	del := deletableGroups(contribs[0].Groups)
	if del.TotalBytes <= 0 {
		t.Fatal("fixture: the committed tree must still be counted as dependency-shaped")
	}
	// Sized so that deleting the tree WOULD clear the cap: the arithmetic is
	// not in question, the authority to delete is.
	got := sizeAdviceMeasured(sizeLeaving(del.TotalBytes, largeEnvelopeBytes-1), body)

	if strings.Contains(got, "is the fix") || strings.Contains(got, "that fixes it.") {
		t.Errorf("deletion of a tree the envelope cannot prove untracked must not be called the fix "+
			"unconditionally; got:\n%s", got)
	}
	for _, want := range []string{fixture, fixesIfUntracked, "git ls-files <dir>", "committed", "#8410"} {
		if !strings.Contains(got, want) {
			t.Errorf("the advice must name the tree, state the condition, give the check, and keep "+
				"the structural fix for a committed tree (%q); got:\n%s", want, got)
		}
	}
	// And the envelope genuinely cannot tell: the same leaves under a path
	// that IS an untracked dependency tree, of the same length so the leaf
	// bytes are identical, get the same advice, path aside.
	untracked := strings.Repeat("x", len(fixture)-len("/node_modules/")) + "/node_modules/"
	other := buildEnvelope(t, []fixtureAttestation{{Type: materialType, MerkleRoot: "aaa",
		Leaves: append(leavesUnder(untracked, 900), leavesUnder("judge-api/pkg/", 100)...)}})
	otherGot := sizeAdviceMeasured(sizeLeaving(del.TotalBytes, largeEnvelopeBytes-1), other)
	// Compare the remedy sentences: the table above them pads the prefix
	// column, so the two differ there by whitespace alone.
	remedy := func(s string) string {
		return strings.ReplaceAll(s[strings.Index(s, "remedy:"):], fixture, untracked)
	}
	if remedy(got) != remedy(otherGot) {
		t.Errorf("a committed fixture tree and an untracked dependency tree are the same bytes to the "+
			"advisor and must get the same conditional advice; got:\n%s\n--- vs ---\n%s", remedy(got), remedy(otherGot))
	}
}

// TestSizeAdvice_AttestorNamesCannotForgeLogLines is the attestor-name twin of
// the path test above. The predicate type comes out of the envelope, which is
// tenant-controlled, and shortAttestorName keeps whatever bytes follow the
// last two slashes — so a type carrying a newline or an ANSI escape reached
// the table and the remedy sentence raw while only the paths were quoted. One
// malicious type per remedy arm, because each arm renders the name itself.
func TestSizeAdvice_AttestorNamesCannotForgeLogLines(t *testing.T) {
	const forged = "FORGED: archivista upload succeeded"
	cases := map[string]struct {
		typeURI string
		want    string // the recognisable name that must survive quoting
		leaves  []fixtureLeaf
	}{
		"material arm": {
			"https://witness.dev/attestations/material/v0.3\x1b[31m\n" + forged,
			"material/v0.3", leavesUnder("web/node_modules/", 300),
		},
		"product arm": {
			"https://witness.dev/attestations/product/v0.3\x1b[31m\n" + forged,
			"product/v0.3", leavesUnder("out/bundle/", 300),
		},
		"default arm": {
			"https://witness.dev/attestations/git/v0.1\r\n" + forged,
			"git/v0.1", nil,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			body := buildEnvelope(t, []fixtureAttestation{
				{Type: c.typeURI, MerkleRoot: "aaa", Leaves: c.leaves},
				{Type: "https://witness.dev/attestations/environment/v0.1", MerkleRoot: "bbb"},
			})
			got := sizeAdviceMeasured(34<<20, body)
			if strings.ContainsAny(got, "\x1b\r") {
				t.Errorf("rendered advice carries a raw control byte from the attestor type; got:\n%q", got)
			}
			for _, line := range strings.Split(got, "\n") {
				if strings.HasPrefix(line, forged) {
					t.Errorf("the attestor type forged a whole log line; got:\n%s", got)
				}
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("the attestor must still be named recognisably (%q); got:\n%s", c.want, got)
			}
			// The raw name still classifies: the dominant attestor's arm must be
			// the one its real prefix selects, not the default arm.
			switch name {
			case "material arm":
				if !strings.Contains(got, "material attestor walks") {
					t.Errorf("a malicious material type must still reach the material arm; got:\n%s", got)
				}
			case "product arm":
				if !strings.Contains(got, "--attestor-product-exclude-glob") {
					t.Errorf("a malicious product type must still reach the product arm; got:\n%s", got)
				}
			}
		})
	}
}

// TestSizeAdvice_AmbiguousDirectoriesAreCandidatesNotPrescriptions pins the
// heuristic's honesty. vendor/, dist/, build/ and target/ are named by
// convention, not by a manifest: a Go module's committed vendor tree or a
// published dist/ is tracked source, and telling an operator to delete it is
// wrong. They are reported as candidates to check and never counted toward the
// deletion the remedy promises will clear the cap.
func TestSizeAdvice_AmbiguousDirectoriesAreCandidatesNotPrescriptions(t *testing.T) {
	leaves := leavesUnder("svc/vendor/github.com/", 600)
	leaves = append(leaves, leavesUnder("web/dist/", 300)...)
	leaves = append(leaves, leavesUnder("judge-api/pkg/", 100)...)
	body := buildEnvelope(t, []fixtureAttestation{{Type: materialType, MerkleRoot: "aaa", Leaves: leaves}})
	contribs := envelopeBreakdown(body)
	if del := deletableGroups(contribs[0].Groups); len(del.Names) != 0 || del.TotalBytes != 0 {
		t.Fatalf("vendor/ and dist/ must not be deletable by name alone, got %+v", del)
	}
	got := sizeAdviceMeasured(largeEnvelopeBytes+1, body)
	if strings.Contains(got, "fixes it") {
		t.Errorf("no deletion may be prescribed on the strength of a directory name; got:\n%s", got)
	}
	for _, want := range []string{"Also present: svc/vendor/, web/dist/", "git ls-files"} {
		if !strings.Contains(got, want) {
			t.Errorf("the candidates must be named with the check to run (%q); got:\n%s", want, got)
		}
	}
}
