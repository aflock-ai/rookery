// Copyright 2025 The Witness Contributors
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

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
)

// This file covers the blind spot the detached-manifest design names
// explicitly: `cilock policy from-bundles` infers artifactsFrom edges by
// intersecting one step's PRODUCT leaf digests with another step's MATERIAL
// leaf digests. Detach the material leaves and, without the manifest read,
// materialDigests silently goes EMPTY, every inferred edge vanishes, and the
// existing edge tests stay green because they all use inline leaves.
//
// So the negative control below is not decoration — it is the test that would
// have caught the regression, and it runs first.

func manifestTestDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// buildManifestSidecarBytes returns the compact manifest predicate and its
// digest for a (path -> digest) input set, using the production sidecar
// builder so the root matches what a real producer would sign.
func buildManifestSidecarBytes(t *testing.T, files map[string]string) (predicate []byte, digest, root string) {
	t.Helper()
	side, err := inclusionproof.BuildSidecar("material", files)
	if err != nil {
		t.Fatalf("build sidecar: %v", err)
	}
	raw, err := json.Marshal(side)
	if err != nil {
		t.Fatalf("marshal sidecar: %v", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatalf("compact: %v", err)
	}
	sum := sha256.Sum256(compact.Bytes())
	return compact.Bytes(), hex.EncodeToString(sum[:]), side.MerkleRoot
}

// writeEnvelope writes a minimally-valid DSSE envelope carrying stmt. "sig" is
// a REQUIRED key of every DSSE signature (envelope v1.0.2), and
// dsse.Envelope's decoder refuses a signature without it, so a fixture that
// omits it is not an envelope at all: the companion-manifest reader would skip
// it as unreadable. The value is never verified here, only decoded.
func writeEnvelope(t *testing.T, path string, stmt any) {
	t.Helper()
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]any{{
			"keyid": "testkeyid",
			"sig":   base64.StdEncoding.EncodeToString([]byte("unverified-test-signature")),
		}},
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeManifestBearingBundle lays out on disk exactly what `cilock run
// --material-manifest` produces: a collection envelope whose material
// attestation carries NO leaves but does carry the manifest reference, plus the
// companion manifest envelope at the sidecar-discovery filename
// `<bundle>-material-manifest.json`.
//
// withSidecar=false omits the companion, which is the "producer said it
// published, we do not hold it" case.
func writeManifestBearingBundle(t *testing.T, dir, step string, materials map[string]string, withSidecar bool) string {
	t.Helper()
	predicate, digest, root := buildManifestSidecarBytes(t, materials)

	bundlePath := filepath.Join(dir, step+".bundle.json")
	writeEnvelope(t, bundlePath, map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://aflock.ai/attestation-collection/v0.1",
		"subject":       []any{},
		"predicate": map[string]any{
			"name": step,
			"attestations": []any{
				map[string]any{
					"type": material.Type,
					"attestation": map[string]any{
						"merkleRoot":       root,
						"treeSize":         len(materials),
						"hashAlgorithm":    "sha256",
						"construction":     "RFC6962",
						"manifestUploaded": true,
						"manifest": map[string]any{
							"digest": map[string]string{"sha256": digest},
							"bytes":  len(predicate),
						},
						// NO "leaves" key — this is the detached shape.
					},
				},
			},
		},
	})

	if withSidecar {
		writeEnvelope(t, bundlePath+"-material-manifest.json", map[string]any{
			"_type":         "https://in-toto.io/Statement/v0.1",
			"predicateType": material.ManifestType,
			"subject":       []any{},
			"predicate":     json.RawMessage(predicate),
		})
	}
	return bundlePath
}

// writeInlineProductBundle writes a producer step whose PRODUCT leaves are
// inline (products are untouched by this change).
func writeInlineProductBundle(t *testing.T, dir, step string, products map[string]string) string {
	t.Helper()
	leaves := make([]any, 0, len(products))
	for p, d := range products {
		leaves = append(leaves, map[string]any{"path": p, "fileDigest": d})
	}
	bundlePath := filepath.Join(dir, step+".bundle.json")
	writeEnvelope(t, bundlePath, map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://aflock.ai/attestation-collection/v0.1",
		"subject":       []any{},
		"predicate": map[string]any{
			"name": step,
			"attestations": []any{
				map[string]any{
					"type": "https://aflock.ai/attestations/product/v0.3",
					"attestation": map[string]any{
						"merkleRoot": manifestTestDigest("product-root-" + step),
						"treeSize":   len(products),
						"leaves":     leaves,
					},
				},
			},
		},
	})
	return bundlePath
}

// TestFromBundlesRecoversDetachedMaterialDigests is the positive case: with the
// companion manifest present, the summarizer recovers exactly the material
// digests an inline predicate would have yielded.
func TestFromBundlesRecoversDetachedMaterialDigests(t *testing.T) {
	dir := t.TempDir()
	materials := map[string]string{
		"bin/app":    manifestTestDigest("app-binary"),
		"src/lib.go": manifestTestDigest("lib-source"),
	}
	path := writeManifestBearingBundle(t, dir, "consumer", materials, true)

	summary, err := summarizeOneBundle(io.Discard, path, "")
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}

	if len(summary.materialDigests) != len(materials) {
		t.Fatalf("recovered %d material digests, want %d — the detached manifest was not read",
			len(summary.materialDigests), len(materials))
	}
	for _, want := range materials {
		if _, ok := summary.materialDigests[want]; !ok {
			t.Errorf("material digest %s missing after manifest hydration", want)
		}
	}
}

// TestFromBundlesWithoutManifestRefusesToGenerate is the NEGATIVE CONTROL, and
// it is what proves the test above is measuring the manifest read rather than
// something incidental. Same bundle, companion removed. The predicate SIGNED
// manifestUploaded:true, so the leaves exist and this generator simply does not
// hold them: the only honest outcome is a refusal. Returning an empty digest
// set here would silently drop every artifactsFrom edge that manifest carries
// and emit an under-constrained policy.
func TestFromBundlesWithoutManifestRefusesToGenerate(t *testing.T) {
	dir := t.TempDir()
	materials := map[string]string{"bin/app": manifestTestDigest("app-binary")}
	path := writeManifestBearingBundle(t, dir, "consumer", materials, false)

	_, err := summarizeOneBundle(io.Discard, path, "")
	if !errors.Is(err, errManifestUnresolved) {
		t.Fatalf("a predicate that signed manifestUploaded:true with NO resolvable manifest must refuse "+
			"policy generation, got err=%v", err)
	}
}

// TestFromBundlesWithheldManifestFindsNoDigests is the benign sibling: a
// producer that signed manifestUploaded:false, or a legacy predicate with no
// such key, contributes no digests and no error. The refusal above is keyed to
// the producer's own claim, not to the absence of a companion file.
func TestFromBundlesWithheldManifestFindsNoDigests(t *testing.T) {
	for name, uploaded := range map[string]any{"withheld (false)": false, "legacy (absent)": nil} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			materials := map[string]string{"bin/app": manifestTestDigest("app-binary")}
			path := writeManifestBearingBundle(t, dir, "consumer", materials, false)
			rewriteManifestUploaded(t, path, uploaded)

			summary, err := summarizeOneBundle(io.Discard, path, "")
			if err != nil {
				t.Fatalf("summarize: %v", err)
			}
			if len(summary.materialDigests) != 0 {
				t.Fatalf("recovered %d material digests with NO manifest present; the leaves must have "+
					"come from somewhere they cannot be trusted", len(summary.materialDigests))
			}
		})
	}
}

// rewriteManifestUploaded rewrites the bundle at path so its material
// predicate carries the given manifestUploaded value (nil removes the key).
func rewriteManifestUploaded(t *testing.T, path string, uploaded any) {
	t.Helper()
	rewriteMaterialAttestation(t, path, func(att map[string]any) {
		if uploaded == nil {
			delete(att, "manifestUploaded")
		} else {
			att["manifestUploaded"] = uploaded
		}
	})
}

// rewriteInlineLeaves rewrites the bundle at path so its material predicate
// carries the given "leaves" value verbatim (an empty []any writes the
// present-but-empty `"leaves": []` shape a published empty tree signs).
func rewriteInlineLeaves(t *testing.T, path string, leaves []any) {
	t.Helper()
	rewriteMaterialAttestation(t, path, func(att map[string]any) {
		att["leaves"] = leaves
	})
}

// rewriteMaterialAttestation applies mutate to the first inner attestation of
// the collection at path and writes the bundle back.
func rewriteMaterialAttestation(t *testing.T, path string, mutate func(att map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test fixture path under t.TempDir
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var stmt map[string]any
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("decode statement: %v", err)
	}
	pred := stmt["predicate"].(map[string]any)
	att := pred["attestations"].([]any)[0].(map[string]any)["attestation"].(map[string]any)
	mutate(att)
	writeEnvelope(t, path, stmt)
}

// TestFromBundlesRejectsMismatchedManifest: a companion whose leaves belong to
// a different tree must be ignored, even though it is well-formed, correctly
// named, and sitting in the right directory. Adjacency is not evidence — the
// digest the signed predicate names is.
func TestFromBundlesRejectsMismatchedManifest(t *testing.T) {
	dir := t.TempDir()
	materials := map[string]string{"bin/app": manifestTestDigest("app-binary")}
	path := writeManifestBearingBundle(t, dir, "consumer", materials, false)

	// Drop in a manifest for a COMPLETELY different input set, under the exact
	// filename discovery looks for.
	otherPredicate, _, _ := buildManifestSidecarBytes(t, map[string]string{
		"evil/injected": manifestTestDigest("attacker-artifact"),
	})
	writeEnvelope(t, path+"-material-manifest.json", map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": material.ManifestType,
		"subject":       []any{},
		"predicate":     json.RawMessage(otherPredicate),
	})

	// The companion does not hash to the signed digest, so it is not this
	// predicate's manifest — and the predicate signed manifestUploaded:true,
	// so "not resolved" is a refusal, never an empty set.
	summary, err := summarizeOneBundle(io.Discard, path, "")
	if !errors.Is(err, errManifestUnresolved) {
		t.Fatalf("a manifest that does NOT match the referenced digest must be rejected AND policy "+
			"generation refused; got err=%v digests=%v", err, summary.materialDigests)
	}
}

// TestFromBundlesWiresEdgeAcrossDetachedManifest is the end-to-end shape the
// design asks for: a producer step whose inline PRODUCT leaves overlap a
// consumer step whose MATERIAL leaves are DETACHED must still get its
// artifactsFrom edge wired. This is the assertion that would have failed
// silently before the manifest read existed.
func TestFromBundlesWiresEdgeAcrossDetachedManifest(t *testing.T) {
	dir := t.TempDir()
	shared := manifestTestDigest("the-artifact-that-crosses-steps")

	producerPath := writeInlineProductBundle(t, dir, "build", map[string]string{"bin/app": shared})
	consumerPath := writeManifestBearingBundle(t, dir, "package", map[string]string{
		"bin/app":   shared,
		"extra.txt": manifestTestDigest("unrelated"),
	}, true)

	summaries, err := summarizeBundles(io.Discard, []string{producerPath, consumerPath}, "")
	if err != nil {
		t.Fatalf("summarize bundles: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("got %d summaries, want 2", len(summaries))
	}

	var producer, consumer bundleSummary
	for _, s := range summaries {
		switch s.stepName {
		case "build":
			producer = s
		case "package":
			consumer = s
		}
	}
	if len(producer.productDigests) == 0 {
		t.Fatal("producer step recovered no product digests")
	}
	if len(consumer.materialDigests) == 0 {
		t.Fatal("consumer step recovered no material digests from its detached manifest")
	}
	if !digestSetsOverlap(producer.productDigests, consumer.materialDigests) {
		t.Fatal("no overlap between the producer's products and the consumer's detached materials; " +
			"the artifactsFrom edge would silently not be wired")
	}
}

// TestFromBundlesCompanionReadOnlyOnSignedPublish is the three-state table
// with the companion PRESENT — the case TestFromBundlesWithheldManifestFindsNoDigests
// deliberately does not exercise. Every row lays out a valid manifest at the
// discovery filename that hashes to the signed digest and rebuilds the signed
// root; only manifestUploaded differs. The digests are recovered on an
// explicit true and on nothing else: a producer that signed false said the
// leaves were not published, and a companion that happens to match is not
// evidence against that statement. The nil row pins the legacy rule — an
// absent key is "decide from leaves", and a leaf-less legacy predicate has
// none — so a stripped field cannot be promoted to a claim by dropping a file
// next to the bundle.
func TestFromBundlesCompanionReadOnlyOnSignedPublish(t *testing.T) {
	cases := []struct {
		name     string
		uploaded any
		want     int
	}{
		{name: "published (true)", uploaded: true, want: 2},
		{name: "withheld (false)", uploaded: false, want: 0},
		{name: "legacy (absent)", uploaded: nil, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			materials := map[string]string{
				"bin/app":    manifestTestDigest("app-binary"),
				"src/lib.go": manifestTestDigest("lib-source"),
			}
			path := writeManifestBearingBundle(t, dir, "consumer", materials, true)
			rewriteManifestUploaded(t, path, tc.uploaded)

			summary, err := summarizeOneBundle(io.Discard, path, "")
			if err != nil {
				t.Fatalf("summarize: %v", err)
			}
			if got := len(summary.materialDigests); got != tc.want {
				t.Fatalf("manifestUploaded=%v with a valid matching companion on disk: recovered %d material digests, want %d",
					tc.uploaded, got, tc.want)
			}
		})
	}
}

// TestFromBundlesPresentEmptyLeavesAreAuthoritative pins JSON field PRESENCE.
// In this rollout a producer keeps its inline leaves even when it publishes a
// companion, so a published EMPTY tree signs `"leaves": []` — a commitment that
// the step consumed nothing. That present key is the authoritative inline set,
// exactly as material.Attestor.HasInlineLeaves reads it, and the generator must
// never mistake it for an absent key and go demanding the companion: zero
// digests, no error, whether or not a companion is on disk. The companion in
// the "present" row carries two leaves, so recovering zero is the proof it was
// not read. Only a truly ABSENT key with manifestUploaded:true still refuses
// when the companion cannot be resolved.
func TestFromBundlesPresentEmptyLeavesAreAuthoritative(t *testing.T) {
	cases := []struct {
		name        string
		emptyLeaves bool // write "leaves": [] (true) or leave the key absent (false)
		withSidecar bool
		wantErr     error
		wantDigests int
	}{
		{name: "published, leaves:[], companion unavailable", emptyLeaves: true, withSidecar: false, wantErr: nil, wantDigests: 0},
		{name: "published, leaves:[], companion present", emptyLeaves: true, withSidecar: true, wantErr: nil, wantDigests: 0},
		{name: "published, leaves absent, companion unavailable", emptyLeaves: false, withSidecar: false, wantErr: errManifestUnresolved, wantDigests: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			materials := map[string]string{
				"bin/app":    manifestTestDigest("app-binary"),
				"src/lib.go": manifestTestDigest("lib-source"),
			}
			path := writeManifestBearingBundle(t, dir, "consumer", materials, tc.withSidecar)
			if tc.emptyLeaves {
				rewriteInlineLeaves(t, path, []any{})
			}

			summary, err := summarizeOneBundle(io.Discard, path, "")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got := len(summary.materialDigests); got != tc.wantDigests {
				t.Fatalf("recovered %d material digests, want %d", got, tc.wantDigests)
			}
		})
	}
}
