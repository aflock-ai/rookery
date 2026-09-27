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

// jade:ring local

package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/material"
)

// #10057 made dsse.Envelope decoding conformant: a signature without its
// REQUIRED sig key is refused. The manifest index decoded companions through
// that path and dropped a refused one silently, while sidecar discovery used
// its own lax decoder and still admitted it. The result was "no sidecar next
// to the bundle hashes to X" about a sidecar that was sitting there, whose
// hash was never computed. These tests pin the two halves of the fix: one
// decoder for discovery and indexing, and a refusal that names what it could
// not read.

// writeDetachedBundleWithCompanionEnvelope writes a collection bundle whose
// material attestation names a detached manifest, and env, verbatim, at the
// companion discovery name next to it.
func writeDetachedBundleWithCompanionEnvelope(t *testing.T, env map[string]any) (bundlePath, companionPath string, materials map[string]string) {
	t.Helper()
	dir := t.TempDir()
	materials = map[string]string{
		"bin/app":    manifestTestDigest("app-binary"),
		"src/lib.go": manifestTestDigest("lib-source"),
	}
	bundlePath = writeManifestBearingBundle(t, dir, "consumer", materials, false)
	companionPath = bundlePath + "-material-manifest.json"
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal companion: %v", err)
	}
	if err := os.WriteFile(companionPath, raw, 0o600); err != nil {
		t.Fatalf("write companion: %v", err)
	}
	return bundlePath, companionPath, materials
}

func manifestStatementBytes(t *testing.T, materials map[string]string, pad string) []byte {
	t.Helper()
	predicate, _, _ := buildManifestSidecarBytes(t, materials)
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": material.ManifestType,
		"subject":       []any{},
		"predicate":     json.RawMessage(predicate),
	}
	if pad != "" {
		stmt["_pad"] = pad
	}
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	return raw
}

// A companion that is not a conformant DSSE envelope is found and cannot be
// read. The refusal still fails closed, and it names that file and why,
// instead of claiming nothing next to the bundle hashes to the manifest.
func TestFromBundlesNamesACompanionItCouldNotRead(t *testing.T) {
	materials := map[string]string{
		"bin/app":    manifestTestDigest("app-binary"),
		"src/lib.go": manifestTestDigest("lib-source"),
	}
	bundle, companion, _ := writeDetachedBundleWithCompanionEnvelope(t, map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(manifestStatementBytes(t, materials, "")),
		"signatures":  []map[string]any{{"keyid": "k"}}, // no sig: not DSSE
	})

	_, err := summarizeOneBundle(io.Discard, bundle, "")
	if !errors.Is(err, errManifestUnresolved) {
		t.Fatalf("an unreadable companion must still refuse generation, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, filepath.Base(companion)) {
		t.Errorf("the refusal must name the companion it could not read: %s", msg)
	}
	if !strings.Contains(msg, "sig") {
		t.Errorf("the refusal must say why the companion could not be read: %s", msg)
	}
	if strings.Contains(msg, "no sidecar next to the bundle hashes to") {
		t.Errorf("a companion that was never decoded was never hashed; do not say none hashes to the manifest: %s", msg)
	}
}

// When every candidate decoded and none is the named manifest, the original
// statement stands.
func TestFromBundlesSaysNoneHashesOnlyWhenEveryCompanionDecoded(t *testing.T) {
	other := map[string]string{"other/file": manifestTestDigest("different-tree")}
	bundle, _, _ := writeDetachedBundleWithCompanionEnvelope(t, map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(manifestStatementBytes(t, other, "")),
		"signatures":  []map[string]any{{"keyid": "k", "sig": "c2ln"}},
	})
	_, err := summarizeOneBundle(io.Discard, bundle, "")
	if !errors.Is(err, errManifestUnresolved) {
		t.Fatalf("a companion for a different tree must not resolve, got %v", err)
	}
	if !strings.Contains(err.Error(), "no sidecar next to the bundle hashes to") {
		t.Errorf("every candidate decoded, so say none hashes to the manifest: %v", err)
	}
}

// Discovery and indexing decode the same way. DSSE requires a verifier to
// accept the URL-safe base64 alphabet; discovery used to decode the payload
// with the standard alphabet only and dropped such a companion before the
// index, which accepts it, ever saw it.
func TestFromBundlesReadsAURLSafeCompanion(t *testing.T) {
	materials := map[string]string{
		"bin/app":    manifestTestDigest("app-binary"),
		"src/lib.go": manifestTestDigest("lib-source"),
	}
	// Pad the statement until its encoding uses an alphabet-specific
	// character, so the two alphabets actually differ on this payload.
	var payload []byte
	for pad := ""; ; pad += "?" {
		payload = manifestStatementBytes(t, materials, pad)
		if strings.ContainsAny(base64.StdEncoding.EncodeToString(payload), "+/") {
			break
		}
		if len(pad) > 64 {
			t.Fatal("could not build a payload whose encodings differ")
		}
	}
	bundle, companion, _ := writeDetachedBundleWithCompanionEnvelope(t, map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.URLEncoding.EncodeToString(payload),
		"signatures":  []map[string]any{{"keyid": "k", "sig": "c2ln"}},
	})

	if _, err := readSidecar(companion, "material-manifest"); err != nil {
		t.Fatalf("discovery refused a DSSE-conformant URL-safe companion: %v", err)
	}
	summary, err := summarizeOneBundle(io.Discard, bundle, "")
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	for _, want := range materials {
		if _, ok := summary.materialDigests[want]; !ok {
			t.Errorf("material digest %s missing: the URL-safe companion was not read", want)
		}
	}
}

// Discovery refuses exactly what the index refuses.
func TestSidecarDiscoveryRefusesASigLessEnvelope(t *testing.T) {
	materials := map[string]string{"a": manifestTestDigest("a")}
	_, companion, _ := writeDetachedBundleWithCompanionEnvelope(t, map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(manifestStatementBytes(t, materials, "")),
		"signatures":  []map[string]any{{"keyid": "k"}},
	})
	if _, err := readSidecar(companion, "material-manifest"); err == nil {
		t.Fatal("discovery admitted an envelope whose signature has no sig")
	}
}
