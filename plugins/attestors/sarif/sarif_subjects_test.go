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

package sarif

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The trivy-image fixture's identity values (see
// testdata/fixtures/trivy-image/results.sarif.json).
const (
	trivyImageManifestDigest = "bf8b47d9f90f4c0d1572f26848eec08ea3d2f8b3816cbda42e4c8ec791d350ea"
	trivyImageConfigDigest   = "1531e4d7ec818745f966295556366eeab7f32a76c78f5d7821d88abd68407f6a"
	trivyImageName           = "nginx:1.27.0"
)

// imageScanReport builds a minimal image-scan SARIF body with the given
// runs[0].properties content.
func imageScanReport(t *testing.T, props map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"version": "2.1.0",
		"runs":    []map[string]any{{"properties": props}},
	})
	require.NoError(t, err)
	return raw
}

// TestSubjects_TrivyImageScan proves the image-subject contract against the
// committed trivy image-scan fixture: the imagedigest subject's DigestSet
// VALUE is the REAL manifest digest lifted from repoDigests (oci-style bare
// hex, NOT a hash of the string), imageref is a sha256-of-string label
// subject, and the imageID config digest is never read.
func TestSubjects_TrivyImageScan(t *testing.T) {
	report, err := os.ReadFile("testdata/fixtures/trivy-image/results.sarif.json")
	require.NoError(t, err)

	a := New()
	a.Report = report

	subjects := a.Subjects()
	require.Len(t, subjects, 2, "exactly imagedigest + imageref, nothing else; got: %v", subjects)

	sha256Key := cryptoutil.DigestValue{Hash: crypto.SHA256}

	digestSubject, ok := subjects["imagedigest:"+trivyImageManifestDigest]
	require.True(t, ok, "imagedigest subject missing; got: %v", subjects)
	assert.Equal(t, trivyImageManifestDigest, digestSubject[sha256Key],
		"the DigestSet value must be the REAL manifest digest, not a hash of the repoDigest string")

	refSubject, ok := subjects["imageref:"+trivyImageName]
	require.True(t, ok, "imageref subject missing; got: %v", subjects)
	wantRefDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(trivyImageName), []cryptoutil.DigestValue{sha256Key})
	require.NoError(t, err)
	assert.Equal(t, wantRefDigest[sha256Key], refSubject[sha256Key],
		"imageref is a label subject: DigestSet is the sha256 of the literal image name")

	// imageID (the config digest) must NOT surface anywhere — it is not the
	// manifest digest and would create a dead-end edge.
	for key := range subjects {
		assert.NotContains(t, key, trivyImageConfigDigest, "imageID config digest must not be read")
	}
}

// TestBackRefs_ImageDigestOnly proves BackRefs ⊆ Subjects and that only the
// imagedigest identity edge is backreffed — the mutable imageref label stays a
// subject only.
func TestBackRefs_ImageDigestOnly(t *testing.T) {
	report, err := os.ReadFile("testdata/fixtures/trivy-image/results.sarif.json")
	require.NoError(t, err)

	a := New()
	a.Report = report

	subjects := a.Subjects()
	refs := a.BackRefs()
	require.Len(t, refs, 1, "only the imagedigest subject is a backref; got: %v", refs)

	wantKey := "imagedigest:" + trivyImageManifestDigest
	require.Contains(t, refs, wantKey)
	assert.Equal(t, subjects[wantKey], refs[wantKey], "backref must carry the same DigestSet as the subject")
	assert.NotContains(t, refs, "imageref:"+trivyImageName, "imageref must not be backreffed")
}

// TestSubjects_MalformedRepoDigestsSkipped: strict hex validation — every
// malformed repoDigests entry is skipped silently while well-formed entries
// still emit.
func TestSubjects_MalformedRepoDigestsSkipped(t *testing.T) {
	valid := trivyImageManifestDigest
	report := imageScanReport(t, map[string]any{
		"repoDigests": []string{
			"noseparator",
			"weird@md5:abc",
			"repo@sha256:",                    // empty digest
			"repo@sha256:abc123",              // too short
			"repo@sha256:" + valid[:63] + "G", // non-hex char
			"repo@sha256:" + valid[:63] + "A", // uppercase hex is not the strict OCI form
			"repo@sha256:" + valid + "ff",     // too long
			"@sha256:" + valid,                // empty repo
			"nginx@sha256:" + valid,           // the one well-formed entry
		},
	})

	a := New()
	a.Report = report

	subjects := a.Subjects()
	require.Len(t, subjects, 1, "only the well-formed repoDigest emits; got: %v", subjects)
	assert.Contains(t, subjects, "imagedigest:"+valid)
}

// TestSubjects_NonImageSARIF: SARIF without runs[0].properties (gosec,
// golangci-lint, the canonical example fixture) yields empty maps — zero
// behavior change for non-image scans.
func TestSubjects_NonImageSARIF(t *testing.T) {
	report, err := os.ReadFile("testdata/example.sarif.json")
	require.NoError(t, err)

	a := New()
	a.Report = report

	assert.Empty(t, a.Subjects(), "non-image SARIF must emit zero subjects")
	assert.Empty(t, a.BackRefs(), "non-image SARIF must emit zero backrefs")
}

// TestSubjects_EmptyAndMalformedReport: an unattested or non-JSON report
// yields empty maps rather than a panic or error.
func TestSubjects_EmptyAndMalformedReport(t *testing.T) {
	a := New()
	assert.Empty(t, a.Subjects())
	assert.Empty(t, a.BackRefs())

	a.Report = json.RawMessage(`{"runs": "not-an-array"}`)
	assert.Empty(t, a.Subjects())

	a.Report = json.RawMessage(`{"runs": []}`)
	assert.Empty(t, a.Subjects())
}

// TestSubjects_ImageNameOnly: an image name without repo digests still emits
// the imageref label subject, and BackRefs stays empty (nothing to anchor).
func TestSubjects_ImageNameOnly(t *testing.T) {
	a := New()
	a.Report = imageScanReport(t, map[string]any{"imageName": "alpine:3.20"})

	subjects := a.Subjects()
	require.Len(t, subjects, 1, "got: %v", subjects)
	assert.Contains(t, subjects, "imageref:alpine:3.20")
	assert.Empty(t, a.BackRefs(), "no manifest digest ⇒ no backref")
}

// TestSubjects_MultipleRepoDigests: one subject per well-formed repoDigests
// entry (an image pushed to several repos carries several repo digests).
func TestSubjects_MultipleRepoDigests(t *testing.T) {
	second := trivyImageConfigDigest // any other valid 64-hex value
	a := New()
	a.Report = imageScanReport(t, map[string]any{
		"repoDigests": []string{
			"nginx@sha256:" + trivyImageManifestDigest,
			fmt.Sprintf("mirror.example.com/nginx@sha256:%s", second),
		},
	})

	subjects := a.Subjects()
	require.Len(t, subjects, 2, "got: %v", subjects)
	assert.Contains(t, subjects, "imagedigest:"+trivyImageManifestDigest)
	assert.Contains(t, subjects, "imagedigest:"+second)
	assert.Len(t, a.BackRefs(), 2, "every imagedigest subject is a backref")
}
