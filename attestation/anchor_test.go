// jade:ring local

// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestation

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHex    = "e2ac70e7319a02c5a477f5825259bd118b94e8b02c279c67afa63adab6d8685b"
	testHexAlt = "4f55086f7dd096d48b0e49be066971a8ed996521c2e190aa21b2435a847198b4"
)

// The registry golden: the embedded table is exactly these rows. A row change
// must edit anchor_registry.json AND this literal, so neither changes alone.
func TestAnchorRegistryGolden(t *testing.T) {
	onDisk, err := os.ReadFile("anchor_registry.json")
	require.NoError(t, err)
	require.Equal(t, string(onDisk), string(anchorRegistryJSON), "embedded registry must equal the checked-in file")

	want := []AnchorRegistryRow{
		{
			Attestor:      "https://aflock.ai/attestations/oci/v0.1",
			Prefix:        "imageid:",
			Class:         ClassAnchor,
			Kind:          KindImageConfig,
			Role:          RoleProduced,
			Basis:         BasisMeasured,
			Algorithm:     "sha256",
			SignedPath:    "$.imageid.sha256",
			Normalization: NormalizationBareHex,
			Measurement:   MeasurementOCIConfigBlob,
			RecomputeFrom: "predicate",
			Evidence:      "plugins/attestors/oci/oci.go:457",
			Since:         "4.5.0",
		},
		{
			Attestor:      "https://aflock.ai/attestations/oci/v0.1",
			Prefix:        "registrydigest:",
			Class:         ClassAcceptor,
			Kind:          KindImageRegistryManifest,
			Role:          RoleAbout,
			Basis:         BasisObserved,
			Algorithm:     "sha256",
			SignedPath:    "$.registrydigests[*].digest.sha256",
			Normalization: NormalizationBareHex,
			Gate:          "the command-run sibling exited 0, passes the push verb test and prints this digest",
			RecomputeFrom: "https://aflock.ai/attestations/command-run/v0.2",
			Evidence:      "plugins/attestors/oci/oci.go:468",
			Since:         "4.5.0",
		},
	}
	got := AnchorRegistryRows()
	require.Equal(t, want, got)

	// Callers get a copy; the compiled table cannot be edited through it.
	got[0].Kind = KindImageRegistryManifest
	assert.Equal(t, KindImageConfig, AnchorRegistryRows()[0].Kind)
}

func TestAnchorClosedListsGolden(t *testing.T) {
	assert.Equal(t, []AnchorKind{KindImageRegistryManifest, KindImageConfig, KindGitCommit, KindFileContent}, AnchorKinds())
	assert.Equal(t, []string{"oci-config-blob"}, AnchorMeasurements(), "L2-1 ships oci-config-blob only")
	_, ok := LookupMeasurement("oci-registry-manifest")
	assert.False(t, ok, "oci-registry-manifest is not a measurement until its own lane")

	assert.Equal(t, []string{
		"parenthash:", "commithash:", "commitsha:", "commit:",
		"pullrequestheadsha:", "pullrequestheadref:", "pullrequest:", "mergecommitsha:", "pipelineurl:",
		"projecturl:", "joburl:", "jenkinsurl:", "codebuild-", "imagetag:", "imagereference:", "imageref:",
		"manifestdigest:", "tardigest:", "name:", "version:", "trivy:", "tree:", "remote:", "refnameshort:",
		"authoremail:", "committeremail:", "reponame:", "repourl:", "repo:", "pr:", "reviewer:", "actionref:",
		"sender:", "event:", "layerdiffid", "materialdigest:", "materialuri:", "runimagedigest:", "artifact:",
		"policy:", "inventory:",
	}, AnchorPrefixDenylist())

	seeds := SeedDenylist()
	keys := make([]string, 0, len(seeds))
	for _, e := range seeds {
		require.NotEmpty(t, e.Note, "%s/%s names why it is denied", e.Attestor, e.Prefix)
		k := e.Attestor + "/"
		if e.Version != "" {
			k += e.Version + "/"
		}
		keys = append(keys, k+e.Prefix)
	}
	assert.Equal(t, []string{
		"docker/materialdigest:", "buildpacks/runimagedigest:", "oci/layerdiffid",
		"material/tree:", "product/tree:", "material/v0.1/file:", "git/parenthash:",
	}, keys)

	reasons := AnchorReasons()
	got := make([]string, 0, len(reasons))
	for _, r := range reasons {
		got = append(got, r.Counter+" "+r.Reason)
	}
	assert.Equal(t, []string{
		"anchors_dropped unregistered",
		"anchors_dropped unrecomputable",
		"anchors_dropped non-canonical",
		"anchors_dropped hub",
		"anchors_dropped legacy-dropped",
		"anchors_dropped role-about",
		"anchors_dropped multi-artifact",
		"anchors_dropped not-admitted-by-product",
		"links_dropped not-hardened",
		"links_dropped multi-commit",
		"links_dropped not-admitted-by-product",
		"policy refused about-needs-policy-v0.2",
		"policy refused about-unknown-value",
		"policy refused policy-type-unknown",
		"acceptors_dropped acceptor-unbacked",
		"witness rejected anchor-unbacked",
		"witness rejected source-commit-mismatch",
		"witness rejected seed-denylist",
		"witness rejected hub-seed",
		"witness rejected vsa-unmarked",
		"seeds_dropped envelope-subject",
		"seeds_dropped envelope-other-commit",
		"seeds_dropped envelope-no-commit",
		"request refused extra-subject-with-commit",
		"request refused other-commit",
		"workflow diagnostic no-candidate-commit",
	}, got)
}

func TestHubValues(t *testing.T) {
	empty := sha256.Sum256(nil)
	dot := sha256.Sum256([]byte("."))
	tree, err := merkle.NewTree(nil)
	require.NoError(t, err)
	emptyRoot := hex.EncodeToString(tree.Root())

	values := map[string]string{}
	for _, h := range HubValues() {
		require.NotEmpty(t, h.Evidence, "hub value %s names its evidence", h.Value)
		_, err := Canonical(KindImageConfig, h.Value, NormalizationBareHex)
		require.NoError(t, err, "hub values are canonical so they compare to identities")
		values[h.Value] = h.Evidence
	}
	assert.Contains(t, values, hex.EncodeToString(empty[:]))
	assert.Contains(t, values, hex.EncodeToString(dot[:]))
	assert.Contains(t, values, emptyRoot, "the empty Merkle root material and product emit")
	assert.Len(t, values, 2, "sha256(\"\") is also the empty RFC 6962 root")
}

// validRow is one well-formed row; each refusal case below changes one field.
func validRow() map[string]any {
	return map[string]any{
		"attestor":       "https://aflock.ai/attestations/oci/v0.1",
		"prefix":         "imageid:",
		"class":          "anchor",
		"kind":           "image-config",
		"role":           "produced",
		"basis":          "measured",
		"algorithm":      "sha256",
		"signed_path":    "$.imageid.sha256",
		"normalization":  "bare-hex",
		"measurement":    "oci-config-blob",
		"recompute_from": "predicate",
		"evidence":       "plugins/attestors/oci/oci.go:457",
		"since":          "4.5.0",
	}
}

func encodeRegistry(t *testing.T, rows ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": 1, "rows": rows})
	require.NoError(t, err)
	return b
}

func TestParseAnchorRegistry_AcceptsValidRows(t *testing.T) {
	acceptor := validRow()
	acceptor["prefix"] = "registrydigest:"
	acceptor["class"] = "acceptor"
	acceptor["kind"] = "image-registry-manifest"
	acceptor["role"] = "about"
	acceptor["basis"] = "observed"
	delete(acceptor, "measurement")
	acceptor["recompute_from"] = "https://aflock.ai/attestations/command-run/v0.2"

	reported := validRow()
	reported["attestor"] = "https://aflock.ai/attestations/trivy/v0.1"
	reported["prefix"] = "imagedigest:"
	reported["class"] = "acceptor"
	reported["kind"] = "image-registry-manifest"
	reported["role"] = "about"
	reported["basis"] = "reported"
	reported["normalization"] = "repo-at-digest"
	delete(reported, "measurement")

	notAnchor := map[string]any{
		"attestor": "https://aflock.ai/attestations/oci/v0.1",
		"prefix":   "tardigest:",
		"class":    "not_anchor",
		"rule":     []string{"A1"},
		"evidence": "plugins/attestors/oci/oci.go:454",
		"since":    "4.5.0",
	}

	rows, err := parseAnchorRegistry(encodeRegistry(t, validRow(), acceptor, reported, notAnchor))
	require.NoError(t, err)
	require.Len(t, rows, 4)
}

func TestParseAnchorRegistry_Refuses(t *testing.T) {
	cases := map[string]func(r map[string]any){
		"unknown field":                      func(r map[string]any) { r["derived_path"] = "$.config.digest" },
		"empty attestor":                     func(r map[string]any) { r["attestor"] = "" },
		"empty prefix":                       func(r map[string]any) { r["prefix"] = "" },
		"prefix without separator":           func(r map[string]any) { r["prefix"] = "imageid" },
		"unknown class":                      func(r map[string]any) { r["class"] = "edge" },
		"unknown kind":                       func(r map[string]any) { r["kind"] = "image-tag" },
		"reserved kind":                      func(r map[string]any) { r["kind"] = "file-content" },
		"sha512":                             func(r map[string]any) { r["algorithm"] = "sha512" },
		"sha1":                               func(r map[string]any) { r["algorithm"] = "sha1" },
		"unknown role":                       func(r map[string]any) { r["role"] = "produced-if-measured-push" },
		"anchor with role about":             func(r map[string]any) { r["role"] = "about" },
		"anchor with reported basis":         func(r map[string]any) { r["basis"] = "reported"; delete(r, "measurement") },
		"acceptor with role produced":        func(r map[string]any) { r["class"] = "acceptor" },
		"unknown basis":                      func(r map[string]any) { r["basis"] = "claimed" },
		"measured without measurement":       func(r map[string]any) { delete(r, "measurement") },
		"measurement not in the closed list": func(r map[string]any) { r["measurement"] = "oci-registry-manifest" },
		"measurement on an observed row": func(r map[string]any) {
			r["basis"] = "observed"
			r["recompute_from"] = "https://aflock.ai/attestations/command-run/v0.2"
		},
		"observed recomputed from the predicate": func(r map[string]any) { r["basis"] = "observed"; delete(r, "measurement") },
		"measured recomputed from a sibling": func(r map[string]any) {
			r["recompute_from"] = "https://aflock.ai/attestations/command-run/v0.2"
		},
		"unknown normalization":  func(r map[string]any) { r["normalization"] = "lowercase" },
		"signed path not rooted": func(r map[string]any) { r["signed_path"] = "imageid.sha256" },
		"no evidence":            func(r map[string]any) { r["evidence"] = "" },
		"no since":               func(r map[string]any) { r["since"] = "" },
		"rule on an anchor row":  func(r map[string]any) { r["rule"] = []string{"A6"} },
		// FE2: the docker-save archive manifest.json digest is not a registry manifest.
		"FE2 manifestdigest as a kind": func(r map[string]any) {
			r["prefix"] = "manifestdigest:"
			r["class"] = "acceptor"
			r["kind"] = "image-registry-manifest"
			r["role"] = "about"
		},
		// FE4: the archive file digest is neither a config nor a registry manifest.
		"FE4 tardigest as a kind": func(r map[string]any) { r["prefix"] = "tardigest:" },
		"commithash as an anchor": func(r map[string]any) { r["prefix"] = "commithash:" },
		"codebuild prefix family": func(r map[string]any) { r["prefix"] = "codebuild-project:" },
		"tree root as an anchor":  func(r map[string]any) { r["prefix"] = "tree:products:" },
		"not_anchor with a kind": func(r map[string]any) {
			for k := range r {
				delete(r, k)
			}
			r["attestor"] = "https://aflock.ai/attestations/oci/v0.1"
			r["prefix"] = "tardigest:"
			r["class"] = "not_anchor"
			r["kind"] = "image-config"
			r["rule"] = []string{"A1"}
			r["evidence"] = "plugins/attestors/oci/oci.go:454"
			r["since"] = "4.5.0"
		},
		"not_anchor without a rule": func(r map[string]any) {
			for k := range r {
				delete(r, k)
			}
			r["attestor"] = "https://aflock.ai/attestations/oci/v0.1"
			r["prefix"] = "tardigest:"
			r["class"] = "not_anchor"
			r["evidence"] = "plugins/attestors/oci/oci.go:454"
			r["since"] = "4.5.0"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRow()
			mutate(r)
			_, err := parseAnchorRegistry(encodeRegistry(t, r))
			require.Error(t, err)
		})
	}

	t.Run("duplicate row", func(t *testing.T) {
		_, err := parseAnchorRegistry(encodeRegistry(t, validRow(), validRow()))
		require.Error(t, err)
	})
	t.Run("unknown version", func(t *testing.T) {
		b, err := json.Marshal(map[string]any{"version": 2, "rows": []any{validRow()}})
		require.NoError(t, err)
		_, err = parseAnchorRegistry(b)
		require.Error(t, err)
	})
	t.Run("no rows", func(t *testing.T) {
		_, err := parseAnchorRegistry([]byte(`{"version":1,"rows":[]}`))
		require.Error(t, err)
	})
	t.Run("trailing document", func(t *testing.T) {
		b := append(encodeRegistry(t, validRow()), []byte(`{"version":1}`)...)
		_, err := parseAnchorRegistry(b)
		require.Error(t, err)
	})
}

func TestCanonical_Accepts(t *testing.T) {
	cases := []struct {
		name string
		kind AnchorKind
		raw  string
		rule Normalization
	}{
		{"bare hex", KindImageConfig, testHex, NormalizationBareHex},
		{"prefixed", KindImageConfig, "sha256:" + testHex, NormalizationPrefixed},
		{"repo at digest", KindImageRegistryManifest, "ghcr.io/org/app@sha256:" + testHex, NormalizationRepoAtDigest},
		{"repo with port at digest", KindImageRegistryManifest, "localhost:5000/app@sha256:" + testHex, NormalizationRepoAtDigest},
		{"purl oci", KindImageRegistryManifest, "pkg:oci/app@sha256%3A" + testHex + "?repository_url=ghcr.io/org/app&arch=amd64", NormalizationPURLVersion},
		{"purl docker lowercase escape", KindImageRegistryManifest, "pkg:docker/library/alpine@sha256%3a" + testHex, NormalizationPURLVersion},
		{"purl literal colon", KindImageRegistryManifest, "pkg:docker/library/alpine@sha256:" + testHex + "#sub", NormalizationPURLVersion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := Canonical(c.kind, c.raw, c.rule)
			require.NoError(t, err)
			assert.Equal(t, Identity{Kind: c.kind, Algorithm: "sha256", Value: testHex}, id)
		})
	}
}

// The negative set of 3c.1: every non-canonical form is refused, never repaired.
func TestCanonical_NegativeSet(t *testing.T) {
	upper := strings.ToUpper(testHex)
	cases := []struct {
		name string
		kind AnchorKind
		raw  string
		rule Normalization
	}{
		{"empty", KindImageConfig, "", NormalizationBareHex},
		{"uppercase", KindImageConfig, upper, NormalizationBareHex},
		{"mixed case", KindImageConfig, "E" + testHex[1:], NormalizationBareHex},
		{"63 chars", KindImageConfig, testHex[:63], NormalizationBareHex},
		{"65 chars", KindImageConfig, testHex + "0", NormalizationBareHex},
		{"leading space", KindImageConfig, " " + testHex, NormalizationBareHex},
		{"trailing newline", KindImageConfig, testHex + "\n", NormalizationBareHex},
		{"non-hex", KindImageConfig, "g" + testHex[1:], NormalizationBareHex},
		{"fullwidth digit", KindImageConfig, "０" + testHex[3:], NormalizationBareHex},
		{"prefixed under bare-hex", KindImageConfig, "sha256:" + testHex, NormalizationBareHex},
		{"gitoid", KindImageConfig, "gitoid:blob:sha256:" + testHex, NormalizationBareHex},
		{"dirhash", KindImageConfig, "h1:" + testHex, NormalizationBareHex},

		{"bare under prefixed", KindImageConfig, testHex, NormalizationPrefixed},
		{"uppercase prefix", KindImageConfig, "SHA256:" + testHex, NormalizationPrefixed},
		{"doubled prefix", KindImageConfig, "sha256:sha256:" + testHex, NormalizationPrefixed},
		{"sha512", KindImageConfig, "sha512:" + testHex + testHex, NormalizationPrefixed},
		{"uppercase value after prefix", KindImageConfig, "sha256:" + upper, NormalizationPrefixed},
		{"encoded prefix outside purl", KindImageConfig, "sha256%3A" + testHex, NormalizationPrefixed},
		{"whitespace before prefix", KindImageConfig, " sha256:" + testHex, NormalizationPrefixed},

		{"empty repo", KindImageRegistryManifest, "@sha256:" + testHex, NormalizationRepoAtDigest},
		{"no separator", KindImageRegistryManifest, "ghcr.io/org/app:" + testHex, NormalizationRepoAtDigest},
		{"repeated separator", KindImageRegistryManifest, "a@sha256:" + testHexAlt + "@sha256:" + testHex, NormalizationRepoAtDigest},
		{"at sign in repo", KindImageRegistryManifest, "a@b@sha256:" + testHex, NormalizationRepoAtDigest},
		{"whitespace in repo", KindImageRegistryManifest, "ghcr.io/org /app@sha256:" + testHex, NormalizationRepoAtDigest},
		{"uppercase algorithm", KindImageRegistryManifest, "app@SHA256:" + testHex, NormalizationRepoAtDigest},
		{"uppercase hex", KindImageRegistryManifest, "app@sha256:" + upper, NormalizationRepoAtDigest},
		{"trailing space", KindImageRegistryManifest, "app@sha256:" + testHex + " ", NormalizationRepoAtDigest},
		{"sha512 digest", KindImageRegistryManifest, "app@sha512:" + testHex + testHex, NormalizationRepoAtDigest},
		{"bare under repo-at-digest", KindImageRegistryManifest, testHex, NormalizationRepoAtDigest},

		{"purl double encoding", KindImageRegistryManifest, "pkg:oci/app@sha256%253A" + testHex, NormalizationPURLVersion},
		{"purl unknown type", KindImageRegistryManifest, "pkg:npm/app@sha256%3A" + testHex, NormalizationPURLVersion},
		{"purl uppercase type", KindImageRegistryManifest, "pkg:OCI/app@sha256%3A" + testHex, NormalizationPURLVersion},
		{"purl no scheme", KindImageRegistryManifest, "oci/app@sha256%3A" + testHex, NormalizationPURLVersion},
		{"purl no name", KindImageRegistryManifest, "pkg:oci/@sha256%3A" + testHex, NormalizationPURLVersion},
		{"purl no version", KindImageRegistryManifest, "pkg:oci/app", NormalizationPURLVersion},
		{"purl tag version", KindImageRegistryManifest, "pkg:oci/app@latest", NormalizationPURLVersion},
		{"purl bare hex version", KindImageRegistryManifest, "pkg:oci/app@" + testHex, NormalizationPURLVersion},
		{"purl uppercase hex", KindImageRegistryManifest, "pkg:oci/app@sha256%3A" + upper, NormalizationPURLVersion},

		{"unknown normalization", KindImageConfig, testHex, Normalization("lowercase")},
		{"unknown kind", AnchorKind("image-tag"), testHex, NormalizationBareHex},
		{"reserved kind", KindFileContent, testHex, NormalizationBareHex},
		{"empty kind", AnchorKind(""), testHex, NormalizationBareHex},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := Canonical(c.kind, c.raw, c.rule)
			require.Error(t, err)
			assert.Equal(t, Identity{}, id, "a refused value yields no identity, never a repaired one")
		})
	}
}

// The known false equivalences of 3c.3, at the identity layer.
func TestCanonical_FalseEquivalences(t *testing.T) {
	// FE1: an index and a platform manifest are both registry manifests of
	// "the image", and they are different documents: never one identity.
	index, err := Canonical(KindImageRegistryManifest, "ghcr.io/org/app@sha256:"+testHex, NormalizationRepoAtDigest)
	require.NoError(t, err)
	platform, err := Canonical(KindImageRegistryManifest, "ghcr.io/org/app@sha256:"+testHexAlt, NormalizationRepoAtDigest)
	require.NoError(t, err)
	assert.NotEqual(t, index, platform)

	// FE3: the same hex in two kinds is two identities; kind typing refuses the match.
	config, err := Canonical(KindImageConfig, testHex, NormalizationBareHex)
	require.NoError(t, err)
	manifest, err := Canonical(KindImageRegistryManifest, testHex, NormalizationBareHex)
	require.NoError(t, err)
	assert.NotEqual(t, config, manifest)

	// The key tail is a label: two pushes of one manifest to two registries
	// are one identity, and equal the bare-hex form of the same digest.
	other, err := Canonical(KindImageRegistryManifest, "registry.example/mirror@sha256:"+testHex, NormalizationRepoAtDigest)
	require.NoError(t, err)
	assert.Equal(t, index, other)
	assert.Equal(t, manifest, index)

	// FE2 and FE4: neither the archive manifest.json digest nor the tarball
	// digest has a registry row, and both prefixes are denied.
	for _, prefix := range []string{"manifestdigest:", "tardigest:"} {
		for _, row := range AnchorRegistryRows() {
			assert.NotEqual(t, prefix, row.Prefix)
		}
		assert.Contains(t, AnchorPrefixDenylist(), prefix)
	}
}

// Each row has a second plausible reading (the purl specification's
// right-to-left split, a first-boundary split as net/url makes, a reading after
// percent-decoding) or breaks the purl grammar, so the encoder refuses it
// (purl-spec docs/specification/how-to-parse.md and standard/Annex-C-ABNF-Grammar.md,
// types/oci-definition.json).
func TestCanonical_PURLRefusesAmbiguous(t *testing.T) {
	a, b, upper := testHex, testHexAlt, strings.ToUpper(testHex)
	rows := []struct{ name, raw string }{
		// Review round 1: the last '?' then the last '@' read b out of the qualifiers.
		{"codex example: digest in qualifier text", "pkg:oci/app@sha256:" + a + "?x=@sha256:" + b + "?y=z"},
		{"@ in name", "pkg:oci/ap@p@sha256:" + a},
		{"? in name", "pkg:oci/a?b@sha256:" + a + "?c=d"},
		{"# in name", "pkg:oci/a#b@sha256:" + a + "#s"},
		{"@ in namespace", "pkg:docker/org@x/app@sha256:" + a},
		{"? in namespace", "pkg:docker/org?x/app@sha256:" + a + "?q=v"},
		{"# in namespace", "pkg:docker/org#x/app@sha256:" + a + "#s"},
		{"@ in version", "pkg:oci/app@sha256:" + a[:32] + "@" + a[32:]},
		{"? in version", "pkg:oci/app@sha256:" + a[:32] + "?" + a[32:] + "?tag=v"},
		{"# in version", "pkg:oci/app@sha256:" + a[:32] + "#" + a[32:] + "#s"},
		{"@ in qualifier value", "pkg:oci/app@sha256:" + a + "?repository_url=u@ghcr.io"},
		{"? in qualifier value", "pkg:oci/app@sha256:" + a + "?tag=v?1"},
		{"# in qualifier value", "pkg:oci/app@sha256:" + a + "?tag=v#1#s"},
		{"@ in subpath", "pkg:oci/app@sha256:" + a + "#s@x"},
		{"? in subpath", "pkg:oci/app@sha256:" + a + "#s?x"},
		{"# in subpath", "pkg:oci/app@sha256:" + a + "#s#x"},
		{"two version @", "pkg:oci/app@sha256:" + b + "@sha256:" + a},
		{"doubled @", "pkg:oci/app@@sha256:" + a},
		{"%40 in name", "pkg:oci/app%40sha256:" + b + "@sha256:" + a},
		{"%40 in namespace", "pkg:docker/org%40x/app@sha256:" + a},
		{"%40 in version", "pkg:oci/app@sha256:" + a + "%40sha256:" + b},
		{"%40 in qualifier value", "pkg:oci/app@sha256:" + a + "?repository_url=u%40ghcr.io"},
		{"%40 in subpath", "pkg:oci/app@sha256:" + a + "#s%40x"},
		{"%3F in name", "pkg:oci/app%3Fx@sha256:" + a},
		{"%3F in namespace", "pkg:docker/org%3Fx/app@sha256:" + a},
		{"%3F in version", "pkg:oci/app@sha256:" + a + "%3Fx=y"},
		{"%3F in qualifier value", "pkg:oci/app@sha256:" + a + "?tag=v%3F1"},
		{"%3F in subpath", "pkg:oci/app@sha256:" + a + "#s%3Fx"},
		{"%23 in name", "pkg:oci/app%23x@sha256:" + a},
		{"uppercase hex", "pkg:oci/app@sha256:" + upper},
		{"63 hex", "pkg:oci/app@sha256:" + a[:63]},
		{"65 hex", "pkg:oci/app@sha256:" + a + "0"},
		{"sha512", "pkg:oci/app@sha512:" + a + a},
		{"sha384", "pkg:oci/app@sha384:" + a + a[:32]},
		{"sha1", "pkg:oci/app@sha1:" + a[:40]},
		{"uppercase algorithm", "pkg:oci/app@SHA256:" + a},
		{"empty version", "pkg:oci/app@"},
		{"empty version before qualifiers", "pkg:oci/app@?tag=v"},
		{"space in name", "pkg:oci/ap p@sha256:" + a},
		{"space in qualifier value", "pkg:oci/app@sha256:" + a + "?tag=a b"},
		{"tab in subpath", "pkg:oci/app@sha256:" + a + "#s\tx"},
		{"trailing space", "pkg:oci/app@sha256:" + a + " "},
		{"trailing newline", "pkg:oci/app@sha256:" + a + "\n"},
		{"leading space", " pkg:oci/app@sha256:" + a},
		{"trailing ?", "pkg:oci/app@sha256:" + a + "?"},
		{"trailing #", "pkg:oci/app@sha256:" + a + "#"},
		{"trailing &", "pkg:oci/app@sha256:" + a + "?tag=v&"},
		{"empty qualifier pair", "pkg:oci/app@sha256:" + a + "?tag=v&&arch=amd64"},
		{"empty qualifier value", "pkg:oci/app@sha256:" + a + "?tag="},
		{"qualifier without =", "pkg:oci/app@sha256:" + a + "?tag"},
		{"repeated qualifier key", "pkg:oci/app@sha256:" + a + "?tag=a&tag=b"},
		{"uppercase qualifier key", "pkg:oci/app@sha256:" + a + "?Tag=v"},
		{"encoded qualifier key", "pkg:oci/app@sha256:" + a + "?t%61g=v"},
		{"digest qualifier", "pkg:oci/app@sha256:" + a + "?digest=sha256:" + b},
		{"digest qualifier equal to the version", "pkg:oci/app@sha256:" + a + "?digest=sha256:" + a},
		{"checksum qualifier", "pkg:oci/app@sha256:" + a + "?checksum=sha256:" + b},
		{"checksums qualifier", "pkg:oci/app@sha256:" + a + "?checksums=sha256:" + b},
		{"digest in another qualifier", "pkg:oci/app@sha256:" + a + "?tag=sha256:" + b},
		{"encoded digest in another qualifier", "pkg:oci/app@sha256:" + a + "?tag=sha256%3A" + b},
		{"= in qualifier value", "pkg:oci/app@sha256:" + a + "?tag=a=b"},
		{"+ in qualifier value", "pkg:oci/app@sha256:" + a + "?tag=v+1"},
		{"double-encoded qualifier value", "pkg:oci/app@sha256:" + a + "?tag=v%2540"},
		{"encoded letters in version", "pkg:oci/app@%73ha256%3A" + a},
		{"encoded hex digit in version", "pkg:oci/app@sha256%3A%65" + a[1:]},
		{"encoded slash in version", "pkg:oci/app@sha256%2F" + a},
		{"encoded name", "pkg:oci/%61pp@sha256:" + a},
		{"oci with a namespace", "pkg:oci/library/app@sha256:" + a},
		{"empty namespace segment", "pkg:docker//app@sha256:" + a},
		{"empty inner namespace segment", "pkg:docker/org//app@sha256:" + a},
		{"pkg:// form", "pkg://oci/app@sha256:" + a},
		{"uppercase scheme", "PKG:oci/app@sha256:" + a},
		{"dot-dot subpath", "pkg:oci/app@sha256:" + a + "#a/../b"},
		{"dot subpath", "pkg:oci/app@sha256:" + a + "#."},
		{"empty subpath segment", "pkg:oci/app@sha256:" + a + "#a//b"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			id, err := Canonical(KindImageRegistryManifest, r.raw, NormalizationPURLVersion)
			require.Error(t, err, "accepted as %s", id.Value)
			assert.Equal(t, Identity{}, id)
		})
	}
}

// The canonical PURL forms produce exactly the identity the version names.
func TestCanonical_PURLAccepts(t *testing.T) {
	a := testHex
	rows := []struct{ name, raw string }{
		{"oci literal colon", "pkg:oci/app@sha256:" + a},
		{"oci encoded colon", "pkg:oci/app@sha256%3A" + a},
		{"oci lowercase encoded colon", "pkg:oci/app@sha256%3a" + a},
		// purl-spec tests/types/oci-test.json carries '/' unencoded in repository_url.
		{"oci spec vector", "pkg:oci/debian@sha256%3A" + a + "?repository_url=docker.io/library/debian&arch=amd64&tag=latest"},
		{"oci canonical qualifiers", "pkg:oci/debian@sha256:" + a + "?arch=amd64&repository_url=docker.io%2Flibrary%2Fdebian&tag=latest"},
		{"oci registry with port", "pkg:oci/app@sha256:" + a + "?repository_url=localhost:5000/app"},
		{"docker namespace", "pkg:docker/customer/dockerimage@sha256%3A" + a + "?repository_url=gcr.io"},
		{"docker subpath", "pkg:docker/library/alpine@sha256:" + a + "#sub/dir"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			id, err := Canonical(KindImageRegistryManifest, r.raw, NormalizationPURLVersion)
			require.NoError(t, err)
			assert.Equal(t, Identity{Kind: KindImageRegistryManifest, Algorithm: "sha256", Value: a}, id)
		})
	}
}

// The same property for the encoder's other readers: repo-at-digest, prefixed
// and bare hex.
func TestCanonical_SiblingReaders(t *testing.T) {
	a, b, upper := testHex, testHexAlt, strings.ToUpper(testHex)
	refused := []struct {
		name string
		rule Normalization
		raw  string
	}{
		{"repo: encoded @ in repo", NormalizationRepoAtDigest, "ghcr.io/org/app%40sha256:" + b + "@sha256:" + a},
		{"repo: ? in repo", NormalizationRepoAtDigest, "ghcr.io/org/app?x=@sha256:" + a},
		{"repo: # in repo", NormalizationRepoAtDigest, "ghcr.io/org/app#x@sha256:" + a},
		{"repo: encoded ? in repo", NormalizationRepoAtDigest, "ghcr.io/org/app%3Fx@sha256:" + a},
		{"repo: digest-shaped tag", NormalizationRepoAtDigest, "app:sha256:" + b + "@sha256:" + a},
		{"repo: two digests", NormalizationRepoAtDigest, "app@sha256:" + b + "@sha256:" + a},
		{"repo: @ after the digest", NormalizationRepoAtDigest, "app@sha256:" + a + "@"},
		{"repo: doubled @", NormalizationRepoAtDigest, "app@@sha256:" + a},
		{"repo: URL scheme", NormalizationRepoAtDigest, "https://ghcr.io/org/app@sha256:" + a},
		{"repo: empty path component", NormalizationRepoAtDigest, "ghcr.io//app@sha256:" + a},
		{"repo: leading slash", NormalizationRepoAtDigest, "/app@sha256:" + a},
		{"repo: empty tag", NormalizationRepoAtDigest, "app:@sha256:" + a},
		{"repo: uppercase path", NormalizationRepoAtDigest, "ghcr.io/Org/App@sha256:" + a},
		{"repo: tab in repo", NormalizationRepoAtDigest, "ghcr.io/org/\tapp@sha256:" + a},
		{"repo: encoded colon", NormalizationRepoAtDigest, "app@sha256%3A" + a},
		{"repo: uppercase hex", NormalizationRepoAtDigest, "app@sha256:" + upper},
		{"repo: 63 hex", NormalizationRepoAtDigest, "app@sha256:" + a[:63]},
		{"repo: 65 hex", NormalizationRepoAtDigest, "app@sha256:" + a + "0"},
		{"repo: sha512", NormalizationRepoAtDigest, "app@sha512:" + a + a},
		{"repo: trailing ?", NormalizationRepoAtDigest, "app@sha256:" + a + "?"},
		{"repo: trailing fragment", NormalizationRepoAtDigest, "app@sha256:" + a + "#x"},
		{"repo: empty digest", NormalizationRepoAtDigest, "app@"},
		{"repo: no digest", NormalizationRepoAtDigest, "app"},
		{"prefixed: second digest", NormalizationPrefixed, "sha256:" + a + "@sha256:" + b},
		{"prefixed: trailing ?", NormalizationPrefixed, "sha256:" + a + "?x"},
		{"prefixed: trailing fragment", NormalizationPrefixed, "sha256:" + a + "#x"},
		{"prefixed: encoded @", NormalizationPrefixed, "sha256:" + a + "%40"},
		{"prefixed: encoded hex digit", NormalizationPrefixed, "sha256:%65" + a[1:]},
		{"bare: second digest", NormalizationBareHex, a + "@sha256:" + b},
		{"bare: trailing ?", NormalizationBareHex, a + "?x"},
		{"bare: encoded hex digit", NormalizationBareHex, "%65" + a[1:]},
	}
	for _, r := range refused {
		t.Run(r.name, func(t *testing.T) {
			id, err := Canonical(KindImageRegistryManifest, r.raw, r.rule)
			require.Error(t, err, "accepted as %s", id.Value)
			assert.Equal(t, Identity{}, id)
		})
	}

	accepted := []string{
		"ghcr.io/org/app@sha256:" + a,
		"localhost:5000/app@sha256:" + a,
		"[::1]:5000/app@sha256:" + a,
		"alpine@sha256:" + a,
		"docker.io/library/alpine:3.20@sha256:" + a,
		"ghcr.io/org/my_app-x.y__z@sha256:" + a,
	}
	for _, raw := range accepted {
		t.Run("repo accepts "+raw[:strings.IndexByte(raw, '@')], func(t *testing.T) {
			id, err := Canonical(KindImageRegistryManifest, raw, NormalizationRepoAtDigest)
			require.NoError(t, err)
			assert.Equal(t, Identity{Kind: KindImageRegistryManifest, Algorithm: "sha256", Value: a}, id)
		})
	}
}

// The two readings the encoder compares, on inputs where they differ; each
// reading must be what it says, and readPURL must refuse the pair.
func TestSplitPURL_Readings(t *testing.T) {
	a, b := testHex, testHexAlt
	cases := []struct{ name, rest, first, last string }{
		{"codex example", "oci/app@sha256:" + a + "?x=@sha256:" + b + "?y=z", "sha256:" + a, "sha256:" + b},
		{"two version @", "oci/app@sha256:" + a + "@sha256:" + b, "sha256:" + a + "@sha256:" + b, "sha256:" + b},
		{"digest in subpath text", "oci/app@sha256:" + a + "#x@sha256:" + b + "#s", "sha256:" + a, "sha256:" + b},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first, ok := splitPURL(c.rest, false)
			require.True(t, ok)
			assert.Equal(t, c.first, first.version, "first-boundary reading")
			last, ok := splitPURL(c.rest, true)
			require.True(t, ok)
			assert.Equal(t, c.last, last.version, "right-to-left reading")
			_, ok = readPURL(c.rest)
			assert.False(t, ok, "the readings differ, so the input is refused")
		})
	}
}

type rendering struct {
	rule Normalization
	raw  string
}

// renderIdentity spells id in every canonical form each rule reads.
func renderIdentity(id Identity) []rendering {
	v := id.Value
	out := make([]rendering, 0, 24)
	out = append(out, rendering{NormalizationBareHex, v}, rendering{NormalizationPrefixed, "sha256:" + v})
	for _, repo := range []string{"ghcr.io/org/app", "localhost:5000/app", "alpine:3.20", "[::1]:5000/a"} {
		out = append(out, rendering{NormalizationRepoAtDigest, repo + "@sha256:" + v})
	}
	for _, base := range []string{"pkg:oci/app@", "pkg:docker/library/alpine@"} {
		for _, colon := range []string{"sha256:", "sha256%3A", "sha256%3a"} {
			for _, tail := range []string{"", "?arch=amd64&repository_url=ghcr.io%2Forg%2Fapp&tag=v1", "#sub"} {
				out = append(out, rendering{NormalizationPURLVersion, base + colon + v + tail})
			}
		}
	}
	return out
}

// Round trip: every canonical rendering of a generated identity encodes back
// to exactly that identity. Injective on the sample: no (kind, rule, raw)
// input is rendered from two identities. The kind is an input of Canonical,
// not part of the string, so it is part of the key.
func TestCanonical_RoundTripInjective(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	values := []string{strings.Repeat("0", 64), strings.Repeat("f", 64), testHex, testHexAlt}
	for len(values) < 300 {
		var b [32]byte
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		values = append(values, hex.EncodeToString(b[:]))
	}
	seen := map[[3]string]Identity{}
	for _, v := range values {
		for _, kind := range []AnchorKind{KindImageRegistryManifest, KindImageConfig} {
			id := Identity{Kind: kind, Algorithm: "sha256", Value: v}
			for _, r := range renderIdentity(id) {
				got, err := Canonical(kind, r.raw, r.rule)
				require.NoError(t, err, "%s %s", r.rule, r.raw)
				require.Equal(t, id, got, "%s %s", r.rule, r.raw)
				key := [3]string{string(kind), string(r.rule), r.raw}
				if prev, ok := seen[key]; ok {
					require.Equal(t, prev, id, "two identities render to %v", key)
				}
				seen[key] = id
			}
		}
	}
}

// purlVersionReadings returns the version of raw under four readings, written
// apart from the encoder: net/url's (first '#', first '?', then the last '@',
// as packageurl-go takes it), the purl specification's right-to-left
// procedure, a split at every first boundary, and that split after
// percent-decoding the whole string once.
func purlVersionReadings(raw string) []string {
	out := purlBoundaryReadings(raw)
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return append(out, "decoded: "+err.Error())
	}
	return append(out, purlBoundaryReadings(decoded)[2])
}

func purlBoundaryReadings(raw string) []string {
	var out []string
	if u, err := url.Parse(raw); err != nil {
		out = append(out, "net/url: "+err.Error())
	} else {
		_, rest, _ := strings.Cut(u.Opaque, "/")
		out = append(out, rest[strings.LastIndex(rest, "@")+1:])
	}

	rest := raw
	if i := strings.LastIndex(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "?"); i >= 0 {
		rest = rest[:i]
	}
	_, rest, _ = strings.Cut(rest, ":")
	_, rest, _ = strings.Cut(strings.TrimLeft(rest, "/"), "/")
	out = append(out, rest[strings.LastIndex(rest, "@")+1:])

	rest, _, _ = strings.Cut(raw, "#")
	rest, _, _ = strings.Cut(rest, "?")
	_, version, _ := strings.Cut(rest, "@")
	return append(out, version)
}

// Whatever the encoder accepts, the digest it returns is the one the version
// names under every reading, and nothing else in the input can be read as it.
func FuzzCanonical(f *testing.F) {
	a, b := testHex, testHexAlt
	for _, seed := range []string{
		"pkg:oci/app@sha256:" + a + "?x=@sha256:" + b + "?y=z",
		"pkg:oci/app@sha256:" + b + "@sha256:" + a,
		"pkg:oci/app%40sha256:" + b + "@sha256:" + a,
		"pkg:oci/app@sha256:" + a + "#s@x",
		"pkg:oci/app@sha256%3A" + a + "?repository_url=ghcr.io/org/app&arch=amd64",
		"pkg:docker/library/alpine@sha256:" + a + "#sub",
		"ghcr.io/org/app%40sha256:" + b + "@sha256:" + a,
		"localhost:5000/app@sha256:" + a,
		"sha256:" + a,
		a,
	} {
		for rule := range 4 {
			f.Add(seed, uint8(rule))
		}
	}
	rules := []Normalization{NormalizationBareHex, NormalizationPrefixed, NormalizationRepoAtDigest, NormalizationPURLVersion}
	f.Fuzz(func(t *testing.T, raw string, ruleIndex uint8) {
		rule := rules[int(ruleIndex)%len(rules)]
		id, err := Canonical(KindImageRegistryManifest, raw, rule)
		if err != nil {
			return
		}
		decoded, err := hex.DecodeString(id.Value)
		require.NoError(t, err)
		require.Len(t, decoded, sha256.Size)
		require.Equal(t, strings.ToLower(id.Value), id.Value)
		switch rule {
		case NormalizationBareHex:
			require.Equal(t, raw, id.Value)
		case NormalizationPrefixed:
			require.Equal(t, "sha256:"+id.Value, raw)
		case NormalizationRepoAtDigest:
			require.Equal(t, 1, strings.Count(raw, "@"), raw)
			require.True(t, strings.HasSuffix(raw, "@sha256:"+id.Value), raw)
			if decoded, err := url.PathUnescape(raw); err == nil {
				require.Equal(t, 1, strings.Count(decoded, "@"), "percent-decoding reads a second digest: %s", raw)
			}
		case NormalizationPURLVersion:
			for _, version := range purlVersionReadings(raw) {
				unescaped, err := url.PathUnescape(version)
				require.NoError(t, err, raw)
				require.Equal(t, "sha256:"+id.Value, unescaped, raw)
			}
		}
	})
}

type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
}

func writeArchive(t *testing.T, entries ...tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: tf}
		if tf == tar.TypeSymlink {
			hdr.Linkname = "elsewhere"
		} else {
			hdr.Size = int64(len(e.body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if hdr.Size > 0 {
			_, err := tw.Write(e.body)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	p := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))
	return p
}

func TestMeasureOCIConfigBlob(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	sum := sha256.Sum256(config)
	configName := "blobs/sha256/" + hex.EncodeToString(sum[:])
	manifest := []byte(`[{"Config":"` + configName + `","RepoTags":["app:latest"],"Layers":[]}]`)

	measure, ok := LookupMeasurement(MeasurementOCIConfigBlob)
	require.True(t, ok)

	t.Run("config after manifest", func(t *testing.T) {
		got, err := measure(writeArchive(t, tarEntry{name: "manifest.json", body: manifest}, tarEntry{name: configName, body: config}))
		require.NoError(t, err)
		assert.Equal(t, config, got)
	})
	t.Run("config before manifest", func(t *testing.T) {
		got, err := measure(writeArchive(t, tarEntry{name: configName, body: config}, tarEntry{name: "layer.tar", body: []byte("x")}, tarEntry{name: "manifest.json", body: manifest}))
		require.NoError(t, err)
		assert.Equal(t, config, got)
	})
	t.Run("config under directory entries", func(t *testing.T) {
		got, err := measure(writeArchive(t,
			tarEntry{name: "blobs/", typeflag: tar.TypeDir}, tarEntry{name: "blobs/sha256/", typeflag: tar.TypeDir},
			tarEntry{name: "manifest.json", body: manifest}, tarEntry{name: configName, body: config}))
		require.NoError(t, err)
		assert.Equal(t, config, got)
	})
	t.Run("replaced config blob measures differently", func(t *testing.T) {
		got, err := measure(writeArchive(t, tarEntry{name: "manifest.json", body: manifest}, tarEntry{name: configName, body: []byte(`{"os":"windows"}`)}))
		require.NoError(t, err)
		gotSum := sha256.Sum256(got)
		assert.NotEqual(t, sum, gotSum)
	})
	// A second entry that extracts to the path read, or a link in its parent
	// path, gives an extracting reader (docker load keeps the last copy and
	// follows the link) other bytes than a reader that keeps the first.
	other := []byte(`[{"Config":"other"}]`)
	refusals := map[string][]tarEntry{
		"duplicate manifest entry":         {{name: "manifest.json", body: manifest}, {name: "manifest.json", body: other}, {name: configName, body: config}},
		"duplicate config entry":           {{name: "manifest.json", body: manifest}, {name: configName, body: config}, {name: configName, body: []byte("{}")}},
		"dot-slash manifest duplicate":     {{name: "manifest.json", body: manifest}, {name: "./manifest.json", body: other}, {name: configName, body: config}},
		"rooted manifest duplicate":        {{name: "manifest.json", body: manifest}, {name: "/manifest.json", body: other}, {name: configName, body: config}},
		"case-variant manifest duplicate":  {{name: "manifest.json", body: manifest}, {name: "Manifest.json", body: other}, {name: configName, body: config}},
		"dot-slash config duplicate":       {{name: "manifest.json", body: manifest}, {name: configName, body: config}, {name: "./" + configName, body: []byte("{}")}},
		"config under a symlinked parent":  {{name: "blobs", typeflag: tar.TypeSymlink}, {name: "manifest.json", body: manifest}, {name: configName, body: config}},
		"manifest only under another name": {{name: "../manifest.json", body: manifest}, {name: configName, body: config}},
		"non-canonical config path": {
			{name: "manifest.json", body: []byte(`[{"Config":"./` + configName + `"}]`)}, {name: "./" + configName, body: config},
		},
		"Config named twice": {
			{name: "manifest.json", body: []byte(`[{"Config":"other","Config":"` + configName + `"}]`)}, {name: configName, body: config},
		},
		"Config in two spellings": {
			{name: "manifest.json", body: []byte(`[{"Config":"` + configName + `","config":"other"}]`)}, {name: configName, body: config}, {name: "other", body: []byte("{}")},
		},
		"no manifest":             {{name: configName, body: config}},
		"empty manifest list":     {{name: "manifest.json", body: []byte(`[]`)}, {name: configName, body: config}},
		"manifest not json":       {{name: "manifest.json", body: []byte(`nope`)}, {name: configName, body: config}},
		"manifest without config": {{name: "manifest.json", body: []byte(`[{"Config":""}]`)}, {name: configName, body: config}},
		"config missing":          {{name: "manifest.json", body: manifest}},
		"empty config":            {{name: "manifest.json", body: manifest}, {name: configName, body: []byte{}}},
		"manifest is a symlink":   {{name: "manifest.json", typeflag: tar.TypeSymlink}, {name: "manifest.json", body: manifest}, {name: configName, body: config}},
		"config is a symlink":     {{name: "manifest.json", body: manifest}, {name: configName, typeflag: tar.TypeSymlink}, {name: configName, body: config}},
		// A contiguous-file entry carries data the tar reader returns; only a
		// regular file is an image blob.
		"config is not a regular file": {{name: "manifest.json", body: manifest}, {name: configName, typeflag: tar.TypeCont, body: config}},
	}
	for name, entries := range refusals {
		t.Run(name, func(t *testing.T) {
			got, err := measure(writeArchive(t, entries...))
			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
	t.Run("missing file", func(t *testing.T) {
		_, err := measure(filepath.Join(t.TempDir(), "absent.tar"))
		require.Error(t, err)
	})
	t.Run("not a tar", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.tar")
		require.NoError(t, os.WriteFile(p, []byte("not a tar archive at all"), 0o600))
		_, err := measure(p)
		require.Error(t, err)
	})
}
