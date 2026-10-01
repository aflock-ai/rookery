// jade:ring local
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

package oci

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// #8082: manifest.json is read whole (up to maxTarEntrySize) and used to be
// handed to json.Unmarshal, which turns 3 bytes of `{},` into a ~80-byte
// Manifest struct and 3 bytes of `"",` into a 16-byte string header. The read
// was bounded; the expansion was not, and maxLayerCount was only checked after
// the slice existed. The decode must refuse past its limits while decoding.

func manifestTar(t *testing.T, manifest []byte) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest))}))
	_, err := tw.Write(manifest)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	p := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))
	return p
}

func manifestCtx(t *testing.T) *attestation.AttestationContext {
	t.Helper()
	ctx, err := attestation.NewContext("manifest-bounds", nil)
	require.NoError(t, err)
	return ctx
}

func parseManifestJSON(t *testing.T, manifest []byte) ([]Manifest, error) {
	t.Helper()
	a := New()
	a.tarFilePath = manifestTar(t, manifest)
	err := a.parseMaifest(manifestCtx(t))
	return a.Manifest, err
}

func repeatJSONArray(elem string, n int) []byte {
	var b bytes.Buffer
	b.Grow(n*(len(elem)+1) + 2)
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(elem)
	}
	b.WriteByte(']')
	return b.Bytes()
}

func TestParseManifest_RefusesTooManyImages(t *testing.T) {
	_, err := parseManifestJSON(t, repeatJSONArray(`{}`, maxManifestEntries+1))
	require.ErrorContains(t, err, fmt.Sprintf("more than %d images", maxManifestEntries))

	got, err := parseManifestJSON(t, repeatJSONArray(`{"Config":"c"}`, maxManifestEntries))
	require.NoError(t, err, "exactly the limit is accepted")
	require.Len(t, got, maxManifestEntries)
}

func TestParseManifest_RefusesTooManyLayersWhileDecoding(t *testing.T) {
	layers := repeatJSONArray(`"l"`, maxLayerCount+1)
	_, err := parseManifestJSON(t, []byte(`[{"Config":"c","Layers":`+string(layers)+`}]`))
	require.ErrorContains(t, err, fmt.Sprintf("more than %d layers", maxLayerCount))

	tags := repeatJSONArray(`"t"`, maxRepoTags+1)
	_, err = parseManifestJSON(t, []byte(`[{"Config":"c","RepoTags":`+string(tags)+`}]`))
	require.ErrorContains(t, err, fmt.Sprintf("more than %d repo tags", maxRepoTags))
}

// The property itself: what decoding allocates is bounded by the input, not
// multiplied by it. 4 MiB of `{},` is ~1.4M structs (~110 MB plus slice growth)
// under json.Unmarshal.
func TestParseManifest_AllocationIsBoundedByInput(t *testing.T) {
	manifest := repeatJSONArray(`{}`, 4<<20/3)
	ctx := manifestCtx(t)
	a := New()
	a.tarFilePath = manifestTar(t, manifest)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := a.parseMaifest(ctx)
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	require.Less(t, allocated, uint64(4*len(manifest)),
		"parseMaifest allocated %d bytes for a %d-byte manifest.json", allocated, len(manifest))
	require.Error(t, err)
}

// Everything json.Unmarshal accepted for a real manifest decodes the same way.
func TestParseManifest_MatchesUnmarshalOnValidInput(t *testing.T) {
	inputs := []string{
		`[{"Config":"config.json","RepoTags":["a:1","b:2"],"Layers":["l1.tar","l2.tar"]}]`,
		`[{"config":"lower.json","repotags":["x:y"],"layers":["z.tar"],"Extra":{"nested":[1,2,{"k":null}]}}]`,
		`[{"Config":"c","Layers":null,"RepoTags":[]},{"Config":"d","Layers":["e"]}]`,
		`[{"Config":"c","Layers":["a",null,"b"]}]`,
		` [ { "Config" : "c" } ] `,
		`[]`,
	}
	for _, in := range inputs {
		t.Run(strings.TrimSpace(in), func(t *testing.T) {
			var want []Manifest
			require.NoError(t, json.Unmarshal([]byte(in), &want))
			got, err := decodeManifestList([]byte(in))
			require.NoError(t, err)
			require.Equal(t, len(want), len(got))
			for i := range want {
				require.Equal(t, want[i].Config, got[i].Config)
				require.Equal(t, want[i].RepoTags, got[i].RepoTags)
				require.Equal(t, want[i].Layers, got[i].Layers)
			}
		})
	}

	for _, bad := range []string{`[{}] trailing`, `{"Config":"c"}`, `[1]`, `[{"Layers":[1]}]`, `[{"Config":5}]`, `[{"Config":"c"}`, `[{"Layers":"x"}]`} {
		t.Run("refuses "+bad, func(t *testing.T) {
			var want []Manifest
			require.Error(t, json.Unmarshal([]byte(bad), &want), "json.Unmarshal refuses it too")
			_, err := decodeManifestList([]byte(bad))
			require.Error(t, err)
		})
	}
}
