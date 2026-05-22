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

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/bundle"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteOutputBundle_MergesLoadedAndArchivista(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.bundle.tar.gz")

	loaded := []dsse.Envelope{
		{PayloadType: "from-file", Payload: []byte(`{"k":1}`)},
	}
	fetched := []dsse.Envelope{
		{PayloadType: "from-archivista", Payload: []byte(`{"k":2}`)},
		{PayloadType: "from-archivista", Payload: []byte(`{"k":3}`)},
	}

	err := writeOutputBundle(out, []string{"sha256:abc"}, bundle.SourceVerifyExport, "https://archivista.example.com", loaded, fetched)
	require.NoError(t, err)

	f, err := os.Open(out)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := bundle.Read(f)
	require.NoError(t, err)

	mani := r.Manifest()
	assert.Equal(t, bundle.SourceVerifyExport, mani.Source)
	assert.Equal(t, "https://archivista.example.com", mani.SourceURL)
	assert.Equal(t, []string{"sha256:abc"}, mani.Subjects)
	assert.Equal(t, 3, mani.Count, "1 loaded + 2 archivista-fetched")

	envs, err := r.Envelopes()
	require.NoError(t, err)
	require.Len(t, envs, 3)
}

func TestLoadEnvelopesFromBundle_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "in.bundle.tar.gz")

	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://aflock.ai/attestations/test/v0.1","subject":[{"name":"x","digest":{"sha256":"a"}}],"predicate":{"name":"step1","attestations":[]}}`)
	env := dsse.Envelope{Payload: stmt, PayloadType: "application/vnd.in-toto+json"}

	f, err := os.Create(bundlePath)
	require.NoError(t, err)
	w := bundle.NewWriter(f)
	require.NoError(t, w.Add(env))
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	mem := source.NewMemorySource()
	envs, err := loadEnvelopesFromBundle(bundlePath, mem)
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

func TestLoadEnvelopesFromBundle_RejectsCorruptBundle(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.bundle.tar.gz")
	require.NoError(t, os.WriteFile(bad, []byte("not a gzip stream"), 0o644))

	mem := source.NewMemorySource()
	_, err := loadEnvelopesFromBundle(bad, mem)
	require.Error(t, err)
}

func TestVerifyCmd_BundleFlagsRegistered(t *testing.T) {
	cmd := VerifyCmd()

	bundleFlag := cmd.Flags().Lookup("bundle")
	require.NotNil(t, bundleFlag, "verify must register --bundle")
	assert.Equal(t, "stringSlice", bundleFlag.Value.Type())

	outFlag := cmd.Flags().Lookup("output-bundle")
	require.NotNil(t, outFlag, "verify must register --output-bundle")
	assert.Equal(t, "string", outFlag.Value.Type())
	assert.Empty(t, outFlag.DefValue)
	assert.Contains(t, outFlag.Usage, "tar.gz")
}

func TestWriteOutputBundle_ParsesAsValidJSON(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.bundle.tar.gz")
	require.NoError(t, writeOutputBundle(out, []string{"s"}, bundle.SourceFile, "", nil, nil))

	f, err := os.Open(out)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := bundle.Read(f)
	require.NoError(t, err)
	mani := r.Manifest()
	maniJSON, err := json.Marshal(mani)
	require.NoError(t, err)
	require.Contains(t, string(maniJSON), "schemaVersion")
}
