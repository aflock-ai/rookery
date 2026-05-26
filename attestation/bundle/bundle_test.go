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

package bundle_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/bundle"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeEnvelope(t *testing.T, payloadType, payload, keyID string) dsse.Envelope {
	t.Helper()
	return dsse.Envelope{
		PayloadType: payloadType,
		Payload:     []byte(payload),
		Signatures: []dsse.Signature{
			{KeyID: keyID, Signature: []byte("sig-" + keyID)},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := bundle.NewWriter(&buf)
	w.SetSource(bundle.SourceArchivista, "https://archivista.example.com")
	w.SetSubjects([]string{"sha256:b", "sha256:a"})
	w.SetCreatedAt(time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC))

	env1 := makeEnvelope(t, "application/vnd.in-toto+json", `{"_type":"link","subject":[{"digest":{"sha256":"a"}}]}`, "key-1")
	env2 := makeEnvelope(t, "application/vnd.in-toto+json", `{"_type":"link","subject":[{"digest":{"sha256":"b"}}]}`, "key-2")

	require.NoError(t, w.Add(env1))
	require.NoError(t, w.Add(env2))
	require.NoError(t, w.Close())
	require.Equal(t, 2, w.Count())

	r, err := bundle.Read(&buf)
	require.NoError(t, err)

	mani := r.Manifest()
	require.Equal(t, bundle.SchemaVersion, mani.SchemaVersion)
	require.Equal(t, bundle.SourceArchivista, mani.Source)
	require.Equal(t, "https://archivista.example.com", mani.SourceURL)
	require.Equal(t, []string{"sha256:a", "sha256:b"}, mani.Subjects, "subjects must be sorted")
	require.Equal(t, 2, mani.Count)
	require.Len(t, mani.Envelopes, 2)
	require.Equal(t, "application/vnd.in-toto+json", mani.Envelopes[0].PayloadType)
	require.Equal(t, []string{"key-1"}, mani.Envelopes[0].SignerKeyIDs)

	envs, err := r.Envelopes()
	require.NoError(t, err)
	require.Len(t, envs, 2)
	assert.Equal(t, env1.Payload, envs[0].Payload)
	assert.Equal(t, env2.Payload, envs[1].Payload)
	assert.Equal(t, "key-1", envs[0].Signatures[0].KeyID)
}

func TestDeduplicatesIdenticalEnvelopes(t *testing.T) {
	var buf bytes.Buffer
	w := bundle.NewWriter(&buf)

	env := makeEnvelope(t, "x", `{"a":1}`, "k")
	require.NoError(t, w.Add(env))
	require.NoError(t, w.Add(env))
	require.NoError(t, w.Add(env))
	require.NoError(t, w.Close())
	require.Equal(t, 1, w.Count())

	r, err := bundle.Read(&buf)
	require.NoError(t, err)

	envs, err := r.Envelopes()
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

func TestAddAfterCloseFails(t *testing.T) {
	var buf bytes.Buffer
	w := bundle.NewWriter(&buf)
	require.NoError(t, w.Close())

	err := w.Add(makeEnvelope(t, "x", `{}`, "k"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestTamperedJSONLDetected(t *testing.T) {
	var buf bytes.Buffer
	w := bundle.NewWriter(&buf)
	require.NoError(t, w.Add(makeEnvelope(t, "type-one", `{"a":1}`, "k1")))
	require.NoError(t, w.Add(makeEnvelope(t, "type-two", `{"a":2}`, "k2")))
	require.NoError(t, w.Close())

	tampered := tamperBundle(t, buf.Bytes(), bundle.EnvelopesFilename, func(orig []byte) []byte {
		return bytes.Replace(orig, []byte(`"payloadType":"type-two"`), []byte(`"payloadType":"type-evil"`), 1)
	})

	r, err := bundle.Read(bytes.NewReader(tampered))
	require.NoError(t, err, "read should succeed; integrity check happens during Envelopes()")

	_, err = r.Envelopes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "digest mismatch")
}

func TestMissingManifest(t *testing.T) {
	buf := buildTarGz(t, map[string][]byte{
		bundle.EnvelopesFilename: []byte("{}\n"),
	})
	_, err := bundle.Read(bytes.NewReader(buf))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing bundle.json")
}

func TestMissingEnvelopes(t *testing.T) {
	mani, err := json.Marshal(bundle.Manifest{SchemaVersion: bundle.SchemaVersion})
	require.NoError(t, err)
	buf := buildTarGz(t, map[string][]byte{
		bundle.ManifestFilename: mani,
	})
	_, err = bundle.Read(bytes.NewReader(buf))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing attestations.jsonl")
}

func TestRejectsNonGzipInput(t *testing.T) {
	_, err := bundle.Read(strings.NewReader("not a gzip stream"))
	require.Error(t, err)
}

func TestEmptyBundleReadsCleanly(t *testing.T) {
	var buf bytes.Buffer
	w := bundle.NewWriter(&buf)
	require.NoError(t, w.Close())

	r, err := bundle.Read(&buf)
	require.NoError(t, err)
	require.Equal(t, 0, r.Manifest().Count)

	envs, err := r.Envelopes()
	require.NoError(t, err)
	require.Empty(t, envs)
}

func TestForwardCompatUnknownEntries(t *testing.T) {
	var buf bytes.Buffer
	w := bundle.NewWriter(&buf)
	require.NoError(t, w.Add(makeEnvelope(t, "x", `{}`, "k")))
	require.NoError(t, w.Close())

	withExtra := tamperBundle(t, buf.Bytes(), "", nil)
	withExtra = injectTarEntry(t, withExtra, "future-signature.sig", []byte("not-real"))

	r, err := bundle.Read(bytes.NewReader(withExtra))
	require.NoError(t, err)
	envs, err := r.Envelopes()
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

func TestMissingEnvelopesInManifestSkipsCheck(t *testing.T) {
	mani := bundle.Manifest{
		SchemaVersion: bundle.SchemaVersion,
		CreatedAt:     time.Now().UTC(),
		Count:         1,
	}
	maniBytes, err := json.Marshal(mani)
	require.NoError(t, err)

	env := makeEnvelope(t, "x", `{"hello":"world"}`, "k")
	envBytes, err := json.Marshal(env)
	require.NoError(t, err)

	buf := buildTarGz(t, map[string][]byte{
		bundle.ManifestFilename:  maniBytes,
		bundle.EnvelopesFilename: append(envBytes, '\n'),
	})

	r, err := bundle.Read(bytes.NewReader(buf))
	require.NoError(t, err)
	envs, err := r.Envelopes()
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

func buildTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func tamperBundle(t *testing.T, in []byte, name string, mutator func([]byte) []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(in))
	require.NoError(t, err)
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)

	out := bytes.Buffer{}
	wgz := gzip.NewWriter(&out)
	tw := tar.NewWriter(wgz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		body := make([]byte, hdr.Size)
		require.NoError(t, readFull(tr, body))
		if name != "" && hdr.Name == name && mutator != nil {
			body = mutator(body)
			hdr.Size = int64(len(body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, wgz.Close())
	return out.Bytes()
}

func injectTarEntry(t *testing.T, in []byte, name string, body []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(in))
	require.NoError(t, err)
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)

	out := bytes.Buffer{}
	wgz := gzip.NewWriter(&out)
	tw := tar.NewWriter(wgz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		buf := make([]byte, hdr.Size)
		require.NoError(t, readFull(tr, buf))
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = tw.Write(buf)
		require.NoError(t, err)
	}
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}))
	_, err = tw.Write(body)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, wgz.Close())
	return out.Bytes()
}

func readFull(r interface{ Read([]byte) (int, error) }, p []byte) error {
	read := 0
	for read < len(p) {
		n, err := r.Read(p[read:])
		read += n
		if err != nil {
			if read == len(p) {
				return nil
			}
			return err
		}
	}
	return nil
}
