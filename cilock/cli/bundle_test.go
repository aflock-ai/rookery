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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/bundle"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleInspect_HumanOutput(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.bundle.tar.gz")

	f, err := os.Create(bundlePath)
	require.NoError(t, err)

	w := bundle.NewWriter(f)
	w.SetSource(bundle.SourceArchivista, "https://archivista.example.com")
	w.SetSubjects([]string{"sha256:abc"})

	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://aflock.ai/attestations/test/v0.1",
		Subject: []intoto.Subject{
			{Name: "x", Digest: map[string]string{"sha256": "abc"}},
		},
		Predicate: json.RawMessage(`{"name":"my-step","attestations":[]}`),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)

	require.NoError(t, w.Add(dsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
		Signatures:  []dsse.Signature{{KeyID: "signer-k", Signature: []byte("s")}},
	}))
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	var out bytes.Buffer
	require.NoError(t, runBundleInspect(bundlePath, false, &out))

	s := out.String()
	assert.Contains(t, s, "Bundle: "+bundlePath)
	assert.Contains(t, s, bundle.SchemaVersion)
	assert.Contains(t, s, "source:    archivista")
	assert.Contains(t, s, "sha256:abc")
	assert.Contains(t, s, "envelopes: 1")
	assert.Contains(t, s, "https://aflock.ai/attestations/test/v0.1")
	assert.Contains(t, s, "collection=my-step")
	assert.Contains(t, s, "signers=[signer-k]")
}

func TestBundleInspect_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.bundle.tar.gz")

	f, err := os.Create(bundlePath)
	require.NoError(t, err)

	w := bundle.NewWriter(f)
	w.SetSubjects([]string{"sha256:zzz"})
	require.NoError(t, w.Add(dsse.Envelope{PayloadType: "x", Payload: []byte(`{}`)}))
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	var out bytes.Buffer
	require.NoError(t, runBundleInspect(bundlePath, true, &out))

	var mani bundle.Manifest
	require.NoError(t, json.Unmarshal(out.Bytes(), &mani))
	require.Equal(t, []string{"sha256:zzz"}, mani.Subjects)
	require.Equal(t, 1, mani.Count)
}

func TestBundleCreate_PullsFromArchivista(t *testing.T) {
	envA := envelopeWithSubjectDigests(t, []string{"d-1", "d-2"})
	envB := envelopeWithSubjectDigests(t, []string{"d-2"})

	mux := http.NewServeMux()
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Variables struct {
				SubjectDigests []string `json:"subjectDigests"`
				ExcludeGitoids []string `json:"excludeGitoids"`
			} `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		type edge struct {
			Node struct {
				Gitoid string `json:"gitoidSha256"`
			} `json:"node"`
		}
		var edges []edge
		excluded := map[string]struct{}{}
		for _, g := range req.Variables.ExcludeGitoids {
			excluded[g] = struct{}{}
		}
		for _, sub := range req.Variables.SubjectDigests {
			switch sub {
			case "d-1":
				if _, ok := excluded["g-a"]; !ok {
					e := edge{}
					e.Node.Gitoid = "g-a"
					edges = append(edges, e)
				}
			case "d-2":
				if _, ok := excluded["g-b"]; !ok {
					e := edge{}
					e.Node.Gitoid = "g-b"
					edges = append(edges, e)
				}
			}
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"dsses": map[string]any{"edges": edges},
			},
		}))
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/g-a"):
			require.NoError(t, json.NewEncoder(w).Encode(envA))
		case strings.HasSuffix(r.URL.Path, "/g-b"):
			require.NoError(t, json.NewEncoder(w).Encode(envB))
		default:
			http.NotFound(w, r)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.bundle.tar.gz")

	err := runBundleCreate(context.Background(), bundleCreateOptions{
		Subjects:      []string{"d-1"},
		ArchivistaURL: srv.URL,
		Output:        outPath,
		MaxEnvelopes:  10,
		MaxDepth:      3,
	})
	require.NoError(t, err)

	f, err := os.Open(outPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := bundle.Read(f)
	require.NoError(t, err)
	envs, err := r.Envelopes()
	require.NoError(t, err)
	assert.Len(t, envs, 2, "should have walked the subject graph from d-1 to d-2")
	assert.Equal(t, bundle.SourceArchivista, r.Manifest().Source)
	assert.Equal(t, srv.URL, r.Manifest().SourceURL)
}

func TestBundleCreate_RequiresFlags(t *testing.T) {
	cases := []struct {
		name string
		opts bundleCreateOptions
		want string
	}{
		{
			name: "missing output",
			opts: bundleCreateOptions{Subjects: []string{"x"}, ArchivistaURL: "u"},
			want: "--output is required",
		},
		{
			name: "missing subject",
			opts: bundleCreateOptions{Output: "o", ArchivistaURL: "u"},
			want: "--subject is required",
		},
		{
			name: "missing archivista url",
			opts: bundleCreateOptions{Output: "o", Subjects: []string{"x"}},
			want: "--archivista-url is required",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := BundleCmd()
			args := []string{"create"}
			if c.opts.Output != "" {
				args = append(args, "--output", c.opts.Output)
			}
			for _, s := range c.opts.Subjects {
				args = append(args, "--subject", s)
			}
			if c.opts.ArchivistaURL != "" {
				args = append(args, "--archivista-url", c.opts.ArchivistaURL)
			}
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}

// TestBundleCreate_FromAttestationFiles covers the offline path: caller
// supplies one or more local DSSE envelope files via --attestation; the
// command packages them verbatim with no Archivista round trip. This is
// the path the release workflow uses to build the offline-replay bundle
// shipped with every GitHub Release.
func TestBundleCreate_FromAttestationFiles(t *testing.T) {
	dir := t.TempDir()

	// Write two DSSE envelopes to disk in the same shape cilock-action
	// emits (`*.attestation.json`).
	envA := envelopeWithSubjectDigests(t, []string{"a-1"})
	envB := envelopeWithSubjectDigests(t, []string{"b-1"})

	pathA := filepath.Join(dir, "a.attestation.json")
	pathB := filepath.Join(dir, "b.attestation.json")
	for path, env := range map[string]dsse.Envelope{pathA: envA, pathB: envB} {
		raw, err := json.Marshal(env)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, raw, 0o600))
	}

	outPath := filepath.Join(dir, "out.bundle.tar.gz")

	err := runBundleCreate(context.Background(), bundleCreateOptions{
		Attestations: []string{pathA, pathB},
		Output:       outPath,
	})
	require.NoError(t, err)

	f, err := os.Open(outPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := bundle.Read(f)
	require.NoError(t, err)
	envs, err := r.Envelopes()
	require.NoError(t, err)
	assert.Len(t, envs, 2, "both supplied envelopes must end up in the bundle")
	assert.Equal(t, bundle.SourceFile, r.Manifest().Source,
		"source should record local file origin, not archivista")
}

// TestBundleCreate_RequiresEitherAttestationsOrArchivista verifies the
// CLI rejects a call with neither input source.
func TestBundleCreate_RequiresEitherAttestationsOrArchivista(t *testing.T) {
	err := runBundleCreate(context.Background(), bundleCreateOptions{
		Output: filepath.Join(t.TempDir(), "out.tar.gz"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--attestation",
		"error should mention the file input flag")
}

func envelopeWithSubjectDigests(t *testing.T, digests []string) dsse.Envelope {
	t.Helper()
	subjects := make([]intoto.Subject, 0, len(digests))
	for _, d := range digests {
		subjects = append(subjects, intoto.Subject{
			Name:   d,
			Digest: map[string]string{"sha256": d},
		})
	}
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://example.com/test",
		Subject:       subjects,
		Predicate:     json.RawMessage(`{}`),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	return dsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
	}
}
