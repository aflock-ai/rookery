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
	"github.com/aflock-ai/rookery/attestation/gitoid"
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
	bodyA, err := json.Marshal(envA)
	require.NoError(t, err)
	bodyB, err := json.Marshal(envB)
	require.NoError(t, err)
	gitoidA := bundleTestGitoid(bodyA)
	gitoidB := bundleTestGitoid(bodyB)

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
				if _, ok := excluded[gitoidA]; !ok {
					e := edge{}
					e.Node.Gitoid = gitoidA
					edges = append(edges, e)
				}
			case "d-2":
				if _, ok := excluded[gitoidB]; !ok {
					e := edge{}
					e.Node.Gitoid = gitoidB
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
		case strings.HasSuffix(r.URL.Path, "/"+gitoidA):
			_, err := w.Write(bodyA)
			require.NoError(t, err)
		case strings.HasSuffix(r.URL.Path, "/"+gitoidB):
			_, err := w.Write(bodyB)
			require.NoError(t, err)
		default:
			http.NotFound(w, r)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.bundle.tar.gz")

	err = runBundleCreate(context.Background(), bundleCreateOptions{
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

func bundleTestGitoid(content []byte) string {
	// Shared implementation — the same one the Archivista client uses for
	// mismatch checks — so the test can't drift from the real gitoid rules
	// (header format, hash options, content-length handling).
	g, err := gitoid.New(bytes.NewReader(content), gitoid.WithSha256(), gitoid.WithContentLength(int64(len(content))))
	if err != nil {
		panic(err)
	}
	return g.String()
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

// An absent --archivista-url is not an error any more: it defaults to the
// platform's own Archivista, the same derivation every sibling command uses
// (run, verify, policy push, policy from-commit). The operator-visible failure
// this pins against is the one measured on 2026-08-28: `cilock bundle create`
// demanded a URL and then 401ed against the platform, for a command whose
// sibling commands authenticate automatically.
func TestBundleCreate_DefaultsToPlatformArchivista(t *testing.T) {
	cmd := BundleCmd()
	cmd.SetArgs([]string{"create", "--output", filepath.Join(t.TempDir(), "b.tgz"), "--subject", "sha256:" + strings.Repeat("a", 64)})
	err := cmd.Execute()
	// The fetch against the real default platform fails in a unit test — the
	// property under test is only that the missing flag is no longer refused
	// up front.
	if err != nil {
		require.NotContains(t, err.Error(), "--archivista-url is required")
	}
}

// The login-session bearer must reach the platform's own Archivista and must
// NOT leak to a third-party --archivista-url. Asserted through the header the
// server actually receives, not through any intermediate state.
func TestBundleCreate_SessionBearerIsSameOriginOnly(t *testing.T) {
	var got []string
	mux := http.NewServeMux()
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"dsses": map[string]any{"edges": []any{}}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Explicit --archivista-headers always win and always attach.
	cmd := BundleCmd()
	cmd.SetArgs([]string{"create",
		"--output", filepath.Join(t.TempDir(), "b.tgz"),
		"--subject", "sha256:" + strings.Repeat("b", 64),
		"--archivista-url", srv.URL,
		"--archivista-headers", "Authorization: Bearer explicit-token"})
	require.NoError(t, cmd.Execute())
	require.NotEmpty(t, got)
	require.Equal(t, "Bearer explicit-token", got[0],
		"an explicit Authorization header must be sent verbatim")

	// A third-party target with no explicit header gets NO bearer: the stored
	// session (if any exists on this machine) must not leak off-platform.
	got = nil
	cmd = BundleCmd()
	cmd.SetArgs([]string{"create",
		"--output", filepath.Join(t.TempDir(), "c.tgz"),
		"--subject", "sha256:" + strings.Repeat("c", 64),
		"--archivista-url", srv.URL})
	require.NoError(t, cmd.Execute())
	require.NotEmpty(t, got)
	require.Equal(t, "", got[0],
		"a session bearer must never be attached to a non-platform archivista URL")
}

// THE SAME-ORIGIN HALF, which the leak test cannot cover on its own.
//
// TestBundleCreate_SessionBearerIsSameOriginOnly asserts that a third-party
// archivista receives NO bearer — but in a unit test there is normally no
// stored credential at all, so that assertion holds whether or not the lookup
// exists. Deleting the auth.Lookup block would leave it green.
//
// This stores a real credential FOR THE SERVER'S OWN ORIGIN and requires the
// bearer to arrive. Now the two tests bracket the rule from both sides: the
// session reaches its own platform, and it reaches nowhere else.
func TestBundleCreate_SessionBearerReachesItsOwnPlatform(t *testing.T) {
	var got []string
	mux := http.NewServeMux()
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"dsses": map[string]any{"edges": []any{}}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The credential is stored for THIS server, and the command is pointed at
	// the same origin — the one case where the bearer must be attached.
	stubSession(t, srv.URL)

	cmd := BundleCmd()
	cmd.SetArgs([]string{"create",
		"--output", filepath.Join(t.TempDir(), "same-origin.tgz"),
		"--subject", "sha256:" + strings.Repeat("d", 64),
		"--platform-url", srv.URL,
		"--archivista-url", srv.URL})
	require.NoError(t, cmd.Execute())

	require.NotEmpty(t, got, "the archivista query must have been made")
	require.Equal(t, "Bearer test-session-token", got[0],
		"a stored session must authenticate the platform's own archivista; without this the "+
			"command 401s against the platform the user is already logged in to")
}
