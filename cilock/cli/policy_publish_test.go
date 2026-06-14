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

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// fakeUploader is an in-memory dsseUploader the push tests substitute for the
// real Archivista client. It records the envelope and returns a fixed gitoid.
type fakeUploader struct {
	gitoid string
	err    error
	stored *dsse.Envelope
}

func (f *fakeUploader) Store(_ context.Context, env dsse.Envelope) (string, error) {
	e := env
	f.stored = &e
	return f.gitoid, f.err
}

// installFakeUploader swaps newArchivistaUploader for the test and restores it.
func installFakeUploader(t *testing.T, up *fakeUploader) {
	t.Helper()
	orig := newArchivistaUploader
	newArchivistaUploader = func(_, _ string) dsseUploader { return up }
	t.Cleanup(func() { newArchivistaUploader = orig })
}

// stubSession writes a credential for platformURL into an isolated store, so
// auth.Lookup resolves a token + tenant without touching the real store.
func stubSession(t *testing.T, platformURL string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	if err := auth.Save(auth.Credential{
		PlatformURL: platformURL,
		Token:       "test-session-token",
		AuthMode:    auth.AuthModeToken,
		TenantID:    "tenant-9",
		TenantName:  "Acme",
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}
}

// writeSignedPolicyFile writes a JSON-encoded dsse.Envelope (the exact format
// `cilock sign -o` produces) to disk.
func writeSignedPolicyFile(t *testing.T, dir string, sigs int) string {
	t.Helper()
	env := dsse.Envelope{
		Payload:     []byte(`{"expires":"2030-01-01T00:00:00Z","steps":{}}`),
		PayloadType: "https://witness.testifysec.com/policy/v0.1",
	}
	for i := 0; i < sigs; i++ {
		env.Signatures = append(env.Signatures, dsse.Signature{KeyID: "k", Signature: []byte("sig")})
	}
	b, err := json.Marshal(&env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	path := filepath.Join(dir, "policy.signed.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

// policyTestServer is an httptest server that serves the discovery doc (pointing
// graphql/archivista back at itself) and routes GraphQL ops to recorded handlers
// keyed by a substring of the operation.
type policyTestServer struct {
	*httptest.Server
	// requests records every GraphQL op name seen, in order.
	requests []string
}

// newPolicyTestServer wires a discovery doc + a GraphQL handler. The handler is
// given the parsed body and writes the response; it should return true when it
// handled the op.
func newPolicyTestServer(t *testing.T, handle func(query string, vars map[string]any, w http.ResponseWriter) bool) *policyTestServer {
	t.Helper()
	pts := &policyTestServer{}
	mux := http.NewServeMux()
	pts.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/judge-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"archivista_url":"`+pts.URL+`/archivista","graphql_url":"`+pts.URL+`/query"}`)
	})
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.Unmarshal(body, &req)
		pts.requests = append(pts.requests, req.Query)
		if !handle(req.Query, req.Variables, w) {
			t.Errorf("unhandled GraphQL op: %s", req.Query)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	t.Cleanup(pts.Close)
	return pts
}

// runCmd executes a cobra command with args, capturing stdout/stderr.
func runCmd(t *testing.T, cmd interface {
	SetArgs([]string)
	SetOut(io.Writer)
	SetErr(io.Writer)
	ExecuteContext(context.Context) error
}, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd.SetArgs(args)
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.ExecuteContext(context.Background())
	return buf.String(), err
}

func TestPolicyPush_CreatesDefinitionAndRelease(t *testing.T) {
	var releaseInput map[string]any
	var createdDef bool
	srv := newPolicyTestServer(t, func(q string, vars map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockDsseByGitoid"):
			_, _ = io.WriteString(w, `{"data":{"dsses":{"edges":[{"node":{"id":"dsse-uuid-1","gitoidSha256":"gitoid-abc"}}]}}}`)
		case strings.Contains(q, "CilockPolicyDefByName"):
			// Not found → push must create it.
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[]}}}`)
		case strings.Contains(q, "CilockCreatePolicyDef"):
			createdDef = true
			_, _ = io.WriteString(w, `{"data":{"createPolicyDefinition":{"id":"def-new","name":"supply-chain"}}}`)
		case strings.Contains(q, "CilockCreatePolicyRelease"):
			releaseInput, _ = vars["input"].(map[string]any)
			_, _ = io.WriteString(w, `{"data":{"createPolicyRelease":{"id":"rel-1","tag":"v1.0.0"}}}`)
		default:
			return false
		}
		return true
	})

	stubSession(t, srv.URL)
	up := &fakeUploader{gitoid: "gitoid-abc"}
	installFakeUploader(t, up)

	dir := t.TempDir()
	file := writeSignedPolicyFile(t, dir, 1)

	out, err := runCmd(t, PolicyPushCmd(),
		"--file", file, "--definition", "supply-chain", "--tag", "v1.0.0", "--platform-url", srv.URL)
	if err != nil {
		t.Fatalf("push: %v\noutput:\n%s", err, out)
	}
	if !createdDef {
		t.Error("expected create-if-missing to create the definition")
	}
	if up.stored == nil || len(up.stored.Signatures) != 1 {
		t.Errorf("uploader did not receive the signed envelope: %#v", up.stored)
	}
	// The release must carry the RESOLVED dsse edge id, not the gitoid.
	if releaseInput["dsseID"] != "dsse-uuid-1" {
		t.Errorf("release dsseID = %v, want dsse-uuid-1 (resolved from gitoid)", releaseInput["dsseID"])
	}
	if releaseInput["policyDefinitionID"] != "def-new" {
		t.Errorf("release policyDefinitionID = %v, want def-new", releaseInput["policyDefinitionID"])
	}
	if !strings.Contains(out, "published") {
		t.Errorf("missing success message; got:\n%s", out)
	}
}

func TestPolicyPush_UsesExistingDefinition(t *testing.T) {
	var createdDef bool
	srv := newPolicyTestServer(t, func(q string, _ map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockDsseByGitoid"):
			_, _ = io.WriteString(w, `{"data":{"dsses":{"edges":[{"node":{"id":"dsse-uuid-1"}}]}}}`)
		case strings.Contains(q, "CilockPolicyDefByName"):
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-existing","name":"supply-chain"}}]}}}`)
		case strings.Contains(q, "CilockCreatePolicyDef"):
			createdDef = true
			_, _ = io.WriteString(w, `{"data":{"createPolicyDefinition":{"id":"x"}}}`)
		case strings.Contains(q, "CilockCreatePolicyRelease"):
			_, _ = io.WriteString(w, `{"data":{"createPolicyRelease":{"id":"rel-1","tag":"v2"}}}`)
		default:
			return false
		}
		return true
	})
	stubSession(t, srv.URL)
	installFakeUploader(t, &fakeUploader{gitoid: "g"})
	file := writeSignedPolicyFile(t, t.TempDir(), 1)

	out, err := runCmd(t, PolicyPushCmd(),
		"-f", file, "-d", "supply-chain", "-t", "v2", "--platform-url", srv.URL)
	if err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if createdDef {
		t.Error("must NOT create a definition that already exists")
	}
}

func TestPolicyPush_RejectsUnsignedPolicy(t *testing.T) {
	srv := newPolicyTestServer(t, func(string, map[string]any, http.ResponseWriter) bool { return true })
	stubSession(t, srv.URL)
	installFakeUploader(t, &fakeUploader{gitoid: "g"})
	file := writeSignedPolicyFile(t, t.TempDir(), 0) // zero signatures

	_, err := runCmd(t, PolicyPushCmd(),
		"-f", file, "-d", "d", "-t", "v1", "--platform-url", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("want unsigned-policy error, got %v", err)
	}
}

func TestPolicyPush_ScopeDeniedSurfacesRemedy(t *testing.T) {
	srv := newPolicyTestServer(t, func(q string, _ map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockDsseByGitoid"):
			_, _ = io.WriteString(w, `{"data":{"dsses":{"edges":[{"node":{"id":"dsse-1"}}]}}}`)
		case strings.Contains(q, "CilockPolicyDefByName"):
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-1","name":"d"}}]}}}`)
		case strings.Contains(q, "CilockCreatePolicyRelease"):
			_, _ = io.WriteString(w, `{"errors":[{"message":"missing required scope \"policy:write\""}]}`)
		default:
			return false
		}
		return true
	})
	stubSession(t, srv.URL)
	installFakeUploader(t, &fakeUploader{gitoid: "g"})
	file := writeSignedPolicyFile(t, t.TempDir(), 1)

	_, err := runCmd(t, PolicyPushCmd(),
		"-f", file, "-d", "d", "-t", "v1", "--platform-url", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "cilock login") {
		t.Fatalf("want scope-denied remedy, got %v", err)
	}
}

func TestPolicyPush_RequiresFlags(t *testing.T) {
	// Missing required --file/--definition/--tag → cobra rejects before RunE.
	_, err := runCmd(t, PolicyPushCmd(), "--definition", "d", "--tag", "v1")
	if err == nil || !strings.Contains(err.Error(), "file") {
		t.Fatalf("want required-flag error for --file, got %v", err)
	}
}

func TestPolicyBind_ResolvesTagAndBinds(t *testing.T) {
	var bindInput map[string]any
	srv := newPolicyTestServer(t, func(q string, vars map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockPolicyDefByName"):
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-1","name":"supply-chain"}}]}}}`)
		case strings.Contains(q, "CilockReleaseByTag"):
			_, _ = io.WriteString(w, `{"data":{"policyReleases":{"edges":[{"node":{"id":"rel-7","tag":"v1.0.0"}}]}}}`)
		case strings.Contains(q, "CilockProductByID"):
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[]}}}`) // miss → fall to name
		case strings.Contains(q, "CilockProductByName"):
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[{"node":{"id":"prod-1","name":"svc"}}]}}}`)
		case strings.Contains(q, "CilockCreatePolicyBinding"):
			bindInput, _ = vars["input"].(map[string]any)
			_, _ = io.WriteString(w, `{"data":{"createPolicyBinding":{"id":"bind-1","policyDefinition":{"id":"def-1","name":"supply-chain"},"policyRelease":{"id":"rel-7","tag":"v1.0.0"},"product":{"id":"prod-1","name":"svc"}}}}`)
		default:
			return false
		}
		return true
	})
	stubSession(t, srv.URL)

	out, err := runCmd(t, PolicyBindCmd(),
		"--definition", "supply-chain", "--tag", "v1.0.0", "--product", "svc", "--platform-url", srv.URL)
	if err != nil {
		t.Fatalf("bind: %v\n%s", err, out)
	}
	if bindInput["policyDefinitionID"] != "def-1" {
		t.Errorf("binding policyDefinitionID = %v, want def-1", bindInput["policyDefinitionID"])
	}
	if bindInput["policyReleaseID"] != "rel-7" {
		t.Errorf("binding policyReleaseID = %v, want rel-7 (resolved from tag)", bindInput["policyReleaseID"])
	}
	if bindInput["productID"] != "prod-1" {
		t.Errorf("binding productID = %v, want prod-1", bindInput["productID"])
	}
	if !strings.Contains(out, "bound") {
		t.Errorf("missing success message; got:\n%s", out)
	}
}

func TestPolicyBind_MissingDefinitionErrors(t *testing.T) {
	srv := newPolicyTestServer(t, func(q string, _ map[string]any, w http.ResponseWriter) bool {
		if strings.Contains(q, "CilockPolicyDefByName") {
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[]}}}`)
			return true
		}
		return false
	})
	stubSession(t, srv.URL)

	_, err := runCmd(t, PolicyBindCmd(),
		"--definition", "ghost", "--product", "svc", "--platform-url", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "no policy definition") {
		t.Fatalf("want missing-definition error, got %v", err)
	}
}

func TestPolicyBind_MissingTagErrors(t *testing.T) {
	srv := newPolicyTestServer(t, func(q string, _ map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockPolicyDefByName"):
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-1","name":"d"}}]}}}`)
			return true
		case strings.Contains(q, "CilockReleaseByTag"):
			_, _ = io.WriteString(w, `{"data":{"policyReleases":{"edges":[]}}}`)
			return true
		}
		return false
	})
	stubSession(t, srv.URL)

	_, err := runCmd(t, PolicyBindCmd(),
		"-d", "d", "-t", "v9", "--product", "svc", "--platform-url", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "no release tagged") {
		t.Fatalf("want missing-tag error, got %v", err)
	}
}

func TestPolicyBind_NotLoggedIn(t *testing.T) {
	// Isolated empty store → no session for the platform.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))

	_, err := runCmd(t, PolicyBindCmd(),
		"-d", "d", "--product", "svc", "--platform-url", "https://platform.example.test")
	if err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("want not-logged-in error, got %v", err)
	}
}
