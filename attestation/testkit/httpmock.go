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

package testkit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// metadataEndpointEnv is the standard AWS SDK env var that overrides the EC2
// Instance Metadata Service base URL. The aws-iid attestor builds its IMDS
// client via config.LoadDefaultConfig/imds.NewFromConfig, which honor it — so
// pointing it at our httptest server replays recorded IMDS responses without a
// single line of attestor change. (GCP's metadata client honors
// GCE_METADATA_HOST; add that env when wiring the gcp-iit fixture.)
const metadataEndpointEnv = "AWS_EC2_METADATA_SERVICE_ENDPOINT"

// IMDS request paths the EC2 metadata service exposes. The AWS SDK does a
// PUT /latest/api/token (IMDSv2) then GET /latest/dynamic/<path> for dynamic
// data; the aws-iid attestor reads instance-identity/document and
// instance-identity/signature.
const (
	imdsTokenPath    = "/latest/api/token"
	imdsDocumentPath = "/latest/dynamic/instance-identity/document"
	imdsSigPath      = "/latest/dynamic/instance-identity/signature"
)

// Fixture option keys for the AWS-IMDS http-mock special case. Values are paths
// (relative to the fixture dir) to the committed recorded IMDS responses,
// captured from a real node. document + signature are REQUIRED; token is
// optional (a fixed stub is served when absent — the token's bytes don't affect
// the attestor output). Their presence selects the IMDS-shaped server below.
const (
	optIMDSDocument  = "imds_document"
	optIMDSSignature = "imds_signature"
	optIMDSToken     = "imds_token"
)

// optEndpoints is the generalized http-mock option key. Its value is a list of
// {env|option, file, path} entries: the driver serves each committed `file` at
// `path` on the stub server and then routes the attestor at the stub via ONE of
// two binding kinds:
//
//   - env:    set the env var named `env` to the stub base URL + `path`. For
//     attestors that read a FULL service URL from an env var — github's OIDC
//     token endpoint (ACTIONS_ID_TOKEN_REQUEST_URL) + JWKS
//     (WITNESS_GITHUB_JWKS_URL), gitlab's JWKS, etc.
//   - option: set the attestor's registered config OPTION named `option` to the
//     stub BASE URL (no path appended — the attestor owns its paths). For
//     attestors whose API base is a flag/option, NOT an env var —
//     github-review's --attestor-github-review-api-url is the motivating case:
//     it reads defaultAPIBaseURL from the `api-url` option and appends
//     repos/<repo>/pulls/<n>[/reviews] itself, so the fixture serves those
//     recorded paths and binds the base via the option. The recorded reviews
//     JSON is still the real evidence; this seam only points the real HTTP
//     client at the replay server, exactly as the env kind does for github.
//
// It is the config-driven sibling of the AWS-IMDS special case above: AWS's SDK
// IMDS client builds fixed paths off ONE base-URL env var (so the AWS branch
// hard-codes the three IMDS paths), whereas these attestors read a FULL URL
// (base+path) from each env var, so the path lives in the fixture.
const optEndpoints = "endpoints"

// mockEndpoint is one generalized http-mock endpoint binding (see optEndpoints).
// Exactly one of Env / Option must be set: Env binds the stub URL (base+path) to
// an env var the attestor reads; Option binds the stub BASE URL to a registered
// attestor config option (the attestor appends its own paths).
type mockEndpoint struct {
	Env    string `yaml:"env"`    // env var the attestor reads the endpoint URL from
	Option string `yaml:"option"` // attestor config option the stub BASE URL binds to
	File   string `yaml:"file"`   // committed response file, relative to the fixture dir
	Path   string `yaml:"path"`   // path served on the stub (defaults to "/" + File's base)
}

// startHTTPMock stands up the http-mock server for a fixture and applies all
// env it implies. It dispatches on the fixture's options:
//   - AWS-IMDS special case (imds_document/imds_signature present): an
//     IMDS-shaped server, pointed at via AWS_EC2_METADATA_SERVICE_ENDPOINT.
//   - generalized `endpoints`: serve each committed file at its path and set
//     each declared env var to the stub base URL + path.
//
// In BOTH cases the fixture's plain setup.env is applied too (combine env +
// endpoints), so an attestor that reads both plain GITHUB_*/RUNNER_* vars and
// endpoint URLs (github) is fully driven. Order is deterministic; the endpoint
// env vars are set last so they win over any same-named plain env.
//
// It returns the attestor-OPTION bindings implied by any `option:` endpoints —
// a map of option name -> stub base URL — for the caller to apply to the
// constructed attestor via attestation.ApplyAttestorOptions (env bindings are
// applied here in-process; option bindings can't be, because the attestor isn't
// built yet at this point). The IMDS special case and env-only fixtures return
// an empty map.
func startHTTPMock(t *testing.T, fx *Fixture) map[string]any {
	t.Helper()

	// Plain env first (verbatim runner/cloud context the attestor reads).
	for k, v := range fx.Env {
		t.Setenv(k, v)
	}

	// AWS-IMDS special case — kept intact for back-compat with the aws-iid
	// fixture, which declares imds_document/imds_signature options.
	if _, ok := fx.Options[optIMDSDocument]; ok {
		srv := startMetadataMock(t, fx)
		t.Setenv(metadataEndpointEnv, srv.URL)
		return nil
	}

	// Generalized endpoints model.
	eps := parseEndpoints(t, fx)
	if len(eps) == 0 {
		t.Fatalf("testkit: http-mock fixture %q declares neither imds_document nor setup.options.endpoints — nothing to serve", fx.Name)
	}

	mux := http.NewServeMux()
	type envBinding struct {
		env  string
		path string
	}
	var envBindings []envBinding
	var optionNames []string
	for _, ep := range eps {
		body := readFixtureFile(t, fx, ep.File)
		path := ep.Path
		if path == "" {
			path = "/" + filepath.Base(ep.File)
		}
		// Serve the file regardless of method / query string / auth header (the
		// github token endpoint is hit with ?audience=witness + a bearer; the
		// github-review reviews endpoint with ?per_page=100). A fresh closure var
		// per iteration avoids the classic loop-capture bug.
		b := body
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(b)
		})
		if ep.Option != "" {
			optionNames = append(optionNames, ep.Option)
		} else {
			envBindings = append(envBindings, envBinding{env: ep.Env, path: path})
		}
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Point each declared env var at the stub base URL + that endpoint's path.
	for _, b := range envBindings {
		t.Setenv(b.env, srv.URL+b.path)
	}

	// Bind each declared attestor option to the stub BASE URL (the attestor
	// appends its own request paths). Returned for the caller to apply once the
	// attestor is constructed.
	if len(optionNames) == 0 {
		return nil
	}
	optBindings := make(map[string]any, len(optionNames))
	for _, name := range optionNames {
		optBindings[name] = srv.URL
	}
	return optBindings
}

// startMetadataMock stands up an httptest server that replays the fixture's
// committed recorded IMDS responses and returns it (auto-closed at test end).
// It serves exactly the three endpoints the AWS SDK touches; any other path is
// a 404 so a fixture that points the attestor at the wrong path fails loudly
// rather than silently returning empty evidence.
func startMetadataMock(t *testing.T, fx *Fixture) *httptest.Server {
	t.Helper()

	doc := readMockFile(t, fx, optIMDSDocument, true)
	sig := readMockFile(t, fx, optIMDSSignature, true)
	token := readMockFile(t, fx, optIMDSToken, false)
	if token == nil {
		token = []byte("AQAEAExAMPLEtokenFORtestkitHTTPmockONLY=") // not secret — a stub IMDSv2 token
	}

	mux := http.NewServeMux()
	mux.HandleFunc(imdsTokenPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write(token)
	})
	mux.HandleFunc(imdsDocumentPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(doc)
	})
	mux.HandleFunc(imdsSigPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// parseEndpoints reads setup.options.endpoints into typed bindings, failing the
// test fatally on a malformed manifest. It is a thin t.Fatalf wrapper around the
// pure decodeEndpoints (which holds the validation logic so it is unit-testable
// without a *testing.T fatal).
func parseEndpoints(t *testing.T, fx *Fixture) []mockEndpoint {
	t.Helper()
	eps, err := decodeEndpoints(fx)
	if err != nil {
		t.Fatalf("testkit: %v", err)
	}
	return eps
}

// decodeEndpoints validates and decodes setup.options.endpoints. The YAML
// decodes options as []any of map[string]any, so we re-encode/decode through a
// small typed pass to keep the fixture struct generic. A missing/empty list
// returns (nil, nil); a malformed entry returns an error — the fixture is
// broken. Each entry needs a non-empty file and EXACTLY ONE of env / option
// (env binds a full URL to an env var; option binds the base URL to an attestor
// config option).
func decodeEndpoints(fx *Fixture) ([]mockEndpoint, error) {
	raw, ok := fx.Options[optEndpoints]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("http-mock fixture %q setup.options.endpoints must be a list", fx.Name)
	}
	var out []mockEndpoint
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("http-mock fixture %q endpoints[%d] must be a mapping {env|option,file,path}", fx.Name, i)
		}
		ep := mockEndpoint{
			Env:    asString(m["env"]),
			Option: asString(m["option"]),
			File:   asString(m["file"]),
			Path:   asString(m["path"]),
		}
		if ep.File == "" {
			return nil, fmt.Errorf("http-mock fixture %q endpoints[%d] requires non-empty file", fx.Name, i)
		}
		// Exactly one of env / option binds the stub to the attestor.
		switch {
		case ep.Env == "" && ep.Option == "":
			return nil, fmt.Errorf("http-mock fixture %q endpoints[%d] requires exactly one of env (URL→env var) or option (base URL→attestor option); got neither", fx.Name, i)
		case ep.Env != "" && ep.Option != "":
			return nil, fmt.Errorf("http-mock fixture %q endpoints[%d] sets both env=%q and option=%q — choose one binding kind", fx.Name, i, ep.Env, ep.Option)
		}
		out = append(out, ep)
	}
	return out, nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// readFixtureFile reads a committed response file (relative to the fixture dir)
// for the generalized endpoints model; a missing file is fatal.
func readFixtureFile(t *testing.T, fx *Fixture, rel string) []byte {
	t.Helper()
	p := filepath.Join(fx.Dir, rel)
	raw, err := os.ReadFile(p) //nolint:gosec // path from the fixture manifest, not user input
	if err != nil {
		t.Fatalf("testkit: http-mock read endpoint file %s: %v", p, err)
	}
	return raw
}

// readMockFile resolves an http-mock option to a committed file under the
// fixture dir and reads it. required=true makes a missing option/file a fatal
// (the fixture is malformed); required=false returns nil when the option is
// absent.
func readMockFile(t *testing.T, fx *Fixture, key string, required bool) []byte {
	t.Helper()
	rel, ok := fx.Options[key].(string)
	if !ok || rel == "" {
		if required {
			t.Fatalf("testkit: http-mock fixture %q missing required setup.options.%s (path to the recorded IMDS response)", fx.Name, key)
		}
		return nil
	}
	p := filepath.Join(fx.Dir, rel)
	raw, err := os.ReadFile(p) //nolint:gosec // path from the fixture manifest, not user input
	if err != nil {
		t.Fatalf("testkit: http-mock read %s (%s): %v", key, p, err)
	}
	return raw
}
