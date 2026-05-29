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

// Fixture option keys for the http-mock mode. Values are paths (relative to the
// fixture dir) to the committed recorded IMDS responses, captured from a real
// node. document + signature are REQUIRED; token is optional (a fixed stub is
// served when absent — the token's bytes don't affect the attestor output).
const (
	optIMDSDocument  = "imds_document"
	optIMDSSignature = "imds_signature"
	optIMDSToken     = "imds_token"
)

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
